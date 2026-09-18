# SPDX-License-Identifier: GPL-3.0-or-later
"""Controls that reported success and changed nothing.

Six of them, in two subsystems, all the same shape: a function that returns
True regardless, a flag nothing reads, a config field nothing enforces. The
pattern matters more than any single instance, because a control that fails
loudly gets fixed and a control that reports success gets trusted.

  delete_key()        returned True unconditionally. "No such entry" and "the
                      keyring is locked / unreachable / refused" went through
                      the same handler. An operator revoking a compromised key
                      was told it was cleared while it sat in the keyring.
  delete_secret()     the same, with `except Exception: pass` and no log at any
                      level, so there was not even a trace to find afterwards.
  _clear_api_key()    discarded the return value entirely and printed green.
  set_secret()        fell back to volatile memory silently. set_key() warned
                      in the same situation; this one said nothing at all.
  registry.disable()  set a flag get_instance() never read, so a plugin the
                      operator had explicitly disabled still loaded and ran.
  PluginConfig.timeout declared and read by nothing, while initialize() was
                      awaited with no deadline of any kind.

And one leak waiting on a gap being closed: ToolContext held the API key as a
bare field on a plain dataclass, while core/logging.py configures RichHandler
with tracebacks_show_locals=True. That path is inert only because
setup_logging() has no caller.
"""
from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"


# ── revocation must be trustworthy ───────────────────────────────────────────


@pytest.fixture
def manager(monkeypatch):
    from netreaper.config.keys import APIKeyManager

    m = APIKeyManager()
    monkeypatch.setattr(m, "_check_keyring", lambda: True)
    return m


def _fake_keyring(monkeypatch, delete_raises: Exception | None):
    import sys
    import types

    mod = types.ModuleType("keyring")

    def delete_password(service, name):
        if delete_raises is not None:
            raise delete_raises

    mod.delete_password = delete_password
    mod.set_password = lambda *a: None
    mod.get_password = lambda *a: None
    monkeypatch.setitem(sys.modules, "keyring", mod)


def test_a_refusing_keyring_is_reported_as_a_failed_deletion(manager, monkeypatch):
    """The case that breaks revocation: the entry is still there."""
    from netreaper.config.keys import APIService

    _fake_keyring(monkeypatch, RuntimeError("the collection is locked"))
    service = next(iter(APIService))
    assert manager.delete_key(service) is False, (
        "a keyring that refused the delete was reported to the operator as a "
        "successful revocation"
    )


def test_a_missing_entry_is_still_a_successful_deletion(manager, monkeypatch):
    """Deleting a key that was never stored is not a failure.

    Without this the fix would swing the other way and cry wolf on every clear
    of an unset key, which trains an operator to ignore the message.
    """
    from netreaper.config.keys import APIService

    _fake_keyring(monkeypatch, RuntimeError("Password not found in keyring"))
    service = next(iter(APIService))
    assert manager.delete_key(service) is True


def test_a_clean_deletion_succeeds(manager, monkeypatch):
    from netreaper.config.keys import APIService

    _fake_keyring(monkeypatch, None)
    assert manager.delete_key(next(iter(APIService))) is True


def test_delete_secret_reports_a_refusal_too(manager, monkeypatch):
    from netreaper.config.keys import APIService

    _fake_keyring(monkeypatch, RuntimeError("dbus unavailable"))
    assert manager.delete_secret(next(iter(APIService))) is False


def test_the_settings_screen_acts_on_the_result_of_delete_key():
    """It printed green without looking. AST, so a comment cannot satisfy it."""
    tree = ast.parse((SRC / "tui" / "screens" / "settings.py").read_text(encoding="utf-8"))
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef) or fn.name != "_clear_api_key":
            continue
        # a bare `api_key_manager.delete_key(...)` as a statement is the bug
        for node in ast.walk(fn):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                called = getattr(node.value.func, "attr", None)
                assert called != "delete_key", (
                    "_clear_api_key calls delete_key and discards the result, "
                    "then tells the operator the key was cleared"
                )
        assert any(isinstance(n, ast.If) for n in ast.walk(fn)), (
            "_clear_api_key has no branch, so it cannot be reporting both outcomes"
        )
        return
    raise AssertionError("_clear_api_key not found")


# ── the secret must not print itself ─────────────────────────────────────────


def test_the_api_key_is_not_in_the_tool_context_repr():
    from netreaper.tui.helpers.preflight_runner import ToolContext

    ctx = ToolContext(tool="nmap")
    ctx.api_key = "SUPERSECRETKEY"
    assert "SUPERSECRETKEY" not in repr(ctx), (
        "a plain dataclass prints every field, and logging is configured with "
        "tracebacks_show_locals=True"
    )
    assert ctx.api_key == "SUPERSECRETKEY", "repr=False must not break the value"


# ── a disabled plugin is disabled ────────────────────────────────────────────


def test_a_disabled_plugin_refuses_to_load():
    from netreaper.core.exceptions import PluginError
    from netreaper.plugins.registry import PluginRegistry

    r = PluginRegistry()
    r._registry["demo"] = type(
        "RP", (), {"group": "netreaper.tools", "enabled": True, "name": "demo"}
    )()
    r.disable("demo")

    with pytest.raises(PluginError, match="disabled"):
        asyncio.run(r.get_instance("demo"))


def test_enable_undoes_disable():
    """The control must work in both directions, or it is just a kill switch."""
    from netreaper.core.exceptions import PluginError
    from netreaper.plugins.registry import PluginRegistry

    r = PluginRegistry()
    r._registry["demo"] = type(
        "RP", (), {"group": "netreaper.tools", "enabled": True, "name": "demo"}
    )()
    r.disable("demo")
    r.enable("demo")
    # It should now get past the enabled check and fail for a different reason
    # (no such entry point), which is what proves the check was passed.
    with pytest.raises(Exception) as excinfo:
        asyncio.run(r.get_instance("demo"))
    assert "disabled" not in str(excinfo.value).lower(), (
        "enable() did not undo disable()"
    )
    assert isinstance(excinfo.value, (PluginError, KeyError))


# ── structural guards on the two dead declarations ───────────────────────────


def test_the_plugin_load_timeout_is_enforced_not_merely_declared():
    """PluginConfig.timeout existed and nothing read it."""
    src = (SRC / "plugins" / "discovery.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef) or fn.name != "load_plugin":
            continue
        calls = {
            getattr(n.func, "attr", None) or getattr(n.func, "id", None)
            for n in ast.walk(fn)
            if isinstance(n, ast.Call)
        }
        assert "wait_for" in calls, (
            "load_plugin awaits initialize() with no deadline; a plugin whose "
            "initialize() never returns hangs the caller for ever"
        )
        return
    raise AssertionError("load_plugin not found")


def test_a_duplicate_entry_point_name_is_refused_not_silently_shadowed():
    """entry_points() returns declarations from EVERY installed distribution.

    A plain dict assignment meant a second package registering the name "nmap"
    replaced the first-party adapter, with iteration order deciding which one
    the operator actually ran, and nothing logged.
    """
    src = (SRC / "plugins" / "discovery.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef) or fn.name != "_discover_group":
            continue
        has_membership_test = any(
            isinstance(n, ast.Compare)
            and any(isinstance(op, ast.In) for op in n.ops)
            for n in ast.walk(fn)
        )
        assert has_membership_test, (
            "_discover_group assigns plugins[ep.name] with no collision check"
        )
        return
    raise AssertionError("_discover_group not found")
