# SPDX-License-Identifier: GPL-3.0-or-later
"""Every command the README shows must be one the CLI accepts.

The release branch's own Quick Start was substantially fictional. Checked by
extracting each command and running it, not by reading:

  four global options that do not exist   --dry-run, --quiet, --verbose, --target
  six commands that do not exist          wifi deauth, wifi list, wifi status,
                                          wifi capture, wizard first, scan -t
  two wrong invocation forms              wifi monitor on / off, where the real
                                          option is --action start / stop
  three shown with no arguments           wifi scan, wifi handshake, wifi auto,
                                          under the claim "NETREAPER resolves
                                          interface, monitor mode and target
                                          itself". All three exit 2.

The claim was not idle: AutoIfaceHandler in automation/handlers/iface.py does
exactly that, and enumerates wireless interfaces properly. It is referenced only
from tui/helpers/preflight_runner.py, itself on the inert preflight path, and
cli.py never touches it. So the README described the intended design, the
capability was built, and no path joined them: the same defect this codebase
keeps producing, this time on the page a new operator reads first.

This guard extracts every `netreaper ...` line from the README and asserts the
CLI parses it. Exit 2 is the failure: Click's usage error, which covers "no such
command", "no such option" and "missing argument". Any other exit code is fine,
because a command that parses and then refuses for want of an engagement or a
real interface has still been documented correctly.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest
from typer.testing import CliRunner

from netreaper.cli import app

README = Path(__file__).resolve().parents[2] / "README.md"

# Commands shown deliberately with a placeholder (<if>, <bssid>) cannot be run
# literally. They are checked for the command PATH only, with the placeholders
# dropped, so `netreaper wifi wep <if> <bssid> <ch> --injection chopchop` still
# proves that `wifi wep` and `--injection` exist.
_PLACEHOLDER = re.compile(r"<[^>]+>")

# Invocations that launch the interactive TUI instead of returning. Checked
# with --help rather than executed; see the branch in the test below.
_INTERACTIVE: frozenset[tuple[str, ...]] = frozenset({(), ("tui",)})


def documented_commands() -> list[str]:
    text = README.read_text(encoding="utf-8")
    # join shell line-continuations first, or a multi-line example is missed
    joined = re.sub(r"\\\n\s*", " ", text)
    found: list[str] = []
    for raw in re.findall(
        r"^\s*(?:\$\s*)?(?:sudo\s+)?(netreaper\b[^\n#]*)", joined, re.M
    ):
        cmd = raw.strip()
        if cmd and cmd not in found:
            found.append(cmd)
    return found


def _argv(cmd: str) -> list[str] | None:
    cmd = _PLACEHOLDER.sub("", cmd)
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return None
    return [p for p in parts if p != "netreaper"]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    """Keep the engagement file out of the real config dir."""
    from netreaper.safety import engagement_store
    from netreaper.safety.scope import get_scope_gate

    monkeypatch.setattr(
        engagement_store, "engagement_file_path", lambda: tmp_path / "engagement.json"
    )
    get_scope_gate().clear_engagement()
    yield
    get_scope_gate().clear_engagement()


def test_the_readme_documents_a_plausible_number_of_commands():
    """If extraction breaks, every assertion below passes for nothing."""
    cmds = documented_commands()
    assert len(cmds) > 15, f"only found {len(cmds)} commands; extraction is broken"


def _plain(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


@pytest.mark.parametrize("cmd", documented_commands(), ids=lambda c: c[:48])
def test_a_documented_command_is_one_the_cli_accepts(cmd):
    argv = _argv(cmd)
    if argv is None:
        pytest.skip(f"not shell-parseable as shown: {cmd}")

    runner = CliRunner()

    # A command shown with a placeholder (`wifi wep <if> <bssid> <ch>`) cannot
    # be run literally, so arity is not the question for it: whether the
    # command path and the options exist is. Checked through --help, which
    # answers both without needing values.
    if _PLACEHOLDER.search(cmd):
        path = [a for a in argv if not a.startswith("-")]
        options = [a.split("=")[0] for a in argv if a.startswith("--")]
        result = runner.invoke(app, [*path, "--help"])
        assert result.exit_code == 0, (
            f"README documents `{cmd}`, but `{' '.join(path)}` is not a command:\n"
            + _plain(result.output).strip()[:200]
        )
        help_text = _plain(result.output)
        missing = [o for o in options if o not in help_text]
        assert not missing, (
            f"README documents `{cmd}`, but `{' '.join(path)}` has no "
            f"{', '.join(missing)} option"
        )
        return

    # A command that STARTS AN INTERACTIVE SESSION never returns. Bare
    # `netreaper` and `netreaper tui` both launch the Textual application,
    # which blocks on its own asyncio event loop waiting for a terminal
    # CliRunner does not provide. The suite then HANGS rather than fails, and
    # in CI that burns the entire six-hour job limit before anything reports.
    #
    # Not hypothetical: the v12.0.0 README truth-up added exactly these two
    # lines, and main sat hung for two days, because a documentation-only
    # change looks incapable of breaking a test. In this repository it is not,
    # precisely because this file executes the README.
    #
    # They are still checked, with --help appended, which walks the same
    # command path and exits without starting the app, so a typo like
    # `netreaper tuii` still fails here. Bare `netreaper` is the application
    # itself and has no command path left to resolve.
    if tuple(argv) in _INTERACTIVE:
        if not argv:
            return
        result = runner.invoke(app, [*argv, "--help"])
        assert result.exit_code == 0, (
            f"README documents `{cmd}`, but `{' '.join(argv)}` is not a command:\n"
            + _plain(result.output).strip()[:200]
        )
        return

    result = runner.invoke(app, argv)

    if result.exit_code != 2:
        return  # parsed; refusing later for want of an engagement is fine

    # Click exits 2 for a usage error, but this CLI also raises typer.Exit(2)
    # for a scope-gate denial, and `wifi auto -i wlan0mon --run` does exactly
    # that: it resolves its four-step plan correctly and is then refused because
    # wlan0mon is not a real adapter on this machine. That is the command
    # working. So only a recognised PARSE signature counts as a failure here.
    out = _plain(result.output)
    reason = None
    for pattern in (
        r"No such command '[^']*'",
        r"No such option: \S+",
        r"Missing argument '[^']*'",
        r"Missing option '[^']*'",
        r"Got unexpected extra argument[^\n]*",
        # An action passed as a free `str` argument: Click accepts any string,
        # so `wifi monitor start` and `config reset` were documented for
        # releases while being no more real than a misspelt command. They are
        # usage errors now, and this is the signature.
        r"is not a valid [a-z ]+",
        r"needs a key[^\n]*",
    ):
        m = re.search(pattern, out)
        if m:
            reason = m.group(0)
            break
    if reason is None:
        return  # parsed, then refused on its own terms

    raise AssertionError(
        f"README documents `{cmd}`, which the CLI rejects: {reason}\n"
        f"Either fix the README or wire the command. A front page that shows "
        f"commands the tool does not have is worse than no front page: it is "
        f"the first thing a new operator tries."
    )


def test_the_check_can_actually_detect_a_bad_command():
    """Negative control. Without this the guard could pass vacuously."""
    runner = CliRunner()
    result = runner.invoke(app, ["wifi", "definitely-not-a-command"])
    assert result.exit_code == 2, "usage errors no longer exit 2; the guard is blind"
