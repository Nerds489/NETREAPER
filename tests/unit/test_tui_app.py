# SPDX-License-Identifier: GPL-3.0-or-later
"""The TUI, driven headlessly. Its first test of any kind.

``netreaper`` with no subcommand launches the TUI, and that is the documented
primary interface. It had never worked. ``cli.py`` imported
``netreaper.tui.app.run_app``, ``tui/__init__.py`` listed "app.py -
NetreaperApp class" among the package's contents, and the module did not exist
in any branch in the history of the repository. What the operator got was

    Error: TUI dependencies not available: No module named 'netreaper.tui.app'
    Install with: pipx install 'netreaper[tui]'

sending them to install an extra that could not have helped, because the
environment was complete and the code was not.

Nothing caught it. The reachability guard walks the package and asserts every
module imports, and a module that does not exist is not walked. The per-command
smoke test exempted `tui` with the reason "launches a full-screen Textual app
and blocks on a real terminal", which was an assumption I wrote without checking
and was false: it blocked on nothing and errored instantly. An exemption
justified by a guess is not an exemption.

So these tests run the real application through Textual's headless pilot. They
open every screen, because three of the five crashed on mount and only running
them showed it.
"""
from __future__ import annotations

import pytest

from netreaper.tui.app import CLI_ONLY, SCREEN_TABLE, NetreaperApp, load_screen

# asyncio_mode = "auto" in pyproject already collects the async tests here; an
# explicit pytestmark also tagged the sync ones and warned on every run.


# ── the module cli.py has always imported ────────────────────────────────────


def test_the_entry_point_cli_imports_actually_exists():
    """cli.py does `from netreaper.tui.app import run_app`. It must resolve."""
    from netreaper.tui.app import run_app

    assert callable(run_app)


def test_launching_the_tui_no_longer_reports_a_dependency_problem(monkeypatch):
    """The old failure blamed the environment for a missing module.

    _launch_tui catches ImportError and tells the operator to install an extra.
    That is the right message for absent Textual and the wrong one for absent
    code, and the two were indistinguishable.
    """
    ran: list[str] = []
    monkeypatch.setattr(NetreaperApp, "run", lambda self, *a, **k: ran.append("ran"))

    from netreaper.cli import _launch_tui

    _launch_tui()
    assert ran == ["ran"], "the TUI entry point did not reach the app"


# ── the app runs ─────────────────────────────────────────────────────────────


async def test_the_app_starts_and_shows_the_main_menu():
    app = NetreaperApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.__class__.__name__ == "MainMenu"
        assert len(app.screen.query_one("#main-menu").children) == len(SCREEN_TABLE)


@pytest.mark.parametrize("screen_id", [row[0] for row in SCREEN_TABLE], ids=lambda s: s)
async def test_every_listed_screen_opens_without_crashing(screen_id):
    """Three of five used to die on mount.

    credentials, traffic and exploit each build a PreflightRunner in on_mount,
    and PreflightRunner's constructor eagerly loaded a module that does not
    exist. Moving that import to "the point of use" moved the crash from import
    time to screen-open time, which from the operator's chair is the same thing.
    """
    app = NetreaperApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.open_operation(screen_id)
        await pilot.pause()
        assert app.screen.__class__.__name__ != "MainMenu", (
            f"{screen_id} did not open"
        )


@pytest.mark.parametrize("screen_id", sorted(CLI_ONLY), ids=lambda s: s)
async def test_an_operation_with_no_screen_explains_itself(screen_id):
    """The command palette offered fourteen entries for five screens.

    The rest fell through a dynamic import into a bare `self.app.bell()`, so a
    third of the menu was a beep with no explanation. A missing screen now names
    the CLI command that does the job.
    """
    app = NetreaperApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.open_operation(screen_id)
        await pilot.pause()
        assert app.screen.__class__.__name__ == "MainMenu"
        assert app._notifications, f"{screen_id} failed silently"


async def test_the_documented_bindings_are_the_real_bindings():
    """screens/help.py promises these to the operator; they must exist."""
    promised = {"ctrl+q", "question_mark", "ctrl+s", "ctrl+w", "ctrl+t", "escape"}
    bound = {b.key for b in NetreaperApp.BINDINGS}
    assert promised <= bound, f"help.py promises {promised - bound} and nothing binds it"


async def test_escape_at_the_root_does_not_leave_a_dead_terminal():
    """Popping the last screen leaves a black window with no way back."""
    app = NetreaperApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        for _ in range(5):
            app.action_back()
            await pilot.pause()
        assert app.screen.__class__.__name__ == "MainMenu"


async def test_the_help_binding_reaches_the_help_screen():
    app = NetreaperApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("question_mark")
        await pilot.pause()
        assert app.screen.__class__.__name__ == "HelpScreen"


async def test_toggling_the_theme_does_not_kill_the_app():
    """Theme names move between Textual releases; a KeyError here is fatal."""
    app = NetreaperApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        for _ in range(3):
            await pilot.press("ctrl+t")
            await pilot.pause()
        assert app.screen.__class__.__name__ == "MainMenu"


# ── the screen table cannot drift from what exists ───────────────────────────


def test_every_table_entry_names_a_screen_that_can_be_built():
    for screen_id, label, module_path, class_name in SCREEN_TABLE:
        screen = load_screen(screen_id)
        assert screen is not None, f"{screen_id} -> {module_path}.{class_name} missing"
        assert label, f"{screen_id} has no label"


def test_an_unknown_operation_returns_none_rather_than_raising():
    assert load_screen("no-such-screen") is None


def test_the_table_and_the_cli_only_list_do_not_overlap():
    overlap = {row[0] for row in SCREEN_TABLE} & set(CLI_ONLY)
    assert not overlap, f"{overlap} is both a real screen and declared CLI-only"


def test_every_command_palette_entry_is_accounted_for():
    """The palette must not offer anything that resolves to neither."""
    import inspect

    from netreaper.tui.commands import tools

    source = inspect.getsource(tools)
    known = {row[0] for row in SCREEN_TABLE} | set(CLI_ONLY) | {
        "quick-scan", "wifi-scan", "stop-all",
    }
    offered = set(
        __import__("re").findall(r'^\s*\("([a-z\-]+)", "[^"]+"', source, __import__("re").M)
    )
    unaccounted = offered - known
    assert not unaccounted, (
        "command palette offers entries that are neither a screen nor a "
        f"declared CLI-only operation: {sorted(unaccounted)}"
    )
