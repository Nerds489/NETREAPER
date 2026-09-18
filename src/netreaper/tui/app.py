# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""The Textual application: the thing every other TUI module was waiting for.

``cli.py`` has always called ``from netreaper.tui.app import run_app`` when
invoked with no subcommand, which is the documented primary interface, and
``tui/__init__.py`` has always listed "app.py - NetreaperApp class" among the
package's contents. The module was never written, in any branch, in the whole
history of the repository. Running ``netreaper`` printed

    Error: TUI dependencies not available: No module named 'netreaper.tui.app'
    Install with: pipx install 'netreaper[tui]'

which sent the operator off to install an extra that could not have helped,
because nothing was missing from the environment. Seven screens, two wizards,
two widgets, a command-palette provider and 582 lines of stylesheet existed with
no application to host any of it.

WHAT THE BINDINGS ARE. Not invented here: ``screens/help.py`` documents them to
the user already (Ctrl+Q quit, Ctrl+P palette, ? help, Ctrl+S scan, Ctrl+W
wireless, Ctrl+T theme, Escape back, j/k navigation). For once the docs in this
repo describe something real and the code is what was missing, so the code is
written to match them rather than the other way round.

WHAT IS HONEST ABOUT THE GAPS. The command palette offers fourteen entries;
screens exist for five of them. The rest resolved through a dynamic import that
failed into a bare ``self.app.bell()``, so a third of the menu was a beep with
no explanation. Anything without a screen now says so and names the CLI command
that does the same job, because "not built yet" is a better answer than a noise.
"""
from __future__ import annotations

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Label, ListItem, ListView, Static

from netreaper import __version__
from netreaper.core.logging import get_logger
from netreaper.tui.commands.tools import NetreaperCommands

logger = get_logger(__name__)

# Screens that exist, as (menu id, label, import path, class name). Driven by a
# table so the menu and the command palette cannot disagree about what is
# available, which is how the palette came to offer nine screens that were never
# written.
SCREEN_TABLE: tuple[tuple[str, str, str, str], ...] = (
    ("traffic", "Traffic Analysis", "netreaper.tui.screens.traffic", "TrafficScreen"),
    (
        "credentials",
        "Credential Attacks",
        "netreaper.tui.screens.credentials",
        "CredentialsScreen",
    ),
    ("exploit", "Exploitation", "netreaper.tui.screens.exploit", "ExploitScreen"),
    ("settings", "Settings", "netreaper.tui.screens.settings", "SettingsScreen"),
    ("help", "Help", "netreaper.tui.screens.help", "HelpScreen"),
)

# Capabilities the CLI has and the TUI does not. Named individually with the
# command that does the job, so the answer is directions rather than a beep.
CLI_ONLY: dict[str, str] = {
    "wireless": "netreaper wifi --help",
    "scan": "netreaper scan --target <cidr>",
    "osint": "netreaper osint subdomains --domain <domain>",
    "recon": "netreaper portscan --target <host>",
    "status": "netreaper status",
    "stress": "not implemented in any interface",
}


def load_screen(screen_id: str) -> Screen | None:
    """Instantiate a screen by its menu id, or None if there is no such screen.

    Returning None rather than raising keeps the caller's decision explicit: the
    palette used to swallow ImportError and AttributeError into a bell, which is
    indistinguishable from a keystroke that did nothing.
    """
    import importlib

    for sid, _label, module_path, class_name in SCREEN_TABLE:
        if sid != screen_id:
            continue
        try:
            module = importlib.import_module(module_path)
            return getattr(module, class_name)()
        except (ImportError, AttributeError, TypeError):
            logger.exception("screen %s is listed but could not be built", screen_id)
            return None
    return None


class MainMenu(Screen):
    """The landing screen: what this tool can do, and how to reach it."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(classes="main-container"):
            with Vertical(classes="sidebar"):
                yield Static("[bold]OPERATIONS[/]", classes="panel-title")
                with ListView(id="main-menu"):
                    for sid, label, _m, _c in SCREEN_TABLE:
                        yield ListItem(
                            Label(label), id=f"menu-{sid}", classes="menu-item"
                        )
            with VerticalScroll(classes="content"):
                yield Static(
                    f"[bold]NETREAPER v{__version__}[/]\n\n"
                    "Select an operation, or press Ctrl+P for the command palette.\n\n"
                    "[dim]Deny-by-default: gated actions need an authorisation "
                    "first.\nRun [/][bold]netreaper engage start --help[/]"
                    "[dim] to set one up.[/]",
                    classes="panel",
                )
        yield Footer()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        self.app.open_operation(item_id.removeprefix("menu-"))

    def action_cursor_down(self) -> None:
        self.query_one("#main-menu", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#main-menu", ListView).action_cursor_up()


class NetreaperApp(App):
    """The application cli.py has been importing since before it existed."""

    TITLE = "NETREAPER"
    SUB_TITLE = "Offensive Security Framework"
    CSS_PATH = "cyberpunk.tcss"
    COMMANDS: ClassVar[set] = App.COMMANDS | {NetreaperCommands}

    BINDINGS: ClassVar[list[Binding]] = [
        # Exactly the shortcuts screens/help.py already promises the operator.
        Binding("ctrl+q", "quit", "Quit"),
        Binding("question_mark", "show_help", "Help"),
        Binding("ctrl+s", "new_scan", "Scan"),
        Binding("ctrl+w", "wireless_menu", "Wireless"),
        Binding("ctrl+t", "toggle_theme", "Theme"),
        Binding("escape", "back", "Back", show=False),
    ]

    def on_mount(self) -> None:
        self.push_screen(MainMenu())

    # ── navigation ───────────────────────────────────────────────────────────

    def open_operation(self, screen_id: str) -> None:
        """Open a screen, or explain precisely why it cannot be opened."""
        screen = load_screen(screen_id)
        if screen is not None:
            self.push_screen(screen)
            return
        hint = CLI_ONLY.get(screen_id)
        if hint:
            self.notify(
                f"{screen_id.title()} has no TUI screen yet. From a shell: {hint}",
                title="Available on the command line",
                severity="warning",
                timeout=8,
            )
        else:
            self.notify(
                f"No screen named {screen_id!r}.",
                severity="error",
            )

    async def action_back(self) -> None:
        # Never pop the last screen: that leaves a black terminal with no way
        # out but the quit binding, which is worse than doing nothing.
        if len(self.screen_stack) > 2:
            self.pop_screen()

    def action_show_help(self) -> None:
        self.open_operation("help")

    def action_new_scan(self) -> None:
        self.open_operation("scan")

    def action_wireless_menu(self) -> None:
        self.open_operation("wireless")

    def action_toggle_theme(self) -> None:
        """Ctrl+T, as help.py promises. Guarded: theme names move between
        Textual releases and a KeyError here would kill the app."""
        try:
            self.theme = (
                "textual-light" if self.theme == "textual-dark" else "textual-dark"
            )
        except Exception:
            self.notify("Theme switching is unavailable.", severity="warning")


def run_app() -> None:
    """Entry point. ``cli.py`` imports exactly this name."""
    NetreaperApp().run()
