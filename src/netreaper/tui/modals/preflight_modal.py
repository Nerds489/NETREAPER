"""Preflight modal dialogs (#31).

`netreaper.tui.helpers.preflight_runner` prompts the operator through these
dialogs when a tool needs something it cannot resolve on its own: an interface to
pick, a confirmation, a target or an API key to type. They were dangling
references left by the v11 Bash-to-Python rebuild, so every `ensure_*` prompt
degraded to a "there is no picker yet" notice and the interactive path did
nothing. These are the real dialogs.

Each is a `ModalScreen` that dismisses with the value the caller expects:
- `ConfirmModal`   -> bool           (Yes / No)
- `InputModal`     -> str | None     (the entered text, or None on cancel)
- `InterfaceSelectModal` -> str|None (the chosen interface name, or None)
- `PreflightModal` -> bool           (proceed after showing unmet requirements)
"""
from __future__ import annotations

from typing import Any, ClassVar

from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class ConfirmModal(ModalScreen[bool]):
    """A yes/no confirmation. Dismisses True on confirm, False otherwise."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        self._title = title
        self._message = message

    def compose(self) -> ComposeResult:
        with Container(classes="modal-container"):
            yield Static(f"[bold magenta]{self._title}[/]", classes="modal-title")
            yield Static(self._message)
            with Horizontal():
                yield Button("Yes", id="confirm-yes", variant="primary")
                yield Button("No", id="confirm-no", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")

    def action_cancel(self) -> None:
        self.dismiss(False)


class InputModal(ModalScreen[str | None]):
    """A single-line prompt. Dismisses the entered text, or None on cancel."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(
        self, title: str, placeholder: str = "", password: bool = False
    ) -> None:
        super().__init__()
        self._title = title
        self._placeholder = placeholder
        self._password = password

    def compose(self) -> ComposeResult:
        with Container(classes="modal-container"):
            yield Static(f"[bold magenta]{self._title}[/]", classes="modal-title")
            yield Input(
                placeholder=self._placeholder,
                password=self._password,
                id="input-field",
            )
            with Horizontal():
                yield Button("Submit", id="input-submit", variant="primary")
                yield Button("Cancel", id="input-cancel", variant="default")

    def _submit(self) -> None:
        value = self.query_one("#input-field", Input).value.strip()
        self.dismiss(value or None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "input-submit":
            self._submit()
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Enter in the field submits.
        self._submit()

    def action_cancel(self) -> None:
        self.dismiss(None)


class InterfaceSelectModal(ModalScreen[str | None]):
    """Pick one interface from a list. Dismisses its name, or None on cancel."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(
        self, interfaces: list[dict[str, Any]], title: str = "Select Interface"
    ) -> None:
        super().__init__()
        self._title = title
        self._interfaces = interfaces
        # Map a stable button id to the interface name, so a name with awkward
        # characters never has to be an id.
        self._by_id = {
            f"iface-{i}": str(iface.get("name", ""))
            for i, iface in enumerate(interfaces)
        }

    def compose(self) -> ComposeResult:
        with Container(classes="modal-container"):
            yield Static(f"[bold magenta]{self._title}[/]", classes="modal-title")
            with Vertical():
                for i, iface in enumerate(self._interfaces):
                    name = iface.get("name", "")
                    detail = " ".join(
                        str(iface[k]) for k in ("type", "driver", "mac") if iface.get(k)
                    )
                    label = f"{name}  [dim]{detail}[/]" if detail else str(name)
                    yield Button(label, id=f"iface-{i}", variant="primary")
                yield Button("Cancel", id="iface-cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(self._by_id.get(event.button.id or ""))

    def action_cancel(self) -> None:
        self.dismiss(None)


class PreflightModal(ModalScreen[bool]):
    """Show unmet requirements and ask whether to proceed.

    Reached only through ``PreflightRunner.run_with_preflight``, which itself
    depends on the not-yet-written ``PreflightChecker``; kept here so the modal
    surface is complete. Reads the result defensively since its type is not
    finalised.
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(self, result: Any, session: Any = None) -> None:
        super().__init__()
        self._result = result
        self._session = session

    def compose(self) -> ComposeResult:
        unmet = getattr(self._result, "unmet", None) or "requirements not met"
        with Container(classes="modal-container"):
            yield Static("[bold magenta]Requirements[/]", classes="modal-title")
            yield Static(str(unmet))
            with Horizontal():
                yield Button("Proceed", id="preflight-proceed", variant="primary")
                yield Button("Cancel", id="preflight-cancel", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "preflight-proceed")

    def action_cancel(self) -> None:
        self.dismiss(False)
