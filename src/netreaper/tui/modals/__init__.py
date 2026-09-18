"""TUI modal dialogs for user interaction.

netreaper.tui.modals.preflight_modal does not exist. It is a dangling reference
from the v11 rebuild: this package re-exported four classes from it at import
time, so importing the package raised ModuleNotFoundError.

The classes (PreflightModal, InterfaceSelectModal, InputModal, ConfirmModal) are
already imported lazily, inside functions, by
netreaper.tui.helpers.preflight_runner, so nothing needs them at import time.
They belong to the TUI rebuild (#31); writing them now would be designing
dialogs for a UI that has no entry point (tui/app.py is absent).

The package therefore exports nothing and imports cleanly.
"""
from __future__ import annotations

__all__: list[str] = []
