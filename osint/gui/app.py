"""
osint/gui/app.py
-----------------
Root application window. Owns the window itself and handles
switching between the SetupWizard and the MainScreen.
"""

from __future__ import annotations

import customtkinter as ctk

from osint.config import load_config
from osint.gui.config_store import apply_keys_to_config, has_completed_setup, load_keys
from osint.gui.main_screen import MainScreen
from osint.gui.setup_wizard import SetupWizard
from osint.logger import setup_logging

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class OSINTApp(ctk.CTk):
    """
    The top-level application window.

    On first launch  → shows SetupWizard.
    After setup      → shows MainScreen.
    Settings button  → slides back to SetupWizard.
    """

    def __init__(self) -> None:
        super().__init__()
        self.title("OSINT Tool")
        self.geometry("960x720")
        self.minsize(800, 580)

        # Load config and apply any saved API keys.
        self._config = load_config()
        setup_logging(
            level=self._config.logging.level,
            write_to_file=self._config.logging.write_to_file,
            log_file=self._config.logging.log_file,
        )
        keys = load_keys()
        apply_keys_to_config(self._config, keys)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._current_frame: ctk.CTkFrame | None = None

        if has_completed_setup():
            self._show_main()
        else:
            self._show_setup()

    # ── Screen switching ──────────────────────────────────────────────────────

    def _show_setup(self) -> None:
        self._clear()
        frame = SetupWizard(self, on_complete=self._on_setup_complete)
        frame.grid(row=0, column=0, sticky="nsew")
        self._current_frame = frame

    def _show_main(self) -> None:
        self._clear()
        # Re-apply keys in case they were just saved by the setup wizard.
        keys = load_keys()
        apply_keys_to_config(self._config, keys)

        frame = MainScreen(
            self,
            config=self._config,
            on_open_settings=self._show_setup,
        )
        frame.grid(row=0, column=0, sticky="nsew")
        self._current_frame = frame

    def _on_setup_complete(self) -> None:
        self._show_main()

    def _clear(self) -> None:
        if self._current_frame is not None:
            self._current_frame.destroy()
            self._current_frame = None


def run() -> None:
    """Entry point — create and start the GUI event loop."""
    app = OSINTApp()
    app.mainloop()
