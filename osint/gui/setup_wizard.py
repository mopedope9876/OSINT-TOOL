"""
osint/gui/setup_wizard.py
--------------------------
First-run setup screen.

Shown once when the user opens the app for the first time. Walks them
through entering their free API keys, with a clickable link to the
signup page for each service. Keys can be skipped — affected plugins
will just report "No key configured" without crashing.
"""

from __future__ import annotations

import webbrowser
from typing import Callable

import customtkinter as ctk

from osint.gui.config_store import API_KEY_REGISTRY, save_keys


class SetupWizard(ctk.CTkFrame):
    """
    A full-window setup frame shown on first launch.

    When the user clicks "Save & Start" or "Skip", on_complete() is
    called so the main App can switch to the main screen.
    """

    def __init__(self, master: ctk.CTk, on_complete: Callable[[], None]):
        super().__init__(master, fg_color="transparent")
        self._on_complete = on_complete
        self._key_entries: dict[str, ctk.CTkEntry] = {}
        self._build()

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)

        # ── Title ──────────────────────────────────────────────────
        title = ctk.CTkLabel(
            self, text="Welcome to OSINT Tool",
            font=ctk.CTkFont(size=26, weight="bold"),
        )
        title.grid(row=0, column=0, pady=(40, 4), padx=40, sticky="w")

        subtitle = ctk.CTkLabel(
            self,
            text=(
                "Enter your free API keys below to unlock all features.\n"
                "Every key listed here is 100% free — no credit card, no trial."
            ),
            font=ctk.CTkFont(size=14),
            text_color="gray70",
            justify="left",
        )
        subtitle.grid(row=1, column=0, pady=(0, 24), padx=40, sticky="w")

        # ── Scrollable key-entry area ──────────────────────────────
        scroll = ctk.CTkScrollableFrame(self, label_text="")
        scroll.grid(row=2, column=0, padx=40, sticky="nsew", pady=(0, 20))
        scroll.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        for row_idx, (plugin_key, info) in enumerate(API_KEY_REGISTRY.items()):
            self._build_key_row(scroll, row_idx, plugin_key, info)

        # ── Info note ─────────────────────────────────────────────
        note = ctk.CTkLabel(
            self,
            text=(
                "ℹ️  You can skip any key now and add it later via the ⚙ Settings button.\n"
                "Plugins without a key will still appear in results — just marked as skipped."
            ),
            font=ctk.CTkFont(size=12),
            text_color="gray60",
            justify="left",
        )
        note.grid(row=3, column=0, padx=40, pady=(0, 20), sticky="w")

        # ── Bottom buttons ─────────────────────────────────────────
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=4, column=0, padx=40, pady=(0, 40), sticky="e")

        ctk.CTkButton(
            btn_frame, text="Skip for now",
            fg_color="transparent", border_width=1,
            text_color=("gray40", "gray70"),
            hover_color=("gray85", "gray25"),
            command=self._skip,
        ).pack(side="left", padx=(0, 12))

        ctk.CTkButton(
            btn_frame, text="Save & Start  →",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40, width=160,
            command=self._save_and_start,
        ).pack(side="left")

    def _build_key_row(
        self,
        parent: ctk.CTkScrollableFrame,
        row_idx: int,
        plugin_key: str,
        info: dict,
    ) -> None:
        """Build one card (plugin name + description + link + entry fields) in the scroll area."""
        card = ctk.CTkFrame(parent, corner_radius=10)
        card.grid(row=row_idx, column=0, sticky="ew", pady=(0, 14))
        card.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        # Plugin name + link on same row
        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 4))
        top_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top_row,
            text=info["display_name"],
            font=ctk.CTkFont(size=15, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        url = info["signup_url"]
        link_text = info.get("link_text", "Get free key →")
        link_btn = ctk.CTkButton(
            top_row,
            text=link_text,
            font=ctk.CTkFont(size=12),
            fg_color="transparent",
            text_color=("#1a7fe8", "#4da6ff"),
            hover_color=("gray90", "gray20"),
            height=24,
            command=lambda u=url: webbrowser.open(u),
        )
        link_btn.grid(row=0, column=1, sticky="e")

        ctk.CTkLabel(
            card,
            text=info["description"],
            font=ctk.CTkFont(size=12),
            text_color="gray60",
            justify="left",
            wraplength=520,
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 8))

        has_secondary = "secondary_field" in info
        primary_bottom_pad = (0, 6) if has_secondary else (0, 14)

        # Primary credential entry (API key / API ID)
        entry = ctk.CTkEntry(
            card,
            placeholder_text=info["placeholder"],
            height=36,
            show="",
        )
        entry.grid(row=2, column=0, sticky="ew", padx=16, pady=primary_bottom_pad)
        self._key_entries[plugin_key] = entry

        # Optional secondary field (e.g. Censys API Secret)
        if has_secondary:
            sf = info["secondary_field"]
            ctk.CTkLabel(
                card,
                text=sf["label"],
                font=ctk.CTkFont(size=11),
                text_color="gray55",
            ).grid(row=3, column=0, sticky="w", padx=16, pady=(4, 0))

            entry2 = ctk.CTkEntry(
                card,
                placeholder_text=sf["placeholder"],
                height=36,
                show="",
            )
            entry2.grid(row=4, column=0, sticky="ew", padx=16, pady=(2, 14))
            self._key_entries[sf["store_key"]] = entry2

    def _save_and_start(self) -> None:
        keys = {name: entry.get() for name, entry in self._key_entries.items()}
        save_keys(keys)
        self._on_complete()

    def _skip(self) -> None:
        # Save an empty file so the wizard doesn't show again next launch.
        save_keys({})
        self._on_complete()
