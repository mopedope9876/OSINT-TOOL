"""
osint/gui/main_screen.py
-------------------------
The main search interface.

Fixes over v1:
  - Placeholder text is pure hint text — click the box and type immediately,
    nothing to delete.
  - Entry is cleared automatically when you switch identifier type.
  - Phone type shows a country-code dropdown to the left of the input.
  - Validation errors shown inline below the input, not in a popup.
  - Search runs on a background thread so the window never freezes.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Callable

import customtkinter as ctk

# ── Identifier types ──────────────────────────────────────────────────────────
IDENTIFIER_TYPES = [
    ("IP Address",  "ip"),
    ("Email",       "email"),
    ("Domain",      "domain"),
    ("Username",    "username"),
    ("Phone",       "phone"),
]

# ── Report formats ────────────────────────────────────────────────────────────
FORMATS = ["JSON", "HTML", "Text"]

# ── Country codes for phone number lookup ─────────────────────────────────────
COUNTRY_CODES: list[str] = [
    "+1   United States / Canada",
    "+7   Russia / Kazakhstan",
    "+20  Egypt",
    "+27  South Africa",
    "+30  Greece",
    "+31  Netherlands",
    "+32  Belgium",
    "+33  France",
    "+34  Spain",
    "+36  Hungary",
    "+39  Italy",
    "+40  Romania",
    "+41  Switzerland",
    "+43  Austria",
    "+44  United Kingdom",
    "+45  Denmark",
    "+46  Sweden",
    "+47  Norway",
    "+48  Poland",
    "+49  Germany",
    "+51  Peru",
    "+52  Mexico",
    "+54  Argentina",
    "+55  Brazil",
    "+56  Chile",
    "+57  Colombia",
    "+60  Malaysia",
    "+61  Australia",
    "+62  Indonesia",
    "+63  Philippines",
    "+64  New Zealand",
    "+65  Singapore",
    "+66  Thailand",
    "+81  Japan",
    "+82  South Korea",
    "+84  Vietnam",
    "+86  China",
    "+90  Turkey",
    "+91  India",
    "+92  Pakistan",
    "+94  Sri Lanka",
    "+98  Iran",
    "+212 Morocco",
    "+213 Algeria",
    "+216 Tunisia",
    "+234 Nigeria",
    "+254 Kenya",
    "+255 Tanzania",
    "+256 Uganda",
    "+351 Portugal",
    "+353 Ireland",
    "+358 Finland",
    "+380 Ukraine",
    "+381 Serbia",
    "+385 Croatia",
    "+420 Czech Republic",
    "+421 Slovakia",
    "+966 Saudi Arabia",
    "+971 UAE",
    "+972 Israel",
    "+974 Qatar",
    "+880 Bangladesh",
    "+886 Taiwan",
]

# Hint text shown inside the entry box (disappears when you click)
_PLACEHOLDERS = {
    "ip":       "8.8.8.8",
    "email":    "user@example.com",
    "domain":   "example.com",
    "username": "torvalds",
    "phone":    "2025551234  (digits only, no country code)",
}


class MainScreen(ctk.CTkFrame):
    def __init__(self, master: ctk.CTk, config, on_open_settings: Callable[[], None]):
        super().__init__(master, fg_color="transparent")
        self._config          = config
        self._on_open_settings = on_open_settings
        self._last_report_path: Path | None = None
        self._selected_type    = ctk.StringVar(value="ip")
        self._type_buttons:    dict[str, ctk.CTkButton] = {}
        self._format_buttons:  dict[str, ctk.CTkButton] = {}
        self._searching        = False

        self.grid_rowconfigure(4, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_header()
        self._build_type_selector()
        self._build_input_row()
        self._build_format_bar()
        self._build_results_area()
        self._build_footer()

        self._select_type("ip")

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=("gray90", "gray15"), corner_radius=0)
        bar.grid(row=0, column=0, sticky="ew")
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            bar, text="  🔍  OSINT Tool",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=("#1a7fe8", "#4da6ff"),
        ).grid(row=0, column=0, padx=16, pady=10, sticky="w")

        ctk.CTkButton(
            bar, text="⚙  API Keys / Settings",
            font=ctk.CTkFont(size=12),
            fg_color="transparent", border_width=1,
            text_color=("gray40", "gray70"),
            hover_color=("gray80", "gray25"),
            height=30, width=170,
            command=self._on_open_settings,
        ).grid(row=0, column=2, padx=16, pady=10, sticky="e")

    # ── Type selector ──────────────────────────────────────────────────────────

    def _build_type_selector(self) -> None:
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.grid(row=1, column=0, sticky="ew", padx=20, pady=(16, 0))

        ctk.CTkLabel(
            outer, text="What are you searching for?",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="gray55",
        ).pack(anchor="w", pady=(0, 8))

        btn_row = ctk.CTkFrame(outer, fg_color="transparent")
        btn_row.pack(anchor="w")

        for label, value in IDENTIFIER_TYPES:
            btn = ctk.CTkButton(
                btn_row, text=label,
                font=ctk.CTkFont(size=13),
                width=118, height=38, corner_radius=8,
                command=lambda v=value: self._select_type(v),
            )
            btn.pack(side="left", padx=(0, 8))
            self._type_buttons[value] = btn

    def _select_type(self, value: str) -> None:
        self._selected_type.set(value)

        # Highlight selected button, reset others
        for v, btn in self._type_buttons.items():
            if v == value:
                btn.configure(fg_color=("#1a7fe8", "#1a7fe8"), text_color="white")
            else:
                btn.configure(fg_color=("gray85", "gray25"), text_color=("gray20", "gray80"))

        # Clear the entry so user can type immediately without deleting anything
        if hasattr(self, "_entry"):
            self._entry.delete(0, "end")
            self._entry.configure(placeholder_text=_PLACEHOLDERS.get(value, ""))

        # Clear any validation error
        if hasattr(self, "_val_label"):
            self._val_label.configure(text="")

        # Show country code picker only for phone
        if hasattr(self, "_country_combo"):
            if value == "phone":
                self._country_combo.grid()
            else:
                self._country_combo.grid_remove()

    # ── Input row ─────────────────────────────────────────────────────────────

    def _build_input_row(self) -> None:
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.grid(row=2, column=0, sticky="ew", padx=20, pady=(12, 0))
        outer.grid_columnconfigure(0, weight=1)

        # Label above input
        ctk.CTkLabel(
            outer,
            text="Enter value  (click the box below and start typing):",
            font=ctk.CTkFont(size=12),
            text_color="gray55",
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))

        # Row: [country_combo?] [entry] [Search]
        row = ctk.CTkFrame(outer, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew")
        row.grid_columnconfigure(1, weight=1)

        # Country code dropdown (shown only for Phone)
        self._country_combo = ctk.CTkComboBox(
            row,
            values=COUNTRY_CODES,
            width=220, height=42,
            state="readonly",
            font=ctk.CTkFont(size=12),
        )
        self._country_combo.set(COUNTRY_CODES[0])
        self._country_combo.grid(row=0, column=0, padx=(0, 8))
        self._country_combo.grid_remove()   # hidden until Phone is selected

        # Main entry box
        self._entry = ctk.CTkEntry(
            row,
            placeholder_text=_PLACEHOLDERS["ip"],
            height=42,
            font=ctk.CTkFont(size=14),
            corner_radius=8,
        )
        self._entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self._entry.bind("<Return>", lambda _: self._start_search())

        # Search button
        self._search_btn = ctk.CTkButton(
            row, text="Search",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=42, width=110, corner_radius=8,
            command=self._start_search,
        )
        self._search_btn.grid(row=0, column=2)

        # Validation label (shows red hint when input is wrong)
        self._val_label = ctk.CTkLabel(
            outer, text="",
            font=ctk.CTkFont(size=12),
            text_color=("#cc3333", "#ff6666"),
        )
        self._val_label.grid(row=2, column=0, sticky="w", pady=(4, 0))

        # Indeterminate progress bar (visible only while searching)
        self._progress = ctk.CTkProgressBar(outer, mode="indeterminate", height=4)
        self._progress.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        self._progress.grid_remove()

    # ── Format bar ────────────────────────────────────────────────────────────

    def _build_format_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=3, column=0, sticky="ew", padx=20, pady=(10, 0))

        ctk.CTkLabel(
            bar, text="Save report as:",
            font=ctk.CTkFont(size=12), text_color="gray55",
        ).pack(side="left", padx=(0, 10))

        for fmt in FORMATS:
            btn = ctk.CTkButton(
                bar, text=fmt,
                font=ctk.CTkFont(size=12),
                width=70, height=28, corner_radius=6,
                command=lambda f=fmt: self._select_format(f),
            )
            btn.pack(side="left", padx=(0, 6))
            self._format_buttons[fmt] = btn

        self._select_format("JSON")

        # Tooltip
        ctk.CTkLabel(
            bar, text="(HTML opens in your browser with full styling)",
            font=ctk.CTkFont(size=11), text_color="gray45",
        ).pack(side="left", padx=(10, 0))

    def _select_format(self, fmt: str) -> None:
        self._selected_format = fmt
        for f, btn in self._format_buttons.items():
            if f == fmt:
                btn.configure(fg_color=("#1a7fe8", "#1a7fe8"), text_color="white")
            else:
                btn.configure(fg_color=("gray85", "gray25"), text_color=("gray20", "gray80"))

    # ── Results area ──────────────────────────────────────────────────────────

    def _build_results_area(self) -> None:
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.grid(row=4, column=0, sticky="nsew", padx=20, pady=(12, 0))
        outer.grid_rowconfigure(1, weight=1)
        outer.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            outer, text="Results",
            font=ctk.CTkFont(size=12, weight="bold"), text_color="gray55",
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))

        self._results_box = ctk.CTkTextbox(
            outer,
            font=ctk.CTkFont(family="Courier New", size=12),
            corner_radius=8, wrap="word", state="disabled",
        )
        self._results_box.grid(row=1, column=0, sticky="nsew")

        self._write_results(
            "  Results appear here after a search.\n\n"
            "  How to use:\n"
            "  1. Click one of the buttons above (IP Address, Email, Domain…)\n"
            "  2. Click the input box and start typing your value\n"
            "  3. Press Enter or click Search\n\n"
            "  Tip: HTML reports open in your browser with a full styled layout.\n"
            "  Reports are saved to the reports/ folder automatically.\n"
        )

    # ── Footer ────────────────────────────────────────────────────────────────

    def _build_footer(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=("gray90", "gray15"), corner_radius=0)
        bar.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        bar.grid_columnconfigure(3, weight=1)

        self._open_btn = ctk.CTkButton(
            bar, text="📂  Open Report",
            font=ctk.CTkFont(size=12),
            height=30, width=130, state="disabled",
            command=self._open_report,
        )
        self._open_btn.grid(row=0, column=0, padx=(12, 6), pady=8)

        ctk.CTkButton(
            bar, text="Copy Results",
            font=ctk.CTkFont(size=12),
            fg_color="transparent", border_width=1,
            text_color=("gray40", "gray70"), hover_color=("gray80", "gray25"),
            height=30, width=110,
            command=self._copy_results,
        ).grid(row=0, column=1, padx=6, pady=8)

        ctk.CTkButton(
            bar, text="Clear",
            font=ctk.CTkFont(size=12),
            fg_color="transparent", border_width=1,
            text_color=("gray40", "gray70"), hover_color=("gray80", "gray25"),
            height=30, width=70,
            command=self._clear,
        ).grid(row=0, column=2, padx=6, pady=8)

        self._status = ctk.CTkLabel(
            bar, text="Ready",
            font=ctk.CTkFont(size=11), text_color="gray50",
        )
        self._status.grid(row=0, column=3, padx=12, sticky="e")

    # ── Search ────────────────────────────────────────────────────────────────

    def _start_search(self) -> None:
        if self._searching:
            return

        id_type = self._selected_type.get()
        raw_value = self._entry.get().strip()

        # For phone: prepend country code unless user already included one
        if id_type == "phone":
            code = self._country_combo.get().split()[0]   # e.g. "+1"
            value = (code + raw_value) if not raw_value.startswith("+") else raw_value
        else:
            value = raw_value

        err = _validate(id_type, value)
        if err:
            self._val_label.configure(text=f"⚠  {err}")
            return
        self._val_label.configure(text="")

        fmt = getattr(self, "_selected_format", "JSON").lower()

        self._searching = True
        self._search_btn.configure(state="disabled", text="Searching…")
        self._progress.grid()
        self._progress.start()
        self._set_status("Querying sources…")
        self._open_btn.configure(state="disabled")
        self._last_report_path = None

        threading.Thread(
            target=self._run_background,
            args=(id_type, value, fmt),
            daemon=True,
        ).start()

    def _run_background(self, id_type: str, value: str, fmt: str) -> None:
        """Runs on a background thread — do NOT touch any CTk widgets here."""
        from osint import dispatcher
        from osint.gui.config_store import apply_keys_to_config, load_keys

        apply_keys_to_config(self._config, load_keys())

        try:
            results, elapsed = dispatcher.run_all(id_type, value, self._config, quiet=True)
        except Exception as exc:
            self.after(0, lambda: self._on_error(str(exc)))
            return

        report_path: Path | None = None
        try:
            report_path = _build_path(id_type, value, fmt)
            _get_reporter(fmt).generate(results, report_path, duration_s=elapsed)
        except Exception:
            report_path = None

        text = _render(results, elapsed, id_type, value)
        self.after(0, lambda: self._on_done(text, report_path, results, elapsed))

    def _on_done(self, text, report_path, results, elapsed) -> None:
        self._searching = False
        self._progress.stop()
        self._progress.grid_remove()
        self._search_btn.configure(state="normal", text="Search")
        self._write_results(text)

        if report_path and report_path.exists():
            self._last_report_path = report_path
            self._open_btn.configure(state="normal")

        ok   = sum(1 for r in results if r.success)
        fail = len(results) - ok
        self._set_status(
            f"Done in {elapsed:.2f}s  ·  {ok} OK  ·  {fail} failed"
            + (f"  ·  {report_path.name}" if report_path else "")
        )

    def _on_error(self, msg: str) -> None:
        self._searching = False
        self._progress.stop()
        self._progress.grid_remove()
        self._search_btn.configure(state="normal", text="Search")
        self._write_results(f"Error running search:\n\n  {msg}\n")
        self._set_status("Search failed.")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _open_report(self) -> None:
        if not self._last_report_path or not self._last_report_path.exists():
            return
        path = str(self._last_report_path.resolve())
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.run(["open", path])
        else:
            subprocess.run(["xdg-open", path])

    def _copy_results(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._results_box.get("1.0", "end"))
        self._set_status("Results copied to clipboard.")

    def _clear(self) -> None:
        self._write_results(
            "  Cleared.  Select an identifier type above and start a new search.\n"
        )
        self._entry.delete(0, "end")
        self._last_report_path = None
        self._open_btn.configure(state="disabled")
        self._set_status("Ready")

    def _write_results(self, text: str) -> None:
        self._results_box.configure(state="normal")
        self._results_box.delete("1.0", "end")
        self._results_box.insert("end", text)
        self._results_box.configure(state="disabled")

    def _set_status(self, msg: str) -> None:
        self._status.configure(text=msg)


# ── Pure helper functions ─────────────────────────────────────────────────────

def _validate(id_type: str, value: str) -> str | None:
    import ipaddress
    if not value:
        return "Please enter a value before searching."
    if id_type == "email" and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        return f"'{value}' doesn't look like a valid email address."
    if id_type == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return f"'{value}' is not a valid IPv4 or IPv6 address."
    if id_type == "domain" and not re.match(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", value
    ):
        return f"'{value}' doesn't look like a valid domain name."
    return None


def _build_path(id_type: str, value: str, fmt: str) -> Path:
    from datetime import datetime, timezone
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", value)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    Path("reports").mkdir(exist_ok=True)
    return Path("reports") / f"{id_type}_{safe}_{ts}.{fmt}"


def _get_reporter(fmt: str):
    from osint.reporters.html_reporter import HTMLReporter
    from osint.reporters.json_reporter import JSONReporter
    from osint.reporters.text_reporter import TextReporter
    return {"json": JSONReporter, "text": TextReporter, "html": HTMLReporter}[fmt]()


def _render(results: list, elapsed: float, id_type: str, value: str) -> str:
    """Format results as readable text for the GUI textbox."""
    W    = 62
    SEP  = "═" * W
    THIN = "─" * W
    lines = [
        SEP,
        f"  OSINT REPORT",
        f"  {id_type.upper()}: {value}",
        f"  {len(results)} source(s)  ·  "
        f"{sum(1 for r in results if r.success)} succeeded  ·  "
        f"{sum(1 for r in results if not r.success)} failed  ·  {elapsed:.2f}s",
        SEP, "",
    ]

    if not results:
        lines += ["  No plugins ran. Check config.yaml enables the right plugins.", ""]
        return "\n".join(lines)

    for result in results:
        icon = "✓" if result.success else "✗"
        lines.append(f"  {icon}  {result.plugin_name}")
        lines.append(f"  {THIN}")
        if result.source_url:
            lines.append(f"  Source : {result.source_url}")
        lines.append("")

        if result.success:
            for key, val in result.data.items():
                if isinstance(val, list):
                    if not val:
                        continue
                    if isinstance(val[0], dict):
                        lines.append(f"  {key}  ({len(val)} item(s)):")
                        for item in val[:4]:
                            parts = "  ·  ".join(
                                f"{k}: {v}" for k, v in item.items() if v is not None
                            )
                            lines.append(f"      {parts[:90]}")
                        if len(val) > 4:
                            lines.append(f"      … and {len(val) - 4} more")
                    else:
                        display = ",  ".join(str(v) for v in val[:8])
                        lines.append(f"  {key:<22}: {display}")
                        if len(val) > 8:
                            lines.append(f"  {'':22}  … +{len(val) - 8} more")
                elif isinstance(val, dict):
                    lines.append(f"  {key}:")
                    for k, v in list(val.items())[:5]:
                        lines.append(f"      {k}: {v}")
                elif val not in (None, ""):
                    lines.append(f"  {key:<22}: {val}")
        else:
            lines.append(f"  ERROR : {result.error}")

        lines.append("")

    lines.append(SEP)
    return "\n".join(lines)
