"""
osint/gui/main_screen.py
-------------------------
The main search interface — what the user sees after setup.

Layout (top to bottom):
  1. Header bar  — logo + Settings button
  2. Type tabs   — clickable buttons: IP / Email / Domain / Username / Phone
  3. Input row   — text field + Search button
  4. Format bar  — JSON / HTML / Text toggle
  5. Results box — scrollable text output
  6. Footer bar  — Open Report · Copy · Clear · status line
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

IDENTIFIER_TYPES = [
    ("IP Address",  "ip"),
    ("Email",       "email"),
    ("Domain",      "domain"),
    ("Username",    "username"),
    ("Phone",       "phone"),
]

FORMATS = ["JSON", "HTML", "Text"]


class MainScreen(ctk.CTkFrame):
    """
    The primary application screen.

    on_open_settings: callable that switches the view to SetupWizard.
    """

    def __init__(
        self,
        master: ctk.CTk,
        config,
        on_open_settings: Callable[[], None],
    ):
        super().__init__(master, fg_color="transparent")
        self._config = config
        self._on_open_settings = on_open_settings
        self._last_report_path: Path | None = None
        self._selected_type = ctk.StringVar(value="ip")
        self._selected_format = ctk.StringVar(value="JSON")
        self._type_buttons: dict[str, ctk.CTkButton] = {}
        self._format_buttons: dict[str, ctk.CTkButton] = {}
        self._searching = False

        self.grid_rowconfigure(4, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_header()
        self._build_type_selector()
        self._build_input_row()
        self._build_format_bar()
        self._build_results_area()
        self._build_footer()

        # Select IP by default
        self._select_type("ip")

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        frame = ctk.CTkFrame(self, fg_color=("gray90", "gray15"), corner_radius=0)
        frame.grid(row=0, column=0, sticky="ew")
        frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            frame, text="  🔍  OSINT Tool",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=("#1a7fe8", "#4da6ff"),
        ).grid(row=0, column=0, padx=16, pady=10, sticky="w")

        ctk.CTkButton(
            frame, text="⚙  API Keys / Settings",
            font=ctk.CTkFont(size=12),
            fg_color="transparent",
            border_width=1,
            text_color=("gray40", "gray70"),
            hover_color=("gray80", "gray25"),
            height=30, width=160,
            command=self._on_open_settings,
        ).grid(row=0, column=2, padx=16, pady=10, sticky="e")

    # ── Identifier type selector ──────────────────────────────────────────────

    def _build_type_selector(self) -> None:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(18, 0))

        ctk.CTkLabel(
            frame, text="What are you searching for?",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="gray60",
        ).pack(anchor="w", pady=(0, 8))

        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(anchor="w")

        for label, value in IDENTIFIER_TYPES:
            btn = ctk.CTkButton(
                btn_row,
                text=label,
                font=ctk.CTkFont(size=13),
                width=110, height=38,
                corner_radius=8,
                command=lambda v=value: self._select_type(v),
            )
            btn.pack(side="left", padx=(0, 8))
            self._type_buttons[value] = btn

    def _select_type(self, value: str) -> None:
        self._selected_type.set(value)
        for v, btn in self._type_buttons.items():
            if v == value:
                btn.configure(fg_color=("#1a7fe8", "#1a7fe8"), text_color="white")
            else:
                btn.configure(fg_color=("gray85", "gray25"), text_color=("gray20", "gray80"))
        # Update placeholder text
        placeholders = {
            "ip":       "e.g.  8.8.8.8  or  2001:4860:4860::8888",
            "email":    "e.g.  user@example.com",
            "domain":   "e.g.  example.com",
            "username": "e.g.  torvalds",
            "phone":    "e.g.  +12025551234",
        }
        if hasattr(self, "_entry"):
            self._entry.configure(placeholder_text=placeholders.get(value, ""))

    # ── Input row ─────────────────────────────────────────────────────────────

    def _build_input_row(self) -> None:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(14, 0))
        frame.grid_columnconfigure(0, weight=1)

        self._entry = ctk.CTkEntry(
            frame,
            placeholder_text="e.g.  8.8.8.8",
            height=42,
            font=ctk.CTkFont(size=14),
            corner_radius=8,
        )
        self._entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self._entry.bind("<Return>", lambda _: self._start_search())

        self._search_btn = ctk.CTkButton(
            frame,
            text="Search",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=42, width=110,
            corner_radius=8,
            command=self._start_search,
        )
        self._search_btn.grid(row=0, column=1)

        # Validation error label (hidden until needed)
        self._validation_label = ctk.CTkLabel(
            frame, text="", font=ctk.CTkFont(size=12),
            text_color=("#cc3333", "#ff6666"),
        )
        self._validation_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Progress bar (hidden until search starts)
        self._progress = ctk.CTkProgressBar(frame, mode="indeterminate", height=4)
        self._progress.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        self._progress.grid_remove()

    # ── Format bar ────────────────────────────────────────────────────────────

    def _build_format_bar(self) -> None:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(12, 0))

        ctk.CTkLabel(
            frame, text="Report format:",
            font=ctk.CTkFont(size=12),
            text_color="gray60",
        ).pack(side="left", padx=(0, 10))

        for fmt in FORMATS:
            btn = ctk.CTkButton(
                frame, text=fmt,
                font=ctk.CTkFont(size=12),
                width=70, height=28,
                corner_radius=6,
                command=lambda f=fmt: self._select_format(f),
            )
            btn.pack(side="left", padx=(0, 6))
            self._format_buttons[fmt] = btn

        self._select_format("JSON")

    def _select_format(self, fmt: str) -> None:
        self._selected_format.set(fmt)
        for f, btn in self._format_buttons.items():
            if f == fmt:
                btn.configure(fg_color=("#1a7fe8", "#1a7fe8"), text_color="white")
            else:
                btn.configure(fg_color=("gray85", "gray25"), text_color=("gray20", "gray80"))

    # ── Results area ──────────────────────────────────────────────────────────

    def _build_results_area(self) -> None:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=4, column=0, sticky="nsew", padx=20, pady=(14, 0))
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame, text="Results",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="gray60",
        ).grid(row=0, column=0, sticky="w", pady=(0, 6))

        self._results_box = ctk.CTkTextbox(
            frame,
            font=ctk.CTkFont(family="Courier New", size=12),
            corner_radius=8,
            wrap="word",
            state="disabled",
        )
        self._results_box.grid(row=1, column=0, sticky="nsew")

        self._set_results_placeholder()

    def _set_results_placeholder(self) -> None:
        self._write_results(
            "Results will appear here after you run a search.\n\n"
            "  1. Select what you are searching for (IP, Email, Domain…)\n"
            "  2. Type the value in the field above\n"
            "  3. Click Search\n"
        )

    # ── Footer ────────────────────────────────────────────────────────────────

    def _build_footer(self) -> None:
        frame = ctk.CTkFrame(
            self, fg_color=("gray90", "gray15"), corner_radius=0,
        )
        frame.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        frame.grid_columnconfigure(3, weight=1)

        self._open_report_btn = ctk.CTkButton(
            frame, text="Open Report",
            font=ctk.CTkFont(size=12),
            height=30, width=120,
            state="disabled",
            command=self._open_report,
        )
        self._open_report_btn.grid(row=0, column=0, padx=(12, 6), pady=8)

        ctk.CTkButton(
            frame, text="Copy Results",
            font=ctk.CTkFont(size=12),
            fg_color="transparent", border_width=1,
            text_color=("gray40", "gray70"),
            hover_color=("gray80", "gray25"),
            height=30, width=110,
            command=self._copy_results,
        ).grid(row=0, column=1, padx=6, pady=8)

        ctk.CTkButton(
            frame, text="Clear",
            font=ctk.CTkFont(size=12),
            fg_color="transparent", border_width=1,
            text_color=("gray40", "gray70"),
            hover_color=("gray80", "gray25"),
            height=30, width=70,
            command=self._clear,
        ).grid(row=0, column=2, padx=6, pady=8)

        self._status_label = ctk.CTkLabel(
            frame, text="Ready",
            font=ctk.CTkFont(size=11),
            text_color="gray55",
        )
        self._status_label.grid(row=0, column=3, padx=12, sticky="e")

    # ── Search logic ──────────────────────────────────────────────────────────

    def _start_search(self) -> None:
        if self._searching:
            return

        value = self._entry.get().strip()
        id_type = self._selected_type.get()

        # Validate
        error = _validate(id_type, value)
        if error:
            self._validation_label.configure(text=f"⚠  {error}")
            return
        self._validation_label.configure(text="")

        self._searching = True
        self._search_btn.configure(state="disabled", text="Searching…")
        self._progress.grid()
        self._progress.start()
        self._set_status("Querying sources…")
        self._last_report_path = None
        self._open_report_btn.configure(state="disabled")

        fmt = self._selected_format.get().lower()

        thread = threading.Thread(
            target=self._run_in_background,
            args=(id_type, value, fmt),
            daemon=True,
        )
        thread.start()

    def _run_in_background(self, id_type: str, value: str, fmt: str) -> None:
        """Runs on a background thread — never touch GUI widgets here."""
        import time
        from osint import dispatcher
        from osint.gui.config_store import apply_keys_to_config, load_keys

        keys = load_keys()
        apply_keys_to_config(self._config, keys)

        try:
            results, elapsed = dispatcher.run_all(
                id_type, value, self._config, quiet=True
            )
        except Exception as exc:
            self.after(0, lambda: self._show_error(str(exc)))
            return

        # Generate report file
        report_path = _build_report_path(id_type, value, fmt)
        try:
            reporter = _get_reporter(fmt)
            reporter.generate(results, report_path, duration_s=elapsed)
        except Exception as exc:
            report_path = None

        # Render text output for display in the textbox
        text_output = _render_text(results, elapsed, id_type, value)

        # Schedule GUI update on the main thread
        self.after(0, lambda: self._finish_search(
            text_output, report_path, results, elapsed
        ))

    def _finish_search(
        self,
        text_output: str,
        report_path: Path | None,
        results: list,
        elapsed: float,
    ) -> None:
        """Called on the main thread when the search is done."""
        self._searching = False
        self._progress.stop()
        self._progress.grid_remove()
        self._search_btn.configure(state="normal", text="Search")

        self._write_results(text_output)

        if report_path and report_path.exists():
            self._last_report_path = report_path
            self._open_report_btn.configure(state="normal")

        ok = sum(1 for r in results if r.success)
        fail = len(results) - ok
        self._set_status(
            f"Done in {elapsed:.2f}s  ·  {ok} succeeded  ·  {fail} failed"
            + (f"  ·  Report: {report_path.name}" if report_path else "")
        )

    def _show_error(self, msg: str) -> None:
        self._searching = False
        self._progress.stop()
        self._progress.grid_remove()
        self._search_btn.configure(state="normal", text="Search")
        self._write_results(f"Error running search:\n\n{msg}\n")
        self._set_status("Search failed.")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _open_report(self) -> None:
        if not self._last_report_path or not self._last_report_path.exists():
            return
        path_str = str(self._last_report_path.resolve())
        if sys.platform == "win32":
            os.startfile(path_str)
        elif sys.platform == "darwin":
            subprocess.run(["open", path_str])
        else:
            subprocess.run(["xdg-open", path_str])

    def _copy_results(self) -> None:
        text = self._results_box.get("1.0", "end")
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Results copied to clipboard.")

    def _clear(self) -> None:
        self._set_results_placeholder()
        self._last_report_path = None
        self._open_report_btn.configure(state="disabled")
        self._set_status("Ready")
        self._entry.delete(0, "end")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _write_results(self, text: str) -> None:
        self._results_box.configure(state="normal")
        self._results_box.delete("1.0", "end")
        self._results_box.insert("end", text)
        self._results_box.configure(state="disabled")

    def _set_status(self, msg: str) -> None:
        self._status_label.configure(text=msg)


# ── Pure functions (no GUI state) ─────────────────────────────────────────────

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


def _build_report_path(id_type: str, value: str, fmt: str) -> Path:
    from datetime import datetime, timezone
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", value)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    Path("reports").mkdir(exist_ok=True)
    return Path("reports") / f"{id_type}_{safe}_{ts}.{fmt}"


def _get_reporter(fmt: str):
    from osint.reporters.html_reporter import HTMLReporter
    from osint.reporters.json_reporter import JSONReporter
    from osint.reporters.text_reporter import TextReporter
    return {"json": JSONReporter, "text": TextReporter, "html": HTMLReporter}[fmt]()


def _render_text(results: list, elapsed: float, id_type: str, value: str) -> str:
    """Format plugin results as readable text for the GUI textbox."""
    SEP  = "═" * 60
    THIN = "─" * 60
    lines = []

    lines.append(SEP)
    lines.append(f"  OSINT REPORT  —  {id_type.upper()}: {value}")
    ok   = sum(1 for r in results if r.success)
    fail = len(results) - ok
    lines.append(f"  {len(results)} source(s) queried  ·  {ok} succeeded  ·  {fail} failed  ·  {elapsed:.2f}s")
    lines.append(SEP)
    lines.append("")

    if not results:
        lines.append("  No applicable plugins found for this identifier type.")
        lines.append("  Check that the correct plugins are enabled in config.yaml.")
        return "\n".join(lines)

    for result in results:
        status = "✓" if result.success else "✗"
        lines.append(f"  {status}  {result.plugin_name}")
        lines.append(f"  {THIN}")

        if result.source_url:
            lines.append(f"  Source    : {result.source_url}")
        lines.append("")

        if result.success:
            for key, val in result.data.items():
                if isinstance(val, list):
                    if not val:
                        continue
                    if isinstance(val[0], dict):
                        lines.append(f"  {key}:")
                        for item in val[:5]:
                            parts = "  ·  ".join(f"{k}: {v}" for k, v in item.items() if v is not None)
                            lines.append(f"      {parts}")
                        if len(val) > 5:
                            lines.append(f"      … and {len(val) - 5} more")
                    else:
                        lines.append(f"  {key:<22}: {',  '.join(str(v) for v in val[:8])}")
                        if len(val) > 8:
                            lines.append(f"  {'':22}  … and {len(val) - 8} more")
                elif isinstance(val, dict):
                    lines.append(f"  {key}:")
                    for k, v in list(val.items())[:6]:
                        lines.append(f"      {k}: {v}")
                elif val is not None and val != "":
                    lines.append(f"  {key:<22}: {val}")
        else:
            lines.append(f"  ERROR: {result.error}")

        lines.append("")

    lines.append(SEP)
    return "\n".join(lines)
