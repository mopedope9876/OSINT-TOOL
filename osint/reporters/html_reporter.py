"""
osint/reporters/html_reporter.py
---------------------------------
Generates a self-contained, styled HTML report using a Jinja2 template.

The output file has no external dependencies — all CSS and JavaScript
are inline. Opening it in any web browser produces a dark-themed,
interactive report with collapsible plugin sections.

WHY JINJA2?
Mixing HTML and Python string concatenation becomes unmanageable fast.
Jinja2 templates keep the presentation (HTML/CSS) separate from the
logic (Python). The template uses the same syntax as Ansible, Flask,
and Django, so learning it here transfers widely.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from osint.models import PluginResult
from osint.reporters.reporter_base import BaseReporter

_TEMPLATE_DIR = Path(__file__).parent / "templates"


class HTMLReporter(BaseReporter):
    format_name = "html"

    def generate(
        self,
        results: list[PluginResult],
        output_path: Path,
        **kwargs,
    ) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )

        # Custom filter: serialise any Python value to pretty JSON.
        def tojson_filter(value, indent=None):
            return json.dumps(value, indent=indent, default=str)

        env.filters["tojson"] = tojson_filter

        template = env.get_template("report.html")

        identifier_type = results[0].identifier_type if results else "unknown"
        identifier_value = results[0].identifier_value if results else "unknown"
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        duration_s = kwargs.get("duration_s")

        # Convert PluginResult objects to plain dicts for the template.
        # We keep them as dict-like objects (using model_dump) but with
        # the success attribute accessible as result.success, etc.
        # Easiest: pass the original objects since Jinja2 accesses attrs.

        html_content = template.render(
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            generated_at=generated_at,
            duration_s=duration_s,
            results=results,
        )

        output_path.write_text(html_content, encoding="utf-8")
