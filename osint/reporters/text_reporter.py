"""
osint/reporters/text_reporter.py
---------------------------------
Writes results to a plain-text file.

Plain text is universally readable, easy to grep, and suitable for
piping into other command-line tools. No dependencies — pure Python
string formatting.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from osint.models import PluginResult
from osint.reporters.reporter_base import BaseReporter

_SEPARATOR = "=" * 70
_THIN = "-" * 70


class TextReporter(BaseReporter):
    format_name = "text"

    def generate(
        self,
        results: list[PluginResult],
        output_path: Path,
        **kwargs,
    ) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        identifier_type = results[0].identifier_type if results else "unknown"
        identifier_value = results[0].identifier_value if results else "unknown"
        duration = kwargs.get("duration_s")
        generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        successes = sum(1 for r in results if r.success)
        failures = len(results) - successes

        lines: list[str] = []

        lines.append(_SEPARATOR)
        lines.append("OSINT TOOL — REPORT")
        lines.append(_SEPARATOR)
        lines.append(f"Identifier : {identifier_type} = {identifier_value}")
        lines.append(f"Generated  : {generated}")
        if duration is not None:
            lines.append(f"Duration   : {duration:.2f}s")
        lines.append(f"Sources    : {len(results)} queried, {successes} succeeded, {failures} failed")
        lines.append("")

        for result in results:
            lines.append(_SEPARATOR)
            status = "OK" if result.success else "FAILED"
            lines.append(f"[{status}] {result.plugin_name}")
            lines.append(_THIN)

            if result.source_url:
                lines.append(f"Source     : {result.source_url}")
            lines.append(f"Timestamp  : {result.timestamp}")
            lines.append("")

            if result.success:
                for key, value in result.data.items():
                    if isinstance(value, list):
                        lines.append(f"  {key}:")
                        for item in value:
                            if isinstance(item, dict):
                                lines.append(f"    {json.dumps(item)}")
                            else:
                                lines.append(f"    - {item}")
                    elif isinstance(value, dict):
                        lines.append(f"  {key}:")
                        lines.append(f"    {json.dumps(value, indent=4)}")
                    else:
                        lines.append(f"  {key:<22}: {value}")
            else:
                lines.append(f"  ERROR: {result.error}")

            lines.append("")

        lines.append(_SEPARATOR)
        lines.append("END OF REPORT")
        lines.append(_SEPARATOR)

        output_path.write_text("\n".join(lines), encoding="utf-8")
