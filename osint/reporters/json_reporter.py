"""
osint/reporters/json_reporter.py
---------------------------------
Serialises results to a structured JSON file.

JSON is ideal for feeding results into other tools, databases, or scripts.
Pydantic's model_dump() converts each PluginResult to a plain dictionary,
and the datetime field is automatically serialised to an ISO 8601 string.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from osint.models import PluginResult
from osint.reporters.reporter_base import BaseReporter


class JSONReporter(BaseReporter):
    format_name = "json"

    def generate(
        self,
        results: list[PluginResult],
        output_path: Path,
        **kwargs,
    ) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        identifier_type = results[0].identifier_type if results else "unknown"
        identifier_value = results[0].identifier_value if results else "unknown"

        payload = {
            "meta": {
                "tool": "osint-tool",
                "version": "0.1.0",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "identifier_type": identifier_type,
                "identifier_value": identifier_value,
                "duration_seconds": kwargs.get("duration_s"),
                "plugin_count": len(results),
                "success_count": sum(1 for r in results if r.success),
                "failure_count": sum(1 for r in results if not r.success),
            },
            "results": [
                r.model_dump(mode="json") for r in results
            ],
        }

        output_path.write_text(
            json.dumps(payload, indent=2, default=str),
            encoding="utf-8",
        )
