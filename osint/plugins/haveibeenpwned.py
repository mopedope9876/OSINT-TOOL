"""
osint/plugins/haveibeenpwned.py
--------------------------------
Checks whether an email address has appeared in a known data breach,
using the HaveIBeenPwned API v3 (haveibeenpwned.com).

REQUIRES A FREE API KEY:
Sign up at https://haveibeenpwned.com/API/Key
Set it in config.yaml:   plugins.haveibeenpwned.api_key: "your_key"
Or via environment var:  export HIBP_API_KEY=your_key
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class HaveIBeenPwnedPlugin(BasePlugin):
    name = "HaveIBeenPwned"
    description = "Checks if an email address appeared in known data breaches. Requires free API key."
    supported_identifiers = ["email"]

    def run(
        self,
        identifier_type: str,
        identifier_value: str,
        config: AppConfig,
    ) -> PluginResult:
        plugin_cfg = config.get_plugin_config("haveibeenpwned")
        api_key = plugin_cfg.api_key
        base_url = plugin_cfg.base_url or "https://haveibeenpwned.com/api/v3"
        source_url = f"{base_url}/breachedaccount/{identifier_value}"
        timeout = config.general.request_timeout

        if not api_key:
            return PluginResult(
                plugin_name=self.name,
                identifier_type=identifier_type,
                identifier_value=identifier_value,
                success=False,
                error=(
                    "No HIBP API key configured. "
                    "Get a free key at haveibeenpwned.com/API/Key and add it to config.yaml."
                ),
                source_url=source_url,
            )

        headers = {
            "hibp-api-key": api_key,
            "user-agent": "osint-tool/0.1",
        }

        logger.debug(f"[{self.name}] GET {source_url}")

        try:
            response = requests.get(
                source_url,
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=timeout,
            )
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, source_url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, source_url, "Could not connect to haveibeenpwned.com.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, source_url, str(exc))

        if response.status_code == 404:
            # 404 from HIBP means "not found in any breach" — this is good news.
            return PluginResult(
                plugin_name=self.name,
                identifier_type=identifier_type,
                identifier_value=identifier_value,
                success=True,
                data={"breaches_found": 0, "breaches": [], "message": "No breaches found for this email address."},
                source_url=source_url,
            )

        if response.status_code == 401:
            return self._error(
                identifier_type, identifier_value, source_url,
                "Invalid HIBP API key. Check the key in config.yaml.",
            )

        if response.status_code == 429:
            retry = response.headers.get("retry-after", "60")
            return self._error(
                identifier_type, identifier_value, source_url,
                f"HIBP rate limit exceeded. Retry after {retry} seconds.",
            )

        try:
            response.raise_for_status()
            breaches_raw = response.json()
        except Exception as exc:
            return self._error(identifier_type, identifier_value, source_url, str(exc))

        # Trim each breach to the most useful fields.
        breaches = [
            {
                "name": b.get("Name"),
                "title": b.get("Title"),
                "breach_date": b.get("BreachDate"),
                "pwn_count": b.get("PwnCount"),
                "data_classes": b.get("DataClasses", []),
                "is_verified": b.get("IsVerified"),
                "is_sensitive": b.get("IsSensitive"),
                "description": _strip_html(b.get("Description", "")),
            }
            for b in breaches_raw
        ]

        return PluginResult(
            plugin_name=self.name,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            success=True,
            data={
                "breaches_found": len(breaches),
                "breach_names": [b["name"] for b in breaches],
                "breaches": breaches,
            },
            source_url=source_url,
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        count = result.data.get("breaches_found", 0)
        if count == 0:
            return "No breaches found"
        names = result.data.get("breach_names", [])
        preview = ", ".join(names[:3])
        if len(names) > 3:
            preview += f" +{len(names) - 3} more"
        return f"{count} breach(es): {preview}"

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name,
            identifier_type=itype,
            identifier_value=ival,
            success=False,
            error=msg,
            source_url=url,
        )


def _strip_html(text: str) -> str:
    """Remove HTML tags from HIBP description strings."""
    import re
    return re.sub(r"<[^>]+>", "", text).strip()
