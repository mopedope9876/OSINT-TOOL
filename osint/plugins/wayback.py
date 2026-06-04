"""
osint/plugins/wayback.py
-------------------------
Domain history via the Wayback Machine (archive.org).

Checks whether a domain has been archived, when the latest snapshot was
taken, and provides the direct Wayback Machine link. Useful for understanding
domain history, detecting freshly-registered vs long-standing domains, and
finding old or deleted content.

No API key required. Completely free.
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class WaybackPlugin(BasePlugin):
    name = "Wayback Machine"
    description = "Shows whether a domain was ever archived and the date of the latest snapshot. No key needed."
    supported_identifiers = ["domain"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        timeout = config.general.request_timeout
        avail_url = f"https://archive.org/wayback/available?url={identifier_value}"
        headers = {"User-Agent": "osint-tool/0.1", "Accept": "application/json"}

        logger.debug(f"[{self.name}] GET {avail_url}")

        try:
            resp = requests.get(avail_url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            avail = resp.json()
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, avail_url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, avail_url, "Could not connect to archive.org.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, avail_url, str(exc))

        snapshot = avail.get("archived_snapshots", {}).get("closest", {})
        if not snapshot.get("available"):
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=True,
                data={"archived": False, "message": "No Wayback Machine snapshots found for this domain."},
                source_url=f"https://web.archive.org/web/*/{identifier_value}",
            )

        ts = snapshot.get("timestamp", "")
        latest_date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts

        # CDX API: count snapshots in the last year
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={identifier_value}/*&output=json&fl=timestamp&limit=1&showNumPages=true"
        )
        page_count = None
        try:
            r = requests.get(cdx_url, headers=headers, timeout=timeout)
            if r.ok:
                pages = r.json()
                if isinstance(pages, int):
                    page_count = pages
        except Exception:
            pass

        data = {
            "archived":        True,
            "latest_snapshot": latest_date,
            "snapshot_url":    snapshot.get("url", ""),
            "wayback_link":    f"https://web.archive.org/web/*/{identifier_value}",
        }
        if page_count is not None:
            data["approx_snapshot_pages"] = page_count

        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=f"https://web.archive.org/web/*/{identifier_value}",
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        if not result.data.get("archived"):
            return "Not archived in Wayback Machine"
        latest = result.data.get("latest_snapshot", "unknown date")
        return f"Archived · latest snapshot {latest}"

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
