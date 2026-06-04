"""
osint/plugins/urlscan.py
-------------------------
Scans domains/URLs using URLScan.io — a free service that visually
renders websites and records all network activity, DOM content,
IP addresses, and technologies used.

Free API key: 1,000 public scans/day and search access.

GET FREE KEY: https://urlscan.io/user/signup
(Create a free account → API Keys section in your profile)
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class URLScanPlugin(BasePlugin):
    name = "URLScan.io"
    description = "Finds recent scans of a domain: IPs, tech stack, screenshot links. Free key required."
    supported_identifiers = ["domain"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        plugin_cfg = config.get_plugin_config("urlscan")
        api_key = plugin_cfg.api_key
        timeout = config.general.request_timeout
        search_url = f"https://urlscan.io/api/v1/search/?q=domain:{identifier_value}&size=5"

        if not api_key:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=False,
                error="No URLScan API key. Get a free key at urlscan.io/user/signup",
                source_url=search_url,
            )

        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        logger.debug(f"[{self.name}] GET {search_url}")

        try:
            resp = requests.get(search_url, headers=headers, timeout=timeout)
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, search_url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, search_url, "Could not connect to urlscan.io.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, search_url, str(exc))

        if resp.status_code == 401:
            return self._error(identifier_type, identifier_value, search_url, "Invalid URLScan API key.")
        if resp.status_code == 429:
            return self._error(identifier_type, identifier_value, search_url, "URLScan rate limit reached.")

        try:
            resp.raise_for_status()
            raw = resp.json()
        except Exception as exc:
            return self._error(identifier_type, identifier_value, search_url, str(exc))

        results_raw = raw.get("results", [])
        if not results_raw:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=True,
                data={"scans_found": 0, "message": "No URLScan results found for this domain."},
                source_url=search_url,
            )

        scans = []
        for r in results_raw:
            page = r.get("page", {})
            task = r.get("task", {})
            stats = r.get("stats", {})
            scans.append({
                "scan_date":    task.get("time", "")[:10],
                "url":          page.get("url"),
                "ip":           page.get("ip"),
                "country":      page.get("country"),
                "server":       page.get("server"),
                "status":       page.get("status"),
                "title":        page.get("title"),
                "screenshot":   r.get("screenshot"),
                "report_url":   f"https://urlscan.io/result/{r.get('task', {}).get('uuid', '')}",
                "malicious":    stats.get("malicious", 0),
            })

        technologies: set[str] = set()
        ips_seen: set[str] = set()
        for r in results_raw:
            for tech in r.get("page", {}).get("mimeType", "").split("/"):
                pass
            ip = r.get("page", {}).get("ip")
            if ip:
                ips_seen.add(ip)

        data = {
            "scans_found":   len(scans),
            "recent_scans":  scans,
            "ips_seen":      list(ips_seen),
        }

        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=f"https://urlscan.io/search/#domain:{identifier_value}",
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        count = result.data.get("scans_found", 0)
        if count == 0:
            return "No scans found"
        scans = result.data.get("recent_scans", [])
        latest = scans[0].get("scan_date", "") if scans else ""
        ips = result.data.get("ips_seen", [])
        return f"{count} scan(s) · latest {latest} · IPs: {', '.join(ips[:3])}"

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
