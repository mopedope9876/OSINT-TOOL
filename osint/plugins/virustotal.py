"""
osint/plugins/virustotal.py
-----------------------------
VirusTotal threat intelligence for IP addresses and domains.

VirusTotal aggregates results from 70+ antivirus engines and URL scanners.
A free API key gives 500 requests per day and 4 requests per minute.

GET FREE KEY: https://www.virustotal.com/gui/join-us
(Create a free account → API Key tab in your profile)
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalPlugin(BasePlugin):
    name = "VirusTotal"
    description = "Checks IPs and domains against 70+ threat intel engines. Free API key required."
    supported_identifiers = ["ip", "domain"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        plugin_cfg = config.get_plugin_config("virustotal")
        api_key = plugin_cfg.api_key
        timeout = config.general.request_timeout

        if not api_key:
            return self._no_key(identifier_type, identifier_value)

        if identifier_type == "ip":
            url = f"{_BASE}/ip_addresses/{identifier_value}"
        else:
            url = f"{_BASE}/domains/{identifier_value}"

        headers = {"x-apikey": api_key, "Accept": "application/json"}
        logger.debug(f"[{self.name}] GET {url}")

        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to virustotal.com.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if resp.status_code == 401:
            return self._error(identifier_type, identifier_value, url, "Invalid VirusTotal API key.")
        if resp.status_code == 404:
            return self._error(identifier_type, identifier_value, url, f"No VirusTotal data found for '{identifier_value}'.")
        if resp.status_code == 429:
            return self._error(identifier_type, identifier_value, url, "VirusTotal rate limit hit (4 req/min on free tier). Wait a moment.")

        try:
            resp.raise_for_status()
            raw = resp.json().get("data", {}).get("attributes", {})
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        stats = raw.get("last_analysis_stats", {})
        data = {
            "malicious_votes":    stats.get("malicious", 0),
            "suspicious_votes":   stats.get("suspicious", 0),
            "harmless_votes":     stats.get("harmless", 0),
            "undetected_votes":   stats.get("undetected", 0),
            "total_engines":      sum(stats.values()) if stats else 0,
            "reputation_score":   raw.get("reputation"),
            "country":            raw.get("country"),
            "continent":          raw.get("continent"),
            "as_owner":           raw.get("as_owner"),
            "asn":                raw.get("asn"),
            "network":            raw.get("network"),
            "categories":         raw.get("categories", {}),
            "tags":               raw.get("tags", []),
            "last_analysis_date": raw.get("last_analysis_date"),
            "registrar":          raw.get("registrar"),
            "creation_date":      raw.get("creation_date"),
        }
        data = {k: v for k, v in data.items() if v not in (None, {}, [])}

        vt_url = (
            f"https://www.virustotal.com/gui/ip-address/{identifier_value}"
            if identifier_type == "ip"
            else f"https://www.virustotal.com/gui/domain/{identifier_value}"
        )

        return PluginResult(
            plugin_name=self.name,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            success=True,
            data=data,
            source_url=vt_url,
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        mal = d.get("malicious_votes", 0)
        total = d.get("total_engines", 0)
        owner = d.get("as_owner", "")
        flag = "[red]FLAGGED[/]" if mal > 0 else "[green]Clean[/]"
        return f"{flag} — {mal}/{total} engines · {owner}"

    def _no_key(self, itype, ival) -> PluginResult:
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False,
            error="No VirusTotal API key. Get a free key at virustotal.com/gui/join-us",
        )

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
