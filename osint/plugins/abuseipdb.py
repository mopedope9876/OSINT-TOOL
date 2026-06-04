"""
osint/plugins/abuseipdb.py
---------------------------
IP reputation check using the AbuseIPDB database.

AbuseIPDB is a community-driven project tracking malicious IP addresses.
Free tier: 1,000 checks per day.

GET FREE KEY: https://www.abuseipdb.com/register
(Create a free account → API tab in your profile)
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class AbuseIPDBPlugin(BasePlugin):
    name = "AbuseIPDB"
    description = "IP abuse/reputation check from community reports. Free API key required."
    supported_identifiers = ["ip"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        plugin_cfg = config.get_plugin_config("abuseipdb")
        api_key = plugin_cfg.api_key
        timeout = config.general.request_timeout
        url = "https://api.abuseipdb.com/api/v2/check"

        if not api_key:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=False,
                error="No AbuseIPDB API key. Get a free key at abuseipdb.com/register",
                source_url=url,
            )

        headers = {"Key": api_key, "Accept": "application/json"}
        params  = {"ipAddress": identifier_value, "maxAgeInDays": 90, "verbose": True}
        logger.debug(f"[{self.name}] GET {url}")

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to abuseipdb.com.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if resp.status_code == 401:
            return self._error(identifier_type, identifier_value, url, "Invalid AbuseIPDB API key.")
        if resp.status_code == 429:
            return self._error(identifier_type, identifier_value, url, "AbuseIPDB daily limit reached (1,000/day on free tier).")

        try:
            resp.raise_for_status()
            raw = resp.json().get("data", {})
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        data = {
            "ip_address":            raw.get("ipAddress"),
            "abuse_confidence_score": raw.get("abuseConfidenceScore"),
            "country_code":          raw.get("countryCode"),
            "country_name":          raw.get("countryName"),
            "isp":                   raw.get("isp"),
            "domain":                raw.get("domain"),
            "usage_type":            raw.get("usageType"),
            "is_tor":                raw.get("isTor"),
            "is_public":             raw.get("isPublic"),
            "is_whitelisted":        raw.get("isWhitelisted"),
            "total_reports":         raw.get("totalReports"),
            "num_distinct_users":    raw.get("numDistinctUsers"),
            "last_reported_at":      raw.get("lastReportedAt"),
        }
        data = {k: v for k, v in data.items() if v is not None}

        source_url = f"https://www.abuseipdb.com/check/{identifier_value}"
        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=source_url,
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        score = d.get("abuse_confidence_score", 0)
        reports = d.get("total_reports", 0)
        isp = d.get("isp", "")
        if score >= 50:
            flag = "[red]HIGH RISK[/]"
        elif score >= 10:
            flag = "[yellow]Suspicious[/]"
        else:
            flag = "[green]Clean[/]"
        return f"{flag} — score {score}/100 · {reports} report(s) · {isp}"

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
