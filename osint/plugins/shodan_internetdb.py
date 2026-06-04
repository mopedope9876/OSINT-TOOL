"""
osint/plugins/shodan_internetdb.py
------------------------------------
Free port and vulnerability summary from Shodan's InternetDB endpoint.

InternetDB is a completely free, no-auth endpoint that returns a quick
summary of open ports, detected CVEs, hostnames, and tags for any
public IP address. It is separate from the main Shodan API (which
requires an API key and returns much more detail).

No API key required. No rate limit (Shodan's own free tier).
https://internetdb.shodan.io/
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class ShodanInternetDBPlugin(BasePlugin):
    name = "Shodan InternetDB (free)"
    description = "Open ports, detected CVEs, hostnames for any IP. Completely free — no key needed."
    supported_identifiers = ["ip"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        url = f"https://internetdb.shodan.io/{identifier_value}"
        timeout = config.general.request_timeout
        headers = {"User-Agent": "osint-tool/0.1"}

        logger.debug(f"[{self.name}] GET {url}")

        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to internetdb.shodan.io.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if resp.status_code == 404:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=True,
                data={"message": "No InternetDB data found for this IP."},
                source_url=url,
            )

        try:
            resp.raise_for_status()
            raw = resp.json()
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        data = {
            "ip":        raw.get("ip"),
            "ports":     raw.get("ports", []),
            "hostnames": raw.get("hostnames", []),
            "tags":      raw.get("tags", []),
            "vulns":     raw.get("vulns", []),
            "cpes":      raw.get("cpes", []),
        }
        data = {k: v for k, v in data.items() if v not in (None, [], "")}

        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=f"https://www.shodan.io/host/{identifier_value}",
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        if "message" in d:
            return d["message"]
        ports = d.get("ports", [])
        vulns = d.get("vulns", [])
        parts = []
        if ports:
            parts.append(f"{len(ports)} open port(s): {', '.join(str(p) for p in ports[:5])}")
        if vulns:
            parts.append(f"{len(vulns)} CVE(s): {', '.join(vulns[:3])}")
        return " · ".join(parts) if parts else "No open ports detected"

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
