"""
osint/plugins/shodan.py
------------------------
Queries Shodan for information about an IP address or domain using
the Shodan REST API directly (no extra library needed).

Shodan is a search engine for internet-connected devices. It passively
scans the entire internet and records open ports, running services,
banners, and vulnerabilities.

REQUIRES A FREE API KEY:
Sign up at https://shodan.io
Set it in config.yaml:   plugins.shodan.api_key: "your_key"
Or via environment var:  export SHODAN_API_KEY=your_key
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class ShodanPlugin(BasePlugin):
    name = "Shodan"
    description = "Open ports, services, CVEs, and banner data for an IP. Requires free API key."
    supported_identifiers = ["ip"]

    def run(
        self,
        identifier_type: str,
        identifier_value: str,
        config: AppConfig,
    ) -> PluginResult:
        plugin_cfg = config.get_plugin_config("shodan")
        api_key = plugin_cfg.api_key
        timeout = config.general.request_timeout
        url = f"https://api.shodan.io/shodan/host/{identifier_value}"

        if not api_key:
            return PluginResult(
                plugin_name=self.name,
                identifier_type=identifier_type,
                identifier_value=identifier_value,
                success=False,
                error=(
                    "No Shodan API key configured. "
                    "Get a free key at shodan.io and add it to config.yaml."
                ),
                source_url=url,
            )

        logger.debug(f"[{self.name}] GET {url}")

        try:
            response = requests.get(url, params={"key": api_key}, timeout=timeout)
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to api.shodan.io.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if response.status_code == 401:
            return self._error(
                identifier_type, identifier_value, url,
                "Invalid Shodan API key. Check config.yaml.",
            )
        if response.status_code == 404:
            return self._error(
                identifier_type, identifier_value, url,
                f"Shodan has no data for IP '{identifier_value}'.",
            )
        if response.status_code == 429:
            return self._error(
                identifier_type, identifier_value, url,
                "Shodan API rate limit exceeded.",
            )

        try:
            response.raise_for_status()
            raw = response.json()
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        # Extract a clean, report-friendly summary from the raw response.
        ports = sorted(raw.get("ports", []))
        services = [
            {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "cpe": item.get("cpe", []),
            }
            for item in raw.get("data", [])
        ]

        data = {
            "ip": raw.get("ip_str"),
            "hostnames": raw.get("hostnames", []),
            "domains": raw.get("domains", []),
            "country": raw.get("country_name"),
            "city": raw.get("city"),
            "org": raw.get("org"),
            "isp": raw.get("isp"),
            "asn": raw.get("asn"),
            "os": raw.get("os"),
            "open_ports": ports,
            "services": services,
            "tags": raw.get("tags", []),
            "vulns": list(raw.get("vulns", {}).keys()),
            "last_update": raw.get("last_update"),
        }

        # Remove None values for a cleaner report.
        data = {k: v for k, v in data.items() if v not in (None, [], {})}

        return PluginResult(
            plugin_name=self.name,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            success=True,
            data=data,
            source_url=f"https://www.shodan.io/host/{identifier_value}",
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        ports = d.get("open_ports", [])
        org = d.get("org") or d.get("isp", "")
        vulns = d.get("vulns", [])
        parts = []
        if org:
            parts.append(org)
        if ports:
            parts.append(f"{len(ports)} open port(s): {', '.join(str(p) for p in ports[:6])}")
        if vulns:
            parts.append(f"{len(vulns)} CVE(s)")
        return " · ".join(parts) if parts else "Data retrieved"

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
