"""
osint/plugins/ipinfo.py
------------------------
IP geolocation and network info from ipinfo.io.

Free for up to 50,000 requests/month with no API key.
Returns: city, region, country, coordinates, hostname, ISP/org, ASN, timezone.

ipinfo.io is more reliable than ip-api.com in cloud/datacenter environments
and supports both IPv4 and IPv6.
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class IPInfoPlugin(BasePlugin):
    name = "IPInfo.io"
    description = "IP geolocation, hostname, ISP, ASN, timezone. 50k free req/month, no key needed."
    supported_identifiers = ["ip"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        url = f"https://ipinfo.io/{identifier_value}/json"
        timeout = config.general.request_timeout
        headers = {"Accept": "application/json", "User-Agent": "osint-tool/0.1"}

        logger.debug(f"[{self.name}] GET {url}")

        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            raw = resp.json()
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to ipinfo.io.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if "bogon" in raw:
            return self._error(
                identifier_type, identifier_value, url,
                f"'{identifier_value}' is a private/reserved (bogon) IP address.",
            )

        # Parse org field which is like "AS15169 Google LLC"
        org_raw = raw.get("org", "")
        asn, org_name = ("", org_raw)
        if org_raw and org_raw.startswith("AS"):
            parts = org_raw.split(" ", 1)
            asn = parts[0]
            org_name = parts[1] if len(parts) > 1 else ""

        # Parse loc field which is "lat,lon"
        loc = raw.get("loc", "")
        lat, lon = ("", "")
        if "," in loc:
            lat, lon = loc.split(",", 1)

        data = {
            "ip":        raw.get("ip"),
            "hostname":  raw.get("hostname"),
            "city":      raw.get("city"),
            "region":    raw.get("region"),
            "country":   raw.get("country"),
            "latitude":  lat or None,
            "longitude": lon or None,
            "org":       org_name or None,
            "asn":       asn or None,
            "postal":    raw.get("postal"),
            "timezone":  raw.get("timezone"),
        }
        data = {k: v for k, v in data.items() if v not in (None, "", [])}

        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=f"https://ipinfo.io/{identifier_value}",
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        location = ", ".join(filter(None, [d.get("city"), d.get("region"), d.get("country")]))
        org = d.get("org", "")
        return f"{location} — {org}" if org else location

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
