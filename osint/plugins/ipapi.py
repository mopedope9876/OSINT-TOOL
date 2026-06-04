"""
osint/plugins/ipapi.py
----------------------
IP geolocation using ip-api.com (free, no API key required).

Returns city, country, region, ISP, ASN, timezone, lat/lon, and
flags for whether the IP belongs to a proxy, hosting provider, or
mobile network.
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)

# The fields we ask ip-api.com to include in its response.
_FIELDS = (
    "status,message,country,countryCode,region,regionName,city,zip,"
    "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)


class IPAPIPlugin(BasePlugin):
    name = "IP Geolocation (ip-api.com)"
    description = "Geolocates an IP address. Returns city, ISP, ASN, proxy flags. No key required."
    supported_identifiers = ["ip"]

    def run(
        self,
        identifier_type: str,
        identifier_value: str,
        config: AppConfig,
    ) -> PluginResult:
        plugin_cfg = config.get_plugin_config("ipapi")
        base_url = plugin_cfg.base_url or "http://ip-api.com/json"
        url = f"{base_url}/{identifier_value}"
        timeout = config.general.request_timeout

        logger.debug(f"[{self.name}] GET {url}")

        try:
            response = requests.get(url, params={"fields": _FIELDS}, timeout=timeout)
            response.raise_for_status()
            data = response.json()
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to ip-api.com.")
        except requests.HTTPError as exc:
            return self._error(identifier_type, identifier_value, url, f"HTTP error: {exc}")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if data.get("status") == "fail":
            return self._error(
                identifier_type,
                identifier_value,
                url,
                data.get("message", "ip-api.com returned failure status."),
            )

        # Remove internal status fields — they're not useful in the report.
        data.pop("status", None)
        data.pop("message", None)

        return PluginResult(
            plugin_name=self.name,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            success=True,
            data=data,
            source_url=url,
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        city = d.get("city", "")
        region = d.get("regionName", "")
        country = d.get("country", "")
        isp = d.get("isp", "")
        flags = []
        if d.get("proxy"):
            flags.append("proxy")
        if d.get("hosting"):
            flags.append("hosting/VPN")
        if d.get("mobile"):
            flags.append("mobile")
        location = ", ".join(filter(None, [city, region, country]))
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        return f"{location} — {isp}{flag_str}"

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
