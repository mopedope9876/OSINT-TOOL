"""
osint/plugins/greynoise.py
---------------------------
Classifies whether an IP is internet background noise using GreyNoise.

GreyNoise distinguishes between three kinds of IPs:
  Noise  — IPs that blindly scan the internet and attack infrastructure.
  RIOT   — Known benign services (Google, Cloudflare, AWS, CDNs, etc.).
  Unknown — Not seen in GreyNoise data.

Knowing an IP is "noise" is critical for triaging alerts — an inbound
connection from a known mass-scanner is much lower priority than one
from an unclassified IP.

FREE API KEY: 1,000 lookups/day
Get key at: https://www.greynoise.io/viz/account/register
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class GreyNoisePlugin(BasePlugin):
    name = "GreyNoise"
    description = "Is this IP a known internet scanner or benign service? 1k free lookups/day with key."
    supported_identifiers = ["ip"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        plugin_cfg = config.get_plugin_config("greynoise")
        api_key = plugin_cfg.api_key
        timeout = config.general.request_timeout
        url = f"https://api.greynoise.io/v3/community/{identifier_value}"

        if not api_key:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=False,
                error="No GreyNoise API key. Get a free key at greynoise.io/viz/account/register",
                source_url=url,
            )

        headers = {"key": api_key, "User-Agent": "osint-tool/0.1"}
        logger.debug(f"[{self.name}] GET {url}")

        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to api.greynoise.io.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if resp.status_code == 401:
            return self._error(identifier_type, identifier_value, url, "Invalid GreyNoise API key.")
        if resp.status_code == 429:
            return self._error(identifier_type, identifier_value, url, "GreyNoise rate limit reached.")
        if resp.status_code == 404:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=True,
                data={"classification": "unknown", "noise": False, "riot": False,
                      "message": "IP not found in GreyNoise database."},
                source_url=f"https://www.greynoise.io/viz/ip/{identifier_value}",
            )

        try:
            resp.raise_for_status()
            raw = resp.json()
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        data = {
            "ip":             raw.get("ip"),
            "noise":          raw.get("noise"),
            "riot":           raw.get("riot"),
            "classification": raw.get("classification"),
            "name":           raw.get("name"),
            "link":           raw.get("link"),
            "last_seen":      raw.get("last_seen"),
            "message":        raw.get("message"),
        }
        data = {k: v for k, v in data.items() if v not in (None, "", False) or k in ("noise", "riot")}

        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=f"https://www.greynoise.io/viz/ip/{identifier_value}",
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        riot = d.get("riot", False)
        noise = d.get("noise", False)
        cls = d.get("classification", "unknown")
        name = d.get("name", "")
        if riot:
            return f"RIOT (known benign service){' — ' + name if name else ''}"
        if noise:
            return f"Noise (internet scanner) · {cls}"
        return f"Not noise · classification: {cls}"

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
