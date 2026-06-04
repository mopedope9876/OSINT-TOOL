"""
osint/plugins/crtsh.py
-----------------------
Subdomain discovery via Certificate Transparency logs (crt.sh).

Every SSL/TLS certificate issued for a domain is logged publicly.
crt.sh aggregates these logs, making it possible to find subdomains,
wildcard certs, and historical infrastructure — all completely free.

No API key required. Useful for domain reconnaissance.
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class CRTShPlugin(BasePlugin):
    name = "Certificate Transparency (crt.sh)"
    description = "Finds subdomains via SSL certificate logs. Reveals hidden infrastructure. No key needed."
    supported_identifiers = ["domain"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        url = f"https://crt.sh/?q=%.{identifier_value}&output=json"
        timeout = config.general.request_timeout
        headers = {"User-Agent": "osint-tool/0.1", "Accept": "application/json"}

        logger.debug(f"[{self.name}] GET {url}")

        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            entries = resp.json()
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to crt.sh.")
        except ValueError:
            return self._error(identifier_type, identifier_value, url, "crt.sh returned non-JSON response. Try again shortly.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if not entries:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=True,
                data={"subdomains_found": 0, "subdomains": [], "message": "No certificates found for this domain."},
                source_url=url,
            )

        # Deduplicate and clean subdomains from the name_value field.
        # name_value can contain multiple names separated by newlines.
        seen: set[str] = set()
        subdomains: list[str] = []
        issuers: set[str] = set()

        for entry in entries:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and name not in seen and identifier_value in name:
                    seen.add(name)
                    subdomains.append(name)
            issuer = entry.get("issuer_name", "")
            if issuer:
                issuers.add(issuer.split(",")[0].replace("O=", "").strip())

        subdomains.sort()

        data = {
            "subdomains_found": len(subdomains),
            "subdomains":       subdomains[:100],   # cap at 100 for readability
            "certificate_count": len(entries),
            "issuers_seen":     list(issuers)[:10],
        }

        if len(subdomains) > 100:
            data["note"] = f"Showing first 100 of {len(subdomains)} unique subdomains."

        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=f"https://crt.sh/?q=%.{identifier_value}",
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        count = result.data.get("subdomains_found", 0)
        if count == 0:
            return "No subdomains found"
        subs = result.data.get("subdomains", [])
        preview = ", ".join(subs[:3])
        return f"{count} subdomain(s): {preview}" + (" …" if count > 3 else "")

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
