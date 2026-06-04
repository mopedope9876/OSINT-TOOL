"""
osint/plugins/whois_lookup.py
------------------------------
WHOIS data for domain names and IP addresses using the python-whois library.

WHOIS is a protocol that lets you query registration information for
internet resources — who registered a domain, when it expires, which
nameservers it uses, and contact information (when not redacted).
"""

from __future__ import annotations

import whois

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


def _normalise(value) -> str | list | None:
    """
    python-whois sometimes returns dates as lists, strings, or datetime objects.
    Normalise everything to strings or lists of strings for clean JSON output.
    """
    if value is None:
        return None
    if isinstance(value, list):
        seen = []
        for item in value:
            s = _normalise(item)
            if s and s not in seen:
                seen.append(s)
        return seen if seen else None
    try:
        return value.isoformat() if hasattr(value, "isoformat") else str(value)
    except Exception:
        return str(value)


class WHOISPlugin(BasePlugin):
    name = "WHOIS Lookup"
    description = "Retrieves domain/IP registration data: registrar, dates, nameservers."
    supported_identifiers = ["domain", "ip"]

    def run(
        self,
        identifier_type: str,
        identifier_value: str,
        config: AppConfig,
    ) -> PluginResult:
        logger.debug(f"[{self.name}] WHOIS query for {identifier_value!r}")
        source_url = f"https://lookup.icann.org/en/lookup?name={identifier_value}"

        try:
            w = whois.whois(identifier_value)
        except whois.parser.PywhoisError as exc:
            return self._error(identifier_type, identifier_value, source_url, str(exc))
        except ConnectionResetError:
            return self._error(
                identifier_type, identifier_value, source_url,
                "WHOIS server reset the connection. Try again shortly.",
            )
        except Exception as exc:
            return self._error(identifier_type, identifier_value, source_url, str(exc))

        if w is None or not w.domain_name:
            return self._error(
                identifier_type, identifier_value, source_url,
                f"No WHOIS data found for '{identifier_value}'.",
            )

        interesting_keys = [
            "domain_name", "registrar", "whois_server", "creation_date",
            "expiration_date", "updated_date", "name_servers", "status",
            "emails", "dnssec", "name", "org", "address", "city",
            "state", "zipcode", "country",
        ]

        data: dict = {}
        for key in interesting_keys:
            val = getattr(w, key, None)
            normalised = _normalise(val)
            if normalised:
                data[key] = normalised

        if not data:
            return self._error(
                identifier_type, identifier_value, source_url,
                "WHOIS returned empty data.",
            )

        return PluginResult(
            plugin_name=self.name,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            success=True,
            data=data,
            source_url=source_url,
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        registrar = d.get("registrar", "")
        expiry = d.get("expiration_date", "")
        if isinstance(expiry, list):
            expiry = expiry[0] if expiry else ""
        if isinstance(expiry, str) and "T" in expiry:
            expiry = expiry.split("T")[0]
        parts = []
        if registrar:
            parts.append(str(registrar)[:40])
        if expiry:
            parts.append(f"expires {expiry}")
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
