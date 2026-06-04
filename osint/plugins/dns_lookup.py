"""
osint/plugins/dns_lookup.py
-----------------------------
Comprehensive DNS record lookup for domain names.

Retrieves A, AAAA, MX, NS, TXT, CNAME, and SOA records using
dnspython. DNS data is public by design — no API key is needed.

TXT records are particularly valuable for OSINT: they often contain
SPF policies (revealing mail infrastructure), DKIM selectors, domain
verification tokens, and misconfigured secrets.
"""

from __future__ import annotations

import dns.exception
import dns.rdatatype
import dns.resolver

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DNSLookupPlugin(BasePlugin):
    name = "DNS Records"
    description = "Queries A, AAAA, MX, NS, TXT, CNAME, SOA records for a domain. No key required."
    supported_identifiers = ["domain"]

    def run(
        self,
        identifier_type: str,
        identifier_value: str,
        config: AppConfig,
    ) -> PluginResult:
        source_url = f"https://dnschecker.org/#A/{identifier_value}"
        resolver = dns.resolver.Resolver()
        resolver.timeout = config.general.request_timeout
        resolver.lifetime = config.general.request_timeout

        data: dict = {}
        errors: list[str] = []

        for rtype in _RECORD_TYPES:
            try:
                answers = resolver.resolve(identifier_value, rtype)
                records = _format_answers(rtype, answers)
                if records:
                    data[rtype] = records
            except dns.resolver.NXDOMAIN:
                return PluginResult(
                    plugin_name=self.name,
                    identifier_type=identifier_type,
                    identifier_value=identifier_value,
                    success=False,
                    error=f"Domain '{identifier_value}' does not exist (NXDOMAIN).",
                    source_url=source_url,
                )
            except dns.resolver.NoAnswer:
                # No records of this type — normal, not an error.
                pass
            except dns.resolver.NoNameservers:
                errors.append(f"{rtype}: no nameservers available")
            except dns.exception.Timeout:
                errors.append(f"{rtype}: query timed out")
            except Exception as exc:
                errors.append(f"{rtype}: {exc}")

        if not data and errors:
            return PluginResult(
                plugin_name=self.name,
                identifier_type=identifier_type,
                identifier_value=identifier_value,
                success=False,
                error="All DNS queries failed: " + "; ".join(errors),
                source_url=source_url,
            )

        if errors:
            data["_errors"] = errors

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
        record_types = [k for k in d if not k.startswith("_")]
        a_records = d.get("A", [])
        mx_count = len(d.get("MX", []))
        parts = [f"Types: {', '.join(record_types)}"]
        if a_records:
            parts.append(f"A → {', '.join(a_records[:3])}")
        if mx_count:
            parts.append(f"{mx_count} MX record(s)")
        return " · ".join(parts)

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


def _format_answers(rtype: str, answers) -> list[str]:
    """Convert dnspython answer objects to plain strings."""
    results = []
    for rdata in answers:
        try:
            if rtype == "MX":
                results.append(f"{rdata.preference} {rdata.exchange}")
            elif rtype == "SOA":
                results.append(
                    f"mname={rdata.mname} rname={rdata.rname} "
                    f"serial={rdata.serial}"
                )
            elif rtype == "TXT":
                parts = [p.decode("utf-8", errors="replace") for p in rdata.strings]
                results.append(" ".join(parts))
            else:
                results.append(str(rdata))
        except Exception:
            results.append(str(rdata))
    return results
