"""
osint/plugins/hackertarget.py
------------------------------
Multiple OSINT lookups via HackerTarget's free API.

For IPs   : reverse IP lookup (other domains on same server) + ASN info.
For domains: DNS record lookup + zone transfer attempt.

Free tier allows ~10 API queries/day without a key. No signup needed.
Results that exceed the daily limit return a plain-text error message
from HackerTarget which this plugin handles gracefully.

https://hackertarget.com/api/
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)

_BASE = "https://api.hackertarget.com"
_HEADERS = {"User-Agent": "osint-tool/0.1"}


class HackerTargetPlugin(BasePlugin):
    name = "HackerTarget"
    description = "Reverse IP (co-hosted domains) + ASN for IPs; DNS records for domains. No key needed."
    supported_identifiers = ["ip", "domain"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        timeout = config.general.request_timeout

        if identifier_type == "ip":
            return self._run_ip(identifier_type, identifier_value, timeout)
        return self._run_domain(identifier_type, identifier_value, timeout)

    # ── IP ────────────────────────────────────────────────────────────────────

    def _run_ip(self, itype: str, ival: str, timeout: int) -> PluginResult:
        source = f"https://hackertarget.com/reverse-ip-lookup/?q={ival}"
        results: dict = {}
        errors: list[str] = []

        # Reverse IP
        ri_url = f"{_BASE}/reverseiplookup/?q={ival}"
        logger.debug(f"[{self.name}] GET {ri_url}")
        try:
            r = requests.get(ri_url, headers=_HEADERS, timeout=timeout)
            text = r.text.strip()
            if "API count" in text or "exceeded" in text.lower():
                errors.append("HackerTarget free daily limit reached.")
            elif r.ok and text and "error" not in text.lower():
                domains = [d.strip() for d in text.split("\n") if d.strip()]
                results["co_hosted_domains"] = domains
            else:
                errors.append(f"Reverse IP: {text[:120]}")
        except Exception as exc:
            errors.append(f"Reverse IP error: {exc}")

        # ASN lookup
        asn_url = f"{_BASE}/aslookup/?q={ival}"
        logger.debug(f"[{self.name}] GET {asn_url}")
        try:
            r = requests.get(asn_url, headers=_HEADERS, timeout=timeout)
            text = r.text.strip()
            if r.ok and "error" not in text.lower() and "API count" not in text:
                parts = [p.strip('"') for p in text.split(",")]
                if len(parts) >= 2:
                    results["asn"]         = parts[1] if len(parts) > 1 else ""
                    results["asn_range"]   = parts[2] if len(parts) > 2 else ""
                    results["asn_org"]     = parts[3] if len(parts) > 3 else ""
                    results["asn_country"] = parts[4] if len(parts) > 4 else ""
        except Exception as exc:
            errors.append(f"ASN lookup error: {exc}")

        if not results and errors:
            return self._error(itype, ival, source, "; ".join(errors))
        if errors:
            results["notes"] = errors
        return PluginResult(
            plugin_name=self.name, identifier_type=itype,
            identifier_value=ival, success=True,
            data={k: v for k, v in results.items() if v not in (None, [], "")},
            source_url=source,
        )

    # ── Domain ────────────────────────────────────────────────────────────────

    def _run_domain(self, itype: str, ival: str, timeout: int) -> PluginResult:
        source = f"https://hackertarget.com/dns-lookup/?q={ival}"
        results: dict = {}
        errors: list[str] = []

        # DNS lookup
        dns_url = f"{_BASE}/dnslookup/?q={ival}"
        logger.debug(f"[{self.name}] GET {dns_url}")
        try:
            r = requests.get(dns_url, headers=_HEADERS, timeout=timeout)
            text = r.text.strip()
            if "API count" in text or "exceeded" in text.lower():
                errors.append("HackerTarget free daily limit reached.")
            elif r.ok and text and "error" not in text.lower():
                lines = [l.strip() for l in text.split("\n") if l.strip()]
                results["dns_records"] = lines[:20]
        except Exception as exc:
            errors.append(f"DNS lookup error: {exc}")

        # Zone transfer check
        zt_url = f"{_BASE}/zonetransfer/?q={ival}"
        logger.debug(f"[{self.name}] GET {zt_url}")
        try:
            r = requests.get(zt_url, headers=_HEADERS, timeout=timeout)
            text = r.text.strip()
            if r.ok and "API count" not in text and text:
                results["zone_transfer_result"] = text[:600]
        except Exception as exc:
            errors.append(f"Zone transfer error: {exc}")

        if not results and errors:
            return self._error(itype, ival, source, "; ".join(errors))
        if errors:
            results["notes"] = errors
        return PluginResult(
            plugin_name=self.name, identifier_type=itype,
            identifier_value=ival, success=True,
            data={k: v for k, v in results.items() if v not in (None, [], "")},
            source_url=source,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        parts = []
        if "co_hosted_domains" in d:
            parts.append(f"{len(d['co_hosted_domains'])} co-hosted domain(s)")
        if "asn_org" in d:
            parts.append(d["asn_org"])
        if "dns_records" in d:
            parts.append(f"{len(d['dns_records'])} DNS record(s)")
        return " · ".join(parts) if parts else "Data retrieved"

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
