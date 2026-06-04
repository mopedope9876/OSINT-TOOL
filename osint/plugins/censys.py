"""
osint/plugins/censys.py
------------------------
IP and domain intelligence from Censys.

Censys continuously scans the internet and maintains a comprehensive
database of open ports, running services, TLS certificates, and protocol
details for every reachable host.

  For IPs:     open ports, services, software, ASN info.
  For domains: matching TLS certificates and issuing CAs found.

FREE PLAN: 250 API queries/month — no credit card required.
REQUIRES:  API ID  +  API Secret  (both obtained from the same account page).

Sign up:  https://search.censys.io/register
Your API credentials: https://search.censys.io/account/api

Authentication is HTTP Basic Auth:  username = API ID, password = API Secret.
These are configured in the Settings screen (⚙) as two separate fields.
"""

from __future__ import annotations

import os

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class CensysPlugin(BasePlugin):
    name = "Censys"
    description = "Open ports, services, TLS certs for IPs and domains. 250 free queries/month (ID + Secret)."
    supported_identifiers = ["ip", "domain"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        api_id     = os.environ.get("CENSYS_API_ID", "")
        api_secret = os.environ.get("CENSYS_API_SECRET", "")
        timeout    = config.general.request_timeout

        if not api_id or not api_secret:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=False,
                error="No Censys credentials. Get a free API ID + Secret at search.censys.io/register",
                source_url="https://search.censys.io/",
            )

        auth    = (api_id, api_secret)
        headers = {"User-Agent": "osint-tool/0.1", "Accept": "application/json"}

        if identifier_type == "ip":
            return self._query_ip(identifier_type, identifier_value, auth, headers, timeout)
        return self._query_domain(identifier_type, identifier_value, auth, headers, timeout)

    # ── IP ────────────────────────────────────────────────────────────────────

    def _query_ip(self, itype, ival, auth, headers, timeout) -> PluginResult:
        url = f"https://search.censys.io/api/v2/hosts/{ival}"
        logger.debug(f"[{self.name}] GET {url}")

        try:
            resp = requests.get(url, auth=auth, headers=headers, timeout=timeout)
        except requests.Timeout:
            return self._error(itype, ival, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(itype, ival, url, "Could not connect to Censys.")
        except Exception as exc:
            return self._error(itype, ival, url, str(exc))

        if resp.status_code == 401:
            return self._error(itype, ival, url, "Invalid Censys API ID or Secret.")
        if resp.status_code == 429:
            return self._error(itype, ival, url, "Censys monthly quota or rate limit reached.")
        if resp.status_code == 404:
            return PluginResult(
                plugin_name=self.name, identifier_type=itype, identifier_value=ival,
                success=True, data={"message": "No Censys data for this IP."},
                source_url=f"https://search.censys.io/hosts/{ival}",
            )

        try:
            resp.raise_for_status()
            raw = resp.json().get("result", {})
        except Exception as exc:
            return self._error(itype, ival, url, str(exc))

        services = []
        for svc in raw.get("services", [])[:10]:
            services.append({
                "port":         svc.get("port"),
                "transport":    svc.get("transport_protocol"),
                "service_name": svc.get("service_name"),
            })

        asn_block = raw.get("autonomous_system", {})
        data = {
            "ip":           raw.get("ip"),
            "asn":          asn_block.get("asn"),
            "asn_name":     asn_block.get("name"),
            "country":      asn_block.get("country_code"),
            "open_ports":   [s.get("port") for s in raw.get("services", [])],
            "services":     services,
            "last_updated": (raw.get("last_updated_at") or "")[:10],
        }
        data = {k: v for k, v in data.items() if v not in (None, [], "", {})}

        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=True, data=data,
            source_url=f"https://search.censys.io/hosts/{ival}",
        )

    # ── Domain ────────────────────────────────────────────────────────────────

    def _query_domain(self, itype, ival, auth, headers, timeout) -> PluginResult:
        url = "https://search.censys.io/api/v2/certificates/search"
        params = {"q": f"parsed.names: {ival}", "per_page": 5}
        logger.debug(f"[{self.name}] GET {url}?q=...")

        try:
            resp = requests.get(url, auth=auth, headers=headers, params=params, timeout=timeout)
        except requests.Timeout:
            return self._error(itype, ival, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(itype, ival, url, "Could not connect to Censys.")
        except Exception as exc:
            return self._error(itype, ival, url, str(exc))

        if resp.status_code == 401:
            return self._error(itype, ival, url, "Invalid Censys API ID or Secret.")
        if resp.status_code == 429:
            return self._error(itype, ival, url, "Censys monthly quota or rate limit reached.")

        try:
            resp.raise_for_status()
            raw = resp.json()
        except Exception as exc:
            return self._error(itype, ival, url, str(exc))

        hits = raw.get("result", {}).get("hits", [])
        total = raw.get("result", {}).get("total", len(hits))

        subjects = []
        issuers: set[str] = set()
        for h in hits:
            parsed = h.get("parsed", {})
            subj = parsed.get("subject_dn", "")
            if subj:
                subjects.append(subj)
            issuer = parsed.get("issuer", {}).get("organization", [])
            for org in (issuer if isinstance(issuer, list) else [issuer]):
                if org:
                    issuers.add(str(org))

        data = {
            "certificates_found": total,
            "sample_subjects":    subjects[:5],
            "issuers":            list(issuers)[:5],
        }
        source = f"https://search.censys.io/certificates?q=parsed.names%3A+{ival}"

        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=True, data=data, source_url=source,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        if "message" in d:
            return d["message"]
        ports = d.get("open_ports", [])
        asn_name = d.get("asn_name", "")
        if ports:
            return f"{len(ports)} open port(s){' · ' + asn_name if asn_name else ''}"
        certs = d.get("certificates_found", 0)
        if certs:
            return f"{certs} certificate(s) found"
        return "Data retrieved"

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
