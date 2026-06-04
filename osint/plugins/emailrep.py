"""
osint/plugins/emailrep.py
--------------------------
Email reputation and breach intelligence from EmailRep.io.

Returns a reputation score and signals for any email address:
  - credentials_leaked   : email+password found in data breaches
  - data_breach          : email seen in at least one data breach
  - spam                 : associated with spam activity
  - malicious_activity   : associated with phishing, malware, etc.
  - disposable           : one-time / throwaway email provider
  - free_provider        : Gmail, Yahoo, Outlook, etc.
  - deliverable          : MX record exists and email can receive mail
  - profiles             : associated social/public profiles found

Works without an API key (rate-limited). With a free key the limit is
much higher. Get one at: https://emailrep.io/key
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class EmailRepPlugin(BasePlugin):
    name = "EmailRep.io"
    description = "Email reputation: breaches, spam, disposable check, associated profiles. Free key optional."
    supported_identifiers = ["email"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        plugin_cfg = config.get_plugin_config("emailrep")
        api_key = plugin_cfg.api_key
        timeout = config.general.request_timeout
        url = f"https://emailrep.io/{identifier_value}"

        headers = {"User-Agent": "osint-tool/0.1"}
        if api_key:
            headers["Key"] = api_key

        logger.debug(f"[{self.name}] GET {url}")

        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to emailrep.io.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if resp.status_code == 400:
            return self._error(identifier_type, identifier_value, url, "Invalid email address format.")
        if resp.status_code == 401:
            return self._error(identifier_type, identifier_value, url, "Invalid EmailRep API key.")
        if resp.status_code == 429:
            return self._error(
                identifier_type, identifier_value, url,
                "EmailRep rate limit reached. Add a free API key at emailrep.io/key for higher limits.",
            )

        try:
            resp.raise_for_status()
            raw = resp.json()
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        details = raw.get("details", {})
        data = {
            "email":              raw.get("email"),
            "reputation":         raw.get("reputation"),
            "suspicious":         raw.get("suspicious"),
            "references":         raw.get("references", 0),
            "credentials_leaked": details.get("credentials_leaked"),
            "data_breach":        details.get("data_breach"),
            "spam":               details.get("spam"),
            "malicious_activity": details.get("malicious_activity"),
            "disposable":         details.get("disposable"),
            "free_provider":      details.get("free_provider"),
            "deliverable":        details.get("deliverable"),
            "domain_exists":      details.get("domain_exists"),
            "domain_reputation":  details.get("domain_reputation"),
            "profiles":           details.get("profiles", []),
        }
        data = {k: v for k, v in data.items() if v not in (None, "", [])}

        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=f"https://emailrep.io/{identifier_value}",
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        rep = d.get("reputation", "unknown")
        flags = []
        if d.get("credentials_leaked"):
            flags.append("credentials leaked")
        if d.get("spam"):
            flags.append("spam")
        if d.get("malicious_activity"):
            flags.append("malicious activity")
        if d.get("suspicious"):
            flags.append("suspicious")
        summary = f"Reputation: {rep}"
        if flags:
            summary += " · " + ", ".join(flags)
        return summary

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
