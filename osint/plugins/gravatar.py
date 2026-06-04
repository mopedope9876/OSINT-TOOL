"""
osint/plugins/gravatar.py
--------------------------
Checks if an email address has a public Gravatar profile.

Gravatar (Globally Recognised Avatar) is a service that links a public
profile to an email address. Because the lookup uses an MD5 hash of the
email, no API key is needed and the original email address is never sent
to Gravatar's servers.

Completely free — no account or key required.
"""

from __future__ import annotations

import hashlib

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


class GravatarPlugin(BasePlugin):
    name = "Gravatar Profile"
    description = "Checks if the email has a public Gravatar profile. No API key needed."
    supported_identifiers = ["email"]

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        email_hash = hashlib.md5(identifier_value.strip().lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/{email_hash}.json"
        timeout = config.general.request_timeout

        logger.debug(f"[{self.name}] GET {url}")

        try:
            resp = requests.get(url, timeout=timeout)
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to gravatar.com.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if resp.status_code == 404:
            return PluginResult(
                plugin_name=self.name, identifier_type=identifier_type,
                identifier_value=identifier_value, success=True,
                data={"profile_found": False, "message": "No public Gravatar profile linked to this email."},
                source_url=url,
            )

        try:
            resp.raise_for_status()
            entry = resp.json().get("entry", [{}])[0]
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        accounts = [
            {"domain": a.get("domain"), "username": a.get("username"), "url": a.get("url")}
            for a in entry.get("accounts", [])
        ]
        urls = [{"title": u.get("title"), "value": u.get("value")} for u in entry.get("urls", [])]

        data = {
            "profile_found":  True,
            "username":       entry.get("preferredUsername"),
            "display_name":   entry.get("displayName"),
            "profile_url":    entry.get("profileUrl"),
            "thumbnail_url":  entry.get("thumbnailUrl"),
            "about_me":       entry.get("aboutMe"),
            "location":       entry.get("currentLocation"),
            "job_title":      entry.get("jobTitle"),
            "company":        entry.get("company"),
            "linked_accounts": accounts,
            "linked_urls":    urls,
        }
        data = {k: v for k, v in data.items() if v not in (None, [], "")}

        return PluginResult(
            plugin_name=self.name, identifier_type=identifier_type,
            identifier_value=identifier_value, success=True,
            data=data, source_url=entry.get("profileUrl", url),
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        if not d.get("profile_found"):
            return "No Gravatar profile found"
        name = d.get("display_name") or d.get("username", "")
        location = d.get("location", "")
        accounts = len(d.get("linked_accounts", []))
        parts = [name]
        if location:
            parts.append(location)
        if accounts:
            parts.append(f"{accounts} linked account(s)")
        return " · ".join(filter(None, parts)) or "Profile found"

    def _error(self, itype, ival, url, msg) -> PluginResult:
        logger.warning(f"[{self.name}] {msg}")
        return PluginResult(
            plugin_name=self.name, identifier_type=itype, identifier_value=ival,
            success=False, error=msg, source_url=url,
        )
