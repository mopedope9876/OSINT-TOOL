"""
osint/plugins/github_user.py
-----------------------------
Fetches a GitHub user's public profile via the GitHub REST API.

No API key is required for basic use, but unauthenticated requests are
limited to 60 per hour per IP. Set a GitHub personal access token in
config.yaml (plugins.github_user.api_key) to raise the limit to 5,000/hr.
"""

from __future__ import annotations

import requests

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)

_KEEP_FIELDS = [
    "login", "name", "bio", "company", "blog", "location", "email",
    "twitter_username", "public_repos", "public_gists", "followers",
    "following", "created_at", "updated_at", "html_url", "avatar_url",
    "site_admin", "hireable",
]


class GitHubUserPlugin(BasePlugin):
    name = "GitHub User Profile"
    description = "Fetches public GitHub profile: repos, followers, bio, location."
    supported_identifiers = ["username"]

    def run(
        self,
        identifier_type: str,
        identifier_value: str,
        config: AppConfig,
    ) -> PluginResult:
        plugin_cfg = config.get_plugin_config("github_user")
        base_url = plugin_cfg.base_url or "https://api.github.com/users"
        url = f"{base_url}/{identifier_value}"
        timeout = config.general.request_timeout

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "osint-tool/0.1",
        }
        if plugin_cfg.api_key:
            headers["Authorization"] = f"Bearer {plugin_cfg.api_key}"

        logger.debug(f"[{self.name}] GET {url}")

        try:
            response = requests.get(url, headers=headers, timeout=timeout)
        except requests.Timeout:
            return self._error(identifier_type, identifier_value, url, "Request timed out.")
        except requests.ConnectionError:
            return self._error(identifier_type, identifier_value, url, "Could not connect to api.github.com.")
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        if response.status_code == 404:
            return self._error(
                identifier_type, identifier_value, url,
                f"GitHub user '{identifier_value}' not found.",
            )
        if response.status_code == 403:
            rate = response.headers.get("X-RateLimit-Remaining", "?")
            return self._error(
                identifier_type, identifier_value, url,
                f"GitHub API rate limit hit (remaining: {rate}). Add an API key to config.yaml.",
            )

        try:
            response.raise_for_status()
            raw = response.json()
        except Exception as exc:
            return self._error(identifier_type, identifier_value, url, str(exc))

        # Keep only relevant fields and remove None values for a clean report.
        data = {k: raw[k] for k in _KEEP_FIELDS if k in raw and raw[k] is not None}

        return PluginResult(
            plugin_name=self.name,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            success=True,
            data=data,
            source_url=f"https://github.com/{identifier_value}",
        )

    def get_summary(self, result: PluginResult) -> str:
        if not result.success:
            return result.error or "Unknown error"
        d = result.data
        name = d.get("name") or d.get("login", "")
        repos = d.get("public_repos", 0)
        followers = d.get("followers", 0)
        location = d.get("location", "")
        parts = [name]
        if location:
            parts.append(location)
        parts.append(f"{followers:,} followers · {repos} repos")
        return " · ".join(filter(None, parts))

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
