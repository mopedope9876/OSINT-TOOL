"""
osint/gui/config_store.py
--------------------------
Saves and loads the user's API keys between sessions.

Keys are stored in the OS-standard config directory:
  Windows : C:\\Users\\<you>\\AppData\\Roaming\\osint-tool\\keys.json
  macOS   : ~/Library/Application Support/osint-tool/keys.json
  Linux   : ~/.config/osint-tool/keys.json

Keys never touch the project folder and can never be accidentally
committed to version control.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import platformdirs

_APP_NAME  = "osint-tool"
_CONFIG_DIR = Path(platformdirs.user_config_dir(_APP_NAME))
_KEYS_FILE  = _CONFIG_DIR / "keys.json"

# Maps plugin module name → display info shown in setup wizard.
API_KEY_REGISTRY: dict[str, dict] = {
    "shodan": {
        "display_name": "Shodan",
        "description":  "Discovers open ports, running services, and banners on any IP address. Invaluable for infrastructure OSINT.",
        "signup_url":   "https://account.shodan.io/register",
        "placeholder":  "Paste your Shodan API key",
        "env_var":      "SHODAN_API_KEY",
    },
    "virustotal": {
        "display_name": "VirusTotal",
        "description":  "Checks IPs and domains against 70+ antivirus and threat-intelligence engines. 500 free queries/day.",
        "signup_url":   "https://www.virustotal.com/gui/join-us",
        "placeholder":  "Paste your VirusTotal API key",
        "env_var":      "VIRUSTOTAL_API_KEY",
    },
    "abuseipdb": {
        "display_name": "AbuseIPDB",
        "description":  "Checks whether an IP has been reported for abuse, spam, or attacks. 1,000 free checks/day.",
        "signup_url":   "https://www.abuseipdb.com/register",
        "placeholder":  "Paste your AbuseIPDB API key",
        "env_var":      "ABUSEIPDB_API_KEY",
    },
    "urlscan": {
        "display_name": "URLScan.io",
        "description":  "Visually scans domains and records all network requests, IPs, and technology stack. 1,000 free scans/day.",
        "signup_url":   "https://urlscan.io/user/signup",
        "placeholder":  "Paste your URLScan.io API key",
        "env_var":      "URLSCAN_API_KEY",
    },
}


def load_keys() -> dict[str, str]:
    """Return saved API keys, or empty dict if none saved yet."""
    if not _KEYS_FILE.exists():
        return {}
    try:
        return json.loads(_KEYS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_keys(keys: dict[str, str]) -> None:
    """Persist API keys to disk (strips whitespace, skips empty values)."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    clean = {k: v.strip() for k, v in keys.items() if v and v.strip()}
    _KEYS_FILE.write_text(json.dumps(clean, indent=2), encoding="utf-8")


def has_completed_setup() -> bool:
    """True if the user has gone through the setup wizard at least once."""
    return _KEYS_FILE.exists()


def apply_keys_to_config(config, keys: dict[str, str]) -> None:
    """
    Inject saved API keys as environment variables so _resolve_env_vars
    picks them up when each plugin calls config.get_plugin_config().

    This is the most reliable injection method — it works regardless of
    how the config was loaded or how Pydantic handles extra fields.
    """
    for plugin_name, key_value in keys.items():
        info = API_KEY_REGISTRY.get(plugin_name, {})
        env_var = info.get("env_var")
        if env_var and key_value:
            os.environ[env_var] = key_value
