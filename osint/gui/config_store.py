"""
osint/gui/config_store.py
--------------------------
Saves and loads the user's API keys between sessions.

Keys are stored in the user's OS-standard config directory:
  Windows : C:\\Users\\<you>\\AppData\\Roaming\\osint-tool\\keys.json
  macOS   : ~/Library/Application Support/osint-tool/keys.json
  Linux   : ~/.config/osint-tool/keys.json

This keeps keys out of the project folder so they can never
accidentally be committed to version control.
"""

from __future__ import annotations

import json
from pathlib import Path

import platformdirs

_APP_NAME = "osint-tool"
_CONFIG_DIR = Path(platformdirs.user_config_dir(_APP_NAME))
_KEYS_FILE = _CONFIG_DIR / "keys.json"

# Every plugin that requires a free API key — key = plugin module name,
# value = display info shown in the setup wizard.
API_KEY_REGISTRY: dict[str, dict] = {
    "shodan": {
        "display_name": "Shodan",
        "description":  "Searches open ports, services, and banners on IP addresses.",
        "signup_url":   "https://account.shodan.io/register",
        "placeholder":  "Paste your Shodan API key here",
    },
    "virustotal": {
        "display_name": "VirusTotal",
        "description":  "Checks IPs and domains against 70+ threat-intel engines. 500 free queries/day.",
        "signup_url":   "https://www.virustotal.com/gui/join-us",
        "placeholder":  "Paste your VirusTotal API key here",
    },
    "abuseipdb": {
        "display_name": "AbuseIPDB",
        "description":  "IP reputation from community abuse reports. 1,000 free checks/day.",
        "signup_url":   "https://www.abuseipdb.com/register",
        "placeholder":  "Paste your AbuseIPDB API key here",
    },
}


def load_keys() -> dict[str, str]:
    """Return saved API keys, or an empty dict if none have been saved yet."""
    if not _KEYS_FILE.exists():
        return {}
    try:
        return json.loads(_KEYS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_keys(keys: dict[str, str]) -> None:
    """Persist API keys to disk, stripping whitespace and empty values."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    clean = {k: v.strip() for k, v in keys.items() if v and v.strip()}
    _KEYS_FILE.write_text(json.dumps(clean, indent=2), encoding="utf-8")


def has_completed_setup() -> bool:
    """Return True if the user has already gone through the setup wizard."""
    return _KEYS_FILE.exists()


def apply_keys_to_config(config, keys: dict[str, str]) -> None:
    """
    Inject saved API keys into an AppConfig object at runtime.

    The config file uses ${ENV_VAR} placeholders. This function bypasses
    that by directly setting the api_key on the config's plugin extra fields.
    Because AppConfig uses extra='allow', we can add arbitrary sub-sections.
    """
    for plugin_name, key_value in keys.items():
        if plugin_name not in config.plugins.model_extra:
            config.plugins.model_extra[plugin_name] = {}
        if isinstance(config.plugins.model_extra.get(plugin_name), dict):
            config.plugins.model_extra[plugin_name]["api_key"] = key_value
