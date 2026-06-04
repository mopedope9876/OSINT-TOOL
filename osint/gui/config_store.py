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
#
# Optional per-entry keys:
#   secondary_field : dict — a second credential (e.g. Censys needs API ID + Secret).
#     Keys inside secondary_field:
#       label       : str — label shown above the second entry box
#       placeholder : str — hint text
#       env_var     : str — os.environ key to set
#       store_key   : str — key in keys.json (must be globally unique)
#   link_text : str — link button label (default "Get free key →")
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
    "greynoise": {
        "display_name": "GreyNoise",
        "description":  "Classifies IPs as internet background noise, known benign services (Google, Cloudflare…), or unknown. 1,000 free lookups/day.",
        "signup_url":   "https://www.greynoise.io/viz/account/register",
        "placeholder":  "Paste your GreyNoise API key",
        "env_var":      "GREYNOISE_API_KEY",
    },
    "emailrep": {
        "display_name": "EmailRep.io",
        "description":  "Email reputation: leaked credentials, spam/malicious activity flags, disposable provider check. Free key raises the rate limit.",
        "signup_url":   "https://emailrep.io/key",
        "placeholder":  "Paste your EmailRep.io API key",
        "env_var":      "EMAILREP_API_KEY",
    },
    "censys": {
        "display_name": "Censys",
        "description":  "Open ports, services, and TLS certificates for IPs and domains. 250 free queries/month. Needs an API ID + API Secret (both on the same account page).",
        "signup_url":   "https://search.censys.io/register",
        "placeholder":  "Paste your Censys API ID",
        "env_var":      "CENSYS_API_ID",
        "link_text":    "Create free account →",
        "secondary_field": {
            "label":       "API Secret",
            "placeholder": "Paste your Censys API Secret",
            "env_var":     "CENSYS_API_SECRET",
            "store_key":   "censys__secret",
        },
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
    Inject saved credentials as environment variables so _resolve_env_vars
    picks them up when each plugin calls config.get_plugin_config().

    Handles both primary keys (stored as "plugin_name") and secondary
    fields for two-credential services like Censys (stored with the
    secondary_field's store_key, e.g. "censys__secret").
    """
    for store_key, key_value in keys.items():
        if not key_value:
            continue

        if "__" in store_key:
            # Secondary field — find matching secondary_field by store_key.
            base_name = store_key.split("__", 1)[0]
            info = API_KEY_REGISTRY.get(base_name, {})
            sf = info.get("secondary_field", {})
            env_var = sf.get("env_var") if sf.get("store_key") == store_key else None
        else:
            info = API_KEY_REGISTRY.get(store_key, {})
            env_var = info.get("env_var")

        if env_var:
            os.environ[env_var] = key_value
