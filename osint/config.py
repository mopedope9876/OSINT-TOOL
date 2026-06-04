"""
osint/config.py
---------------
Reads config.yaml from disk and returns a validated AppConfig object.

WHY A DEDICATED MODULE FOR THIS?
All other modules that need a setting import AppConfig from models.py
and receive an already-validated instance. None of them call open() or
yaml.safe_load() themselves. This means:
  - If config.yaml moves or its format changes, you update ONE place.
  - If the YAML is invalid, the error appears here at startup with a
    clear message, not buried inside a plugin mid-run.
  - Tests can create AppConfig objects directly without needing a file.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from osint.models import AppConfig

# Default location of the config file, relative to the project root.
DEFAULT_CONFIG_PATH = Path("config.yaml")


def load_config(config_path: Path | str | None = None) -> AppConfig:
    """
    Load and validate the configuration file.

    If no path is given, looks for config.yaml in the current directory.
    If the file does not exist, creates a default config file and returns
    default values — the tool can run without a config file.

    Args:
        config_path: Path to the YAML config file. Defaults to config.yaml.

    Returns:
        A fully validated AppConfig instance.

    Raises:
        SystemExit: If the file exists but contains invalid YAML or
                    fails Pydantic validation. We exit here rather than
                    letting a broken config cause mysterious errors later.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    if not path.exists():
        _create_default_config(path)
        return AppConfig()

    raw_text = path.read_text(encoding="utf-8")

    try:
        raw_dict = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        print(f"[ERROR] config.yaml is not valid YAML:\n{exc}")
        raise SystemExit(1)

    try:
        return AppConfig.model_validate(raw_dict)
    except ValidationError as exc:
        print(f"[ERROR] config.yaml has invalid values:\n{exc}")
        raise SystemExit(1)


def _create_default_config(path: Path) -> None:
    """
    Write a minimal default config.yaml so the user has a starting point.

    Called automatically when config.yaml is missing.
    """
    default_content = """\
# OSINT Tool — auto-generated default configuration.
# Edit this file to customise behaviour.
general:
  output_dir: "reports"
  default_format: "json"
  request_timeout: 10

logging:
  level: "INFO"
  write_to_file: true
  log_file: "logs/osint.log"

plugins:
  enabled:
    - ipapi
    - github_user
    - whois_lookup

rate_limiting:
  delay_between_requests: 1
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(default_content, encoding="utf-8")
    print(f"[INFO] No config.yaml found. Created a default one at: {path}")
