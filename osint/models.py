"""
osint/models.py
---------------
Pydantic data models that define the shape of all data in this program.

WHY PYDANTIC?
A "model" is just a Python class that describes what fields a piece of
data has and what type each field should be. Pydantic enforces these rules
at runtime — if a plugin tries to create a PluginResult with a string where
an integer is expected, Pydantic raises a clear error immediately, instead
of letting bad data propagate silently until something crashes later.

Pydantic models also provide free serialisation: calling .model_dump()
converts the object into a plain Python dictionary, and .model_dump_json()
converts it to a JSON string. Both are used by the reporters.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# The complete set of identifier types the tool understands.
# Every plugin declares which of these it supports.
SUPPORTED_IDENTIFIER_TYPES = {"username", "email", "domain", "ip", "phone"}


class PluginResult(BaseModel):
    """
    The standard output of every plugin.

    Every plugin's run() method must return exactly one of these.
    Because every plugin returns the same shape, the dispatcher and
    reporters can handle all results uniformly — they never need to
    know which specific plugin produced a given result.
    """

    plugin_name: str = Field(
        description="Human-readable name of the plugin that produced this result."
    )
    identifier_type: str = Field(
        description="The kind of identifier that was searched (e.g. 'email', 'ip')."
    )
    identifier_value: str = Field(
        description="The actual value that was searched (e.g. 'user@example.com')."
    )
    success: bool = Field(
        description="True if the plugin completed without errors, False otherwise."
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="The information returned by this plugin. Structure varies by plugin.",
    )
    error: str | None = Field(
        default=None,
        description="If success is False, a human-readable description of what went wrong.",
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp of when the plugin ran.",
    )
    source_url: str | None = Field(
        default=None,
        description="The URL or endpoint that was queried. Useful for manual verification.",
    )


class PluginConfig(BaseModel):
    """
    Per-plugin settings read from config.yaml.

    Each plugin receives its own PluginConfig so it can read options
    like base_url or api_key without touching the global config object.
    """

    api_key: str | None = Field(default=None)
    base_url: str | None = Field(default=None)
    enabled: bool = Field(default=True)

    model_config = {"extra": "allow"}
    # extra="allow" means unknown fields (like ipapi's custom options)
    # are accepted rather than raising a validation error. This lets
    # each plugin define its own options in config.yaml freely.


class LoggingConfig(BaseModel):
    """Settings that control how and where log messages are written."""

    level: str = Field(default="INFO")
    write_to_file: bool = Field(default=True)
    log_file: str = Field(default="logs/osint.log")


class GeneralConfig(BaseModel):
    """Top-level settings that apply to the whole program."""

    output_dir: str = Field(default="reports")
    default_format: str = Field(default="json")
    request_timeout: int = Field(default=10)


class RateLimitingConfig(BaseModel):
    """Settings that control how fast the tool sends requests."""

    delay_between_requests: float = Field(default=1.0)


class PluginsSection(BaseModel):
    """
    The [plugins] section of config.yaml.

    enabled is the list of plugin names to run.
    The remaining fields are per-plugin config blocks.
    """

    enabled: list[str] = Field(default_factory=list)

    model_config = {"extra": "allow"}
    # extra="allow" so that ipapi:, github_user:, etc. are accepted
    # as arbitrary sub-sections without needing to declare them here.


class AppConfig(BaseModel):
    """
    The complete, validated application configuration.

    This is the single object passed around the program that represents
    everything read from config.yaml. All other modules import this type
    and receive an instance of it — they never read config.yaml directly.
    """

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    plugins: PluginsSection = Field(default_factory=PluginsSection)
    rate_limiting: RateLimitingConfig = Field(default_factory=RateLimitingConfig)

    def get_plugin_config(self, plugin_name: str) -> PluginConfig:
        """
        Return the config sub-section for a specific plugin.

        If the plugin has no sub-section in config.yaml, return a
        default PluginConfig with all fields set to None/defaults.

        Args:
            plugin_name: The key as it appears under [plugins] in config.yaml.

        Returns:
            A PluginConfig instance for that plugin.
        """
        raw = self.plugins.model_extra or {}
        plugin_data = raw.get(plugin_name, {})

        # Resolve environment variable references like "${SHODAN_API_KEY}".
        resolved = _resolve_env_vars(plugin_data)

        return PluginConfig.model_validate(resolved)


def _resolve_env_vars(data: dict) -> dict:
    """
    Replace "${VAR_NAME}" strings with the value of the environment variable.

    This lets users put API keys in environment variables instead of
    directly in config.yaml, which is safer (the key never touches a
    file that might be committed to git).

    For example, if config.yaml has:
        api_key: "${SHODAN_API_KEY}"
    and the environment has SHODAN_API_KEY=abc123, this function
    returns {"api_key": "abc123"}.
    """
    import os
    import re

    resolved = {}
    pattern = re.compile(r"^\$\{(.+)\}$")

    for key, value in data.items():
        if isinstance(value, str):
            match = pattern.match(value)
            if match:
                env_var_name = match.group(1)
                resolved[key] = os.environ.get(env_var_name)
            else:
                resolved[key] = value
        elif isinstance(value, dict):
            resolved[key] = _resolve_env_vars(value)
        else:
            resolved[key] = value

    return resolved
