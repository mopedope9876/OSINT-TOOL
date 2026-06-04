"""
tests/test_models.py
---------------------
Tests for the Pydantic data models in osint/models.py.

These tests run without any network access — they verify that our
data structures behave correctly with valid and invalid input.
"""

import os
from datetime import datetime

import pytest
from pydantic import ValidationError

from osint.models import (
    AppConfig,
    GeneralConfig,
    LoggingConfig,
    PluginResult,
    PluginsSection,
    _resolve_env_vars,
)


class TestPluginResult:
    def test_minimal_success_result(self):
        result = PluginResult(
            plugin_name="TestPlugin",
            identifier_type="ip",
            identifier_value="1.2.3.4",
            success=True,
        )
        assert result.plugin_name == "TestPlugin"
        assert result.success is True
        assert result.data == {}
        assert result.error is None
        assert isinstance(result.timestamp, datetime)

    def test_failure_result(self):
        result = PluginResult(
            plugin_name="TestPlugin",
            identifier_type="email",
            identifier_value="user@example.com",
            success=False,
            error="Connection refused",
        )
        assert result.success is False
        assert result.error == "Connection refused"

    def test_model_dump_is_json_serialisable(self):
        import json
        result = PluginResult(
            plugin_name="TestPlugin",
            identifier_type="ip",
            identifier_value="1.2.3.4",
            success=True,
            data={"city": "London"},
        )
        dumped = result.model_dump(mode="json")
        # Should not raise
        json.dumps(dumped)
        assert dumped["data"]["city"] == "London"

    def test_invalid_data_type_raises(self):
        with pytest.raises(ValidationError):
            # plugin_name is a required string — passing None raises
            PluginResult(
                plugin_name=None,  # type: ignore
                identifier_type="ip",
                identifier_value="1.2.3.4",
                success=True,
            )


class TestAppConfig:
    def test_defaults(self):
        config = AppConfig()
        assert config.general.output_dir == "reports"
        assert config.general.request_timeout == 10
        assert config.logging.level == "INFO"

    def test_custom_values(self):
        config = AppConfig(
            general=GeneralConfig(output_dir="/tmp/reports", request_timeout=30),
            logging=LoggingConfig(level="DEBUG"),
        )
        assert config.general.output_dir == "/tmp/reports"
        assert config.general.request_timeout == 30
        assert config.logging.level == "DEBUG"

    def test_get_plugin_config_missing_section(self):
        config = AppConfig()
        plugin_cfg = config.get_plugin_config("nonexistent_plugin")
        assert plugin_cfg.api_key is None

    def test_get_plugin_config_with_data(self):
        raw = {
            "plugins": {
                "enabled": ["ipapi"],
                "ipapi": {"base_url": "http://example.com/json"},
            }
        }
        config = AppConfig.model_validate(raw)
        plugin_cfg = config.get_plugin_config("ipapi")
        assert plugin_cfg.base_url == "http://example.com/json"


class TestResolveEnvVars:
    def test_resolves_existing_variable(self, monkeypatch):
        monkeypatch.setenv("MY_TEST_KEY", "secret123")
        result = _resolve_env_vars({"api_key": "${MY_TEST_KEY}"})
        assert result["api_key"] == "secret123"

    def test_missing_variable_returns_none(self):
        result = _resolve_env_vars({"api_key": "${DEFINITELY_NOT_SET_XYZ}"})
        assert result["api_key"] is None

    def test_plain_string_unchanged(self):
        result = _resolve_env_vars({"url": "http://example.com"})
        assert result["url"] == "http://example.com"

    def test_nested_dict_resolved(self, monkeypatch):
        monkeypatch.setenv("NESTED_KEY", "nested_val")
        result = _resolve_env_vars({"outer": {"inner": "${NESTED_KEY}"}})
        assert result["outer"]["inner"] == "nested_val"
