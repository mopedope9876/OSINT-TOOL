"""
tests/test_dispatcher.py
-------------------------
Tests for the dispatcher: plugin discovery and run orchestration.

These tests use mock plugins to verify the dispatcher's behaviour
without depending on real network calls or real plugin implementations.
"""

from __future__ import annotations

import pytest

from osint.dispatcher import discover_plugins, run_all
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin


class _AlwaysSucceedPlugin(BasePlugin):
    """A test plugin that always succeeds."""
    name = "AlwaysSucceed"
    description = "Test plugin"
    supported_identifiers = ["ip"]

    def run(self, identifier_type, identifier_value, config):
        return PluginResult(
            plugin_name=self.name,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            success=True,
            data={"result": "ok"},
        )


class _AlwaysFailPlugin(BasePlugin):
    """A test plugin that always fails."""
    name = "AlwaysFail"
    description = "Test plugin"
    supported_identifiers = ["ip"]

    def run(self, identifier_type, identifier_value, config):
        return PluginResult(
            plugin_name=self.name,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            success=False,
            error="Intentional failure",
        )


class _RaisePlugin(BasePlugin):
    """A test plugin that raises an unexpected exception."""
    name = "RaisePlugin"
    description = "Test plugin"
    supported_identifiers = ["ip"]

    def run(self, identifier_type, identifier_value, config):
        raise RuntimeError("Unexpected crash")


class TestDiscoverPlugins:
    def test_returns_list(self):
        plugins = discover_plugins()
        assert isinstance(plugins, list)

    def test_all_discovered_inherit_base(self):
        for cls in discover_plugins():
            assert issubclass(cls, BasePlugin), f"{cls} does not inherit BasePlugin"

    def test_all_have_required_attributes(self):
        for cls in discover_plugins():
            instance = cls()
            assert isinstance(instance.name, str) and instance.name, \
                f"{cls.__name__} has empty name"
            assert isinstance(instance.supported_identifiers, list), \
                f"{cls.__name__} supported_identifiers is not a list"


class TestRunAll:
    def _config_with_plugins(self, plugin_names: list[str]) -> AppConfig:
        return AppConfig.model_validate({
            "plugins": {"enabled": plugin_names}
        })

    def test_no_applicable_plugins_returns_empty(self):
        config = self._config_with_plugins(["ipapi"])
        # "phone" is not supported by ipapi
        results, elapsed = run_all("phone", "12345", config, quiet=True)
        assert results == []
        assert elapsed >= 0

    def test_elapsed_is_nonnegative(self):
        config = self._config_with_plugins(["ipapi"])
        results, elapsed = run_all("ip", "8.8.8.8", config, quiet=True)
        assert elapsed >= 0

    def test_dispatcher_catches_plugin_exception(self, monkeypatch):
        """
        Verify that a plugin raising an unhandled exception produces a
        failed PluginResult rather than crashing the whole run.
        """
        import osint.dispatcher as dispatcher_module

        original_discover = dispatcher_module.discover_plugins

        def mock_discover():
            return [_RaisePlugin]

        monkeypatch.setattr(dispatcher_module, "discover_plugins", mock_discover)

        config = AppConfig.model_validate({
            "plugins": {"enabled": ["raisePlugin".lower()]}
        })
        # Patch is_enabled to always return True for this test.
        monkeypatch.setattr(_RaisePlugin, "is_enabled", lambda self, cfg: True)

        results, _ = run_all("ip", "1.2.3.4", config, quiet=True)
        assert len(results) == 1
        assert results[0].success is False
        assert "Unexpected crash" in results[0].error

        monkeypatch.setattr(dispatcher_module, "discover_plugins", original_discover)

    def test_failed_plugin_does_not_block_others(self, monkeypatch):
        """Two plugins: one fails, one succeeds. Both results are returned."""
        import osint.dispatcher as dispatcher_module

        monkeypatch.setattr(dispatcher_module, "discover_plugins",
                            lambda: [_AlwaysFailPlugin, _AlwaysSucceedPlugin])
        monkeypatch.setattr(_AlwaysFailPlugin, "is_enabled", lambda self, cfg: True)
        monkeypatch.setattr(_AlwaysSucceedPlugin, "is_enabled", lambda self, cfg: True)

        config = AppConfig()
        results, _ = run_all("ip", "1.2.3.4", config, quiet=True)

        assert len(results) == 2
        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]
        assert len(successes) == 1
        assert len(failures) == 1
