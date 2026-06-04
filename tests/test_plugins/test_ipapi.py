"""
tests/test_plugins/test_ipapi.py
---------------------------------
Tests for the IP geolocation plugin (ipapi.py).

We use the `responses` library to intercept real HTTP calls and return
fake responses. This lets tests run without internet access and without
depending on ip-api.com's availability or data.
"""

from __future__ import annotations

import pytest
import responses as resp_lib

from osint.models import AppConfig
from osint.plugins.ipapi import IPAPIPlugin


def _make_config(timeout: int = 5) -> AppConfig:
    return AppConfig.model_validate({
        "general": {"request_timeout": timeout},
        "plugins": {
            "enabled": ["ipapi"],
            "ipapi": {"base_url": "http://ip-api.com/json"},
        },
    })


class TestIPAPIPlugin:
    def setup_method(self):
        self.plugin = IPAPIPlugin()
        self.config = _make_config()

    def test_plugin_attributes(self):
        assert self.plugin.name
        assert "ip" in self.plugin.supported_identifiers
        assert self.plugin.supports("ip")
        assert not self.plugin.supports("email")

    @resp_lib.activate
    def test_successful_response(self):
        resp_lib.add(
            resp_lib.GET,
            "http://ip-api.com/json/8.8.8.8",
            json={
                "status": "success",
                "country": "United States",
                "countryCode": "US",
                "regionName": "California",
                "city": "Mountain View",
                "isp": "Google LLC",
                "org": "Google LLC",
                "as": "AS15169 Google LLC",
                "query": "8.8.8.8",
                "proxy": False,
                "hosting": True,
                "mobile": False,
            },
            status=200,
        )

        result = self.plugin.run("ip", "8.8.8.8", self.config)

        assert result.success is True
        assert result.plugin_name == self.plugin.name
        assert result.identifier_type == "ip"
        assert result.identifier_value == "8.8.8.8"
        assert result.data["city"] == "Mountain View"
        assert result.data["isp"] == "Google LLC"
        # status and message should be stripped from the data
        assert "status" not in result.data

    @resp_lib.activate
    def test_api_failure_status(self):
        resp_lib.add(
            resp_lib.GET,
            "http://ip-api.com/json/999.999.999.999",
            json={"status": "fail", "message": "invalid query", "query": "999.999.999.999"},
            status=200,
        )

        result = self.plugin.run("ip", "999.999.999.999", self.config)

        assert result.success is False
        assert "invalid query" in result.error

    @resp_lib.activate
    def test_network_timeout(self):
        import requests.exceptions
        resp_lib.add(
            resp_lib.GET,
            "http://ip-api.com/json/1.2.3.4",
            body=requests.exceptions.Timeout(),
        )

        result = self.plugin.run("ip", "1.2.3.4", self.config)

        assert result.success is False
        assert "timed out" in result.error.lower()

    @resp_lib.activate
    def test_connection_error(self):
        import requests.exceptions
        resp_lib.add(
            resp_lib.GET,
            "http://ip-api.com/json/1.2.3.4",
            body=requests.exceptions.ConnectionError(),
        )

        result = self.plugin.run("ip", "1.2.3.4", self.config)

        assert result.success is False
        assert "connect" in result.error.lower()

    @resp_lib.activate
    def test_get_summary_success(self):
        resp_lib.add(
            resp_lib.GET,
            "http://ip-api.com/json/8.8.8.8",
            json={
                "status": "success",
                "city": "Mountain View",
                "regionName": "California",
                "country": "United States",
                "isp": "Google LLC",
                "proxy": False,
                "hosting": True,
                "mobile": False,
            },
            status=200,
        )
        result = self.plugin.run("ip", "8.8.8.8", self.config)
        summary = self.plugin.get_summary(result)
        assert "Mountain View" in summary
        assert "Google" in summary

    def test_get_summary_failure(self):
        from osint.models import PluginResult
        result = PluginResult(
            plugin_name=self.plugin.name,
            identifier_type="ip",
            identifier_value="1.2.3.4",
            success=False,
            error="Connection refused",
        )
        assert self.plugin.get_summary(result) == "Connection refused"
