"""
osint/dispatcher.py
-------------------
The orchestrator. Discovers plugins, runs them, and collects results.

WHY A SEPARATE DISPATCHER?
The dispatcher is the only part of the program that knows about ALL
plugins. By isolating that knowledge here, individual plugins never
need to know about each other, and the CLI doesn't need to know how
plugins work internally. Everything is loosely coupled.

STAGE 1 NOTES:
This dispatcher is the sequential version — plugins run one after another.
In Stage 3 it will be upgraded to run plugins concurrently using asyncio,
which will be significantly faster. The interface (what run_all() accepts
and returns) will not change, so nothing else in the program needs updating
when that upgrade happens.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import time
from pathlib import Path

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


def discover_plugins() -> list[type[BasePlugin]]:
    """
    Scan the osint/plugins/ folder and return all plugin classes found.

    This function uses Python's pkgutil and importlib to automatically
    import every .py file in the plugins package, then inspects each
    module for classes that inherit from BasePlugin.

    WHY AUTO-DISCOVERY?
    You should be able to add a new plugin by dropping a file into
    osint/plugins/ — no registration list to update, no central config
    to change. Auto-discovery makes that possible.

    Returns:
        A list of plugin CLASSES (not instances). The dispatcher
        instantiates them when it needs to run them.
    """
    import osint.plugins as plugins_package

    plugin_classes: list[type[BasePlugin]] = []

    for module_info in pkgutil.iter_modules(plugins_package.__path__):
        module_name = f"osint.plugins.{module_info.name}"
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            logger.warning(f"Could not import plugin module {module_name!r}: {exc}")
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BasePlugin)
                and obj is not BasePlugin
                and obj.__module__ == module_name
            ):
                plugin_classes.append(obj)
                logger.debug(f"Discovered plugin: {obj.__name__} in {module_name}")

    logger.info(f"Discovered {len(plugin_classes)} plugin(s).")
    return plugin_classes


def run_all(
    identifier_type: str,
    identifier_value: str,
    config: AppConfig,
) -> list[PluginResult]:
    """
    Run all applicable plugins for the given identifier and collect results.

    Steps:
      1. Discover all plugin classes in osint/plugins/.
      2. Filter: keep only plugins that support this identifier type
         and are listed in config.plugins.enabled.
      3. Run each plugin sequentially, catching any unexpected exceptions.
      4. Return the collected list of PluginResult objects.

    Args:
        identifier_type:  One of "username", "email", "domain", "ip", "phone".
        identifier_value: The value to search for.
        config:           The validated application configuration.

    Returns:
        A list of PluginResult objects, one per plugin that ran.
        Failed plugins are included as PluginResult(success=False, ...).
    """
    plugin_classes = discover_plugins()
    results: list[PluginResult] = []

    applicable = [
        cls for cls in plugin_classes
        if cls().supports(identifier_type) and cls().is_enabled(config)
    ]

    if not applicable:
        logger.warning(
            f"No enabled plugins found for identifier type '{identifier_type}'. "
            "Check config.yaml plugins.enabled list."
        )
        return results

    logger.info(
        f"Running {len(applicable)} plugin(s) for {identifier_type}={identifier_value!r}"
    )

    delay = config.rate_limiting.delay_between_requests

    for i, plugin_cls in enumerate(applicable):
        plugin = plugin_cls()
        logger.info(f"  [{i + 1}/{len(applicable)}] Running plugin: {plugin.name}")

        try:
            result = plugin.run(identifier_type, identifier_value, config)
        except Exception as exc:
            # A plugin should never raise here — it should catch its own
            # errors and return success=False. This outer catch is a
            # safety net for bugs in the plugin itself.
            logger.error(
                f"Plugin {plugin.name!r} raised an unexpected exception: {exc}",
                exc_info=True,
            )
            result = PluginResult(
                plugin_name=plugin.name,
                identifier_type=identifier_type,
                identifier_value=identifier_value,
                success=False,
                error=f"Unexpected exception: {exc}",
            )

        if result.success:
            logger.info(f"  [OK] {plugin.name} completed successfully.")
        else:
            logger.warning(f"  [FAIL] {plugin.name}: {result.error}")

        results.append(result)

        # Respect rate limiting between plugin runs (except after the last one).
        if delay > 0 and i < len(applicable) - 1:
            time.sleep(delay)

    return results
