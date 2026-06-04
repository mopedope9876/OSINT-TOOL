"""
osint/dispatcher.py
-------------------
Discovers plugins, runs them concurrently, and collects results.

CONCURRENCY MODEL:
HTTP requests are "I/O-bound" — most of the time is spent waiting for
the remote server to respond, not doing CPU work. Python's
ThreadPoolExecutor lets multiple plugins send their requests at the same
time and wait in parallel, so the total time is roughly the slowest
single plugin's response time instead of the sum of all of them.

No async/await needed: threading is sufficient for I/O-bound work and
is far easier to reason about, especially for synchronous libraries like
requests and python-whois.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from osint.logger import get_logger
from osint.models import AppConfig, PluginResult
from osint.plugin_base import BasePlugin

logger = get_logger(__name__)


def discover_plugins() -> list[type[BasePlugin]]:
    """
    Scan osint/plugins/ and return all plugin classes found.

    Uses pkgutil to iterate every module in the plugins package, then
    uses inspect to find classes that inherit from BasePlugin. Dropping
    a new .py file into osint/plugins/ is all that is required to add
    a new source — no registration list to maintain.

    Returns:
        A list of plugin CLASSES (not instances).
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
                logger.debug(f"Discovered plugin: {obj.__name__}")

    logger.debug(f"Discovered {len(plugin_classes)} plugin(s) total.")
    return plugin_classes


def _run_plugin_safely(
    plugin: BasePlugin,
    identifier_type: str,
    identifier_value: str,
    config: AppConfig,
) -> PluginResult:
    """
    Run one plugin and guarantee a PluginResult is returned no matter what.

    Plugins are expected to catch their own errors internally. This wrapper
    is a second safety net for programming bugs in the plugin itself
    (e.g. an unhandled edge case that raises an unexpected exception).
    """
    try:
        return plugin.run(identifier_type, identifier_value, config)
    except Exception as exc:
        logger.error(
            f"Plugin {plugin.name!r} raised an unhandled exception: {exc}",
            exc_info=True,
        )
        return PluginResult(
            plugin_name=plugin.name,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            success=False,
            error=f"Unhandled exception: {exc}",
        )


def run_all(
    identifier_type: str,
    identifier_value: str,
    config: AppConfig,
    quiet: bool = False,
) -> tuple[list[PluginResult], float]:
    """
    Run all applicable enabled plugins concurrently and collect results.

    Args:
        identifier_type:  One of "username", "email", "domain", "ip", "phone".
        identifier_value: The value to search for.
        config:           Validated application configuration.
        quiet:            If True, suppress the Rich progress bar.

    Returns:
        A tuple of (list of PluginResult, elapsed_seconds).
    """
    plugin_classes = discover_plugins()

    applicable: list[BasePlugin] = []
    for cls in plugin_classes:
        instance = cls()
        if instance.supports(identifier_type) and instance.is_enabled(config):
            applicable.append(instance)

    if not applicable:
        logger.warning(
            f"No enabled plugins found for identifier type '{identifier_type}'. "
            "Check the plugins.enabled list in config.yaml."
        )
        return [], 0.0

    logger.info(
        f"Running {len(applicable)} plugin(s) for "
        f"{identifier_type}={identifier_value!r}"
    )

    results: list[PluginResult | None] = [None] * len(applicable)
    start_time = time.monotonic()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        transient=True,
        disable=quiet,
    )

    with progress:
        task_id = progress.add_task(
            f"[cyan]Querying {len(applicable)} source(s)…",
            total=len(applicable),
        )

        max_workers = min(len(applicable), 10)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(
                    _run_plugin_safely,
                    plugin,
                    identifier_type,
                    identifier_value,
                    config,
                ): i
                for i, plugin in enumerate(applicable)
            }

            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                results[idx] = future.result()
                progress.advance(task_id)

    elapsed = time.monotonic() - start_time
    final_results = [r for r in results if r is not None]

    successes = sum(1 for r in final_results if r.success)
    failures = len(final_results) - successes
    logger.info(
        f"Completed in {elapsed:.2f}s — "
        f"{successes} succeeded, {failures} failed."
    )

    return final_results, elapsed
