"""
osint/cli.py
------------
Defines all command-line flags, wires the dispatcher to the reporters,
and renders terminal output.

This module has two responsibilities:
  1. Parse the user's command-line arguments (via Typer).
  2. Orchestrate the run: call the dispatcher, pick a reporter, display
     a results table, and tell the user where the report was saved.

It deliberately contains no OSINT logic — that all lives in plugins.
It contains no formatting logic — that lives in reporters.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from osint.config import load_config
from osint.logger import get_logger, setup_logging

console = Console()
app = typer.Typer(
    name="osint-tool",
    help="Modular OSINT aggregation tool. Query multiple public sources at once.",
    add_completion=False,
    pretty_exceptions_enable=False,
)


def _version_callback(value: bool) -> None:
    if value:
        console.print("[bold cyan]OSINT Tool[/] version [bold]0.1.0[/]")
        raise typer.Exit()


@app.command()
def main(
    # ── Identifier flags ──────────────────────────────────────────────────
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Username to investigate."),
    email: Optional[str]    = typer.Option(None, "--email",    "-e", help="Email address to investigate."),
    domain: Optional[str]   = typer.Option(None, "--domain",   "-d", help="Domain name (e.g. example.com)."),
    ip: Optional[str]       = typer.Option(None, "--ip",       "-i", help="IPv4 or IPv6 address."),
    phone: Optional[str]    = typer.Option(None, "--phone",    "-p", help="Phone number (E.164: +12025551234)."),

    # ── Output flags ─────────────────────────────────────────────────────
    output_format: str          = typer.Option(None, "--format", "-f", help="text | json | html"),
    output_file: Optional[str]  = typer.Option(None, "--output", "-o", help="Override the output file path."),

    # ── Behaviour flags ──────────────────────────────────────────────────
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml."),
    plugins_only: Optional[str] = typer.Option(None, "--plugins", help="Comma-separated plugin names to run."),
    list_plugins: bool = typer.Option(False, "--list-plugins", help="List all available plugins and exit."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output."),
    version: bool = typer.Option(False, "--version", "-v", callback=_version_callback, is_eager=True, help="Show version."),
) -> None:
    """
    Run OSINT queries against one or more public sources.

    Provide at least one identifier flag and the tool will automatically
    query all applicable enabled plugins and save a report.

    Examples:\n
      osint-tool --ip 8.8.8.8\n
      osint-tool --email user@example.com --format html\n
      osint-tool --domain example.com --plugins dns_lookup,whois_lookup\n
      osint-tool --username torvalds --format text
    """
    # 1. Load config and set up logging.
    config = load_config(config_path)
    setup_logging(
        level=config.logging.level,
        write_to_file=config.logging.write_to_file,
        log_file=config.logging.log_file,
    )
    logger = get_logger(__name__)

    # 2. Handle --list-plugins.
    if list_plugins:
        _print_plugin_list(config, console)
        raise typer.Exit()

    # 3. Identify which identifier was provided.
    identifier_map = {
        "username": username,
        "email":    email,
        "domain":   domain,
        "ip":       ip,
        "phone":    phone,
    }
    provided = {k: v for k, v in identifier_map.items() if v is not None}

    if not provided:
        console.print(
            "[bold red]Error:[/] Provide at least one identifier.\n"
            "Run [bold]osint-tool --help[/] for usage."
        )
        raise typer.Exit(code=1)

    if len(provided) > 1 and not quiet:
        console.print(
            "[yellow]Note:[/] Multiple identifiers given — only the first is used per run.\n"
        )

    identifier_type, identifier_value = next(iter(provided.items()))

    # 4. Validate identifier format.
    error_msg = _validate_identifier(identifier_type, identifier_value)
    if error_msg:
        console.print(f"[bold red]Error:[/] {error_msg}")
        raise typer.Exit(code=1)

    # 5. Determine output format.
    fmt = output_format or config.general.default_format
    if fmt not in ("text", "json", "html"):
        console.print(f"[bold red]Error:[/] Unknown format {fmt!r}. Choose: text, json, html.")
        raise typer.Exit(code=1)

    # 6. Override enabled plugins if --plugins was used.
    if plugins_only:
        config.plugins.enabled = [p.strip() for p in plugins_only.split(",")]
        logger.info(f"Running only: {config.plugins.enabled}")

    # 7. Print the startup panel.
    if not quiet:
        _print_panel(identifier_type, identifier_value, fmt, config, console)

    # 8. Run the dispatcher.
    from osint import dispatcher
    start = time.monotonic()
    results, elapsed = dispatcher.run_all(
        identifier_type, identifier_value, config, quiet=quiet
    )
    elapsed = time.monotonic() - start

    if not results:
        console.print("[yellow]No results returned. Check that plugins are enabled and identifiers match.[/]")
        raise typer.Exit()

    # 9. Display terminal results table.
    if not quiet:
        _print_results_table(results, elapsed, console, dispatcher)

    # 10. Build output path and generate the report.
    report_path = _build_output_path(
        output_file, identifier_type, identifier_value, fmt,
        config.general.output_dir,
    )
    reporter = _get_reporter(fmt)
    reporter.generate(results, report_path, duration_s=elapsed)

    if not quiet:
        console.print(f"\n[bold green]Report saved:[/] {report_path}\n")

    logger.info(f"Report written to: {report_path}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_identifier(identifier_type: str, value: str) -> str | None:
    """Return an error string if the value is invalid for its type, else None."""
    import ipaddress

    if identifier_type == "email":
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            return f"{value!r} is not a valid email address."

    elif identifier_type == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return f"{value!r} is not a valid IPv4 or IPv6 address."

    elif identifier_type == "domain":
        if not re.match(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
            value,
        ):
            return f"{value!r} is not a valid domain name."

    return None


def _build_output_path(
    user_path: str | None,
    identifier_type: str,
    identifier_value: str,
    fmt: str,
    default_dir: str,
) -> Path:
    """Construct a report file path with a sanitised, timestamped name."""
    if user_path:
        return Path(user_path)

    # Sanitise identifier value for use in a filename.
    safe_value = re.sub(r"[^a-zA-Z0-9._-]", "_", identifier_value)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{identifier_type}_{safe_value}_{timestamp}.{fmt}"
    return Path(default_dir) / filename


def _get_reporter(fmt: str):
    """Return the reporter instance for the requested format."""
    from osint.reporters.html_reporter import HTMLReporter
    from osint.reporters.json_reporter import JSONReporter
    from osint.reporters.text_reporter import TextReporter

    return {"json": JSONReporter, "text": TextReporter, "html": HTMLReporter}[fmt]()


def _print_panel(identifier_type, identifier_value, fmt, config, console) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column(style="white")
    table.add_row("Identifier type", identifier_type)
    table.add_row("Identifier value", identifier_value)
    table.add_row("Output format", fmt)
    table.add_row("Enabled plugins", ", ".join(config.plugins.enabled) or "(none)")
    console.print(Panel(table, title="[bold]OSINT Tool[/]", border_style="cyan"))
    console.print()


def _print_results_table(results, elapsed, console, dispatcher_module) -> None:
    """Render a summary table after all plugins have run."""
    from osint.dispatcher import discover_plugins
    from osint.plugin_base import BasePlugin

    # Build a name → plugin_instance map so we can call get_summary.
    plugin_map: dict[str, BasePlugin] = {}
    for cls in discover_plugins():
        instance = cls()
        plugin_map[instance.name] = instance

    table = Table(title="Results", show_lines=True, highlight=True)
    table.add_column("Plugin", style="bold", min_width=22)
    table.add_column("Status", justify="center", min_width=10)
    table.add_column("Summary")

    for result in results:
        status = "[green]✓  OK[/]" if result.success else "[red]✗  Failed[/]"
        plugin_instance = plugin_map.get(result.plugin_name)
        if plugin_instance:
            summary = plugin_instance.get_summary(result)
        else:
            summary = result.error or f"{len(result.data)} field(s)" if result.success else result.error or ""

        table.add_row(result.plugin_name, status, summary)

    console.print(table)
    console.print(
        f"  [dim]Completed in {elapsed:.2f}s · "
        f"{sum(1 for r in results if r.success)} succeeded · "
        f"{sum(1 for r in results if not r.success)} failed[/]"
    )


def _print_plugin_list(config, console) -> None:
    """Print a table of all discovered plugins."""
    from osint.dispatcher import discover_plugins

    plugin_classes = discover_plugins()
    if not plugin_classes:
        console.print("[yellow]No plugins found in osint/plugins/.[/]")
        return

    table = Table(title="Available Plugins", show_lines=True)
    table.add_column("Plugin Name", style="bold cyan")
    table.add_column("Module Key")
    table.add_column("Identifiers", style="white")
    table.add_column("Description", style="dim")
    table.add_column("Enabled", justify="center")

    for cls in plugin_classes:
        p = cls()
        key = cls.__module__.split(".")[-1]
        enabled = "[green]yes[/]" if key in config.plugins.enabled else "[red]no[/]"
        table.add_row(
            p.name,
            key,
            ", ".join(p.supported_identifiers),
            p.description,
            enabled,
        )

    console.print(table)
