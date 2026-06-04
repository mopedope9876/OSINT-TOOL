"""
osint/cli.py
------------
Defines all command-line flags and wires them to the dispatcher.

WHY TYPER?
Typer builds the CLI from Python type annotations. The type hint
str | None on a parameter means it's optional. The docstring becomes
the --help text automatically. This is far less boilerplate than
argparse and produces better help output.

STAGE 1 BEHAVIOUR:
The CLI parses arguments and prints them back. The dispatcher import
is present but the actual query is placeholder'd — this proves the
skeleton is wired correctly before real plugins exist.

STAGE 2 ADDITION:
The TODO comments below mark where dispatcher.run_all() and the
reporter get called once they exist.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from osint.config import load_config
from osint.logger import get_logger, setup_logging
from osint.models import SUPPORTED_IDENTIFIER_TYPES

console = Console()
app = typer.Typer(
    name="osint-tool",
    help="Modular OSINT aggregation tool. Query multiple public sources at once.",
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        console.print("[bold cyan]OSINT Tool[/] version [bold]0.1.0[/]")
        raise typer.Exit()


@app.command()
def main(
    # --- Identifier flags (at least one must be provided) ---
    username: Optional[str] = typer.Option(
        None, "--username", "-u", help="Username to investigate."
    ),
    email: Optional[str] = typer.Option(
        None, "--email", "-e", help="Email address to investigate."
    ),
    domain: Optional[str] = typer.Option(
        None, "--domain", "-d", help="Domain name to investigate (e.g. example.com)."
    ),
    ip: Optional[str] = typer.Option(
        None, "--ip", "-i", help="IP address to investigate."
    ),
    phone: Optional[str] = typer.Option(
        None, "--phone", "-p", help="Phone number to investigate (E.164 format: +12025551234)."
    ),
    # --- Output flags ---
    output_format: str = typer.Option(
        None, "--format", "-f",
        help="Report format: text, json, or html. Defaults to value in config.yaml."
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o", help="Path for the output report file."
    ),
    # --- Behaviour flags ---
    config_path: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to config.yaml. Defaults to ./config.yaml."
    ),
    plugins_only: Optional[str] = typer.Option(
        None, "--plugins",
        help="Comma-separated list of plugin names to run (e.g. --plugins whois,github_user)."
    ),
    list_plugins: bool = typer.Option(
        False, "--list-plugins", help="List all available plugins and exit."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress terminal output. Logs still written to file."
    ),
    version: bool = typer.Option(
        False, "--version", "-v", callback=_version_callback, is_eager=True,
        help="Show version and exit."
    ),
) -> None:
    """
    Run OSINT queries against one or more public sources.

    Provide at least one identifier (--username, --email, --ip,
    --domain, or --phone) and the tool will query all applicable
    enabled plugins automatically.

    Examples:
      osint-tool --ip 8.8.8.8
      osint-tool --email user@example.com --format html
      osint-tool --domain example.com --plugins whois_lookup,shodan
    """
    # 1. Load and validate configuration.
    config = load_config(config_path)

    # 2. Set up logging using settings from config.
    setup_logging(
        level=config.logging.level,
        write_to_file=config.logging.write_to_file,
        log_file=config.logging.log_file,
    )
    logger = get_logger(__name__)

    # 3. Handle --list-plugins.
    if list_plugins:
        _print_plugin_list(config)
        raise typer.Exit()

    # 4. Determine which identifier was provided.
    identifier_map = {
        "username": username,
        "email": email,
        "domain": domain,
        "ip": ip,
        "phone": phone,
    }
    provided = {k: v for k, v in identifier_map.items() if v is not None}

    if not provided:
        console.print(
            "[bold red]Error:[/] Please provide at least one identifier.\n"
            "Run [bold]osint-tool --help[/] to see available options."
        )
        raise typer.Exit(code=1)

    if len(provided) > 1:
        console.print(
            "[bold yellow]Warning:[/] Multiple identifiers provided. "
            "Only the first will be used per run. "
            "Run the tool separately for each identifier."
        )

    identifier_type, identifier_value = next(iter(provided.items()))

    # 5. Validate the identifier format.
    validation_error = _validate_identifier(identifier_type, identifier_value)
    if validation_error:
        console.print(f"[bold red]Error:[/] {validation_error}")
        raise typer.Exit(code=1)

    # 6. Determine the report format.
    fmt = output_format or config.general.default_format
    if fmt not in ("text", "json", "html"):
        console.print(
            f"[bold red]Error:[/] Unknown format {fmt!r}. "
            "Choose from: text, json, html."
        )
        raise typer.Exit(code=1)

    # 7. Override enabled plugins if --plugins flag was used.
    if plugins_only:
        requested = [p.strip() for p in plugins_only.split(",")]
        config.plugins.enabled = requested
        logger.info(f"Running only requested plugins: {requested}")

    # 8. Print a summary panel (unless --quiet).
    if not quiet:
        _print_run_summary(identifier_type, identifier_value, fmt, config)

    # 9. Run the dispatcher.
    #    In Stage 1 this is a placeholder — the actual call is:
    #      from osint import dispatcher
    #      results = dispatcher.run_all(identifier_type, identifier_value, config)
    #    That will be wired in Stage 2 once real plugins exist.

    logger.info(
        f"[Stage 1 skeleton] Would query: {identifier_type}={identifier_value!r} "
        f"format={fmt!r}"
    )

    if not quiet:
        console.print(
            "\n[bold green]Stage 1 skeleton is working correctly.[/]\n"
            f"  Identifier: [cyan]{identifier_type}[/] = [bold]{identifier_value}[/]\n"
            f"  Format:     [cyan]{fmt}[/]\n"
            f"  Plugins:    [cyan]{', '.join(config.plugins.enabled) or 'none'}[/]\n"
            "\nDispatcher and reporters will be wired in Stage 2."
        )


def _validate_identifier(identifier_type: str, value: str) -> str | None:
    """
    Basic format validation for identifiers.

    Returns an error message string if invalid, or None if valid.
    """
    import ipaddress
    import re

    if identifier_type == "email":
        pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        if not pattern.match(value):
            return f"{value!r} does not look like a valid email address."

    elif identifier_type == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return f"{value!r} is not a valid IPv4 or IPv6 address."

    elif identifier_type == "domain":
        pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )
        if not pattern.match(value):
            return f"{value!r} does not look like a valid domain name."

    return None


def _print_run_summary(
    identifier_type: str,
    identifier_value: str,
    fmt: str,
    config,
) -> None:
    """Print a styled summary panel before running."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value", style="white")
    table.add_row("Identifier type", identifier_type)
    table.add_row("Identifier value", identifier_value)
    table.add_row("Output format", fmt)
    table.add_row("Enabled plugins", ", ".join(config.plugins.enabled) or "(none)")

    console.print(
        Panel(
            table,
            title="[bold]OSINT Tool[/]",
            subtitle="Starting query...",
            border_style="cyan",
        )
    )


def _print_plugin_list(config) -> None:
    """List all discovered plugins with their supported identifier types."""
    from osint.dispatcher import discover_plugins

    plugin_classes = discover_plugins()

    if not plugin_classes:
        console.print("[yellow]No plugins found in osint/plugins/.[/]")
        return

    table = Table(title="Available Plugins", show_lines=True)
    table.add_column("Plugin Name", style="bold cyan")
    table.add_column("Supported Identifiers", style="white")
    table.add_column("Description", style="dim")
    table.add_column("Enabled", style="green")

    for cls in plugin_classes:
        p = cls()
        plugin_key = cls.__module__.split(".")[-1]
        enabled_str = "yes" if plugin_key in config.plugins.enabled else "[red]no[/]"
        table.add_row(
            p.name,
            ", ".join(p.supported_identifiers),
            p.description,
            enabled_str,
        )

    console.print(table)
