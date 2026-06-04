"""
osint/logger.py
---------------
Sets up one shared logger for the entire program.

WHY ONE SHARED LOGGER?
Every module in this project calls get_logger(__name__) and gets back
a "child" logger. All child loggers inherit the same handlers and
format defined here, so every log message — regardless of which plugin
or reporter produced it — goes to the same file and terminal output in
the same consistent format.

Without this, each module would need its own logging setup, leading to
duplicate messages, inconsistent formats, and scattered config.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.logging import RichHandler

# The name of the root logger for this application.
# All child loggers will be named "osint.something".
ROOT_LOGGER_NAME = "osint"

# Track whether setup has already been called so we don't add
# duplicate handlers if get_logger() is called multiple times.
_configured = False


def setup_logging(level: str = "INFO", write_to_file: bool = True, log_file: str = "logs/osint.log") -> None:
    """
    Configure the root logger once at program startup.

    Call this exactly once from cli.py before anything else runs.

    Args:
        level:        One of "DEBUG", "INFO", "WARNING", "ERROR".
        write_to_file: If True, also write logs to a rotating file.
        log_file:     Path to the log file.
    """
    global _configured
    if _configured:
        return

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    root = logging.getLogger(ROOT_LOGGER_NAME)
    root.setLevel(numeric_level)

    # --- Terminal handler (via Rich for coloured output) ---
    # RichHandler formats log records with colours, icons, and readable
    # timestamps directly in the terminal.
    rich_handler = RichHandler(
        rich_tracebacks=True,   # Show pretty tracebacks on exceptions.
        markup=True,            # Allow [bold] style tags in log messages.
        show_path=False,        # Don't show the file path — keeps lines short.
    )
    rich_handler.setLevel(numeric_level)
    root.addHandler(rich_handler)

    # --- File handler (rotating, so the log never grows forever) ---
    if write_to_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            filename=log_path,
            maxBytes=5 * 1024 * 1024,  # 5 MB per file.
            backupCount=3,              # Keep 3 old files (osint.log.1, .2, .3).
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)

        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger named after the calling module.

    Usage in any module:
        from osint.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Hello")

    __name__ is a built-in Python variable that equals the module's
    full name (e.g. "osint.plugins.whois_lookup"). Using it as the
    logger name means log messages automatically show which module
    produced them.

    Args:
        name: Typically pass __name__ from the calling module.

    Returns:
        A configured Logger instance.
    """
    return logging.getLogger(name)
