"""
osint/reporters/reporter_base.py
---------------------------------
Defines the contract that every reporter must follow.

WHY THE SAME ABSTRACT BASE CLASS PATTERN AS PLUGINS?
Same reason: the CLI picks which reporter to instantiate based on the
--format flag. Without a contract, the CLI would need to know the
internal details of each reporter. With BaseReporter, the CLI just
calls reporter.generate(results, output_path) on whatever reporter
it received — it doesn't care which one.

Adding a new output format is creating one new file here that inherits
from BaseReporter and implements generate().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from osint.models import PluginResult


class BaseReporter(ABC):
    """
    Abstract base class for all report formats.

    Every reporter must implement generate() to write the results
    to a file. The format, content, and styling are entirely up to
    the reporter — only the interface (the method signature) is fixed.
    """

    # A short label used in log messages and the --format flag.
    # Example: "json", "text", "html"
    format_name: str = ""

    @abstractmethod
    def generate(
        self,
        results: list[PluginResult],
        output_path: Path,
    ) -> None:
        """
        Write the results to a file at output_path.

        The reporter is responsible for creating the file and writing
        all content. The dispatcher determines the output_path based
        on the --output flag or the default naming convention.

        Args:
            results:     The list of PluginResult objects to report on.
            output_path: Where to write the report file.
        """
        ...

    def __repr__(self) -> str:
        return f"<Reporter format={self.format_name!r}>"
