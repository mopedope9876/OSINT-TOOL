"""
osint/plugin_base.py
--------------------
Defines the contract that every plugin must follow.

WHY AN ABSTRACT BASE CLASS?
An abstract base class (ABC) is like a job description written in code.
It says: "any class that calls itself a plugin MUST have these attributes
and MUST implement these methods." If a developer writes a plugin and
forgets to add run(), Python raises TypeError the moment the program
tries to load that plugin — at startup, not mid-run.

Without this, you'd need to check manually whether each discovered file
has the right methods. That checking code is complex and error-prone.
The ABC makes Python enforce the contract automatically.

HOW TO WRITE A PLUGIN (summary for developers):
  1. Create a new .py file in osint/plugins/
  2. Define a class that inherits from BasePlugin
  3. Set name, description, and supported_identifiers as class attributes
  4. Implement the run() method
  5. Done — the dispatcher will find it automatically next run.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from osint.models import AppConfig, PluginResult


class BasePlugin(ABC):
    """
    Abstract base class for all OSINT plugins.

    Every plugin must:
      - Set `name` to a human-readable string.
      - Set `description` to a short explanation of what it does.
      - Set `supported_identifiers` to the list of identifier types
        it can handle (from: "username", "email", "domain", "ip", "phone").
      - Implement run() to perform the actual lookup and return a PluginResult.
    """

    # A human-readable name shown in reports and log messages.
    # Example: "HaveIBeenPwned"
    name: str = ""

    # A one-sentence description shown in --list-plugins output.
    description: str = ""

    # The identifier types this plugin handles.
    # Must be a subset of: {"username", "email", "domain", "ip", "phone"}
    # Example: ["email"] means this plugin only runs when --email is used.
    supported_identifiers: list[str] = []

    @abstractmethod
    def run(
        self,
        identifier_type: str,
        identifier_value: str,
        config: AppConfig,
    ) -> PluginResult:
        """
        Perform the OSINT lookup and return the result.

        This method is called by the dispatcher for each applicable plugin.
        It should:
          1. Read any needed settings from config.get_plugin_config(...)
          2. Make an HTTP request (or use a library) to gather information
          3. Return a PluginResult with success=True and the data in data={}
          4. If anything goes wrong, return a PluginResult with success=False
             and a description of the error in error=""

        Plugins should NEVER raise exceptions out of this method.
        All errors must be caught here and returned as a failed PluginResult.
        This ensures one plugin failure cannot crash the entire run.

        Args:
            identifier_type:  What kind of value is being searched.
                              One of: "username", "email", "domain", "ip", "phone".
            identifier_value: The actual value to look up.
            config:           The validated application configuration object.

        Returns:
            A PluginResult describing what was found (or what went wrong).
        """
        ...

    def supports(self, identifier_type: str) -> bool:
        """
        Return True if this plugin handles the given identifier type.

        The dispatcher calls this to decide whether to run the plugin.
        Plugins don't override this — it reads supported_identifiers.

        Args:
            identifier_type: One of "username", "email", "domain", "ip", "phone".

        Returns:
            True if the plugin should run for this identifier type.
        """
        return identifier_type in self.supported_identifiers

    def is_enabled(self, config: AppConfig) -> bool:
        """
        Return True if this plugin is listed in config's enabled plugins.

        Plugins don't override this. The dispatcher uses it to skip
        plugins the user has removed from the enabled list in config.yaml.

        Args:
            config: The validated application configuration object.

        Returns:
            True if the plugin's name is in config.plugins.enabled.
        """
        plugin_key = self.__class__.__module__.split(".")[-1]
        return plugin_key in config.plugins.enabled

    def __repr__(self) -> str:
        return f"<Plugin name={self.name!r} supports={self.supported_identifiers}>"
