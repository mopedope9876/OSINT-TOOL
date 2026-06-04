# OSINT Tool

A modular, plugin-based OSINT (Open Source Intelligence) aggregation tool.
Enter a username, email, IP address, domain, or phone number and the tool
automatically queries multiple public sources in parallel — giving you one
unified report instead of a dozen browser tabs.

---

## Features

- **Plugin architecture** — every source is a self-contained file. Add a new source by creating one file. Remove it by deleting the file. No central registry to update.
- **Concurrent execution** — all plugins run at the same time, so total query time is roughly the slowest single plugin's response time.
- **Three report formats** — JSON (for scripts), plain text (for terminals and grep), and HTML (for sharing — opens in any browser with a styled dark-theme layout).
- **Validated configuration** — `config.yaml` is loaded and type-checked at startup. If a value is wrong, you get a clear error before any network call is made.
- **Graceful failure** — one broken plugin never crashes the tool. Failed plugins appear in the report marked as failed.
- **Environment variable support** — API keys can live in environment variables instead of config files, keeping them out of version control.

---

## Supported Identifier Types

| Flag | What to pass | Example |
|---|---|---|
| `--ip` | IPv4 or IPv6 address | `8.8.8.8` |
| `--email` | Email address | `user@example.com` |
| `--domain` | Domain name | `example.com` |
| `--username` | Username on a platform | `torvalds` |
| `--phone` | Phone number (E.164) | `+12025551234` |

---

## Built-in Plugins

| Plugin | Identifiers | API Key? | What it returns |
|---|---|---|---|
| IP Geolocation | ip | No | City, country, ISP, ASN, proxy/hosting flags |
| GitHub User Profile | username | No (optional for higher limits) | Name, bio, location, repos, followers |
| WHOIS Lookup | domain, ip | No | Registrar, creation/expiry dates, nameservers |
| DNS Records | domain | No | A, AAAA, MX, NS, TXT, CNAME, SOA records |
| HaveIBeenPwned | email | Yes (free) | Data breaches containing this email |
| Shodan | ip | Yes (free) | Open ports, running services, CVEs |

---

## Installation

### Option 1 — run directly (development)

```bash
git clone https://github.com/mopedope9876/osint-tool.git
cd osint-tool
pip install -r requirements.txt
python main.py --help
```

### Option 2 — install as a command

```bash
pip install .
osint-tool --help
```

---

## Quick Start

```bash
# Look up an IP address
python main.py --ip 8.8.8.8

# Investigate an email and generate an HTML report
python main.py --email user@example.com --format html

# Look up a domain across all applicable plugins
python main.py --domain example.com

# Look up a GitHub username
python main.py --username torvalds

# Run only specific plugins
python main.py --ip 8.8.8.8 --plugins ipapi,shodan

# List all available plugins
python main.py --list-plugins

# Suppress terminal output (write report only)
python main.py --ip 8.8.8.8 --quiet
```

Reports are saved to the `reports/` folder with an auto-generated timestamped name:
```
reports/ip_8.8.8.8_20260604_155022.json
```

---

## Configuration

Edit `config.yaml` to customise the tool. Every option has a comment explaining it.

### API Keys

Two plugins require free API keys:

**HaveIBeenPwned** — get a free key at [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)

```bash
# Recommended: use an environment variable
export HIBP_API_KEY=your_key_here
```

**Shodan** — get a free key at [shodan.io](https://shodan.io)

```bash
export SHODAN_API_KEY=your_key_here
```

Plugins without a key configured will run but report themselves as "No API key configured" — they will not crash the tool.

---

## Writing a New Plugin

1. Create a file in `osint/plugins/` — for example `osint/plugins/my_source.py`.
2. Write a class that inherits from `BasePlugin`.
3. Set `name`, `description`, and `supported_identifiers`.
4. Implement `run()` — it must return a `PluginResult`.
5. Add your plugin's key (`my_source`) to `config.yaml` under `plugins.enabled`.
6. Done. The dispatcher discovers it automatically next run.

```python
# osint/plugins/my_source.py
import requests
from osint.plugin_base import BasePlugin
from osint.models import AppConfig, PluginResult

class MySourcePlugin(BasePlugin):
    name = "My Source"
    description = "Fetches data from my-source.example.com"
    supported_identifiers = ["email"]   # or ["ip"], ["domain"], etc.

    def run(self, identifier_type: str, identifier_value: str, config: AppConfig) -> PluginResult:
        timeout = config.general.request_timeout
        url = f"https://my-source.example.com/api?q={identifier_value}"

        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            return PluginResult(
                plugin_name=self.name,
                identifier_type=identifier_type,
                identifier_value=identifier_value,
                success=True,
                data=data,
                source_url=url,
            )
        except Exception as exc:
            return PluginResult(
                plugin_name=self.name,
                identifier_type=identifier_type,
                identifier_value=identifier_value,
                success=False,
                error=str(exc),
                source_url=url,
            )
```

### Plugin rules

- **Never raise exceptions out of `run()`** — catch all errors and return `PluginResult(success=False, error=...)`.
- **Always include `source_url`** — helps with manual verification.
- **Override `get_summary()`** — a one-line string shown in the terminal results table.
- Name the file to match the key in `config.yaml` (e.g. file `my_source.py` → key `my_source`).

---

## Running Tests

```bash
pytest
```

Tests use the `responses` library to mock HTTP calls, so they work without internet access.

---

## Project Structure

```
osint-tool/
├── main.py               Entry point (12 lines)
├── config.yaml           User-editable configuration
├── requirements.txt      Dependencies
│
├── osint/
│   ├── cli.py            CLI flags and terminal display
│   ├── config.py         Loads and validates config.yaml
│   ├── dispatcher.py     Discovers plugins, runs them concurrently
│   ├── logger.py         Shared rotating logger
│   ├── models.py         Pydantic data models (PluginResult, AppConfig, …)
│   ├── plugin_base.py    BasePlugin abstract class (the plugin contract)
│   │
│   ├── plugins/          One file = one OSINT source
│   │   ├── ipapi.py
│   │   ├── github_user.py
│   │   ├── whois_lookup.py
│   │   ├── dns_lookup.py
│   │   ├── haveibeenpwned.py
│   │   └── shodan.py
│   │
│   └── reporters/        One file = one output format
│       ├── json_reporter.py
│       ├── text_reporter.py
│       ├── html_reporter.py
│       └── templates/
│           └── report.html
│
├── reports/              Generated reports saved here
├── logs/                 Log files saved here
└── tests/                Automated tests
```

---

## Licence

MIT
