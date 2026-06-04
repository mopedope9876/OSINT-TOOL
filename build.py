"""
build.py
--------
Creates a standalone executable using PyInstaller.

Run this once after confirming the GUI works (python main_gui.py):
  python build.py

Output:
  Windows  →  dist/OSINT-Tool.exe
  macOS    →  dist/OSINT-Tool   (or .app with --windowed)
  Linux    →  dist/OSINT-Tool

The executable bundles Python + all dependencies + HTML templates
into a single file. No Python installation needed on the target machine.

NOTES:
  - Build takes 1-3 minutes — this is normal.
  - First launch of the .exe may take 5-10 seconds to unpack — also normal.
  - Windows Defender may flag it as suspicious (false positive — it is just
    a bundled Python program). You can add an exclusion in Windows Security.
"""

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def main() -> None:
    print("=" * 60)
    print("  OSINT Tool — Executable Build")
    print("=" * 60)

    # Verify customtkinter is installed before trying to build.
    try:
        import customtkinter  # noqa: F401
    except ImportError:
        print("\n[ERROR] customtkinter is not installed.")
        print("Run:  pip install customtkinter")
        sys.exit(1)

    # Path separator: ";" on Windows, ":" on Mac/Linux.
    sep = os.pathsep

    # The Jinja2 HTML template must be bundled so reports can be generated
    # after installation. SOURCE is the folder on disk; DEST is where
    # PyInstaller places it inside the executable bundle.
    templates_src  = str(HERE / "osint" / "reporters" / "templates")
    templates_dest = "osint/reporters/templates"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",          # overwrite previous build without asking
        "--onefile",            # single executable file
        "--windowed",           # no console window (pure GUI)
        "--name=OSINT-Tool",

        # Bundle the HTML report template.
        f"--add-data={templates_src}{sep}{templates_dest}",

        # Bundle all of customtkinter's assets (themes, fonts, images).
        # --collect-all is simpler and more reliable than a manual --add-data.
        "--collect-all=customtkinter",

        # Tell PyInstaller about modules it may not detect automatically.
        # (The plugin system loads these dynamically at runtime, so static
        #  analysis won't find them.)
        "--hidden-import=osint.plugins.ipapi",
        "--hidden-import=osint.plugins.ipinfo",
        "--hidden-import=osint.plugins.shodan_internetdb",
        "--hidden-import=osint.plugins.hackertarget",
        "--hidden-import=osint.plugins.github_user",
        "--hidden-import=osint.plugins.whois_lookup",
        "--hidden-import=osint.plugins.dns_lookup",
        "--hidden-import=osint.plugins.shodan",
        "--hidden-import=osint.plugins.virustotal",
        "--hidden-import=osint.plugins.abuseipdb",
        "--hidden-import=osint.plugins.gravatar",
        "--hidden-import=osint.plugins.crtsh",
        "--hidden-import=osint.plugins.wayback",
        "--hidden-import=osint.plugins.phone_info",
        "--hidden-import=osint.plugins.urlscan",
        "--hidden-import=osint.plugins.greynoise",
        "--hidden-import=osint.plugins.emailrep",
        "--hidden-import=osint.plugins.censys",
        "--hidden-import=phonenumbers",
        "--hidden-import=osint.reporters.json_reporter",
        "--hidden-import=osint.reporters.text_reporter",
        "--hidden-import=osint.reporters.html_reporter",
        "--hidden-import=dns.resolver",
        "--hidden-import=whois",

        "main_gui.py",
    ]

    print("\nRunning PyInstaller — this takes 1-3 minutes…\n")
    result = subprocess.run(cmd, cwd=str(HERE))

    if result.returncode == 0:
        print("\n" + "=" * 60)
        print("  Build succeeded!")
        dist = HERE / "dist"
        if dist.exists():
            for f in dist.iterdir():
                print(f"  → {f}")
        print("\n  Double-click the file above to launch OSINT Tool.")
        print("=" * 60)
    else:
        print("\n[ERROR] Build failed. See the PyInstaller output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
