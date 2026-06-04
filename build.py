"""
build.py
--------
Creates a standalone executable using PyInstaller.

Run this script once to produce the executable:
  python build.py

Output:
  Windows  →  dist/OSINT-Tool.exe
  macOS    →  dist/OSINT-Tool.app
  Linux    →  dist/OSINT-Tool  (binary)

The executable includes everything (Python, all dependencies, templates)
in a single file. No Python installation needed on the target machine.

REQUIREMENTS:
  pip install pyinstaller customtkinter

NOTES:
  - First run of the executable may take a few seconds to unpack.
  - On macOS you may need to right-click → Open the first time
    (Gatekeeper warning for unsigned apps).
  - On Windows, antivirus software sometimes flags PyInstaller executables
    as suspicious. This is a false positive — the file contains Python.
    You can submit it to your AV vendor for whitelisting.
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

    # Locate the customtkinter data directory (assets it needs at runtime).
    try:
        import customtkinter
        ctk_path = Path(customtkinter.__file__).parent
        ctk_data = f"{ctk_path}{os.pathsep}customtkinter"
    except ImportError:
        print("\n[ERROR] customtkinter is not installed.")
        print("Run:  pip install customtkinter")
        sys.exit(1)

    templates_src  = HERE / "osint" / "reporters" / "templates"
    templates_dest = os.path.join("osint", "reporters", "templates")

    sep = os.pathsep  # ":" on Mac/Linux, ";" on Windows

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",                         # overwrite previous build without asking
        "--onefile",                           # pack everything into one file
        "--windowed",                          # no console window (GUI app)
        "--name", "OSINT-Tool",
        # Include the Jinja2 HTML template
        f"--add-data={templates_src}{sep}{templates_dest}",
        # Include customtkinter's bundled assets (fonts, themes, images)
        f"--add-data={ctk_data}{sep}customtkinter",
        # Hidden imports that PyInstaller may miss
        "--hidden-import", "osint.plugins.ipapi",
        "--hidden-import", "osint.plugins.github_user",
        "--hidden-import", "osint.plugins.whois_lookup",
        "--hidden-import", "osint.plugins.dns_lookup",
        "--hidden-import", "osint.plugins.shodan",
        "--hidden-import", "osint.plugins.virustotal",
        "--hidden-import", "osint.plugins.abuseipdb",
        "--hidden-import", "osint.plugins.gravatar",
        "--hidden-import", "osint.reporters.json_reporter",
        "--hidden-import", "osint.reporters.text_reporter",
        "--hidden-import", "osint.reporters.html_reporter",
        "--hidden-import", "dns.resolver",
        "--hidden-import", "whois",
        "main_gui.py",
    ]

    print("\nRunning PyInstaller…\n")
    result = subprocess.run(cmd, cwd=str(HERE))

    if result.returncode == 0:
        print("\n" + "=" * 60)
        print("  Build succeeded!")
        dist = HERE / "dist"
        for f in dist.iterdir():
            print(f"  → {f}")
        print("=" * 60)
    else:
        print("\n[ERROR] Build failed. See output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
