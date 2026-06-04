"""
main.py
-------
Entry point. This file should stay small — its only job is to start
the CLI. All real logic lives in osint/.

WHY SO SHORT?
Keeping main.py minimal means every other part of the program can be
imported and tested without accidentally "running" the whole tool.
If the actual application logic were here, `import main` in a test
would execute everything.
"""

from osint.cli import app

if __name__ == "__main__":
    app()
