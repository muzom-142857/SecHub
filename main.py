#!/usr/bin/env python3
"""SecHub — penetration testing workflow TUI."""

import sys

MIN_PYTHON = (3, 11)
if sys.version_info < MIN_PYTHON:
    print(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required.")
    sys.exit(1)

from ui.app import SecHubApp


def main() -> None:
    app = SecHubApp()
    app.run()


if __name__ == "__main__":
    main()
