#!/usr/bin/env python3
"""Sentry — entry point for standalone / headless use.

    python main.py selftest      verify the read-only collectors run on this host
    python main.py scan          dry-run comparison against the baseline
    python main.py watch-once    one persisted watch pass (what launchd calls)
    python main.py watch         foreground watch loop
    python main.py report        print the recorded findings log
    python main.py --headless    alias for watch-once (background watcher entry)
"""

import sys

from sentry.cli import main

if __name__ == "__main__":
    argv = sys.argv[1:]
    # launchd runs the watcher headless; map the shared flag to one watch pass.
    if "--headless" in argv:
        argv = ["watch-once"]
    sys.exit(main(argv))
