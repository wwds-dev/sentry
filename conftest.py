"""Make the ``sentry`` package importable when running this repo's own tests.

Only loaded when pytest collects files under agents/sentry/, so the parent
Sentinel suite (testpaths = tests) never sees it. Mirrors how each agent under
sentinel/agents/ is its own repo.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
