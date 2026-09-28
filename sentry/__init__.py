"""Sentry — Sentinel's read-only network anomaly watch.

Public surface:
    collect_snapshot() -> Snapshot        observe the live system (read-only)
    diff(baseline, current) -> [Finding]  pure anomaly comparison
    run_watch(store) -> dict              one persisted watch pass
    BaselineStore                         where seen state and findings live
"""

from __future__ import annotations

from .baseline import BaselineStore
from .engine import collect_snapshot, diff, merge_into_baseline, run_watch
from .models import Connection, Device, Finding, Listener, Snapshot

__all__ = [
    "BaselineStore",
    "Connection",
    "Device",
    "Finding",
    "Listener",
    "Snapshot",
    "collect_snapshot",
    "diff",
    "merge_into_baseline",
    "run_watch",
]
