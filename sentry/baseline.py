"""Persistence for what Sentry has already seen.

The baseline is the union of every device, listener and outbound relationship
observed on trusted passes. A finding is raised the *first* time something new
appears; the watcher then folds it into the baseline so it is reported once, not
on every tick. Findings themselves are appended to a rolling log the panel and
the background watcher both read.

Storage lives under Sentinel's normal writable base (Application Support, the
portable volume, or the project root in development) so it follows the app's
existing data-location rules rather than inventing a new one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding, Snapshot

MAX_FINDINGS = 500


def default_state_dir() -> Path:
    """Sentry's writable directory, following Sentinel's runtime path rules."""
    try:
        from services.runtime_paths import user_data_base

        base = user_data_base() / "data" / "sentry"
    except Exception:
        # Standalone / headless use with the app package unavailable: fall back
        # to the repo's own data dir, mirroring how Bug Spray stores its feed.
        base = Path(__file__).resolve().parents[1] / "data"
    base.mkdir(parents=True, exist_ok=True)
    return base


class BaselineStore:
    def __init__(self, state_dir: Path | None = None):
        self.state_dir = Path(state_dir) if state_dir else default_state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_path = self.state_dir / "baseline.json"
        self.findings_path = self.state_dir / "findings.json"

    # ── baseline ──────────────────────────────────────────────────────────
    def load_baseline(self) -> Snapshot | None:
        if not self.baseline_path.is_file():
            return None
        try:
            return Snapshot.from_dict(json.loads(self.baseline_path.read_text("utf-8")))
        except (json.JSONDecodeError, OSError, TypeError):
            return None

    def save_baseline(self, snapshot: Snapshot) -> None:
        self.baseline_path.write_text(
            json.dumps(snapshot.as_dict(), indent=2), encoding="utf-8"
        )

    def has_baseline(self) -> bool:
        return self.baseline_path.is_file()

    # ── findings log ──────────────────────────────────────────────────────
    def load_findings(self) -> list[dict]:
        if not self.findings_path.is_file():
            return []
        try:
            return json.loads(self.findings_path.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def append_findings(self, findings: list[Finding]) -> list[dict]:
        if not findings:
            return self.load_findings()
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        records = self.load_findings()
        for finding in findings:
            record = finding.as_dict()
            record["observed_at"] = stamp
            records.append(record)
        records = records[-MAX_FINDINGS:]
        self.findings_path.write_text(
            json.dumps(records, indent=2), encoding="utf-8"
        )
        return records

    def clear_findings(self) -> None:
        if self.findings_path.is_file():
            self.findings_path.unlink()
