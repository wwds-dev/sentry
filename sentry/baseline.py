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
import os
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

try:
    import fcntl
except ImportError:  # non-POSIX; the app targets macOS, so this is a safe no-op
    fcntl = None

from .models import Finding, Snapshot

MAX_FINDINGS = 500


@contextmanager
def _file_lock(path: Path):
    """Serialise writers across processes (the in-app worker and the launchd
    watcher share these files). A no-op where fcntl is unavailable."""
    if fcntl is None:
        yield
        return
    lock_fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _atomic_write_text(path: Path, text: str) -> None:
    """Write to a temp file in the same directory, then os.replace().

    A plain write_text() left the JSON truncated if the process was killed
    mid-write; load_baseline() then swallowed the decode error and run_watch()
    re-adopted the baseline, silently suppressing every finding for that pass.
    os.replace() is atomic, so a reader sees either the old or the new file
    whole, never a partial one.
    """
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
        self.watch_lock_path = self.state_dir / "watch.lock"

    @contextmanager
    def transaction(self):
        """Serialise a whole watch pass across processes.

        The per-file locks on save_baseline/append_findings stop a single write
        from being torn, but not the load→diff→merge→save read-modify-write of a
        full pass: two watchers (the in-app worker and the launchd watcher) could
        each load the same baseline and the later save would drop the other's
        merged devices/listeners/connections, re-reporting them later. Holding
        this lock across the whole pass (see run_watch) prevents that."""
        with _file_lock(self.watch_lock_path):
            yield

    # ── baseline ──────────────────────────────────────────────────────────
    def load_baseline(self) -> Snapshot | None:
        if not self.baseline_path.is_file():
            return None
        try:
            return Snapshot.from_dict(json.loads(self.baseline_path.read_text("utf-8")))
        except (json.JSONDecodeError, OSError, TypeError):
            return None

    def save_baseline(self, snapshot: Snapshot) -> None:
        with _file_lock(self.baseline_path):
            _atomic_write_text(
                self.baseline_path, json.dumps(snapshot.as_dict(), indent=2)
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
        # Hold the lock across the whole read-modify-write so a concurrent pass
        # (the in-app worker vs. the launchd watcher) cannot clobber the other's
        # appended findings.
        with _file_lock(self.findings_path):
            records = self.load_findings()
            for finding in findings:
                record = finding.as_dict()
                record["observed_at"] = stamp
                records.append(record)
            records = records[-MAX_FINDINGS:]
            _atomic_write_text(self.findings_path, json.dumps(records, indent=2))
        return records

    def clear_findings(self) -> None:
        if self.findings_path.is_file():
            self.findings_path.unlink()
