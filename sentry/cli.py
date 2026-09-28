"""Command line for Sentry: one-shot scans, a foreground watch loop, selftest.

The background watcher (launchd) calls ``main.py --headless``, which routes here
to ``cmd_watch_once``. Everything prints plain text so it is readable in a
terminal and in launchd's log.
"""

from __future__ import annotations

import argparse
import time

from .baseline import BaselineStore
from .engine import collect_snapshot, run_watch

_SEVERITY_MARK = {
    "alert": "[ALERT]",
    "warning": "[WARN ]",
    "notice": "[NOTE ]",
    "info": "[info ]",
}


def render_summary(summary: dict) -> str:
    lines: list[str] = []
    counts = (
        f"{summary.get('device_count', 0)} devices, "
        f"{summary.get('listener_count', 0)} listeners, "
        f"{summary.get('connection_count', 0)} connections"
    )
    if summary.get("baseline_established"):
        lines.append(f"Baseline established ({counts}).")
        lines.append("No findings on a first pass — future passes compare against this.")
        return "\n".join(lines)

    findings = summary.get("findings", [])
    lines.append(f"Watch pass at {summary.get('taken_at', '?')} — {counts}.")
    if not findings:
        lines.append("No new anomalies since the last trusted baseline.")
        return "\n".join(lines)
    lines.append(f"{len(findings)} finding(s):")
    for finding in findings:
        mark = _SEVERITY_MARK.get(finding.get("severity", "info"), "[info ]")
        lines.append(f"  {mark} {finding.get('title', '')}")
        if finding.get("detail"):
            lines.append(f"          {finding['detail']}")
    return "\n".join(lines)


def cmd_scan(_args) -> int:
    """A one-off comparison that does not persist anything (dry run)."""
    store = BaselineStore()
    baseline = store.load_baseline()
    current = collect_snapshot()
    if baseline is None:
        print(render_summary({
            "baseline_established": True,
            "device_count": len(current.devices),
            "listener_count": len(current.listeners),
            "connection_count": len(current.connections),
        }))
        print("(dry run — baseline not written; use 'watch-once' to persist)")
        return 0
    from .engine import diff
    findings = diff(baseline, current)
    print(render_summary({
        "baseline_established": False,
        "findings": [f.as_dict() for f in findings],
        "device_count": len(current.devices),
        "listener_count": len(current.listeners),
        "connection_count": len(current.connections),
        "taken_at": current.taken_at,
    }))
    return 0


def cmd_watch_once(_args) -> int:
    summary = run_watch()
    print(render_summary(summary))
    return 0


def cmd_watch(args) -> int:
    interval = max(30, int(args.interval))
    print(f"Sentry watching every {interval}s. Ctrl-C to stop.")
    try:
        while True:
            print(render_summary(run_watch()))
            print("-" * 60)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped.")
    return 0


def cmd_selftest(_args) -> int:
    """Prove the collectors run and parse without raising, on this machine."""
    snapshot = collect_snapshot()
    print(
        "selftest OK — "
        f"{len(snapshot.devices)} devices, "
        f"{len(snapshot.listeners)} listeners, "
        f"{len(snapshot.connections)} connections, "
        f"gateway {snapshot.gateway_ip or '?'}"
    )
    return 0


def cmd_report(_args) -> int:
    findings = BaselineStore().load_findings()
    if not findings:
        print("No findings recorded yet.")
        return 0
    for record in findings[-50:]:
        mark = _SEVERITY_MARK.get(record.get("severity", "info"), "[info ]")
        print(f"{record.get('observed_at', '?')} {mark} {record.get('title', '')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentry", description="Sentinel network watch")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("scan", help="dry-run comparison, nothing persisted").set_defaults(func=cmd_scan)
    sub.add_parser("watch-once", help="one persisted watch pass").set_defaults(func=cmd_watch_once)
    watch = sub.add_parser("watch", help="foreground watch loop")
    watch.add_argument("--interval", type=int, default=300, help="seconds between passes")
    watch.set_defaults(func=cmd_watch)
    sub.add_parser("selftest", help="verify collectors run on this host").set_defaults(func=cmd_selftest)
    sub.add_parser("report", help="print the recorded findings log").set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)
