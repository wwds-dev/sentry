# Sentry — network anomaly watch

Sentry is Sentinel's **read-only** watch over the network the Mac is connected to.
It records a trusted baseline of the local segment and this host, then reports what
is new or anomalous on every later pass — a fresh device, ARP-spoofing / gateway
impersonation, an unexpected listening service, or a new outbound connection. It
can keep watching in the background while Sentinel is closed.

It ships as an in-app agent (roster key `sentry`) and as a standalone CLI.

## The honest boundary

The pitch for a tool like this is usually "an IDS that catches hackers on your
network." Real intrusion detection at that level needs packet capture (root/BPF),
signatures, and a place to run continuously. Sentry is a narrower, real version:

- It reads what the OS already knows — the ARP/NDP **neighbour table**, the
  **default route**, and this host's own **sockets** (`arp`, `ndp`, `route`,
  `lsof`). No `sudo`, no packet sniffing, no traffic inspection.
- It never scans, probes, or touches **other** hosts. Defensive, own-network only.
- It changes nothing — no interface, route, or remote state is modified.

What it catches well: a new device appearing, ARP spoofing / a gateway MAC change
(a credible man-in-the-middle signal), a new service listening on this Mac, and
new outbound connections to public endpoints. What it does **not** do: deep packet
inspection, Snort-style signatures, or catching an attacker who never touches the
ARP table or this host's sockets. Deep inspection is a future item (`SUGGESTIONS.md`).

## Layout

```
sentry/            engine package (pure, testable)
  collectors.py    read-only probes + their parsers (arp/ndp/route/lsof)
  models.py        Device / Listener / Connection / Finding / Snapshot
  engine.py        diff(baseline, current) -> findings; run_watch()
  baseline.py      JSON baseline + rolling findings log
  watchd.py        install/remove the launchd background watch
  cli.py           scan / watch-once / watch / selftest / report
main.py            standalone + headless (--headless) entry
tests/             engine tests (parsers, classification, diff, persistence)
launchd/           launch-agent plist template
```

In the app, the panel is `ui/panels/sentry.py` and the chat agent is
`sentinel_chat_agent.py → SentryAgent`. Developer reference:
`../../docs/agents/sentry.md`.

## CLI

```bash
python main.py selftest      # verify the read-only collectors run on this host
python main.py scan          # dry-run diff against the baseline, nothing written
python main.py watch-once    # one persisted pass (what launchd runs)
python main.py watch --interval 300
python main.py report        # print the recorded findings log
```

## Tests

```bash
cd agents/sentry && ../../.venv/bin/python -m pytest -q
```

Runs from this directory (a scoped `conftest.py` puts the package on the path).
The parent Sentinel suite (`testpaths = tests`) does not collect these.
