# Sentry — TODO

> **Legend** — priority `P0` critical · `P1` high · `P2` normal · `P3` low
> categories `security` `bug` `feature` `performance` `design` `docs` `testing` `infra` `research`
> owner `@me` (needs you — judgement, a real network to watch) · `@ai` (Claude can do this)

---

## v1 — current (2026-09-28): read-only baseline watch + continuous background

- [x] `P1` `feature` `@ai` Read-only collectors: ARP + NDP neighbour table (merged), default gateway, host listeners and established outbound connections — no sudo, no packet capture.
- [x] `P1` `feature` `@ai` Pure `diff(baseline, current)` producing severity-tagged findings: new device, ARP-spoof / gateway-MAC change, new listener, new outbound connection.
- [x] `P1` `feature` `@ai` Baseline + rolling findings log under Sentinel's writable base; first pass records, later passes report-then-fold.
- [x] `P1` `feature` `@ai` Continuous background watch via a launchd StartInterval agent (`main.py --headless`); install/remove from the panel.
- [x] `P1` `feature` `@ai` In-app panel with findings render, optional AI read behind the shared request guard, baseline reset, and background-watch controls.
- [x] `P1` `testing` `@ai` Engine tests (parsers, classification, diff scenarios, persistence) and panel tests (`tests/test_ui_panels.py::TestSentryPanel`).
- [x] `P1` `docs` `@ai` `docs/agents/sentry.md`, README roster 7 → 8.
- [x] `P1` `bug` `security` `@ai` Code-review fixes (2026-09-29): arp-spoof findings now dedupe against the baseline (a steady benign duplicate mapping no longer re-emits an identical finding every pass and evict real history through the 500-record cap); lsof parsing locates the protocol column from the right so a process name with a space (e.g. the truncated "Google Ch") no longer shifts the columns and drops the row; baseline/findings are written atomically under a cross-process flock (a truncated write no longer makes `load_baseline` return None and `run_watch` silently suppress every finding); the connections baseline is capped; the unused one-MAC-many-IPs path (ordinary for dual-stack/routers, not a spoof signal) was removed.

## v2 — planned

- [ ] `P2` `feature` `@me` OUI vendor lookup for new-device findings (offline prefix table) so a MAC reads as "Apple, Inc." instead of raw hex.
- [ ] `P2` `feature` `@ai` Acknowledge / trust a specific finding from the panel (mute a known device or service without resetting the whole baseline).
- [ ] `P2` `feature` `@ai` Desktop notification / Lab Hub badge when a background pass raises an `alert`-severity finding.
- [ ] `P3` `feature` `@me` Per-network baselines keyed on gateway MAC + SSID, so moving between home/office/coffee-shop does not read as a flood of new devices.
- [ ] `P3` `research` `@me` Optional privileged deep-inspection mode (BPF/pcap) as a clearly-gated, separate capability — see SUGGESTIONS.
