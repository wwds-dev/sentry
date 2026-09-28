# Sentry — Suggestions

Status: `IDEA` · `CONSIDERING` · `PLANNED` · `DONE` · `REJECTED`

---

## Detection depth

| # | Suggestion | Category | Effort | Status |
|---|---|---|---|---|
| 1 | Privileged deep-inspection mode (BPF/pcap) as a separate, clearly-gated capability — real IDS-style signatures need packet capture and root, which v1 deliberately avoids. Keep it opt-in and never the default. | feature | L | CONSIDERING |
| 2 | Passive OS/service fingerprinting from data already collected (TTL, listening-port heuristics) to label a new device's likely type without probing it. | feature | M | IDEA |
| 3 | Rogue-DHCP / rogue-router-advertisement detection (a second host answering DHCP or sending RAs) — a strong MITM signal that does not need packet capture. | feature | M | IDEA |
| 4 | Reuse Beacon's Wi-Fi read for duplicate-SSID / evil-twin flags, surfaced as Sentry findings on the wireless segment. | feature | S | IDEA |

## Usability

| # | Suggestion | Category | Effort | Status |
|---|---|---|---|---|
| 5 | Offline OUI vendor table so new-device findings name the manufacturer. | feature | S | PLANNED |
| 6 | Acknowledge/trust a single finding without resetting the whole baseline. | feature | S | PLANNED |
| 7 | Desktop notification / Lab Hub badge on an `alert`-severity background finding. | feature | S | PLANNED |
| 8 | Per-network baselines keyed on gateway MAC + SSID, so switching networks isn't a flood of "new device". | feature | M | PLANNED |
| 9 | A findings timeline view (from the persisted log) rather than only the latest pass. | design | M | IDEA |
