# Metrics

How we prove the reduction. One CSV per measurement run, e.g. `2026-10-30_baseline.csv`:

```
stage,alert_count,notes
raw,1000,24h window, all agents
after_dedup,250,
after_grouping,80,
after_enrichment,30,
incidents_for_analyst,10,
```

Always note the time window, agents included and rule-set version, so runs are comparable.

## Collection method

- `scripts/collect_alerts.py` runs every 6h via cron on wazuh-master, reading
  `/var/ossec/logs/alerts/` (read-only). Writes per-window counts to `counts/` and the
  full alerts of the window to `raw/` (real IPs — not committed).
- `scripts/aggregate_baseline.py` combines four 6h windows into one 24h measurement in
  the format above, and a `*_baseline-by-rule.csv` breakdown by agent/rule_id/level.
- Counting rule used for every measurement below: all alert levels (`min_level=0`), all
  agents including the manager (`000`).

## Baseline measurement (with attack)

**Date: 2026-10-30, 00:00–24:00 (Europe/Warsaw)**
Files: `2026-10-30_baseline.csv`, `2026-10-30_baseline-by-rule.csv`

- Environment: Wazuh manager `wazuh-master`; agents `wazuh-master` (000), `opnsense` (005),
  `SOC-WIN11-AI` (004), `SOC-LIN-01` (006), `SOC-WIN10-01` (007), `SOC-DC01` (008).
- Rule-set version: noise reduction rules (`local_rules_noise_reduction.xml`, v2) **not
  deployed** during this measurement — file exists in the repo but was not active in
  `/var/ossec/etc/rules/`. This is intentional: baseline must reflect the un-reduced state.
- Attack: from Kali, against `SOC-LIN-01` / DVWA (`10.10.10.100`), ~17:36–19:36:
  - `nmap -sS -sV -p- 10.10.10.100` (port/service scan)
  - `gobuster dir -u http://10.10.10.100/dvwa/ ...` (directory enumeration, run twice)
  - repeated `curl -X POST .../dvwa/login.php` with an invalid password and no CSRF
    token, intended as ~5 attempts but re-run multiple times as a 1000-iteration loop
    (one invocation used invalid shell syntax `{1...1000}` and silently did nothing,
    so the loop was retried several times)
- Result: the 18:00–00:00 window alone produced **166,795 alerts**, 93.8% of it three
  rules on `SOC-LIN-01`: rule 31101 "Web server 400 error code" (73.3%), 31516 "Suspicious
  URL access" (18.1%), 31151 "Multiple web server 400 error codes from same source ip"
  (6.4%). This is a known, intentional characteristic of this run: the repeated-login
  loop was re-run several times rather than once, so the day's volume is dominated by one
  repeated low-sophistication pattern rather than a varied attack. See the by-rule CSV
  for the full breakdown and `samples/datasets/baseline.jsonl` for the raw (anonymised)
  dataset once produced.

## Comparison days (no attack, for context)

Same lab, same counting rule, collected before the attack day. These are **not** the
official baseline (the task calls for 24h + one attack scenario) — kept here to show
what a normal day looks like, and how much of 30.10's volume is attack noise vs.
background activity.

| Date | Alerts (raw, 24h) | File |
|---|---|---|
| 2026-10-22 | 669 | `2026-10-22_baseline.csv` |
| 2026-10-23 | 357 | `2026-10-23_baseline.csv` |
| 2026-10-24 | 1766 | `2026-10-24_baseline.csv` |
| 2026-10-26 | 411 | `2026-10-26_baseline.csv` |
| 2026-10-27 | 724 | `2026-10-27_baseline.csv` |
| 2026-10-28 | 640 | `2026-10-28_baseline.csv` |

2026-10-25 excluded: 25h day due to the DST change that night, not comparable.
2026-10-29 excluded: incomplete (collection covers only 00:00–12:00).

Median of the six normal days: ~655 alerts/24h (range 357–1766). The 2026-10-30 total
is several orders of magnitude higher, almost entirely attack-driven rather than
background noise — see the breakdown above.
