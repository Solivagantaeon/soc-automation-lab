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
  the format above, plus a `*_baseline-by-rule.csv` / `*_normal-day-by-rule.csv`
  breakdown by agent/rule_id/level.
- Counting rule used for every measurement below: all alert levels (`min_level=0`), all
  agents including the manager (`000`).

## Rule-set state (applies to every file below)

Custom rule-set `local_rules_noise_reduction.xml` (v2, dated 2026-10-10, sha256
`c429ba346bc3611d2168835718c26f76e61331b15fb48a26d5ff781cf01debf4`, 29 rules,
IDs 100100–100191) is loaded on wazuh-master via the directory-wide
`<rule_dir>etc/rules</rule_dir>` entry in `ossec.conf` (`<ruleset>` block) — no
per-file `<include>` is needed for it to be active. It has been in this state since
before data collection started on 2026-10-22, so **every** file in this directory
(comparison days and the attack baseline alike) already reflects Wazuh's output with
this rule-set applied. Rules in this set are `level="0"`, so Wazuh suppresses matching
events before they reach `alerts.json` — our collectors never see what it filters.
Treat "raw" in this project's CSVs as *"what the manager's currently configured
rule-set outputs"*, not a stock/default Wazuh count.

- Wazuh manager: v4.14.9 rc2 (server)
- Agents (all `Active` at measurement time): `wazuh-master` (000, local), `SOC-WIN11-AI`
  (004), `opnsense` (005), `SOC-LIN-01` (006), `SOC-WIN10-01` (007), `SOC-DC01` (008)
- `custom-n8n` integration in `ossec.conf` is itself scoped by `rule_id`: one block
  forwards `86601,31105,31106,31151,31152,31153,31154,31168,31169,550,553,554,92213`,
  a second forwards only `31103`. Rules `31101` and `31516` are not in either list, so
  they never reach n8n regardless of what happens later in the pipeline — confirmed
  directly in `ossec.conf`, not inferred from volume alone.

## Baseline measurement (with attack)

**Date: 2026-10-30, 00:00–24:00 (Europe/Warsaw)**
Files: `2026-10-30_baseline.csv`, `2026-10-30_baseline-by-rule.csv`

- Attack: from Kali (10.10.30.100) against `SOC-LIN-01` / DVWA (`10.10.10.100`),
  ~17:36–19:36:
  - `nmap -sS -sV -p- 10.10.10.100` (port/service scan, includes NSE http-* scripts)
  - `gobuster dir -u http://10.10.10.100/dvwa/ ...` and again against `/dvwa/config/`,
    each run at least twice, wordlist `directory-list-2.3-small.txt` with
    `-x php,txt,bak,zip`
  - repeated `curl -X POST .../dvwa/login.php` with an invalid password and no CSRF
    token, intended as ~5 attempts but re-run as a 1000-iteration loop several times
    after one invocation used invalid shell syntax (`{1...1000}`) and silently did
    nothing
- Result: **167,089 alerts** over the full 24h (raw stage), ~255x the ~655/day median
  of the six comparison days below. Rules 31101 "Web server 400 error code" (73.2%),
  31516 "Suspicious URL access" (18.0%) and 31151 "Multiple web server 400 error codes
  from same source ip" (6.4%) together account for **97.7%** of the day's total.
- Attribution, checked directly against the raw alert data for 31101+31516
  (152,457 alerts combined): **93.7%** carry a `gobuster` user-agent string, a further
  **6.3%** show the same wordlist/extension-fuzzing pattern (random filename, varying
  extensions) from the same source IP without an identifiable user-agent, and the
  earlier nmap service scan contributed a negligible **8 hits (0.005%)**. The repeated
  login-POST loop contributed **0** — `/dvwa/login.php` does not appear among the hit
  URLs at all, because DVWA re-renders the login form (HTTP 200) on a missing/invalid
  CSRF token rather than returning an error code, so that loop never triggered either
  rule. In short: this day's volume is driven almost entirely by the gobuster
  directory/extension enumeration, not by the credential-stuffing loop.

## Comparison days (no attack, for context)

Same lab, same counting rule, same rule-set state as above, collected before the
attack day. These are **not** the official baseline (the task calls for 24h + one
attack scenario) — kept here to show what a normal day looks like, and how much of
30.10's volume is attack noise vs. background activity.

| Date | Alerts (raw, 24h) | File |
|---|---|---|
| 2026-10-22 | 669 | `2026-10-22_normal-day.csv` |
| 2026-10-23 | 357 | `2026-10-23_normal-day.csv` |
| 2026-10-24 | 1766 | `2026-10-24_normal-day.csv` |
| 2026-10-26 | 411 | `2026-10-26_normal-day.csv` |
| 2026-10-27 | 724 | `2026-10-27_normal-day.csv` |
| 2026-10-28 | 640 | `2026-10-28_normal-day.csv` |

2026-10-25 excluded: 25h day due to the DST change that night, not comparable.
2026-10-29 excluded: incomplete (collection covers only 00:00–12:00).

Median of the six normal days: ~655 alerts/24h (range 357–1766).

## Open item

Where `custom-n8n`'s rule_id filtering (see above) fits in the `stage` column for the
after-run funnel is not yet decided — rules 31101/31516 are dropped before n8n ever
sees them, which may warrant its own stage between `raw` and `after_dedup` rather than
being folded into an existing one. TBD once the after-run pipeline is finalised.
