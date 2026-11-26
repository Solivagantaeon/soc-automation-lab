#!/usr/bin/env python3
"""
collect_alerts.py - Collects Wazuh alerts from alerts.json for a single
time window (6 hours by default).

Read-only operation: reads alerts.json and rotated .json.gz archives,
then writes NEW files to --out.

Does not modify /var/ossec, use Git, or transmit data over the network.

Time windows are fixed and aligned to the manager's local clock
(00:00, 06:00, 12:00, and 18:00).

Each window uses the interval [start, end).
By default, the script processes the most recently COMPLETED window.

For each window, e.g. 2026-10-21T00-00_2026-10-21T06-00,
three files are generated:

  counts/<window>_baseline.csv
      Format defined in metrics/README.md:
      stage,alert_count,notes (stage=raw)

  counts/<window>_baseline-by-rule.csv
      Breakdown by agent, rule_id, level, count, and percent_of_window.

  raw/<window>.jsonl
      Full alert records from the window.
      WARNING: Contains real IP addresses and potentially sensitive data.
      DO NOT commit this file to the repository.

Existing files are never overwritten. If any file for the selected
window already exists, the script exits with an error without writing
new files.

Examples:
  collect_alerts.py --dry-run
  collect_alerts.py --out /opt/soc-metrics
  collect_alerts.py --out /opt/soc-metrics --start 2026-10-21T06:00
"""

import argparse
import csv
import gzip
import json
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

ALERTS_DIR = Path("/var/ossec/logs/alerts")

MONTHS = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]


def parse_ts(s):
    # Wazuh timestamp format: "2026-10-21T04:52:11.123+0200"
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")


def window_name(start, end):
    f = "%Y-%m-%dT%H-%M"
    return f"{start.strftime(f)}_{end.strftime(f)}"


def pick_window(args):
    # Use a named time zone instead of a fixed UTC offset to account
    # for daylight saving time changes.
    local_tz = ZoneInfo(args.tz)
    hours = args.window_hours

    if args.start:
        start = datetime.fromisoformat(args.start).replace(tzinfo=local_tz)
    else:
        now = datetime.now(local_tz)

        floored = now.replace(
            minute=0,
            second=0,
            microsecond=0,
        )

        floored -= timedelta(hours=floored.hour % hours)

        # Select the most recently completed time window.
        start = floored - timedelta(hours=hours)

    return start, start + timedelta(hours=hours)


def candidate_files(start, end):
    """
    Select exactly one source file for each date covered by the window.

    Wazuh writes current alerts both to alerts.json and to a dated file
    (ossec-alerts-DD.json). Reading both would count the same alerts twice.

    Source priority:
      1. Dated compressed archive (.json.gz)
      2. Dated JSON file (.json)
      3. alerts.json, only for the current date when no dated file exists
    """

    files = []
    today = datetime.now().astimezone().date()

    day = start.date()
    last_day = (end - timedelta(seconds=1)).date()

    while day <= last_day:
        base = (
            ALERTS_DIR
            / str(day.year)
            / MONTHS[day.month - 1]
        )

        dated = [
            base / f"ossec-alerts-{day.day:02d}.json.gz",
            base / f"ossec-alerts-{day.day:02d}.json",
        ]

        found = next(
            (p for p in dated if p.exists()),
            None,
        )

        if found:
            files.append(found)
        elif day == today and (ALERTS_DIR / "alerts.json").exists():
            files.append(ALERTS_DIR / "alerts.json")

        day += timedelta(days=1)

    return files


def open_any(path):
    if path.suffix == ".gz":
        return gzip.open(
            path,
            "rt",
            encoding="utf-8",
            errors="replace",
        )

    return open(
        path,
        "r",
        encoding="utf-8",
        errors="replace",
    )


def iter_window_alerts(start, end, stats):
    for path in candidate_files(start, end):
        stats["files"].append(str(path))

        with open_any(path) as fh:
            for line in fh:
                line = line.strip()

                if not line:
                    continue

                try:
                    alert = json.loads(line)
                    ts = parse_ts(alert["timestamp"])

                except (ValueError, KeyError):
                    stats["unparsable_lines"] += 1
                    continue

                if start <= ts < end:
                    yield line, alert


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    ap.add_argument(
        "--out",
        default=".",
        help="Output directory",
    )

    ap.add_argument(
        "--window-hours",
        type=int,
        default=6,
        help="Time window duration in hours (default: 6)",
    )

    ap.add_argument(
        "--start",
        help="Window start time in local time, e.g. 2026-10-21T06:00",
    )

    ap.add_argument(
        "--tz",
        default="Europe/Warsaw",
        help="Time zone used for windows (default: Europe/Warsaw)",
    )

    ap.add_argument(
        "--min-level",
        type=int,
        default=0,
        help="Count alerts with level >= N (default: all levels)",
    )

    ap.add_argument(
        "--exclude-agent-ids",
        default="",
        help="Comma-separated agent IDs to exclude, e.g. 000",
    )

    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Display the summary without writing any files",
    )

    args = ap.parse_args()

    if 24 % args.window_hours != 0:
        sys.exit(
            "--window-hours must be a positive divisor of 24 "
            "(1, 2, 3, 4, 6, 8, 12, or 24)"
        )

    excluded = {
        x.strip()
        for x in args.exclude_agent_ids.split(",")
        if x.strip()
    }

    start, end = pick_window(args)
    name = window_name(start, end)

    out = Path(args.out)

    p_total = out / "counts" / f"{name}_baseline.csv"
    p_rules = out / "counts" / f"{name}_baseline-by-rule.csv"
    p_raw = out / "raw" / f"{name}.jsonl"

    if not args.dry_run:
        existing = [
            str(p)
            for p in (p_total, p_rules, p_raw)
            if p.exists()
        ]

        if existing:
            sys.exit(
                "Files for this window already exist. "
                "Refusing to overwrite:\n  "
                + "\n  ".join(existing)
            )

    stats = {
        "files": [],
        "unparsable_lines": 0,
    }

    # Count alerts by agent ID, agent name, rule ID, and severity level.
    counts = Counter()

    raw_lines = []
    total = 0

    for line, alert in iter_window_alerts(start, end, stats):
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})

        level = int(rule.get("level", 0))
        agent_id = str(agent.get("id", "000"))

        if level < args.min_level or agent_id in excluded:
            continue

        counts[
            (
                agent_id,
                agent.get("name", "?"),
                str(rule.get("id", "?")),
                level,
            )
        ] += 1

        total += 1
        raw_lines.append(line)

    print(
        f"Window: {start.isoformat()} .. {end.isoformat()} "
        f"({name})"
    )

    print(
        f"Source files: "
        f"{stats['files'] or 'NONE - check the path and permissions'}"
    )

    print(
        f"Unparsable lines: {stats['unparsable_lines']}"
    )

    print(
        f"Alerts matching the counting criteria: {total}"
    )

    for (aid, aname, rid, lvl), n in counts.most_common(10):
        print(
            f"  {n:6d}  {100 * n / total:5.1f}%  "
            f"rule {rid}  level {lvl}  agent {aid}/{aname}"
        )

    if args.dry_run:
        return

    if not stats["files"]:
        sys.exit(
            "No alert source files found. Nothing was written."
        )

    (out / "counts").mkdir(
        parents=True,
        exist_ok=True,
    )

    (out / "raw").mkdir(
        parents=True,
        exist_ok=True,
    )

    agents_note = (
        "all agents"
        if not excluded
        else f"excluding agent ids {','.join(sorted(excluded))}"
    )

    notes = (
        f"6h window {start.isoformat()} .. {end.isoformat()}, "
        f"{agents_note}, min_level={args.min_level}"
    )

    notes = notes.replace(
        "6h",
        f"{args.window_hours}h",
        1,
    )

    # Mode "x" creates a new file exclusively and raises an error
    # if the file already exists.
    with open(p_total, "x", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)

        w.writerow([
            "stage",
            "alert_count",
            "notes",
        ])

        w.writerow([
            "raw",
            total,
            notes,
        ])

    with open(p_rules, "x", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)

        w.writerow([
            "agent_id",
            "agent_name",
            "rule_id",
            "level",
            "count",
            "percent_of_window",
        ])

        for (aid, aname, rid, lvl), n in counts.most_common():
            w.writerow([
                aid,
                aname,
                rid,
                lvl,
                n,
                f"{100 * n / total:.2f}",
            ])

    with open(p_raw, "x", encoding="utf-8") as fh:
        fh.write(
            "\n".join(raw_lines)
            + ("\n" if raw_lines else "")
        )

    print(
        f"Files written:\n"
        f"  {p_total}\n"
        f"  {p_rules}\n"
        f"  {p_raw}"
    )


if __name__ == "__main__":
    main()
