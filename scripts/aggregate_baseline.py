#!/usr/bin/env python3
"""
aggregate_baseline.py - sklada pliki okien 6 h (z collect_alerts.py) w jeden pomiar (domyslnie 24 h).

Tylko odczyt plikow counts/*.csv, zapisuje NOWE pliki do --out. Nie dotyka raw/ ani /var/ossec.
Pliki wynikowe zawieraja same liczniki (bez IP), wiec nadaja sie do repo (metrics/).

Wyjscie (nazwy jak w zadaniu):
  <out>/<data>_baseline.csv          format z metrics/README.md: stage,alert_count,notes (stage=raw)
  <out>/<data>_baseline-by-rule.csv  rozbicie: agent, rule_id, level, count, percent_of_total

NIE NADPISUJE: jesli ktorykolwiek plik juz istnieje, konczy sie bledem.
Przerywa, jesli brakuje ktoregokolwiek okna albo okna maja rozne reguly liczenia.

Przyklad:
  aggregate_baseline.py --start 2026-10-30T00:00 --dry-run
  aggregate_baseline.py --start 2026-10-30T00:00 --out /opt/soc-metrics/metrics --note "attack: nmap from Kali at 10:15"
"""
import argparse
import csv
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

WINDOW_HOURS = 6


def window_name(start, end):
    f = "%Y-%m-%dT%H-%M"
    return f"{start.strftime(f)}_{end.strftime(f)}"


def read_total(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r.get("stage") == "raw"]
    if len(rows) != 1:
        sys.exit(f"{path}: oczekiwano dokladnie jednego wiersza stage=raw, jest {len(rows)}")
    return int(rows[0]["alert_count"]), rows[0]["notes"]


def read_by_rule(path):
    counts = Counter()
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            counts[(r["agent_id"], r["agent_name"], r["rule_id"], r["level"])] += int(r["count"])
    return counts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--start", required=True, help="poczatek pomiaru, lokalny czas, np. 2026-10-30T00:00")
    ap.add_argument("--hours", type=int, default=24, help="dlugosc pomiaru, wielokrotnosc 6 (domyslnie 24)")
    ap.add_argument("--counts-dir", default="/opt/soc-metrics/counts", help="katalog z plikami okien")
    ap.add_argument("--out", default="metrics", help="katalog wyjsciowy")
    ap.add_argument("--tz", default="Europe/Warsaw")
    ap.add_argument("--note", default="", help="dopisek do notes, np. godzina ataku")
    ap.add_argument("--dry-run", action="store_true", help="nic nie zapisuj, wypisz podsumowanie")
    args = ap.parse_args()

    tz = ZoneInfo(args.tz)
    start = datetime.fromisoformat(args.start).replace(tzinfo=tz)
    if args.hours % WINDOW_HOURS or start.minute or start.hour % WINDOW_HOURS:
        sys.exit("--start musi byc wyrownany do 00/06/12/18, a --hours wielokrotnoscia 6")

    windows = []
    cur = start
    for _ in range(args.hours // WINDOW_HOURS):
        nxt = cur + timedelta(hours=WINDOW_HOURS)
        windows.append((cur, nxt))
        cur = nxt
    end = cur

    cdir = Path(args.counts_dir)
    missing = []
    for s, e in windows:
        n = window_name(s, e)
        for suffix in ("_baseline.csv", "_baseline-by-rule.csv"):
            if not (cdir / f"{n}{suffix}").exists():
                missing.append(f"{n}{suffix}")
    if missing:
        sys.exit("Brakuje plikow (okno jeszcze trwa albo nie zostalo zebrane):\n  " + "\n  ".join(missing))

    total = 0
    by_rule = Counter()
    tails = set()
    for s, e in windows:
        n = window_name(s, e)
        w_total, notes = read_total(cdir / f"{n}_baseline.csv")
        w_rules = read_by_rule(cdir / f"{n}_baseline-by-rule.csv")
        if sum(w_rules.values()) != w_total:
            sys.exit(f"Okno {n}: suma z by-rule ({sum(w_rules.values())}) != raw ({w_total})")
        tails.add(notes.split(", ", 1)[1] if ", " in notes else notes)
        total += w_total
        by_rule.update(w_rules)
        print(f"  {n}: {w_total}")

    if len(tails) != 1:
        sys.exit("Okna maja rozne reguly liczenia (agenci / min_level), nie lacze:\n  " + "\n  ".join(sorted(tails)))
    tail = tails.pop()

    notes = f"{args.hours}h window {start.isoformat()} .. {end.isoformat()} ({len(windows)} windows of {WINDOW_HOURS}h), {tail}"
    if args.note:
        notes += f", {args.note}"

    print(f"\nrazem: {total} alertow ({start.isoformat()} .. {end.isoformat()})")
    print(f"notes: {notes}")

    per_rule = Counter()
    rule_level = {}
    for (aid, aname, rid, lvl), n in by_rule.items():
        per_rule[rid] += n
        rule_level[rid] = lvl
    print("\ntop 10 regul (po rule_id, wszyscy agenci):")
    for rid, n in per_rule.most_common(10):
        print(f"  {n:6d}  {100 * n / total:5.1f}%  rule {rid}  level {rule_level[rid]}")

    if args.dry_run:
        return

    out = Path(args.out)
    label = start.strftime("%Y-%m-%d")
    p_total = out / f"{label}_baseline.csv"
    p_rules = out / f"{label}_baseline-by-rule.csv"
    existing = [str(p) for p in (p_total, p_rules) if p.exists()]
    if existing:
        sys.exit("Pliki juz istnieja, nie nadpisuje:\n  " + "\n  ".join(existing))

    out.mkdir(parents=True, exist_ok=True)
    with open(p_total, "x", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["stage", "alert_count", "notes"])
        w.writerow(["raw", total, notes])
    with open(p_rules, "x", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["agent_id", "agent_name", "rule_id", "level", "count", "percent_of_total"])
        for (aid, aname, rid, lvl), n in by_rule.most_common():
            w.writerow([aid, aname, rid, lvl, n, f"{100 * n / total:.2f}"])
    print(f"\nzapisano:\n  {p_total}\n  {p_rules}")


if __name__ == "__main__":
    main()
