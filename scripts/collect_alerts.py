#!/usr/bin/env python3
"""
collect_alerts.py - zbiera alerty Wazuh z alerts.json z jednego okna czasowego (domyslnie 6 h).

Tylko odczyt: czyta alerts.json (+ rotowane archiwa .json.gz) i zapisuje NOWE pliki do --out.
Niczego w /var/ossec nie zmienia, nie uzywa gita, nie wysyla nic w siec.

Okna sa stale, wyrownane do zegara (00/06/12/18 czasu lokalnego managera), przedzial [start, end).
Domyslnie przetwarzane jest ostatnie ZAKONCZONE okno.

Dla okna <okno> (np. 2026-10-21T00-00_2026-10-21T06-00) powstaja trzy pliki:
  counts/<okno>_baseline.csv          format z metrics/README.md: stage,alert_count,notes (stage=raw)
  counts/<okno>_baseline-by-rule.csv  rozbicie: agent, rule_id, level, count, percent_of_window
  raw/<okno>.jsonl                    pelne alerty z okna (PRAWDZIWE IP - nie commitowac!)

NIE NADPISUJE: jesli ktorykolwiek z plikow dla tego okna juz istnieje, skrypt konczy sie bledem
i niczego nie zapisuje.

Przyklady:
  collect_alerts.py --dry-run
  collect_alerts.py --out /opt/soc-metrics
  collect_alerts.py --out /opt/soc-metrics --start 2026-10-21T06:00   # reczne okno
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
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def parse_ts(s):
    # Wazuh: "2026-10-21T04:52:11.123+0200"
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")


def window_name(start, end):
    f = "%Y-%m-%dT%H-%M"
    return f"{start.strftime(f)}_{end.strftime(f)}"


def pick_window(args):
    # strefa po nazwie (nie stale przesuniecie), zeby okna byly poprawne przez zmiane czasu
    local_tz = ZoneInfo(args.tz)
    hours = args.window_hours
    if args.start:
        start = datetime.fromisoformat(args.start).replace(tzinfo=local_tz)
    else:
        now = datetime.now(local_tz)
        floored = now.replace(minute=0, second=0, microsecond=0)
        floored -= timedelta(hours=floored.hour % hours)
        start = floored - timedelta(hours=hours)  # ostatnie zakonczone okno
    return start, start + timedelta(hours=hours)


def candidate_files(start, end):
    """Dla kazdej daty, ktora dotyka okno, dokladnie JEDNO zrodlo.

    Wazuh zapisuje biezace alerty rownolegle do alerts.json i do pliku datowanego
    (ossec-alerts-DD.json), wiec czytanie obu liczyloby alerty podwojnie.
    Kolejnosc: plik datowany (.json.gz, potem .json); alerts.json tylko dla dzisiejszej
    daty, gdy pliku datowanego brak.
    """
    files = []
    today = datetime.now().astimezone().date()
    day = start.date()
    last_day = (end - timedelta(seconds=1)).date()
    while day <= last_day:
        base = ALERTS_DIR / str(day.year) / MONTHS[day.month - 1]
        dated = [base / f"ossec-alerts-{day.day:02d}.json.gz",
                 base / f"ossec-alerts-{day.day:02d}.json"]
        found = next((p for p in dated if p.exists()), None)
        if found:
            files.append(found)
        elif day == today and (ALERTS_DIR / "alerts.json").exists():
            files.append(ALERTS_DIR / "alerts.json")
        day += timedelta(days=1)
    return files


def open_any(path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


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
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=".", help="katalog wyjsciowy")
    ap.add_argument("--window-hours", type=int, default=6, help="dlugosc okna (domyslnie 6)")
    ap.add_argument("--start", help="poczatek okna, lokalny czas, np. 2026-10-21T06:00")
    ap.add_argument("--tz", default="Europe/Warsaw", help="strefa czasowa okien (domyslnie Europe/Warsaw)")
    ap.add_argument("--min-level", type=int, default=0, help="zliczaj alerty o level >= N (domyslnie wszystkie)")
    ap.add_argument("--exclude-agent-ids", default="", help="id agentow do pominiecia, np. 000")
    ap.add_argument("--dry-run", action="store_true", help="nic nie zapisuj, wypisz podsumowanie")
    args = ap.parse_args()

    if 24 % args.window_hours != 0:
        sys.exit("--window-hours musi dzielic 24 (1,2,3,4,6,8,12,24)")

    excluded = {x.strip() for x in args.exclude_agent_ids.split(",") if x.strip()}
    start, end = pick_window(args)
    name = window_name(start, end)

    out = Path(args.out)
    p_total = out / "counts" / f"{name}_baseline.csv"
    p_rules = out / "counts" / f"{name}_baseline-by-rule.csv"
    p_raw = out / "raw" / f"{name}.jsonl"

    if not args.dry_run:
        existing = [str(p) for p in (p_total, p_rules, p_raw) if p.exists()]
        if existing:
            sys.exit("Pliki dla tego okna juz istnieja, nie nadpisuje:\n  " + "\n  ".join(existing))

    stats = {"files": [], "unparsable_lines": 0}
    counts = Counter()  # (agent_id, agent_name, rule_id, level) -> n
    raw_lines = []
    total = 0

    for line, alert in iter_window_alerts(start, end, stats):
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        level = int(rule.get("level", 0))
        agent_id = str(agent.get("id", "000"))
        if level < args.min_level or agent_id in excluded:
            continue
        counts[(agent_id, agent.get("name", "?"), str(rule.get("id", "?")), level)] += 1
        total += 1
        raw_lines.append(line)

    print(f"okno: {start.isoformat()} .. {end.isoformat()}  ({name})")
    print(f"pliki zrodlowe: {stats['files'] or 'BRAK - sprawdz sciezke i uprawnienia'}")
    print(f"niesparsowane linie: {stats['unparsable_lines']}")
    print(f"alerty po regule liczenia: {total}")
    for (aid, aname, rid, lvl), n in counts.most_common(10):
        print(f"  {n:6d}  {100 * n / total:5.1f}%  rule {rid}  level {lvl}  agent {aid}/{aname}")

    if args.dry_run:
        return
    if not stats["files"]:
        sys.exit("Nie znaleziono zadnego pliku z alertami - nic nie zapisuje.")

    (out / "counts").mkdir(parents=True, exist_ok=True)
    (out / "raw").mkdir(parents=True, exist_ok=True)

    agents_note = "all agents" if not excluded else f"excluding agent ids {','.join(sorted(excluded))}"
    notes = f"6h window {start.isoformat()} .. {end.isoformat()}, {agents_note}, min_level={args.min_level}"
    notes = notes.replace("6h", f"{args.window_hours}h", 1)

    # "x" = tworzenie wylacznie nowego pliku, blad jesli juz istnieje
    with open(p_total, "x", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["stage", "alert_count", "notes"])
        w.writerow(["raw", total, notes])

    with open(p_rules, "x", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["agent_id", "agent_name", "rule_id", "level", "count", "percent_of_window"])
        for (aid, aname, rid, lvl), n in counts.most_common():
            w.writerow([aid, aname, rid, lvl, n, f"{100 * n / total:.2f}"])

    with open(p_raw, "x", encoding="utf-8") as fh:
        fh.write("\n".join(raw_lines) + ("\n" if raw_lines else ""))

    print(f"zapisano:\n  {p_total}\n  {p_rules}\n  {p_raw}")


if __name__ == "__main__":
    main()
