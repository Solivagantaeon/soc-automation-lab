#!/usr/bin/env python3
"""Create labels, milestones and issues from scripts/github_plan.json using the GitHub CLI (gh).

Safe to run more than once: labels are updated, existing milestones and issues
(matched by title) are skipped.

Usage:
  python scripts/bootstrap_github.py --repo OWNER/REPO --dry-run   # show what would happen
  python scripts/bootstrap_github.py --repo OWNER/REPO             # do it

Requires: gh installed and logged in (gh auth login).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

PLAN = Path(__file__).with_name("github_plan.json")


def gh(args: list[str], stdin: str | None = None, dry: bool = False) -> str:
    if dry:
        shown = " ".join(a if " " not in a else f'"{a}"' for a in args)
        print(f"  [dry-run] gh {shown}")
        return ""
    res = subprocess.run(
        ["gh", *args], input=stdin, capture_output=True, text=True, encoding="utf-8"
    )
    if res.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} … failed:\n{res.stderr.strip()}")
    return res.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True, help="OWNER/REPO, e.g. Solivagantaeon/soc-automation-lab")
    ap.add_argument("--dry-run", action="store_true", help="print actions, change nothing")
    args = ap.parse_args()
    repo, dry = args.repo, args.dry_run

    if not dry and not shutil.which("gh"):
        print("GitHub CLI (gh) not found. Install: winget install GitHub.cli, then: gh auth login")
        return 1

    plan = json.loads(PLAN.read_text(encoding="utf-8"))

    print(f"Labels ({len(plan['labels'])})")
    for lb in plan["labels"]:
        gh(["label", "create", lb["name"], "--color", lb["color"],
            "--description", lb["description"], "--force", "-R", repo], dry=dry)
        if not dry:
            print(f"  ok  {lb['name']}")

    print(f"Milestones ({len(plan['milestones'])})")
    existing_ms = set()
    if not dry:
        out = gh(["api", f"repos/{repo}/milestones?state=all&per_page=100"])
        existing_ms = {m["title"] for m in json.loads(out)}
    for ms in plan["milestones"]:
        if ms["title"] in existing_ms:
            print(f"  skip (exists)  {ms['title']}")
            continue
        gh(["api", "-X", "POST", f"repos/{repo}/milestones",
            "-f", f"title={ms['title']}", "-f", f"due_on={ms['due_on']}",
            "-f", f"description={ms['description']}"], dry=dry)
        if not dry:
            print(f"  ok  {ms['title']}")

    print(f"Issues ({len(plan['issues'])})")
    existing_issues = set()
    if not dry:
        out = gh(["issue", "list", "-R", repo, "--state", "all", "--limit", "1000", "--json", "title"])
        existing_issues = {i["title"] for i in json.loads(out)}
    created = 0
    for iss in plan["issues"]:
        if iss["title"] in existing_issues:
            print(f"  skip (exists)  {iss['title']}")
            continue
        cmd = ["issue", "create", "-R", repo, "--title", iss["title"],
               "--body-file", "-", "--milestone", iss["milestone"]]
        for label in iss["labels"]:
            cmd += ["--label", label]
        url = gh(cmd, stdin=iss["body"], dry=dry).strip()
        if not dry:
            print(f"  ok  {url}  {iss['title']}")
            created += 1
            time.sleep(1)  # stay well below GitHub's content-creation rate limit

    print(f"\nDone. New issues: {created}." if not dry else "\nDry run finished, nothing changed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
