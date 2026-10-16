#!/usr/bin/env python3
"""Remove secrets from Shuffle / TheHive / Cortex / MISP JSON exports and Wazuh XML snippets.

Usage:
  sanitize_export.py INPUT [-o OUTPUT]     write a sanitised copy (stdout if no -o)
  sanitize_export.py --check PATH [PATH…]  report findings, exit 1 if anything is found

What is treated as a secret:
  * JSON keys that look like credentials (apikey, api_key, password, token, secret,
    authorization, cookie, private_key, …)
  * Shuffle-style parameters: {"name": "apikey", "value": "…"} -> value is redacted
  * Shuffle webhook URLs (/api/v1/hooks/webhook_<uuid>) — anyone with the URL can trigger the workflow
  * "Bearer …" / "Basic …" tokens and user:password@ in URLs, anywhere in strings
  * Wazuh <api_key> and <hook_url> elements in XML

Placeholders like <CORTEX_API_KEY>, __NAME__ and the word REDACTED are not reported.
Standard library only, so it runs anywhere without installing anything.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REDACTED = "REDACTED"

SECRET_KEY_RE = re.compile(
    r"^(?:x[-_])?(?:api[-_]?key|apikey|api[-_]?token|access[-_]?token|refresh[-_]?token|token|"
    r"auth[-_]?token|password|passwd|pwd|secret|client[-_]?secret|authorization|cookie|"
    r"private[-_]?key|session[-_]?id)$",
    re.IGNORECASE,
)
# Keys that match the pattern above but are not secrets in Shuffle/TheHive exports.
SAFE_KEYS = {"authentication_id", "token_type", "key_type"}

PLACEHOLDER_RE = re.compile(r"^(?:<[A-Z0-9_]+>|__[A-Z0-9_]+__|REDACTED|\s*)$")

STRING_PATTERNS = [
    # Shuffle webhook id
    (re.compile(r"(/api/v1/hooks/)webhook_[0-9a-fA-F-]{36}"), r"\1webhook_" + REDACTED),
    # Authorization header values inside strings
    (re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    # credentials embedded in URLs
    (re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1" + REDACTED + "@"),
]

XML_ELEMENT_RE = re.compile(r"(<(api_key|hook_url|password)>)(.*?)(</\2>)", re.IGNORECASE | re.DOTALL)


def is_placeholder(value: object) -> bool:
    return isinstance(value, str) and bool(PLACEHOLDER_RE.match(value))


def scrub_string(s: str, findings: list[str], where: str) -> str:
    for pattern, repl in STRING_PATTERNS:
        new = pattern.sub(repl, s)
        if new != s:
            findings.append(f"{where}: {pattern.pattern[:40]}…")
            s = new
    return s


def scrub_json(obj, findings: list[str], path: str = "$"):
    if isinstance(obj, dict):
        # Shuffle parameter object: {"name": "apikey", "value": "..."}
        name = obj.get("name")
        is_secret_param = (
            isinstance(name, str)
            and SECRET_KEY_RE.match(name.strip())
            and name.strip().lower() not in SAFE_KEYS
        )
        out = {}
        for k, v in obj.items():
            here = f"{path}.{k}"
            if is_secret_param and k == "value" and isinstance(v, str) and not is_placeholder(v):
                findings.append(f"{here} (parameter '{name}')")
                out[k] = REDACTED
            elif (
                isinstance(k, str)
                and SECRET_KEY_RE.match(k)
                and k.lower() not in SAFE_KEYS
                and isinstance(v, str)
                and not is_placeholder(v)
            ):
                findings.append(here)
                out[k] = REDACTED
            else:
                out[k] = scrub_json(v, findings, here)
        return out
    if isinstance(obj, list):
        return [scrub_json(v, findings, f"{path}[{i}]") for i, v in enumerate(obj)]
    if isinstance(obj, str):
        return scrub_string(obj, findings, path)
    return obj


def scrub_text(text: str, findings: list[str], name: str) -> str:
    def repl(m: re.Match) -> str:
        value = m.group(3).strip()
        if is_placeholder(value):
            return m.group(0)
        findings.append(f"{name}: <{m.group(2)}>")
        return f"{m.group(1)}{REDACTED}{m.group(4)}"

    text = XML_ELEMENT_RE.sub(repl, text)
    return scrub_string(text, findings, name)


def sanitize_file(path: Path) -> tuple[str, list[str]]:
    findings: list[str] = []
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return scrub_text(raw, findings, "text"), findings
        cleaned = scrub_json(data, findings)
        return json.dumps(cleaned, indent=2, ensure_ascii=False) + "\n", findings
    return scrub_text(raw, findings, "text"), findings


CHECK_SUFFIXES = {".json", ".xml", ".conf", ".yml", ".yaml", ".txt", ".md"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "fixtures"}


def iter_files(paths: list[str]):
    for p in map(Path, paths):
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in CHECK_SUFFIXES and not (SKIP_DIRS & set(f.parts)):
                    yield f


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-o", "--output", help="output file (sanitise mode)")
    ap.add_argument("--check", action="store_true", help="only report, exit 1 on findings")
    args = ap.parse_args(argv)

    if args.check:
        total = 0
        for f in iter_files(args.paths):
            _, findings = sanitize_file(f)
            for item in findings:
                print(f"[SECRET?] {f}: {item}")
            total += len(findings)
        print(f"{total} finding(s)." if total else "OK: no secrets found.", file=sys.stderr)
        return 1 if total else 0

    if len(args.paths) != 1:
        ap.error("sanitise mode takes exactly one input file")
    cleaned, findings = sanitize_file(Path(args.paths[0]))
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(cleaned, encoding="utf-8")
    else:
        sys.stdout.write(cleaned)
    print(f"Redacted {len(findings)} value(s).", file=sys.stderr)
    for item in findings:
        print(f"  - {item}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
