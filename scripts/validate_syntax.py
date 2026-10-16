#!/usr/bin/env python3
"""Check that every JSON, XML and YAML file in the repo parses. Exit 1 on the first broken file list."""
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", "node_modules", ".venv", "venv"}
errors = []

for f in sorted(ROOT.rglob("*")):
    if not f.is_file() or SKIP & set(f.parts):
        continue
    try:
        if f.suffix == ".json":
            json.loads(f.read_text(encoding="utf-8"))
        elif f.suffix == ".xml":
            ET.parse(f)
        elif f.suffix in {".yml", ".yaml"} and yaml:
            yaml.safe_load(f.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        errors.append(f"{f.relative_to(ROOT)}: {e}")

for e in errors:
    print(f"[INVALID] {e}")
print(f"{len(errors)} invalid file(s)." if errors else "OK: all JSON/XML/YAML files parse.")
sys.exit(1 if errors else 0)
