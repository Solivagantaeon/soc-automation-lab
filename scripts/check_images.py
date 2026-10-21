#!/usr/bin/env python3
"""Check screenshots and other images for data that must not become public.

Usage:
  check_images.py [--ocr] [--require-ocr] PATH...   report findings, exit 1 if anything is found
  check_images.py --strip FILE...                   remove all metadata (EXIF, GPS, XMP, text) in place

Checks
  * metadata: GPS position, camera / owner / computer name, serial numbers, author fields
  * text stored inside the file (PNG text chunks, XMP, comments, EXIF text), scanned with the
    same secret and personal-data rules as sanitize_export.py
  * --ocr: the visible pixels are read with tesseract and scanned the same way, which catches
    API keys, webhook URLs, e-mails or public IPs that are visible in a screenshot

OCR is best effort: it reduces risk but cannot replace looking at a screenshot before uploading.
Needs Pillow (pip install pillow); --ocr also needs the tesseract program
(macOS: brew install tesseract, Ubuntu: sudo apt install tesseract-ocr, Windows: UB-Mannheim build).
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sanitize_export as se  # noqa: E402

try:
    from PIL import Image, ImageOps, ImageStat
except ImportError:  # pragma: no cover - reported in main()
    Image = None
    ImageOps = None
    ImageStat = None

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".tif", ".tiff", ".bmp"}
GPS_IFD = 0x8825
EXIF_IFD = 0x8769
IDENTIFYING_TAGS = {
    0x010F: "camera-make", 0x0110: "camera-model", 0x013B: "artist", 0x8298: "copyright",
    0x013C: "host-computer", 0xA430: "camera-owner", 0xA431: "body-serial", 0xA435: "lens-serial",
    0x9C9D: "xp-author",
}
TEXT_TAGS = {0x010E: "image-description", 0x9286: "user-comment", 0x9C9C: "xp-comment",
             0x9C9B: "xp-title", 0x9C9F: "xp-subject", 0x9C9E: "xp-keywords"}
IDENTIFYING_INFO_KEYS = {"author", "artist", "copyright", "creator", "owner", "host computer", "hostcomputer"}
SKIP_INFO_KEYS = {"icc_profile", "exif", "dpi", "gamma", "transparency", "duration", "loop", "background",
                  "aspect", "interlace", "srgb", "chromaticity", "progressive", "progression", "jfif",
                  "jfif_version", "jfif_unit", "jfif_density", "adobe", "adobe_transform", "compression",
                  "photoshop", "mp", "mpoffset"}
XMP_IDENTIFYING = re.compile(
    r"<(?P<tag>dc:creator|exifEX:CameraOwnerName|aux:SerialNumber|exifEX:BodySerialNumber|tiff:Artist"
    r"|exif:GPSLatitude|exif:GPSLongitude|photoshop:Credit|xmpRights:Owner)\b[^>]*>(?P<v>.*?)</(?P=tag)>",
    re.S,
)


def _text(value) -> str:
    if isinstance(value, bytes):
        if value[:8] in (b"ASCII\x00\x00\x00", b"UNICODE\x00", b"JIS\x00\x00\x00\x00\x00"):
            value = value[8:]
        if value.count(b"\x00") > len(value) // 4:  # UTF-16 (XP* tags)
            return value.decode("utf-16-le", errors="replace").replace("\x00", "")
        return value.decode("utf-8", errors="replace").replace("\x00", "")
    if isinstance(value, tuple) and all(isinstance(x, int) for x in value):  # XP* tags as int tuples
        return bytes(value).decode("utf-16-le", errors="replace").replace("\x00", "")
    return str(value)


def metadata_findings(img, scanner: se.Scanner) -> None:
    exif = img.getexif()
    if exif:
        if exif.get_ifd(GPS_IFD):
            scanner.add("PII", "exif-gps-location", "EXIF", "GPS position")
        for source in (exif, exif.get_ifd(EXIF_IFD)):
            for tag, value in source.items():
                text = _text(value).strip()
                if not text:
                    continue
                if tag in IDENTIFYING_TAGS:
                    scanner.add("PII", "exif-" + IDENTIFYING_TAGS[tag], "EXIF", text)
                elif tag in TEXT_TAGS:
                    scanner.text(text, lambda _p, n=TEXT_TAGS[tag]: f"EXIF {n}")
    for key, value in img.info.items():
        name = str(key).lower()
        if name in SKIP_INFO_KEYS or not isinstance(value, (str, bytes)):
            continue
        text = _text(value)
        if name in IDENTIFYING_INFO_KEYS and text.strip():
            scanner.add("PII", "metadata-" + name.replace(" ", "-"), f"metadata '{key}'", text.strip())
        for m in XMP_IDENTIFYING.finditer(text):
            inner = re.sub(r"<[^>]+>", " ", m.group("v")).strip()
            if inner:
                scanner.add("PII", "xmp-" + m.group("tag").split(":")[1].lower(), "XMP", inner)
        scanner.text(text, lambda _p, k=key: f"metadata '{k}'")


def ocr_text(img) -> str:
    """Read the visible text. Dark UIs (Wazuh, Shuffle) are inverted first: tesseract reads
    dark text on a light background far better. Mid-grey images are read both ways."""
    gray = ImageOps.exif_transpose(img).convert("L")
    mean = ImageStat.Stat(gray).mean[0]
    variants = [ImageOps.invert(gray)] if mean < 110 else [gray] if mean > 145 else [gray, ImageOps.invert(gray)]
    factor = 2 if max(gray.size) < 2400 else 1
    env = {**os.environ, "OMP_THREAD_LIMIT": "1"}  # we parallelise over files instead
    texts = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, variant in enumerate(variants):
            if factor > 1:
                variant = variant.resize((variant.width * factor, variant.height * factor), Image.LANCZOS)
            path = Path(tmp) / f"v{i}.png"
            variant.save(path)
            res = subprocess.run(["tesseract", str(path), "stdout", "--psm", "11"],
                                 capture_output=True, text=True, timeout=300, check=False, env=env)
            texts.append(res.stdout)
    return "\n".join(texts)


def strip_metadata(path: Path) -> None:
    with Image.open(path) as original:
        if getattr(original, "n_frames", 1) > 1:
            raise SystemExit(f"{path}: animated images are not supported - export a still image instead")
        fmt = original.format
        img = ImageOps.exif_transpose(original)
        clean = Image.frombytes(img.mode, img.size, img.tobytes())
        if img.mode == "P":
            clean.putpalette(img.getpalette())
        kwargs = {}
        if "transparency" in original.info:
            kwargs["transparency"] = original.info["transparency"]
    if fmt == "JPEG":
        kwargs.update(quality=95, subsampling=0)
    elif fmt == "PNG":
        kwargs["optimize"] = True
    clean.save(path, format=fmt, **kwargs)


def iter_images(paths):
    for p in map(Path, paths):
        if p.is_file():
            if p.suffix.lower() in IMAGE_SUFFIXES:
                yield p
        elif p.is_dir():
            files = se._git_files(p)
            if files is None:
                files = sorted(f for f in p.rglob("*") if f.is_file())
            for f in files:
                if f.is_file() and f.suffix.lower() in IMAGE_SUFFIXES and not (se.SKIP_DIRS & set(f.parts)):
                    yield f


def check_image(path: Path, ocr: bool, allow=None, local=None) -> list[se.Finding]:
    scanner = se.Scanner(scrub=False, allow=allow, local=local)
    with Image.open(path) as img:
        img.load()
        metadata_findings(img, scanner)
        if ocr:
            scanner.ocr_mode = True
            scanner.text(ocr_text(img), lambda _p: "OCR (visible text)")
    return scanner.findings


def _check_one(args):
    path, ocr, allow, local = args
    try:
        return path, check_image(path, ocr, allow, local), None
    except (OSError, SyntaxError, ValueError, subprocess.TimeoutExpired) as e:  # unreadable image
        return path, [], e


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--ocr", action="store_true", help="also read the visible text with tesseract")
    ap.add_argument("--require-ocr", action="store_true", help="fail if tesseract is missing (CI)")
    ap.add_argument("--strip", action="store_true", help="remove all metadata in place")
    ap.add_argument("--jobs", type=int, default=0, help="parallel OCR workers (default: CPU count)")
    args = ap.parse_args(argv)

    if Image is None:
        print("check_images.py needs Pillow: pip install pillow", file=sys.stderr)
        return 2
    files = list(iter_images(args.paths))

    if args.strip:
        for f in files:
            strip_metadata(f)
            print(f"metadata removed: {f}")
        return 0

    ocr = args.ocr and shutil.which("tesseract") is not None
    if args.ocr and not ocr:
        msg = "tesseract not found - OCR skipped (macOS: brew install tesseract; Ubuntu: apt install tesseract-ocr)"
        if args.require_ocr:
            print(msg, file=sys.stderr)
            return 2
        print(f"note: {msg}", file=sys.stderr)

    allow, local = se.load_allowlist(), se.load_local_denylist()
    todo = [f for f in files if not allow.file_reviewed(f)]
    total = 0
    with ThreadPoolExecutor(max_workers=args.jobs or os.cpu_count() or 2) as pool:
        for f, findings, error in pool.map(_check_one, [(f, ocr, allow, local) for f in todo]):
            if error is not None:
                print(f"{se._display(f)}: cannot read image ({error})")
                total += 1
                continue
            for line in se.report(findings):
                print(f"{se._display(f)}: {line}")
                total += 1
    if total:
        print(f"{total} finding(s).\n"
              "  * metadata -> python3 scripts/check_images.py --strip FILE\n"
              "  * visible secret / personal data -> crop or blur it and take a new screenshot;\n"
              "    if a real secret was pushed, ROTATE it (SECURITY.md)\n"
              "  * OCR misread -> add the value to .leakcheck-allow with a reason", file=sys.stderr)
        return 1
    reviewed = len(files) - len(todo)
    note = f" ({reviewed} reviewed by hash in {se.ALLOW_FILE})" if reviewed else ""
    print(f"OK: {len(todo)} image(s) checked{' with OCR' if ocr else ''}, nothing found{note}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
