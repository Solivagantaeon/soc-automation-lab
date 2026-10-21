import hashlib
import shutil
import string
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sanitize_export as se  # noqa: E402

try:
    from PIL import Image, ImageDraw, ImageFont, PngImagePlugin

    import check_images as ci  # noqa: E402
except ImportError:  # Pillow is installed in CI; locally: pip install pillow
    Image = None

B62 = string.ascii_letters + string.digits


def tok(seed: str, n: int = 32) -> str:
    out, i = "", 0
    while len(out) < n:
        out += "".join(B62[b % 62] for b in hashlib.sha256(f"{seed}{i}".encode()).digest())
        i += 1
    return out[:n]


def fake_uuid(seed: str) -> str:
    h = hashlib.md5(seed.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def rules(path: Path, ocr: bool = False) -> set:
    return {f.rule for f in ci.check_image(path, ocr, se.Allowlist(), [])}


@unittest.skipIf(Image is None, "Pillow not installed")
class MetadataTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_gps_camera_and_computer_name_are_found_and_stripped(self):
        exif = Image.Exif()
        exif[0x0110] = "Phone 9"  # camera model
        exif[0x013C] = "Jans-" + "MacBook-Pro"  # host computer, often contains a real name
        exif[0x8825] = {1: "N", 2: (52.0, 13.0, 30.0), 3: "E", 4: (21.0, 0.0, 10.0)}  # GPS
        path = self.dir / "photo.jpg"
        Image.new("RGB", (64, 48), (200, 200, 200)).save(path, exif=exif)

        self.assertEqual(rules(path), {"exif-gps-location", "exif-camera-model", "exif-host-computer"})
        self.assertEqual(ci.main(["--strip", str(path)]), 0)
        self.assertEqual(rules(path), set())
        self.assertEqual(Image.open(path).size, (64, 48))

    def test_png_text_chunks_are_scanned(self):
        info = PngImagePlugin.PngInfo()
        info.add_text("Author", "Jan " + "Kowalski")
        info.add_text("Comment", "sent by jan.kowalski" + "@" + "gmail.com")
        path = self.dir / "shot.png"
        Image.new("RGB", (64, 48), (10, 10, 10)).save(path, pnginfo=info)

        self.assertEqual(rules(path), {"metadata-author", "email"})
        ci.main(["--strip", str(path)])
        self.assertEqual(rules(path), set())

    def test_clean_image_passes(self):
        path = self.dir / "clean.png"
        Image.new("RGB", (64, 48), (255, 255, 255)).save(path)
        self.assertEqual(ci.main([str(path)]), 0)

    def test_ocr_required_but_missing_fails(self):
        path = self.dir / "clean.png"
        Image.new("RGB", (8, 8)).save(path)
        with mock.patch.object(ci.shutil, "which", return_value=None):
            self.assertEqual(ci.main(["--ocr", "--require-ocr", str(path)]), 2)


@unittest.skipIf(Image is None or shutil.which("tesseract") is None, "needs Pillow and tesseract")
class OcrTest(unittest.TestCase):
    """Text that is only visible in the pixels of a screenshot."""

    LINES = [
        "Webhook URI  https://shuffle.lab:3443/api/v1/hooks/webhook_" + fake_uuid("ocr"),
        "authorization: Bearer " + tok("ocr-bearer"),
        "Logged in as jan.kowalski" + "@" + "gmail.com",
        "WAN address " + ".".join(["83", "12", "145", "77"]) + " (DHCP)",
        "API key  " + tok("ocr-key", 40) + "   [Renew] [Reveal]",
    ]
    EXPECTED = {"shuffle-webhook-id", "authorization-header", "email", "public-ip", "labelled-secret"}

    def render(self, background, foreground) -> Path:
        font = ImageFont.load_default(size=18)
        img = Image.new("RGB", (1400, 40 + 36 * len(self.LINES)), background)
        draw = ImageDraw.Draw(img)
        for i, line in enumerate(self.LINES):
            draw.text((20, 20 + 36 * i), line, fill=foreground, font=font)
        path = Path(tempfile.mkdtemp()) / "screenshot.png"
        img.save(path)
        return path

    def test_dark_ui(self):
        found = rules(self.render((30, 30, 30), (220, 220, 220)), ocr=True)
        self.assertTrue(self.EXPECTED <= found, self.EXPECTED - found)

    def test_light_ui(self):
        found = rules(self.render((250, 250, 250), (40, 40, 40)), ocr=True)
        self.assertTrue(self.EXPECTED <= found, self.EXPECTED - found)


if __name__ == "__main__":
    unittest.main()
