import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sanitize_export as se  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


class SanitizeJsonTest(unittest.TestCase):
    def setUp(self):
        self.out, self.findings = se.sanitize_file(FIX / "shuffle_export_with_fake_secrets.json")
        self.data = json.loads(self.out)

    def test_no_fake_secret_survives(self):
        for needle in ("FAKEcortexKEY", "FAKEtoken", "FAKEpass", "0f1e2d3c-4b5a"):
            self.assertNotIn(needle, self.out, needle)

    def test_shuffle_parameter_redacted(self):
        params = self.data["actions"][0]["parameters"]
        self.assertEqual(params[0]["value"], "REDACTED")

    def test_placeholders_and_refs_kept(self):
        self.assertEqual(self.data["actions"][1]["parameters"][0]["value"], "<THEHIVE_API_KEY>")
        self.assertEqual(self.data["actions"][0]["authentication_id"], "a1b2c3d4-auth-ref")
        self.assertEqual(self.data["org"]["token_type"], "bearer")
        self.assertEqual(self.data["actions"][0]["parameters"][1]["value"], "http://10.10.20.247:9001/cortex")

    def test_output_is_valid_and_clean_on_second_pass(self):
        tmp = FIX.parent / "_tmp_clean.json"
        try:
            tmp.write_text(self.out)
            _, again = se.sanitize_file(tmp)
            self.assertEqual(again, [])
        finally:
            tmp.unlink(missing_ok=True)


class SanitizeXmlTest(unittest.TestCase):
    def test_xml_elements_redacted(self):
        out, findings = se.sanitize_file(FIX / "ossec_with_fake_secrets.xml")
        self.assertNotIn("FAKEapikey", out)
        self.assertNotIn("0f1e2d3c", out)
        self.assertIn("<rule_id>86601</rule_id>", out)
        self.assertGreaterEqual(len(findings), 2)

    def test_repo_snippet_with_placeholder_is_clean(self):
        _, findings = se.sanitize_file(ROOT / "detection/wazuh/integrations/shuffle-integration.xml")
        self.assertEqual(findings, [])


class CheckModeTest(unittest.TestCase):
    def test_check_fails_on_fixtures_and_passes_on_repo_content(self):
        self.assertEqual(se.main(["--check", str(FIX / "ossec_with_fake_secrets.xml")]), 1)
        dirs = [str(ROOT / d) for d in ("soar", "detection", "enrichment", "case-management", "samples")]
        self.assertEqual(se.main(["--check", *dirs]), 0)


if __name__ == "__main__":
    unittest.main()
