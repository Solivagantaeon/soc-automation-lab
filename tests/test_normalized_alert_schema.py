
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_FILE = ROOT / "soar/shuffle/schema/normalized-alert.schema.json"
SAMPLE_FILE = ROOT / "soar/shuffle/samples/alerts/normalized-alert-example.json"


class NormalizedAlertSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        cls.sample = json.loads(SAMPLE_FILE.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(
            cls.schema,
            format_checker=FormatChecker()
        )

    def test_normalized_alert_is_valid(self):
        errors = list(self.validator.iter_errors(self.sample))
        self.assertEqual(
            errors,
            [],
            "\n".join(error.message for error in errors)
        )

    def test_sha256_with_wrong_length_is_rejected(self):
        alert = json.loads(json.dumps(self.sample))
        hash_observable = next(
            item for item in alert["observables"]
            if item.get("type") == "hash"
        )
        hash_observable["algorithm"] = "sha256"
        hash_observable["value"] = "a" * 32

        errors = list(self.validator.iter_errors(alert))
        self.assertTrue(
            errors,
            "A 32-character value must not be accepted as SHA256."
        )

    def test_unknown_observable_type_is_rejected(self):
        alert = json.loads(json.dumps(self.sample))
        alert["observables"].append({
            "type": "unknown",
            "value": "test"
        })

        errors = list(self.validator.iter_errors(alert))
        self.assertTrue(
            errors,
            "Unknown observable types must be rejected."
        )


if __name__ == "__main__":
    unittest.main()
