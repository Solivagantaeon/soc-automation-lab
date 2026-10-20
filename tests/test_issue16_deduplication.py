import base64
import contextlib
import io
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / "soar" / "shuffle" / "workflows" / "soc-automation-v1.0.json"


class Issue16DeduplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = json.loads(WORKFLOW_PATH.read_text(encoding="utf-8"))
        cls.actions = {item["label"]: item for item in cls.workflow["actions"]}

    def action_parameter(self, label, parameter_name):
        action = self.actions[label]
        return next(
            parameter["value"]
            for parameter in action["parameters"]
            if parameter["name"] == parameter_name
        )

    def run_id_extractor(self, response):
        return self.run_id_extractor_text(json.dumps(response))

    def run_id_extractor_text(self, response_text):
        code = self.action_parameter("Extract_TheHive_Alert_ID", "code")
        encoded = base64.b64encode(
            response_text.encode("utf-8")
        ).decode("ascii")
        code = code.replace("{{ '$incident' | base64_encode }}", encoded)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(code, "<Shuffle action>", "exec"), {})
        return json.loads(output.getvalue())

    def test_extracts_single_id_from_successful_response_in_list(self):
        response = [
            {"status": 201, "body": {"_id": "~test-alert-1"}},
            {"status": 400, "body": {"type": "CreateError"}},
            {"status": 400, "body": {"type": "CreateError"}},
        ]

        result = self.run_id_extractor(response)

        self.assertEqual(
            {"valid": True, "alert_id": "~test-alert-1", "reason": "ok"},
            result,
        )

    def test_extracts_id_from_python_repr_response(self):
        response = repr(
            [{"status": 201, "body": {"_id": "~test-alert-1"}, "success": True}]
        )

        result = self.run_id_extractor_text(response)

        self.assertEqual("~test-alert-1", result["alert_id"])
        self.assertTrue(result["valid"])

    def test_rejects_ambiguous_multiple_successful_ids(self):
        response = [
            {"status": 201, "body": {"_id": "~test-alert-1"}},
            {"status": 201, "body": {"_id": "~test-alert-2"}},
        ]

        result = self.run_id_extractor(response)

        self.assertEqual("multiple_successful_alert_ids", result["reason"])
        self.assertIsNone(result["alert_id"])

    def test_repeated_copy_of_same_successful_id_is_unambiguous(self):
        response = [
            {"status": 201, "body": {"_id": "~test-alert-1"}},
            {"status": 201, "body": {"_id": "~test-alert-1"}},
        ]

        result = self.run_id_extractor(response)

        self.assertEqual(
            {"valid": True, "alert_id": "~test-alert-1", "reason": "ok"},
            result,
        )

    def test_cache_mapping_uses_dynamic_id_and_same_fingerprint(self):
        self.assertEqual(
            "$get_hash_sum.sha256",
            self.action_parameter("Save_TheHive_Alert_ID", "key"),
        )
        self.assertEqual(
            "$extract_thehive_alert_id.message.alert_id",
            self.action_parameter("Save_TheHive_Alert_ID", "value"),
        )
        self.assertEqual(
            "soc_thehive_ids_test",
            self.action_parameter("Save_TheHive_Alert_ID", "category"),
        )

    def test_duplicate_fingerprint_includes_tested_observable_fields(self):
        fingerprint = self.action_parameter("Get_Hash_sum", "value")
        self.assertEqual(
            [
                "$exec.all_fields.agent.id",
                "$exec.all_fields.rule.id",
                "$exec.all_fields.data.srcip",
                "$exec.all_fields.data.dstip",
                "$exec.all_fields.data.domain",
                "$exec.all_fields.data.win.eventdata.hashes",
            ],
            fingerprint.split("|"),
        )

    def test_patch_uses_the_cached_id_in_the_url(self):
        self.assertEqual(
            "https://thehive.example.invalid/api/v1/alert/"
            "$get_thehive_alert_id.value",
            self.action_parameter("PATCH_TheHive_Duplicate", "url"),
        )

    def test_id_cache_write_is_connected_after_create_and_valid_extraction(self):
        actions = {item["label"]: item["id"] for item in self.workflow["actions"]}
        edges = {
            (item["source_id"], item["destination_id"]): item
            for item in self.workflow["branches"]
        }

        self.assertIn(
            (actions["Incident"], actions["Extract_TheHive_Alert_ID"]),
            edges,
        )
        conditional_edge = edges[
            (
                actions["Extract_TheHive_Alert_ID"],
                actions["Save_TheHive_Alert_ID"],
            )
        ]
        check = conditional_edge["conditions"][0]
        self.assertEqual(
            "$extract_thehive_alert_id.message.valid",
            check["source"]["value"],
        )
        self.assertEqual("true", check["destination"]["value"])


if __name__ == "__main__":
    unittest.main()
