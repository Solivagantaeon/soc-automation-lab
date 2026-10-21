import hashlib
import json
import string
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sanitize_export as se  # noqa: E402

FIX = Path(__file__).parent / "fixtures"

# Fake secrets are generated at run time, so no scanner (ours, gitleaks, GitHub) ever sees a
# literal token in this file.
B62 = string.ascii_letters + string.digits


def tok(seed: str, n: int = 32) -> str:
    out, i = "", 0
    while len(out) < n:
        out += "".join(B62[b % 62] for b in hashlib.sha256(f"{seed}{i}".encode()).digest())
        i += 1
    return out[:n]


def hexs(seed: str, n: int = 64) -> str:
    return (hashlib.sha256(seed.encode()).hexdigest() * 4)[:n]


def fake_uuid(seed: str) -> str:
    h = hashlib.md5(seed.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# A made-up "home" address, also assembled at run time.
HOME_IP = ".".join(["83", "12", "145", "77"])
HOME_IP6 = ":".join(["2a01", "4f8", "1c1c", "", "1"])


def scan(text: str, scrub: bool = False, **kw):
    sc = se.Scanner(scrub=scrub, allow=kw.pop("allow", se.Allowlist()), local=kw.pop("local", []), **kw)
    out = sc.text(text, lambda pos: f"pos {pos}")
    return out, sc.findings


# --------------------------------------------------------------------------- original tests


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
    def test_check_fails_on_fixtures(self):
        self.assertEqual(se.main(["--check", str(FIX / "ossec_with_fake_secrets.xml")]), 1)

    def test_whole_repository_is_clean(self):
        """The same check CI runs: nothing in the repository may be reported."""
        self.assertEqual(se.main(["--check", str(ROOT)]), 0)


# --------------------------------------------------------------------------- secrets


SECRET_CASES = {
    # the real leak of PR #45: TheHive key hard-coded in a Shuffle http node
    "shuffle-http-headers": lambda: "authorization: Bearer " + tok("thehive"),
    "misp-raw-authorization": lambda: "Authorization: " + tok("misp", 40),
    "virustotal-header": lambda: "x-apikey: " + hexs("vt"),
    "abuseipdb-header-in-json-string": lambda: "Content-Type: application/json\\nKey: " + hexs("abuse", 80),
    "url-query-key": lambda: "https://api.example.com/v1/check?apikey=" + tok("q", 24),
    "url-credentials": lambda: "https://admin:" + "S3cr3t" + "Pass@thehive.lab/thehive",
    "webhook-url": lambda: "https://shuffle.lab:3443/api/v1/hooks/webhook_" + fake_uuid("wh"),
    "webhook-tmp-parameter": lambda: "webhook_" + fake_uuid("tmp"),
    "jwt": lambda: "eyJ" + tok("h", 20) + ".eyJ" + tok("p", 30) + "." + tok("s", 30),
    "private-key": lambda: "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + tok("k", 64)
    + "\n-----END OPENSSH " + "PRIVATE KEY-----",
    "wireguard": lambda: "[Interface]\nPrivateKey = " + tok("wg", 43) + "=",
    "proxmox-token": lambda: "Authorization: PVEAPIToken=root@pam!ci=" + fake_uuid("pve"),
    "bcrypt-hash": lambda: "admin:" + "$2y$12$" + tok("bc", 53).replace("_", "."),
    "ntlm-hash": lambda: "Administrator:500:" + hexs("lm", 32) + ":" + hexs("nt", 32) + ":::",
    "wazuh-client-keys": lambda: "007 SOC-WIN10-01 any " + hexs("agent"),
    "xml-password": lambda: "<" + "password>" + "Lab" + "Pass2026!" + "</" + "password>",
    "opnsense-privkey": lambda: "<" + "privkey>" + tok("opn", 43) + "=</" + "privkey>",
    "env-assignment": lambda: "MISP_ADMIN_PASSPHRASE=" + "Very" + "Secret123",
    "yaml-assignment": lambda: "indexer:\n  password: " + "Hunter" + "2hunter2",
    "powershell-assignment": lambda: "$Password = '" + "Lab" + "Pass2026!'",
    "curl-basic": lambda: "curl -k -u admin:" + "Pa55" + "word! https://wazuh.lab:55000",
    "github-token": lambda: "token " + "ghp_" + tok("gh", 36),
    "aws-key": lambda: "AKIA" + "".join(c for c in tok("aws", 64).upper() if c.isalnum())[:16],
    "cookie": lambda: "Cookie: session=" + tok("ck", 32),
}


class SecretRulesTest(unittest.TestCase):
    def test_each_secret_is_found_and_removed(self):
        for name, make in SECRET_CASES.items():
            with self.subTest(name):
                text = make()
                _, findings = scan(text)
                self.assertTrue([f for f in findings if f.kind == "SECRET"], f"not found: {name}")
                cleaned, _ = scan(text, scrub=True)
                _, again = scan(cleaned)
                self.assertEqual([f for f in again if f.kind == "SECRET"], [], f"not removed: {name}")

    def test_secret_value_is_never_printed(self):
        secret = tok("print")
        _, findings = scan("authorization: Bearer " + secret)
        for f in findings:
            self.assertNotIn(secret[:6], str(f))

    def test_webhook_id_becomes_zero_uuid(self):
        cleaned, _ = scan("webhook_" + fake_uuid("z"), scrub=True)
        self.assertEqual(cleaned, "webhook_" + se.ZERO_UUID)


NOT_SECRETS = [
    "Authorization: Bearer <THEHIVE_API_KEY>",
    "Authorization: Bearer $thehive_api_key",
    "authorization: Bearer REDACTED",
    "Content-Type: application/json\\nAccept: application/json",
    "Managed by JWT bearer authorization",
    "HTTP Basic authentication is disabled",
    "token_type: bearer",
    "password: <WAZUH_API_PASSWORD>",
    "WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD}",
    "webhook_00000000-0000-0000-0000-000000000000",
    '"sha256": "' + hexs("file") + '"',
    '"key": "$get_hash_sum.sha256"',
    '"key": "dupcount_$get_hash_sum.sha256"',
    "MISP_VERIFY_TLS=false",
    "api_key_header: X-API-Key",
    "Agent version 4.14.9, Windows 10.0.19045.6456",
    "curl -sk -X POST https://shuffle.lab:3443/api/v1/hooks/webhook_<id>",
    "mysql -u root -p",
]


class FalsePositiveTest(unittest.TestCase):
    def test_ordinary_text_is_not_a_secret(self):
        for text in NOT_SECRETS:
            with self.subTest(text):
                _, findings = scan(text)
                self.assertEqual([str(f) for f in findings], [])

    def test_code_assignments_are_not_secrets(self):
        sc = se.Scanner(scrub=False, allow=se.Allowlist(), local=[])
        sc.code_mode = True
        sc.text('secret = m.group("s")\ntoken = self.next_token\n', lambda p: "x")
        self.assertEqual(sc.findings, [])

    def test_hard_coded_literal_in_code_is_a_secret(self):
        sc = se.Scanner(scrub=False, allow=se.Allowlist(), local=[])
        sc.code_mode = True
        sc.text('password = "' + "Lab" + 'Pass2026!"\n', lambda p: "x")
        self.assertEqual([f.rule for f in sc.findings], ["assignment-secret"])


# --------------------------------------------------------------------------- personal data


class PersonalDataTest(unittest.TestCase):
    def test_public_ip_found_and_mapped_to_documentation_range(self):
        text = f"src_ip {HOME_IP} dst {HOME_IP} and {HOME_IP6}"
        cleaned, findings = scan(text, scrub=True)
        self.assertEqual({f.rule for f in findings}, {"public-ip"})
        self.assertNotIn(HOME_IP, cleaned)
        self.assertIn("203.0.113.10", cleaned)
        self.assertEqual(cleaned.count("203.0.113.10"), 2, "the same IP must map to the same address")

    def test_private_documentation_and_resolver_ips_are_fine(self):
        _, findings = scan("10.10.20.243 192.168.1.1 203.0.113.5 198.51.100.7 8.8.8.8 2001:db8::1 ::1 "
                           "fe80::1 8.8.8.0/24")
        self.assertEqual(findings, [])

    def test_email(self):
        real = "jan.kowalski" + "@" + "gmail.com"
        cleaned, findings = scan(f"owner: {real}", scrub=True)
        self.assertEqual([f.rule for f in findings], ["email"])
        self.assertIn("user1@example.com", cleaned)
        _, ok = scan("admin@admin.test user@example.com git@github.com logo@2x.png "
                     "117302339+someone@users.noreply.github.com")
        self.assertEqual(ok, [])

    def test_home_paths(self):
        cleaned, findings = scan("/Users/" + "jkowalski/Downloads and C:\\\\Users\\\\" + "akowalska\\\\Desktop",
                                 scrub=True)
        self.assertEqual(sorted(f.value for f in findings), ["akowalska", "jkowalski"])
        self.assertIn("/Users/<user>/Downloads", cleaned)
        _, ok = scan("C:\\Users\\Administrator\\AppData /home/runner/work /home/socadmin C:\\Users\\user01")
        self.assertEqual(ok, [])

    def test_keep_pii_still_removes_secrets(self):
        sc = se.Scanner(scrub=True, keep_pii=True, allow=se.Allowlist(), local=[])
        out = sc.text(HOME_IP + " authorization: Bearer " + tok("k"), lambda p: "x")
        self.assertIn(HOME_IP, out)
        self.assertIn("Bearer REDACTED", out)

    def test_allowlist(self):
        allow = se.Allowlist(networks=[se.ipaddress.ip_network("50.16.16.211/32")])
        _, findings = scan("IOC 50.16.16.211", allow=allow)
        self.assertEqual(findings, [])

    def test_local_denylist(self):
        private = "MyRouter" + "Pass77"
        cleaned, findings = scan(f"note: {private.lower()} here", scrub=True, local=[private])
        self.assertEqual([f.kind for f in findings], ["LOCAL"])
        self.assertNotIn(private.lower(), cleaned)
        self.assertNotIn(private[:4], str(findings[0]))


# --------------------------------------------------------------------------- Shuffle exports


def shuffle_export() -> dict:
    wid = fake_uuid("trigger")
    return {
        "name": "SOC Automation",
        "owner": "jan.kowalski" + "@" + "gmail.com",
        "workflow_variables": [{"name": "thehive_key", "value": tok("var")}],
        "triggers": [{
            "id": wid, "app_name": "Webhook", "trigger_type": "WEBHOOK",
            "parameters": [
                {"name": "url", "value": "REDACTED_WEBHOOK_URL"},
                {"name": "tmp", "value": "webhook_" + wid},
                {"name": "auth_headers", "value": "X-Hook-Token: " + tok("hdr")},
            ],
        }],
        "branches": [{"source_id": wid, "destination_id": "alert-in"}],
        "actions": [{
            "id": "alert-in", "app_name": "http", "label": "PATCH_TheHive",
            "parameters": [{"name": "headers", "value": "authorization: Bearer " + tok("th")}],
        }],
    }


class ShuffleExportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()) / "workflow.json"
        self.tmp.write_text(json.dumps(shuffle_export()))

    def test_check_reports_the_webhook_trigger_and_secrets(self):
        _, findings = se.sanitize_file(self.tmp, scrub=False)
        rules = {f.rule for f in findings}
        for rule in ("shuffle-webhook-trigger-id", "shuffle-webhook-auth-headers",
                     "shuffle-workflow-variable", "authorization-header"):
            self.assertIn(rule, rules)

    def test_sanitise_replaces_the_id_everywhere_and_is_clean(self):
        out, _ = se.sanitize_file(self.tmp)
        data = json.loads(out)
        new_id = data["triggers"][0]["id"]
        self.assertTrue(new_id.startswith(se.ZERO_UUID_PREFIX))
        self.assertEqual(data["branches"][0]["source_id"], new_id, "branches must still point at the trigger")
        self.assertEqual(data["triggers"][0]["parameters"][1]["value"], "webhook_" + new_id)
        self.assertEqual(data["owner"], "")
        clean = self.tmp.with_name("clean.json")
        clean.write_text(out)
        self.assertEqual(se.sanitize_file(clean, scrub=False)[1], [])

    def test_reviewed_file_hash_is_skipped(self):
        allow_dir = self.tmp.parent
        (allow_dir / se.ALLOW_FILE).write_text(f"sha256:{se.file_sha256(self.tmp)}  workflow.json  # test\n")
        allow = se.Allowlist(hashes={se.file_sha256(self.tmp)})
        self.assertTrue(allow.file_reviewed(self.tmp))
        self.tmp.write_text(self.tmp.read_text() + " ")
        self.assertFalse(allow.file_reviewed(self.tmp), "a changed file must be checked again")


# --------------------------------------------------------------------------- git history


class CommitCheckTest(unittest.TestCase):
    """A secret added in one commit and removed in the next is still public on GitHub."""

    def git(self, *args):
        import subprocess
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com",
                               "-c", "commit.gpgsign=false", *args],
                              cwd=self.repo, check=True, capture_output=True, text=True).stdout.strip()

    def setUp(self):
        import shutil as _sh
        if _sh.which("git") is None:
            self.skipTest("git not installed")
        self.repo = Path(tempfile.mkdtemp())
        self.git("init", "-q", "-b", "main")
        (self.repo / "README.md").write_text("lab\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "init")
        self.base = self.git("rev-parse", "HEAD")
        conf = self.repo / "headers.txt"
        conf.write_text("authorization: Bearer " + tok("history") + "\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "add headers")
        self.leaky = self.git("rev-parse", "HEAD")
        conf.write_text("authorization: Bearer <THEHIVE_API_KEY>\n")
        self.git("commit", "-q", "-am", "remove the key again")

    def run_check(self, allow: se.Allowlist) -> int:
        import os
        old = os.getcwd()
        os.chdir(self.repo)
        try:
            return se.check_commits(f"{self.base}..HEAD", allow, [])
        finally:
            os.chdir(old)

    def test_removed_secret_is_still_found(self):
        self.assertEqual(se.main(["--check", str(self.repo / "headers.txt")]), 0, "current file is clean")
        self.assertEqual(self.run_check(se.Allowlist()), 1, "but the history is not")

    def test_acknowledged_commit_is_skipped(self):
        self.assertEqual(self.run_check(se.Allowlist(commits={self.leaky[:12]})), 0)


if __name__ == "__main__":
    unittest.main()
