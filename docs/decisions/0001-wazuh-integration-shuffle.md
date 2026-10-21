# ADR 0001 – Wazuh → Shuffle integration: transport, TLS and alert filter

- **Status:** Accepted
- **Date:** 2026-10-19
- **Issue:** #7 – [Z2] Wazuh and IDS → Shuffle: webhook

## Context

Alerts from Wazuh and the IDS (Suricata) must reach Shuffle automatically and start a workflow execution.

State found on 2026-10-19 on `wazuh-master` (Wazuh 4.14.9, 10.10.20.243):

- `ossec.conf` contained **two** `<integration name="shuffle">` blocks:
  1. `https://shuffle.lab:3443/.../webhook_bfb744a3…`, `<level>3</level>` – every call failed with `CERTIFICATE_VERIFY_FAILED: self-signed certificate`.
  2. `http://10.10.20.245:3001/.../webhook_8f08eeb6…`, `<rule_id>86601,31103,31105,31106</rule_id>` – no errors, but none of these rules fired.
- The current Shuffle workflow listens on a **third** webhook (`webhook_9c7f89d1…`), referenced by neither block. Result: no Wazuh alert reached the workflow; only manual `curl -k` tests did (`-k` skips certificate verification, so those tests did not prove TLS worked).
- Shuffle serves a self-signed certificate: `CN=shuffle.lab`, SAN `DNS:shuffle.lab, IP:10.10.20.245`, valid until 2029-01-12, SHA-256 `3B:1A:53:2F:6E:6F:C4:70:38:C6:5F:05:B2:81:C2:D7:DF:90:A3:20:26:54:08:4F:AD:ED:4B:16:50:DD:BF:68`.
- The integration script (`/var/ossec/integrations/shuffle.py`) runs on Wazuh's bundled Python and verifies TLS against that Python's `certifi` bundle, **not** the OS trust store. Verification against that bundle returned `18 (self-signed certificate)`.

## Decisions

### 1. Transport: HTTPS to `shuffle.lab:3443`, Shuffle certificate trusted by the manager

The Shuffle certificate was appended to
`/var/ossec/framework/python/lib/python3.10/site-packages/certifi/cacert.pem`
(backup: `cacert.pem.bak-2026-10-19`).

After the change: `openssl s_client … -CAfile <certifi>` → `0 (ok)`, and a POST from Wazuh's Python without disabling verification returned `{"success": true, "execution_id": …}`.

**Rejected – plain HTTP inside the SOC VLAN (port 3001):** the same webhook returned `{"success": false}` over `http://10.10.20.245:3001` while returning `success: true` over HTTPS, so that path does not work for this webhook. It would also send alert content unencrypted.

**Rejected – disabling verification in `shuffle.py`:** removes the protection TLS is there for and would be lost on the next package update anyway.

### 2. Filter: `<level>3</level>` (all alerts Wazuh logs), not a `rule_id` list

All base Wazuh alerts are sent to Shuffle. `log_alert_level` is 3, so `level 3` means "every alert Wazuh records". Filtering, deduplication, scoring and enrichment are done in the Shuffle workflow – that is the subject of the project ("alert reduction"), and keeping it in one place makes it visible and testable.

A `rule_id` allow-list was rejected because it silently drops every detection not on the list (exactly what happened with block 2 above) and must be maintained by hand whenever rules change.

Wazuh filters (`level`, `rule_id`, `group`) are combined with AND, so they must not be mixed in one block by accident.

The only rules dropped before Shuffle are the hard-coded `SKIP_RULE_IDS` in `shuffle.py` (879xx Docker events, to avoid self-recursion when Shuffle starts containers).

### 3. One integration block, one webhook

The two old blocks were removed and replaced with a single block pointing at the workflow's webhook (`detection/wazuh/integrations/shuffle-integration.xml`, URL as placeholder). The real webhook URL is kept only on the server.

### 4. IDS path: Suricata → Wazuh → Shuffle (not IDS → Shuffle directly)

Suricata runs on OPNsense (interface `vlan01`). The Wazuh agent on OPNsense ships `eve.json`, and Wazuh raises rule 86601 for every Suricata alert, which then follows decision 2. This gives one entry point into Shuffle, a uniform payload format, and Wazuh context (agent, rule, MITRE mapping) on IDS alerts.

The project document shows IDS → Shuffle directly. **Pending: confirmation from the instructor that this deviation is acceptable.**

## Consequences

- **Trust is stored in a file owned by the Wazuh package.** A Wazuh upgrade can replace `certifi/cacert.pem` and break the integration with the same `CERTIFICATE_VERIFY_FAILED` error. The runbook contains the re-apply and verify steps.
- The certificate expires on 2029-01-12. If Shuffle's certificate is replaced, the new one must be trusted the same way.
- Every alert of level ≥ 3 reaches Shuffle, including noisy ones (e.g. Sysmon 92910 OneDrive → explorer.exe every 30 min, Suricata `ET INFO … APT User-Agent`). Enrichment nodes must run only where needed (new alerts with an IP/hash), otherwise external API quotas are consumed quickly. Noise reduction is handled in later issues.
- The manager log (`ossec.log`) prints the full webhook URL on every integration error – redact before sharing logs or screenshots.
