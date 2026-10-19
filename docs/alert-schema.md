# Alert normalization and observable extraction

## Purpose

The Shuffle workflow normalizes incoming alerts into a common structure used by later enrichment, scoring, deduplication and TheHive integration steps.

The normalized structure preserves the original alert for traceability while extracting common fields and typed observables for downstream processing.

The confirmed inputs currently include Wazuh alerts, Suricata events wrapped by Wazuh, Sysmon events delivered through Wazuh, and a synthetic web-server alert format.

## Workflow

Current main processing flow:

`Webhook → Alert IN → Normalize Alert → NEW ALERT → MISP 1`

The workflow also contains validation and enrichment branches for IP addresses, hashes and domains.

## Normalized alert schema

The `Normalize Alert` node returns a JSON object with a `message` containing the normalized alert.

| Field | Description |
|---|---|
| `source` | Alert source; `wazuh` for Wazuh inputs and the input source for the supported synthetic web alert |
| `timestamp` | Alert timestamp normalized to ISO 8601 UTC when available |
| `hostname` | Wazuh agent hostname, Sysmon computer name or supported web alert host |
| `agent_id` | Wazuh agent ID, when present |
| `source_alert_id` | Original alert ID, when present |
| `rule_id` | Original rule ID |
| `alert_type` | List of alert categories derived from rule groups or the web event type |
| `severity` | Common severity value |
| `severity_source` | Source used for severity mapping |
| `wazuh_level` | Original Wazuh rule level, when present |
| `description` | Alert description or message |
| `ip` | List of extracted IP observables |
| `user` | Username, when present |
| `observables` | Typed observable objects |
| `original_alert` | Original incoming alert retained for traceability |

The normalizer supports Wazuh alerts whose fields are provided directly and alerts whose Wazuh fields are nested inside `all_fields`.

For Suricata events wrapped by Wazuh, the normalizer extracts `src_ip` and `dest_ip` from the event data. Standard Wazuh `srcip` fields are also supported.

For Sysmon events delivered through Wazuh, the normalizer extracts supported fields from `data.win.eventdata`, including the user and file hashes. The hostname and timestamp can also be obtained from nested Windows event system fields when available.

For the supported synthetic web alert format, the normalizer extracts the client IP from `client.ip`, the domain from `http.host`, and the host name from `host`.

### Observable format

Observables use typed objects:

- IP: `{"type": "ip", "value": "..."}`
- Domain: `{"type": "domain", "value": "..."}`
- Hash: `{"type": "hash", "algorithm": "...", "value": "..."}`

The normalizer extracts domain values from the alert's domain field or, when available, the DNS question name. It can also use the Sysmon `destinationHostname` field and the supported web alert's `http.host`.

It recognizes MD5, SHA1, SHA256 and SHA512 hashes from the supported Sysmon event-data hash string format. Hash algorithms are normalized to lowercase, and hash values are converted to lowercase hexadecimal.

The `ip` field contains the extracted IP addresses as a list. The original alert is retained so later workflow steps can access source-specific fields when required.

### Severity mapping

For Wazuh alerts, the `Normalize Alert` node maps the original `rule.level` to a common severity scale from 1 to 5.

| Wazuh rule level | Normalized severity | Meaning |
|---|---:|---|
| 0–3 | 1 | Informational / lowest priority |
| 4–6 | 2 | Low |
| 7–9 | 3 | Medium |
| 10–11 | 4 | High |
| 12 and above | 5 | Critical / highest priority |

The original Wazuh level is retained in `wazuh_level`, and `severity_source` is set to `wazuh_level` to preserve traceability.

For the supported synthetic web alert format, textual rule severity is mapped using a project-defined mapping:

| Web rule severity | Normalized severity |
|---|---:|
| `low` | 2 |
| `medium` / `moderate` | 3 |
| `high` | 4 |
| `critical` | 5 |

This mapping is a project-defined normalization policy, not an official Wazuh or web-server severity classification. If the severity is missing or invalid, the normalized severity is `null`. If the Wazuh rule level is missing or invalid, `wazuh_level` is `null`.

## Validation

### Public IPv4

The `Validate Public IP` node reads an IP address from the normalized alert's original payload.

It accepts only globally routable IPv4 addresses. Private, reserved, documentation and invalid addresses are rejected.

Output fields:

- `valid`
- `ip`
- `reason`

A valid address returns `reason: "public_ipv4"`. Rejected addresses return an empty `ip` and a reason describing the rejection.

### File hashes

The `Validate Hash` node extracts hashes from the normalized alert's `observables` list. It recognizes MD5, SHA1, SHA256 and SHA512, validates the expected hexadecimal length and format, and removes duplicate hashes.

When multiple valid hashes are present, the node selects one hash for downstream VirusTotal and Team Cymru analysis using the following priority:

1. SHA256
2. SHA1
3. MD5
4. SHA512

The `hashes` field retains all valid, unique hashes. The `hash` and `algorithm` fields identify the selected hash.

Output fields:

- `valid`
- `hash`
- `algorithm`
- `hashes`
- `count`
- `reason`

A successful validation returns `reason: "valid_hashes_found"`. If no valid hashes are found, `valid` remains `false` and `reason` is `"no_valid_hashes"`. Unexpected processing errors return `reason: "validation_error"`.

### Domains

The `Validate Domain` node checks the domain supplied by the alert, with a fallback to the DNS question name when available. It rejects IP literals, malformed domains and configured internal/test suffixes.

Output fields:

- `valid`
- `domain`
- `reason`

## MISP lookup

The `MISP 1` node sends a POST request to the MISP attribute REST search endpoint using JSON input.

The current workflow references the normalized `ip` field using the Shuffle expression:

`$normalize_alert.message.ip.#`

This field represents a list of extracted IP addresses. Shuffle may treat list values as collections, so the request body and branch behavior must be verified to ensure the intended IP value is passed to MISP.

The IP validation node is separate from the main MISP path. The MISP branch should not be assumed to enforce public-IP validation unless that validation is explicitly connected to the path or implemented in the request preparation logic.

An empty attribute list is a valid lookup result and means that no matching attributes were returned. An unsuccessful request, malformed request body or skipped branch must not be interpreted as a negative IOC match.

Private, reserved and documentation-range addresses must not be submitted to external analyzers.

## Testing evidence

### Existing validation checks

The workflow and validation logic have previously been checked with synthetic test data.

- The public IP validator rejected `198.51.100.25`, a documentation-range address.
- The public IP validator accepted `8.8.8.8` and returned `reason: "public_ipv4"`.
- The MISP request body was updated during testing to use normalized alert data rather than the obsolete `$exec.all_fields` reference.
- The MISP endpoint returned HTTP 200 with an empty `Attribute` list for a lookup that returned no matching attributes.
- During testing, an invalid request body was reported as `MISP body missing or invalid JSON`. The request body was subsequently adjusted and the MISP endpoint returned a successful response.

### Suricata alert wrapped by Wazuh

**Status: PASS — manual execution**

The `Normalize Alert` node was manually executed using a Wazuh alert containing Suricata EVE event data nested inside `all_fields`.

The actual output confirmed the following values:

| Field | Observed result |
|---|---|
| `source` | `wazuh` |
| `timestamp` | `2026-10-19T01:44:35.126Z` |
| `hostname` | `opnsense` |
| `agent_id` | `005` |
| `source_alert_id` | `1792374275.233682` |
| `rule_id` | `86601` |
| `alert_type` | `["ids", "suricata"]` |
| `wazuh_level` | `3` |
| `severity` | `1` |
| `description` | `Suricata: Alert - ET INFO Packed Executable Download` |

The normalizer extracted both the source and destination IP addresses into `ip` and `observables`:

- `77.111.102.201`
- `10.10.10.171`

The timestamp was converted from the original `+0200` offset to UTC. The result matched the configured severity mapping for Wazuh rule level 3.

Evidence artifact:

`soar/shuffle/samples/alerts/normalized-suricata-wazuh-output.json`

This test confirms normalization of this Suricata event in a Wazuh wrapper. It does not confirm support for raw Suricata EVE JSON.

### Sysmon alert delivered through Wazuh

**Status: PASS — manual execution**

The `Normalize Alert` node was manually executed using a Wazuh alert generated from Sysmon Event ID 7.

The output confirmed the following values:

| Field | Observed result |
|---|---|
| `source` | `wazuh` |
| `timestamp` | `2026-10-19T08:34:26.744Z` |
| `hostname` | `SOC-WIN10-01` |
| `agent_id` | `007` |
| `source_alert_id` | `1792398866.567750` |
| `rule_id` | `92154` |
| `alert_type` | `["sysmon", "sysmon_eid7_detections", "windows"]` |
| `wazuh_level` | `4` |
| `severity` | `2` |
| `user` | `ZARZĄDZANIE NT\\SYSTEM` |

The normalizer extracted three valid file hashes from `data.win.eventdata.hashes`:

- SHA1: `633c92f5a5000cde3235c7fdc306b2b04c501c48`
- MD5: `84f942c1a4bd60c94ebec6643e0216c9`
- SHA256: `bbe733452e6ce871d5d2064948847aab2a71f7feda2c962ba4002f64e2d198f2`

No IP observables were present in this particular event, which is consistent with the available event data.

The test also confirmed that the Wazuh input was successfully parsed and retained in `original_alert`.

Evidence artifact:

`soar/shuffle/samples/alerts/normalized-sysmon-wazuh-output.json`

This test confirms normalization of a Sysmon Event ID 7 alert delivered through Wazuh. It does not confirm support for raw Sysmon events sent directly to Shuffle.

### Synthetic web alert

**Status: PASS — manual execution**

The `Normalize Alert` node was manually executed using the synthetic `web.json` sample. The sample represents an illustrative web alert and is not a vendor-specific raw access log.

The output confirmed the following values:

| Field | Observed result |
|---|---|
| `source` | `web_server` |
| `timestamp` | `2026-10-18T12:12:00.000Z` |
| `hostname` | `SOC-LAB-WEB01` |
| `rule_id` | `WEB-LAB-001` |
| `alert_type` | `["http_access"]` |
| `severity` | `3` |
| `severity_source` | `web_rule_severity` |
| `ip` | `["192.0.2.40"]` |

The normalizer extracted the client IP and HTTP host as typed observables:

- IP: `192.0.2.40`
- Domain: `web.example.test`

The public IP validator rejected `192.0.2.40` with `reason: "not_public_ipv4"`. The domain validator rejected `web.example.test` with `reason: "internal_domain"`. These are expected results because the sample uses documentation and test values.

The sample does not establish support for raw web-server logs from a specific vendor.

Evidence artifact:

`soar/shuffle/samples/alerts/normalized-web-output.json`

### CI checks

The GitHub Actions run `Create test_normalized_alert_schema.py #16` on `main` completed successfully, including the secret scan and the sanitization, syntax and unit-test job.

This confirms that the checks passed for that run and commit. It does not establish that every subsequent feature-branch change has passed CI.

Additional test evidence and sanitized workflow exports are stored under `samples/results/normalized/` and `soar/shuffle/workflows/` when available.

## Security and privacy

- Use synthetic or anonymized alerts in repository samples.
- Replace real external IP addresses with RFC 5737 documentation ranges in committed examples.
- Never commit API keys, authentication headers, cookies or other secrets.
- Do not send private or reserved IP addresses to external analyzers.
- The normalization stage may retain private IP addresses as observables; downstream validation must prevent them from being submitted to external analysis services.
- Evidence artifacts should contain only the normalized fields needed to demonstrate test results. Avoid committing full original alerts if they include sensitive host, user or infrastructure information.
- Do not treat an empty MISP response as proof that an IOC is benign.
- Keep MISP credentials, authentication headers and session cookies out of source code, workflow exports and test artifacts.

## Known limitations and next steps

- The confirmed manual tests cover a Suricata alert wrapped by Wazuh, a Sysmon Event ID 7 alert delivered through Wazuh, and a synthetic web alert.
- Raw Suricata EVE JSON, raw Sysmon events and vendor-specific raw web-server logs have not been confirmed by the manual tests described above.
- The `ip` field is a list. The current MISP expression `$normalize_alert.message.ip.#` should be checked to ensure that the intended single IP value is passed to the request body.
- The MISP path and the public IP validator are separate. Public-IP validation must be enforced before external analysis; the presence of a separate validator does not by itself guarantee that MISP only receives public IP addresses.
- Alerts without observables need a verified workflow path that skips IOC enrichment without treating the alert as an error or a negative IOC match.
- Public IP validation and downstream analyzer routing should be verified against the actual normalized observable list, especially when an alert contains both public and private IP addresses.
