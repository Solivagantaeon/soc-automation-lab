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
| `misp_ip` | First extracted IPv4 address accepted as globally routable; empty when no such address is found |
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

The `ip` field retains extracted IP addresses for downstream workflow steps. The `misp_ip` field is a separate single-value field intended for MISP IP lookup. It is set only when an extracted address is an IPv4 address for which Python's `ipaddress` implementation returns `is_global = True`.

The `misp_ip` field does not replace public-IP validation in other workflow branches. Downstream routing should use the intended validated field and must not submit private, reserved or documentation-range addresses to external analyzers.

The original alert is retained so later workflow steps can access source-specific fields when required.

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

- `valid
