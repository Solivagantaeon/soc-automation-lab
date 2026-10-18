
# Alert normalization and observable extraction

## Purpose

The Shuffle workflow normalizes incoming Wazuh alerts into a common structure used by later enrichment, scoring, deduplication and TheHive integration steps.

## Workflow

Current processing flow:

`Webhook → Alert IN → Normalize Alert → NEW ALERT`

The workflow also contains validation and enrichment branches for IP addresses, hashes and domains, as well as a MISP attribute lookup.

## Normalized alert schema

The `Normalize Alert` node returns a JSON object with a `message` containing the normalized alert.

| Field | Description |
|---|---|
| `source` | Alert source; currently `wazuh` |
| `timestamp` | Original alert timestamp, normalized to ISO 8601 UTC when available |
| `hostname` | Wazuh agent hostname |
| `agent_id` | Wazuh agent ID |
| `source_alert_id` | Original Wazuh alert ID |
| `rule_id` | Original Wazuh rule ID |
| `alert_type` | List of alert categories derived from the rule groups |
| `severity` | Common severity value |
| `severity_source` | Source used for severity mapping |
| `wazuh_level` | Original Wazuh rule level |
| `description` | Alert description |
| `ip` | List of extracted IP observables |
| `user` | Username, when present |
| `observables` | Typed observable objects |
| `original_alert` | Original Wazuh alert retained for traceability |

### Observable format

Observables use typed objects:

- IP: `{"type": "ip", "value": "..."}`
- Domain: `{"type": "domain", "value": "..."}`
- Hash: `{"type": "hash", "algorithm": "...", "value": "..."}`

The original alert is retained so later workflow steps can access source-specific fields when required.

## Validation

### Public IPv4

The `Validate Public IP` node reads the source IP from the normalized alert's original payload.

It accepts only globally routable IPv4 addresses. Private, reserved, documentation and invalid addresses are rejected.

Output fields:

- `valid`
- `ip`
- `reason`

A valid address returns `reason: "public_ipv4"`. Rejected addresses return an empty `ip` and a reason describing the rejection.

### File hashes

The `Validate Hash` node extracts hashes from the Windows/Sysmon `hashes` field. It recognizes MD5, SHA1 and SHA256, validates their hexadecimal format and prefers SHA256, followed by SHA1 and MD5.

Output fields:

- `valid`
- `hash`
- `algorithm`
- `reason`

### Domains

The `Validate Domain` node checks the domain supplied by the alert, with a fallback to the DNS question name when available. It rejects IP literals, malformed domains and configured internal/test suffixes.

Output fields:

- `valid`
- `domain`
- `reason`

## MISP lookup

The `MISP 1` node sends a POST request to the MISP attribute REST search endpoint using JSON input. The current lookup uses the IP observable from the normalized alert.

An empty attribute list is a valid lookup result and means that no matching attributes were returned. An unsuccessful request must not be interpreted as a negative IOC match.

## Testing evidence

The workflow was manually executed with a synthetic Wazuh alert.

- The normalization node returned a structured alert with source fields retained.
- The public IP validator rejected `198.51.100.25`, a documentation-range address.
- The public IP validator accepted `8.8.8.8` and returned `reason: "public_ipv4"`.
- The MISP condition was updated to use the normalized alert's original payload instead of the obsolete `$exec.all_fields` reference.

Additional test evidence and sanitized workflow exports are stored under `samples/results/normalized/` and `soar/shuffle/workflows/` when available.

## Security and privacy

- Use synthetic or anonymized alerts in repository samples.
- Replace real external IP addresses with RFC 5737 documentation ranges in committed examples.
- Never commit API keys, authentication headers, cookies or other secrets.
- Do not send private or reserved IP addresses to external analyzers.
