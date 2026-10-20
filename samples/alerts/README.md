# Sample alerts

Synthetic alerts in Wazuh JSON format, used to test the Shuffle workflow without generating real traffic
(POST to the webhook with `curl`). External addresses use documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

Do not paste real alerts with personal data — anonymise first.

The MISP Issue #10 synthetic alert is [`misp-issue10-all-observable-types.json`](misp-issue10-all-observable-types.json). It contains two IPs, a domain, an MD5 and a SHA-256 for the per-observable lookup test. The IP values are documentation-only replacements; see [`../results/misp/all-observable-types-issue10.json`](../results/misp/all-observable-types-issue10.json) for the corresponding sanitized MISP and Aggregate Score results.
