# Sample alerts

Alerts in Wazuh JSON format (synthetic, or real lab alerts after anonymisation), used to test the Shuffle
workflow without generating real traffic (POST to the webhook with `curl`). External addresses use
documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

Real alerts: anonymise them first, then upload the cleaned copy.

```bash
python3 scripts/sanitize_export.py raw-alert.json -o samples/alerts/<source>-<rule_id>-<what>.json
```

This replaces public IPs with RFC 5737 addresses, e-mails with `userN@example.com` and user names in
paths with `<user>`, and removes secrets. Known test IOCs that must keep their real value (e.g. MISP test
indicators) go into `.leakcheck-allow` with a reason. Normalised outputs belong in `samples/normalized/`.

The MISP Issue #10 synthetic alert is [`misp-issue10-all-observable-types.json`](misp-issue10-all-observable-types.json). It contains two IPs, a domain, an MD5 and a SHA-256 for the per-observable lookup test. The IP values are documentation-only replacements; see [`../results/misp/all-observable-types-issue10.json`](../results/misp/all-observable-types-issue10.json) for the corresponding sanitized MISP and Aggregate Score results.
