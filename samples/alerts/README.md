# Sample alerts

Samples are grouped by format:

| Folder | Format | Used for |
|---|---|---|
| `raw/` | Source log before Wazuh (Suricata EVE, Windows event, web log) | Normalisation tests |
| `wazuh/` | Wazuh alert JSON, as stored in the indexer | Detection evidence, MISP lookup tests |
| `shuffle-integration/` | Payload sent by the Wazuh `shuffle` integration (`all_fields` envelope) | Replaying alerts to the v0.1 Shuffle webhook |

Alerts and source logs (synthetic, or real lab alerts after anonymisation), used to test the pipeline without generating real traffic.
Real alerts: anonymise them first, then upload the cleaned copy.

```bash
python3 scripts/sanitize_export.py raw-alert.json -o samples/alerts/<format>/<source>-<rule_id>-<what>.json
```

This replaces public IPs with RFC 5737 addresses, e-mails with `userN@example.com` and user names in
paths with `<user>`, and removes secrets. Known test IOCs that must keep their real value (e.g. MISP test
indicators) go into `.leakcheck-allow` with a reason. Normalised outputs belong in `samples/normalized/`.

The MISP Issue #10 synthetic alert is [`wazuh/misp-all-observable-types.json`](wazuh/misp-all-observable-types.json).
 It contains two IPs, a domain, an MD5 and a SHA-256 for the per-observable lookup test. The IP values are documentation-only replacements; see [`../results/misp/all-observable-types-issue10.json`](../results/misp/all-observable-types-issue10.json) for the corresponding sanitized MISP and Aggregate Score results.
