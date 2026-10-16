# Architecture

## Data flow

```mermaid
sequenceDiagram
    autonumber
    participant W as Wazuh manager
    participant S as Shuffle
    participant C as Cortex
    participant M as MISP
    participant T as TheHive
    participant A as Analyst

    W->>S: Alert JSON via webhook (<integration>, filtered by rule_id)
    S->>S: normalize — map fields, extract IOCs (IPs, hashes, domains)
    S->>C: cortex_run — start analyzers per IOC
    C-->>S: cortex_report — analyzer verdicts
    S->>M: misp_lookup — known indicators / events
    M-->>S: matches
    S->>S: decide — score, deduplicate, choose verdict
    alt benign / false positive
        S->>T: alert closed with justification
    else uncertain
        S->>T: alert → case for analyst
        T->>A: notification
    else confirmed malicious
        S->>T: high-priority case
        S-->>W: optional Active Response (time-limited)
    end
```

## Shuffle workflow (target)

`Webhook → normalize → cortex_run → cortex_report → misp_lookup → decide → thehive_alert`

Built iteratively:

1. **Thin slice** — one alert end-to-end with a simple `if` instead of scoring.
2. **Scoring** — weighted score from rule level, enrichment verdicts and MISP hits.
3. **Deduplication & grouping** — same rule + same source/destination within a time window.
4. **Error handling** — timeouts and fallbacks when an analyzer or MISP is unavailable (alert still reaches TheHive, marked "not enriched").
5. **Response** — optional Wazuh Active Response, only for high-confidence verdicts and always with a timeout.

## Key design decisions

See [`decisions/`](decisions/). Highlights:

- Wazuh integration filtered by `rule_id`, not by `level` (Suricata alerts arrive at level 3). — ADR 0001
- TheHive as the case-management system, DFIR-IRIS evaluated as an alternative. — ADR 0002

## Network segmentation

| Segment | Purpose |
|---|---|
| Management | Hypervisor and firewall administration |
| VICTIM | Active Directory domain and Windows endpoints (attack targets) |
| SOC | SIEM, SOAR, enrichment and case-management tools |
| ATTACK | Kali Linux; allowed to reach VICTIM only |
| VPN | WireGuard access for team members (SOC dashboards only) |

No lab segment can reach the home network. Details: [`lab-setup.md`](lab-setup.md).
