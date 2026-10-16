# Wazuh rules

Custom rules deployed to `/var/ossec/etc/rules/` on the manager.

| File | Purpose | Status |
|---|---|---|
| `local_rules_noise_reduction.xml` | Noise reduction (v2) | to add |

Rule IDs: use the custom range **100000–120000**. After each change: `/var/ossec/bin/wazuh-logtest` + manager restart, then record the alert-count before/after in `metrics/`.
