# Cortex IOC enrichment

**Related issue:** [#9 — IOC enrichment](https://github.com/Solivagantaeon/soc-automation-lab/issues/9)

This page summarizes the Cortex enrichment paths and test evidence for Issue #9. The issue-specific workflow change is maintained separately; these notes and screenshots document how analyzer routes and normalized results fit the SOC workflow.

## Enrichment flow

1. `Normalize Alert` extracts typed observables from the incoming Wazuh alert.
2. Validation checks public IPv4 addresses, file hashes, and domains before the corresponding lookup paths.
3. Shuffle starts Cortex analyzer jobs and retrieves their reports.
4. Normalizers preserve source-specific report fields; `Aggregate_Score` calculates the score and routing decision for each observable.
5. Enrichment results are passed to alert handling in TheHive.

| Observable | Cortex analyzers |
|---|---|
| Public IPv4 | AbuseIPDB and DShield |
| File hash | VirusTotal and Team Cymru |
| Domain | Google DNS and Maltiverse |

The public-IP route validates that the IPv4 address is globally routable before starting external IP lookups. The Cortex actions use lookup requests with `to_file` disabled; VirusTotal uses a hash report lookup.

## Normalized results

The analyzer normalizers retain fields such as VirusTotal detection counts, Team Cymru reputation data, DNS response records, Maltiverse classification, and source-specific IP reputation details. The all-observable test run returned usable normalized results from all six paths:

- VirusTotal reported 0 malicious detections from 60 engines for the test hash.
- Maltiverse returned a whitelist classification and 21 resolved IPs for the test domain.
- Google DNS returned `No Error` with HINFO and RRSIG records for the test domain.
- AbuseIPDB and DShield results are preserved separately so their source signals can be reviewed together.

Example normalized reports are available for [AbuseIPDB](../../samples/normalized/abuseipdb-normalized-example.json), [DShield](../../samples/normalized/dshield-normalized-example.json), [Team Cymru](../../samples/normalized/teamcymru-normalized-example.json), [VirusTotal](../../samples/normalized/virustotal-normalized-example.json), [Google DNS](../../samples/normalized/googledns-normalized-example.json), and [Maltiverse](../../samples/normalized/maltiverse-normalized-example.json).

## Screenshots

![Shuffle Cortex routing](../../docs/images/cortex/02-shuffle-cortex-routes.png)

*Figure 1. Shuffle routes public IP, file hash, and domain observables to their Cortex analyzer paths.*

![Cortex analyzer job history](../../docs/images/cortex/01-analyzer-jobs.png)

*Figure 2. Successful Cortex analyzer jobs for the test observables.*

The Wazuh duplicate-alert flow and TheHive Update Alert action are documented in [Shuffle alert deduplication](../../docs/shuffle-deduplication.md).

## Safe exports

Keep API keys, webhook URLs, session cookies, and credentials in the protected Shuffle and Cortex settings. Run `python scripts/sanitize_export.py --check` on workflow exports before sharing them.
