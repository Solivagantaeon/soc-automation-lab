# Shuffle workflow (v0.1, archived)

> **Archived.** Shuffle was the SOAR engine of this project until 2026-10-22, when n8n replaced it.
> The current pipeline is in [`soar/n8n/`](../n8n/), and the reasons for the change are in the
> [SOAR engine comparison](../../docs/research/soar-engine-comparison.md).
> Nothing in this folder is deployed. It is kept as the record of v0.1 and as evidence for issues #7, #9, #10, #11 and #16.
> The whole repository as it was at the end of v0.1: tag [`v0.1`](https://github.com/Solivagantaeon/soc-automation-lab/tree/v0.1).

## What v0.1 did

Wazuh sent every alert of level 3 and above to a Shuffle webhook. The workflow `SOC Automation - v1.0`
(39 actions) deduplicated the alert, checked its observables in MISP and with Cortex analyzers, scored it
and created an alert in TheHive. A repeated alert updated the existing TheHive alert instead of creating a new one.

Why it was replaced, in short: the on-premises edition counts every executed action as an app run, with a
default allowance of 25,000 runs per month, and one alert used dozens of them. The full comparison of SOAR
engines is in the research note linked above.

## Contents

| Path | Content |
|---|---|
| [`workflows/soc-automation-v1.0.json`](workflows/soc-automation-v1.0.json) | Sanitised export of the workflow |
| [`integration/shuffle-integration.xml`](integration/shuffle-integration.xml) | `<integration>` block for `ossec.conf` on the Wazuh manager |
| [`samples/`](samples/) | Six Wazuh alerts as Shuffle received them (Suricata, Sysmon, web attacks, FIM) |
| [`docs/wazuh-integration.md`](docs/wazuh-integration.md) | Runbook: connecting Wazuh to the Shuffle webhook |
| [`docs/deduplication.md`](docs/deduplication.md) | How the workflow deduplicated alerts and updated TheHive (#16) |
| [`docs/deployment.md`](docs/deployment.md) | Shuffle VM, ports and start-up checks |
| [`docs/cortex-enrichment.md`](docs/cortex-enrichment.md) | Cortex analyzer routing, scoring and evidence from the workflow (#9) |
| [`docs/misp-lookup.md`](docs/misp-lookup.md) | MISP attribute lookups and the all-observable test (#10) |
| [`docs/thehive-alerts.md`](docs/thehive-alerts.md) | TheHive alert fields, tags and the end-to-end test (#11) |

Related files kept elsewhere:

- [ADR 0001](../../docs/decisions/0001-wazuh-integration-shuffle.md) - the Wazuh → Shuffle integration decision (superseded).
- [`docs/images/shuffle/`](../../docs/images/shuffle/) - screenshots of the workflow and its test runs.
- [`soar/schema/`](../schema/) - the normalised alert schema. It started here, but both engines use it.
- [`tests/test_issue16_deduplication.py`](../../tests/test_issue16_deduplication.py) - checks the deduplication path in the exported workflow.

## Exporting and importing (reference)

How the export in `workflows/` was made:

1. Shuffle → Workflows → ⋮ → **Export** → save as `soc-automation.raw.json` (`*.raw.json` is git-ignored).
2. Sanitise:
   ```bash
   python3 scripts/sanitize_export.py soc-automation.raw.json -o soar/shuffle/workflows/soc-automation-v1.0.json
   python3 scripts/sanitize_export.py --check soar/
   ```
   Besides keys and tokens, the script replaces the webhook trigger `id` with `00000000-...`:
   in an export that ID **is** the webhook URL (`/api/v1/hooks/webhook_<id>`).
3. Review the diff by eye, then commit. Never upload the raw export through the browser.

Keys were never typed into `http` nodes (e.g. an `Authorization: Bearer ...` header), because such a key ends up
in every export. The workflow used the apps' saved authentication instead. After importing the workflow,
select the authentication for each app again: no keys are stored in this repository.