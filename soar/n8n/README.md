# SOAR: n8n (v0.2)

n8n is the SOAR engine of the pipeline: Wazuh pushes selected alerts to an n8n webhook, and n8n normalizes them,
removes duplicates, enriches observables with MISP and Cortex, scores the result and creates alerts in TheHive.
It replaced Shuffle in October 2026 - the Shuffle workflow is archived as v0.1 in [`soar/shuffle/`](../shuffle/),
and the trade-offs behind the switch are compared in the [SOAR engine comparison](../../docs/research/soar-engine-comparison.md#72-findings).

n8n runs self-hosted in queue mode on a dedicated VM in the SOC VLAN, behind an HTTPS reverse proxy, so a burst of
alerts is queued and processed by a worker instead of slowing down the web interface.

## Architecture

```mermaid
flowchart LR
    W["Wazuh manager<br/>custom-n8n integration"]
    B["Analyst browser"]

    subgraph VM["VM n8n-soar-1 (Docker Compose)"]
        C["Caddy<br/>HTTPS, internal CA"]
        M["n8n-main<br/>UI, API, webhooks"]
        R[("Redis<br/>queue")]
        WK["n8n-worker<br/>runs workflows"]
        RN["n8n-runner<br/>Code node sandbox"]
        P[("PostgreSQL<br/>workflows, credentials,<br/>execution history")]
    end

    subgraph EXT["SOC VLAN"]
        TI["MISP / Cortex"]
        TH["TheHive"]
    end

    W -->|"HTTPS 443<br/>X-Wazuh-Token"| C
    B -->|"HTTPS 443"| C
    C -->|"HTTP 5678"| M
    M -->|"enqueue"| R
    R -->|"job"| WK
    WK <-->|"task broker 5679"| RN
    M --- P
    WK --- P
    WK -->|"REST API"| TI
    WK -->|"REST API"| TH
```

| Docker network | Members | Access outside the VM |
|---|---|---|
| `edge` | caddy, n8n-main, n8n-worker | yes - Caddy publishes 80/443, the worker calls MISP, Cortex and TheHive |
| `data` | n8n-main, n8n-worker, postgres, redis | none (`internal`) |
| `sandbox` | n8n-worker, n8n-runner | none (`internal`) |

Only Caddy publishes ports. PostgreSQL, Redis and n8n itself are not reachable from the network.

## Layout

| Path | Content |
|---|---|
| [`deploy/`](deploy/) | `compose.yml`, `Caddyfile` and `make-env.sh` (generates `.env` on the VM) |
| [`nodes/`](nodes/) | JavaScript of the Code nodes in the triage workflow, one file per node, named after the node. The first line of each file names the node and its version; older versions are in the git history |
| [`workflows/`](workflows/) | Workflow exports ready to import: the queue smoke test [`soc-queue-smoke-test.json`](workflows/soc-queue-smoke-test.json) |
| [`triage/enrichment-routing.json`](triage/enrichment-routing.json) | MISP request settings, Cortex loop connections and final merge inputs for the existing triage workflow. Use this reference with the [enrichment runbook](../../docs/runbooks/n8n-triage.md#4-misp-and-cortex). |

## Deployment

Step-by-step runbook, with a test after every step: [`docs/runbooks/n8n-deploy.md`](../../docs/runbooks/n8n-deploy.md).

First working end-to-end test (Wazuh → n8n → MISP/Cortex → TheHive): [`docs/validation/e2e-first-run.md`](../../docs/validation/e2e-first-run.md).

| Component | Tested version |
|---|---|
| Proxmox VE | 9.2 |
| Ubuntu | 24.04.5 LTS (cloud image), kernel 6.8.0-147 |
| Docker Engine / Compose | 29.9.2 / v5.6.1 |
| n8n (`n8nio/n8n`, `n8nio/runners`) | 2.44.6 |
| PostgreSQL / Redis / Caddy | 17.11 / 7.4.11-alpine / 2.11.7-alpine |

