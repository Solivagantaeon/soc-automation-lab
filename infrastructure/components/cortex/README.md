
## 6. Cortex — observable analysis and enrichment

### 6.1 Purpose and deployment

Cortex provides analyzers that enrich extracted observables such as IP addresses, hashes and domains. Results can support Shuffle scoring and analyst triage in TheHive; external intelligence lookups depend on each analyzer's own provider connection.

| Property | Configuration |
|---|---|
| Version | **4.1.0** |
| Host | Shared TheHive/Cortex host |
| Private IP | `10.10.20.247` |
| Installation | Docker deployment using the StrangeBee `testing` profile described in the lab baseline |
| Service convention | Cortex HTTP application and REST API on `9001/TCP` inside the trusted network |
| Authentication | Cortex users/organizations and API keys for authorized analyzers/API consumers |

### 6.2 APIs and ports

- Cortex exposes an authenticated API for listing analyzers and submitting analysis jobs.
- API path used during lab testing: `GET /api/analyzer?range=0-30`, with an API key header.
- TheHive/Shuffle integration uses configured API credentials; credentials are never stored in Markdown or screenshots.

### 6.3 Startup and standalone verification

On the shared Docker host:

```bash
sudo docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
# Use the actual Cortex container name reported by the command:
sudo docker logs --tail 50 <CORTEX_CONTAINER>
```

An authenticated Cortex session can list available analyzers without Wazuh, Shuffle, MISP or TheHive. During lab analyzer testing on 16 October 2026, `GET /api/analyzer?range=0-30` returned **15 enabled analyzers**, including AbuseIPDB and VirusTotal report integrations. Successful analyzer listing demonstrates the Cortex API and organization configuration; completion of a particular enrichment job additionally depends on the external provider.

### 6.4 Problems and solutions

- **Analyzer enablement:** after deployment, analyzers must be configured and enabled for their organization. The test configuration enabled analyzer definitions and verified them with the API listing.
- **Provider configuration:** analyzers that depend on external services must have authorized credentials and network access; API listings are tested separately from provider verdicts so troubleshooting can isolate a failing dependency.

### 6.5 Evidence and references

- Cortex configuration notes: [`../enrichment/cortex/README.md`](../enrichment/cortex/README.md)
- Cortex and TheHive host: [lab setup](lab-setup.md)
- Workflow connection: [architecture](architecture.md)

---
