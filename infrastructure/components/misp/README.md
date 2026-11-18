## 7. MISP — threat-intelligence repository

### 7.1 Purpose and deployment

MISP stores and exposes threat-intelligence events and observable attributes for enrichment. The automation architecture allows extracted observables to be looked up against MISP data before the final analyst decision.

| Property | Configuration |
|---|---|
| Host private IP | `10.10.20.50` |
| Operating system | Ubuntu 24.04 |
| Installation | `misp-docker` self-hosted stack (Docker Compose) |
| User interface | Web application, normally exposed over HTTPS `443/TCP` |
| API authentication | Authorization API key, associated with an authorized MISP user |
| Relevant REST operations | `POST /attributes/restSearch`, `POST /events/restSearch` |

### 7.2 Startup and standalone verification

On the MISP Docker host, from the deployed Compose project:

```bash
sudo docker compose ps
sudo docker compose up -d
```

Open the MISP UI and sign in locally; verify that the administration/status interface loads and that an attribute lookup can be performed against a known local test indicator. This verifies MISP independently of the SOAR workflow. An authenticated REST search can exercise `POST /attributes/restSearch`; keep the key in a protected runtime secret store, not in a committed command or output.

### 7.3 Problems and solutions

- **Separation between installation and integration:** running MISP containers and adding a Shuffle MISP node are distinct steps from successfully returning enrichment results. Test a MISP search within MISP before interpreting downstream workflow scores.
- **Lookup scope:** a no-match result is not a network failure. Distinguish authentication errors, provider connectivity, empty datasets and legitimate zero-hit intelligence responses.

### 7.4 Evidence and references

- MISP configuration notes: [`../../../enrichment/misp/README.md`](../../../enrichment/misp/README.md)
- Host inventory: [lab setup](../../architecture/lab-setup.md)
- API reference: [MISP OpenAPI](https://www.misp.software/openapi/)

---
