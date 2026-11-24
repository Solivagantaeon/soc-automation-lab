# SOC Automation Lab — Component Documentation

> **Related:** [#6 ](https://github.com/Solivagantaeon/soc-automation-lab/issues/6)  
> **Environment baseline:** 18 October 2026  
> **Scope:** Components, deployment, interfaces, standalone checks, troubleshooting, and communication paths (final report sections 21.2–21.3)

## 1. Purpose and scope

This document describes the deployed components of the isolated SOC Automation Lab and how each can be started, accessed, checked, and integrated. Wazuh collects endpoint and IDS alerts; Shuffle processes selected alerts through the triage workflow; Cortex and MISP provide enrichment; TheHive is used for analyst-facing alert and case management.

**Evidence notation:** Commands, screenshots and logged events dated 18 October 2026 represent observed operation. Product-standard endpoints and ports identify how a component is normally accessed; local network exposure is governed by the actual service and firewall configuration. A visible workflow node is not by itself proof of successful execution of that connector.

**Security:** Only private lab addresses are reproduced. Do not commit passwords, API keys, full webhook URLs, access tokens, cookies, public IPs, real user identifiers from alerts, or unredacted configurations. All examples below use placeholders or credential-free checks.

### 1.1 Lab segments and component locations

| Network / role | Address or network | Component |
|---|---|---|
| VICTIM  | `10.10.10.0/24` | Domain controller Windows, and Linux endpoints |
| SOC / tooling | `10.10.20.0/24` | Wazuh, Shuffle, Cortex, MISP, TheHive |
| ATTACK | `10.10.30.0/24` | Kali test host |

Detailed network isolation and the build order are described in [lab setup](lab-setup.md). The [architecture diagram](../docs/architecture/architecture.md) and [communication matrix](#2-communication-matrix) follow the same component names and pathways.

---


## 2. Communication matrix

The matrix deliberately separates **observed collection** from **workflow/integration routes**. Product-standard service ports are indicated where the host's container exposure was not part of the captured Wazuh port inventory. The same edges appear in [architecture.md](../docs/architecture/architecture.md).

| Source | Destination | Port / protocol | Authentication | Purpose / status |
|---|---|---|---|---|
| Windows Sysmon | Windows Operational Event Log | Local Event Log (no network port) | Windows service permissions | Local telemetry generation; records observed via Wazuh |
| Windows Wazuh agents (`10.10.10.150`, `.171`, `.200`) | Wazuh `10.10.20.243` | `1514/TCP` | Enrolled Wazuh agent identity/key | Endpoint event shipping; observed active |
| Linux agent (`10.10.10.100`) | Wazuh `10.10.20.243` | `1514/TCP` | Enrolled agent identity/key | Host event shipping; observed active |
| Suricata | OPNsense local Wazuh agent | Local IDS logs (no network port) | Local log access | IDS record collection |
| OPNsense `10.10.20.1` | Wazuh `10.10.20.243` | `1514/TCP` | Enrolled agent identity/key | Suricata alert shipping; agent active |
| Endpoints / OPNsense | Wazuh `10.10.20.243` | `1515/TCP` | Wazuh enrollment controls | Enrollment/registration as needed |
| SOC analyst | Wazuh Dashboard `10.10.20.243` | `443/TCP` (HTTPS) | Authenticated UI session | Threat Hunting and investigations |
| Wazuh Dashboard | Wazuh Manager API (same VM) | `55000/TCP` (HTTPS) | API credentials → JWT | Manager status and agent queries |
| Wazuh | Shuffle `10.10.20.245` | `3443/TCP` (HTTPS entry point) | Secret workflow webhook endpoint | Selected Wazuh alerts to triage workflow |
| Shuffle | Cortex `10.10.20.247` | `9001/TCP` (service default / private HTTP) | Cortex API key | Analyzer submission and verdict lookup; workflow route |
| Shuffle | MISP `10.10.20.50` | `443/TCP` (HTTPS, standard) | MISP API key | Threat-intelligence lookup; workflow route |
| Shuffle | TheHive `10.10.20.247` | `9000/TCP` (service default; or configured proxy) | TheHive API key | Alert/case creation; test records visible |
| TheHive | Cortex (same Docker host) | `9001/TCP` (internal service default) | Cortex API key | Case-management analyzer integration / architecture route |

**Protocol notes:** `1514/TCP` and `1515/TCP` are the observed listener sockets on VM 203. HTTPS `3443` for Shuffle matches the lab UI access used in configuration testing; the internal Cortex/TheHive and MISP ports follow product deployment conventions rather than a full audited firewall ruleset. Connectivity within Docker networks should be checked against the actual Compose service names and proxy mappings before building an allowlist.
