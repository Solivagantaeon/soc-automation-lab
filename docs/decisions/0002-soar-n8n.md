# ADR 0002 – Choosing the SOAR engine for v0.2

- **Status:** Proposed
- **Date:** 2026-10-23
- **Authors:** @login
- **Issue:** #NN

## 1. Context

<!-- Dopiszcie, jeśli czegoś brakuje w wymaganiach. -->

The SOAR engine is the core of our pipeline: it receives Wazuh alerts, deduplicates and enriches them (MISP, Cortex), scores them and decides what reaches TheHive. v0.1 used Shuffle (tag [`v0.1`](https://github.com/Solivagantaeon/soc-automation-lab/tree/v0.1)). For v0.2 we want to compare the available options before choosing.

**Requirements:** self-hosted, free for a university project, works with Wazuh / TheHive / Cortex / MISP, handles thousands of alerts, workflows exportable to Git, ready before 10 Nov 2026.

## 2. Options considered

The comparison focuses on free self-hosted editions. 

| Tool | Type | License |
|---|---|---|
| Shuffle Open Source | Security automation / SOAR | AGPL-3.0 core |
| n8n Community | Workflow automation | Sustainable Use License |
| Tracecat Open Source | Security automation / SOAR | AGPL-3.0 core |
| StackStorm | Event-driven automation | Apache-2.0 |

Paid n8n plans are included to explain differences in collaboration, security and cost.

## 3. Comparison

**Legend:** 
 - Yes = available
 - No = not included
 - External = requires another component
 - TBD = requires clarification.

Feature availability does not mean enabled by default. Detailed mechanisms, limitations and deployment findings belong in **Section 4**.

### 3.1 Workflow capabilities

| Capability | Shuffle OSS | n8n Community | Tracecat OSS | StackStorm |
|---|---|---|---|---|
| Free self-hosting | Yes | Yes | Yes | Yes |
| Workflow automation | Yes | Yes | Yes | Yes |
| Custom code / actions | Yes | Yes | Yes | Yes |
| Outbound API requests | Yes | Yes | Yes | Yes |
| Webhook triggers | Yes | Yes | Yes | Yes |
| Storage for deduplication logic | Yes | Yes | Yes | Yes |
| Workflow export / source format | JSON | JSON | YAML | YAML + code |
| Built-in Git sync | TBD | No | No | External tooling |
| Shared workflow access | Yes | Creator + owner only | Yes | Yes |

### 3.2 Security stack integrations

**Legend:** 
 - Node = built-in n8n integration
 - Integration = documented product integration
 - API = HTTP requests or custom actions
 - Existing = used in our v0.1 pipeline

| Integration / operation | Shuffle | n8n Community | Tracecat OSS | StackStorm |
|---|---|---|---|---|
| Wazuh alert ingestion | Existing webhook | Webhook + forwarding | Webhook + forwarding | Webhook + forwarding |
| MISP IOC lookup | Existing | MISP node / API | API | API / Python |
| Cortex analyzer execution and results | Existing | API | API | API / Python |
| TheHive alerts and cases | Existing | TheHive / TheHive 5 node | API | API / Python |
| VirusTotal enrichment | Via Cortex | Cortex API / direct API | Integration / Cortex API | API / Python |
| AbuseIPDB enrichment | Via Cortex | Cortex API / direct API | Integration / Cortex API | API / Python |
| Other Cortex analyzers | Via Cortex | Cortex API | Cortex API | Cortex API |

### 3.3 Cybersecurity capabilities

| Capability | Shuffle OSS | n8n Community | Tracecat OSS | StackStorm |
|---|---|---|---|---|
| Local user authentication | Yes | Yes | Yes | Yes |
| Centralised authentication | SAML | No | SAML / OIDC | LDAP / proxy |
| MFA approach | Built-in | Built-in user 2FA | External IdP | External setup |
| Role-based permissions | Tenant roles | Limited | Built-in roles | Configurable RBAC |
| Webhook authentication | Required headers | Basic / Header / JWT | URL secret; additional controls* | API key / token |
| Encrypted credential storage | Yes | Yes | Yes | Yes |
| Audit evidence | Audit logging | Execution/application logs | Organisation audit logs | Action audit logs |
| External secret-store integration | TBD | No | No | Custom integration |

**Main security considerations:**

- **Shuffle:** restrict tenant permissions and explicitly configure webhook authentication.
- **n8n:** Community lacks ordinary-user workflow/credential sharing. Restrict unnecessary command and file-access nodes.
- **Tracecat:** protect secret-bearing URLs and select the appropriate executor isolation. Advanced roles and management API capabilities are edition-dependent.
- **StackStorm:** enable RBAC, configure encryption and mark secret parameters/outputs correctly. API keys do not expire automatically.

All platforms require HTTPS, restricted network access, least-privilege credentials and sanitised exports.

### 3.4 n8n self-hosted editions

| Capability | Community | Business | Enterprise |
|---|---|---|---|
| Software price | Free | €667/month, billed annually* | Custom quote |
| Execution allowance | No paid quota specified | 40,000/month* | Custom |
| User-enabled 2FA | Yes | Yes | Yes |
| SSO / LDAP | No | Yes | Yes |
| Shared projects | No | 6 | Unlimited |
| Credential encryption | Yes | Yes | Yes |
| External secret stores | No | No | Yes |
| Built-in log streaming | No | No | Yes |
| JSON export/import | Yes | Yes | Yes |
| Built-in Git integration | No | Yes | Yes |
| Managed environments | No | Yes | Yes |
| Queue mode / workers | Yes | Yes | Yes |
| LLM integration | Yes | Yes | Yes |
| Dedicated support with SLA | No | No | Contract-dependent |

### 3.5 LLM integration

| Capability | Shuffle | n8n | Tracecat | StackStorm |
|---|---|---|---|---|
| Integration approach | App / HTTP | Dedicated nodes / HTTP | Provider configuration | Python / REST action |
| Local inference approach | Local endpoint | Ollama node | OpenAI-compatible endpoint | Custom API call |

## Sources for Sections 2–3 

- **Shuffle:** [Licensing](https://github.com/shuffle/Shuffle/blob/master/.github/CONTRIBUTING.md), [Architecture](https://shuffler.io/docs/architecture), [Workflows](https://shuffler.io/docs/workflows), [Pricing](https://shuffler.io/pricing?env=Self-Hosted), [Usage restrictions](https://github.com/orgs/Shuffle/discussions/1958), [AI](https://shuffler.io/docs/AI).
- **n8n:** [Editions](https://docs.n8n.io/hosting/community-edition-features/), [Pricing](https://n8n.io/pricing/), [Export/import](https://docs.n8n.io/workflows/export-import/), [MISP](https://docs.n8n.io/integrations/builtin/app-nodes/n8n-nodes-base.misp/), [TheHive 5](https://docs.n8n.io/integrations/builtin/app-nodes/n8n-nodes-base.thehive5), [Webhook authentication](https://github.com/n8n-io/n8n-docs/blob/main/docs/integrations/builtin/credentials/webhook.md), [Ollama](https://docs.n8n.io/integrations/builtin/cluster-nodes/sub-nodes/n8n-nodes-langchain.lmchatollama).
- **Tracecat:** [Repository](https://github.com/TracecatHQ/tracecat), [Pricing](https://www.tracecat.com/pricing), [Workflows](https://docs.tracecat.com/automations/workflows), [Webhooks](https://docs.tracecat.com/automations/triggers/webhooks), [Security](https://github.com/TracecatHQ/tracecat/blob/main/SECURITY.md), [VirusTotal](https://docs.tracecat.com/tools/virustotal), [AbuseIPDB](https://docs.tracecat.com/tools/abuseipdb), [LLM providers](https://docs.tracecat.com/agents/custom-llm-providers).
- **StackStorm:** [License](https://github.com/StackStorm/st2/blob/master/LICENSE), [Overview](https://docs.stackstorm.com/overview.html), [Authentication](https://docs.stackstorm.com/authentication.html), [RBAC](https://docs.stackstorm.com/rbac.html), [Datastore](https://docs.stackstorm.com/datastore.html), [Secret masking](https://docs.stackstorm.com/reference/secrets_masking.html).
- **Supporting services:** [Cortex](https://github.com/TheHive-Project/Cortex), [Ollama authentication](https://docs.ollama.com/api/authentication).

- done by @MKonrad-afk (blame on me ;); Status- proposed

## 4. Research notes

<!-- Jedna podsekcja na temat: co sprawdzałeś, jak (docs / test w labie), co wyszło, linki. Reasercherujemy pod kątem odpowiadania na poniższe pytania -->

### 4.1 _Topic_ – @login

## 5. Questions to answer before the decision

<!-- Odpowiadamy w ramach researchu, zanim wybierzemy narzędzie. Można dopisywać pytania. -->

1. How does each tool handle deduplication and updating an existing TheHive alert?
2. What can we reuse from v0.1, and what must be rebuilt?
3. How does each tool handle security measures

## 6. Decision

<!-- Wspólnie, w dyskusji pod PR-em, z odwołaniem do §3 i §5. -->

- **Chosen engine:**
- **Why:**
- **Rejected options:**

## 7. Consequences

<!-- "What we lose" jest wstępnie opisane – rozbudujcie po researchu. -->

**What we gain:**

**What we lose:**
- the working Shuffle v1.0 workflow (must be rebuilt and retested),
- the built-in Wazuh → Shuffle integration and Shuffle's ready-made apps,
- deduplication behaviour from v1.0 (unless re-implemented),
- team know-how and time before the deadline.

**Risks:**

## 8. Feature parity (v0.1 vs v0.2)

<!-- Uzupełniamy dopiero po postawieniu i udokumentowaniu wybranego narzędzia. -->

_To be completed after deployment._
