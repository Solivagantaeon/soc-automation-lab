# MISP

MISP (misp-docker) used for threat-intel lookups from Shuffle and as an external source in TheHive.

Document here: enabled feeds, how lookups are done (attribute search), how matches influence the score.

## Feeds

Two public OSINT feeds are enabled. Both are free, require no authentication, and are widely used in production SOC environments.

| Feed | Provider | Format | Why enabled |
|------|----------|--------|-------------|
| **CIRCL OSINT Feed** | CIRCL (Computer Incident Response Center Luxembourg) | MISP JSON | Rich, structured threat intelligence — full MISP events with IOC context, MITRE ATT\&CK mappings, TLP tags, and campaign descriptions. Covers IPs, domains, URLs, file hashes, and more. |
| **Feodo IP Blocklist** | abuse.ch | CSV | Focused list of active botnet C2 IP addresses (Emotet, QakBot, Dridex, etc.). Lightweight, updated frequently, high signal-to-noise ratio. |

### Fetch and store vs cache only

Both feeds are configured with **Fetch and store** (not *Cache only*):

| Mode | What it does | API searchable? |
|------|-------------|-----------------|
| **Fetch and store** | Downloads feed content and saves it as MISP events | ✅ Yes — via `/attributes/restSearch` |
| Cache only | Downloads and hashes IOC values locally for fast lookup | ❌ No — not visible through REST API |

**Fetch and store** is required so that Shuffle can query IOCs via the standard REST API and receive full event context (tags, related events, campaign info).

### Why only two feeds

In a test lab environment, feed selection is driven by coverage quality rather than quantity. Large feeds with hundreds of thousands of entries introduce unnecessary resource overhead and noise without improving detection accuracy for the test scenarios in scope.

CIRCL and Feodo together provide full IOC coverage for lab purposes:

- **CIRCL** covers diverse IOC types (IP, domain, hash) with contextual metadata
- **Feodo** covers active C2 infrastructure with near-real-time updates
Both feeds have **caching enabled** and are set to **Fetch and store**, so all fetched IOCs are saved as MISP events and are searchable via the REST API (`/attributes/restSearch`).
