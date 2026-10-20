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

![MISP feeds configuration](../../docs/images/misp/02-misp-feeds.png)

## `soc-lab:*` tag convention

Custom tags are used to label events by expected outcome and downstream routing:

| Tag | Meaning |
|-----|---------|
| `soc-lab:malicious` | IOC is known-bad; attribute has `to_ids = true` |
| `soc-lab:benign` | IOC is known-good; attribute has `to_ids = false` |
| `soc-lab:thehive` | Event should be imported into TheHive (malicious events only) |

## TheHive import filter

TheHive is configured to import MISP events **only** when they carry the tag `soc-lab:thehive`.

The tag is added automatically by Shuffle: when a MISP lookup returns a hit (`to_ids = true`), Shuffle writes the `soc-lab:thehive` tag back to the MISP event via the API. TheHive then picks up the tagged event and creates a case automatically.

This prevents feed events (CIRCL, Feodo — thousands of events) from flooding TheHive — only events confirmed malicious by the automation pipeline appear as cases.

![TheHive MISP import](../../docs/images/misp/02-thehive-misp-import.png)

## How to add an IOC to MISP

1. Open MISP → **Event Actions → Add Event**
2. Give it a title, set the organisation to **SOC-Lab**, add tags (`soc-lab:malicious` or `soc-lab:benign`)
3. Click **Add Attribute**
4. Set the correct type (`ip-dst`, `domain`, `md5`, etc.)
5. Set `to_ids = true` for malicious indicators, `to_ids = false` for benign
6. Save — the IOC is now searchable via `/attributes/restSearch`
