# Current Limitations and Verification Backlog

**Source:** `Wazuh_copy.json` export supplied 17 October 2026, plus synthetic lab responses.  
**Status:** Engineering review notes, not a claim that the live workflow has not changed since export.

This document records issues relevant to Cortex, MISP, duplicate handling, and the TheHive extension. It does not assign ownership or claim completion of other team members' features.

| ID | Area | Finding in exported configuration | Why it matters | Recommended next action |
|---|---|---|---|---|
| L-01 | Cortex AbuseIPDB | POST action uses the same analyzer ID as DShield | May run the wrong analyzer despite a successful response | Match analyzer name and ID from `GET /api/analyzer`, correct mapping, then verify report identifies AbuseIPDB |
| L-02 | Cortex VirusTotal | Static test hash in POST request | Real hashes would be ignored | Bind validated dynamic hash and confirm with two distinct synthetic samples |
| L-03 | TheHive ID mapping | MID/HIGH/CRITICAL Save ID links check `$http_low.status` | May not execute after a valid POST from those categories | Use `$http_mid.status`, `$http_high.status`, `$http_critical.status` respectively |
| L-04 | Deduplication | No explicit time window | Does not yet meet time-scoped incident correlation criteria | Agree on TTL/window and test out-of-window events |
| L-05 | Deduplication | Counter cache uses read-modify-write | Concurrent duplicates may lose increments | Add atomic increment or serialized update; load test |
| L-06 | TheHive PATCH | Adds diagnostic tag only | Occurrence count and last-seen not visible in TheHive | Extend update after the counter path, validate supported API fields |
| L-07 | IOC enrichment | Independent result branches, no combined JSON | Cannot build a complete evidence-based score | Aggregate normalized Cortex and MISP reports |
| L-08 | MISP | IPv4 regex checks shape only | Private/malformed address might be queried | Use explicit parsed IP validation per agreed policy |
| L-09 | Availability | No proven complete fallback for Cortex/MISP outages | Missing TI must not be scored as clean | Record unavailable/timeout states and route to analyst appropriately |
| L-10 | Security | Literal bearer authorization data in original export; TLS verification disabled in lab | Public disclosure or MITM exposure | Sanitize export with approved script, independently inspect, rotate affected keys if exposed, implement trusted TLS |
| L-11 | End-to-end | Trigger is marked stopped in supplied export | Live Wazuh → Shuffle route not proven by this snapshot | Check live trigger and configured webhook destination; run authorized lab SSH test later |
| L-12 | TheHive | Existing alert creation occurs independently of enrichment | Ticket may be created before TI results | Align enrichment/decision gate with issue #11 requirements |

## Evidence boundaries

**Observed:** synthetic NEW/DUPLICATE routing, TheHive create HTTP 201, TheHive duplicate PATCH HTTP 204, cached alert ID retrieval, initial occurrence counter value 2 stored; successful individual Cortex and MISP API responses.

**Not yet established:** counter 2→3, a normalized aggregated enrichment object, complete incident correlation across Wazuh and IDS, trustworthy risk score, failure-mode behavior, 1,000-event scale test, or live end-to-end SSH → Wazuh → Shuffle → TheHive in the current workflow.

Document each future test with its date, source event, expected/actual results, and a sanitized screenshot or log excerpt. Close the related GitHub issues only when their own acceptance checklists are met.
