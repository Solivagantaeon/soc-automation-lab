# Proof of concept: three alerts through the live workflow



Issue: #92 · Run on: 15.11.2026 · Run by: @Solivagantaeon

Every stage of the n8n triage workflow was built and tested on its own, mostly with pinned test data in the Webhook node. This page shows the whole chain working at once. Something happens on a lab machine, Wazuh raises an alert, n8n enriches and scores it, and the alert either lands in TheHive or is closed automatically with a written reason.

We ran three alerts, one for each outcome the Decision node can return.

## Results

| # | What we did | Wazuh rule | Expected | Actual | Result |
|---|---|---|---|---|---|
| 1 | Deployed jQuery from the Ubuntu package to the web root on SOC-LIN-01 | 554, File added to the system (level 5) | `closed`, a row in `SOC_Audit`, nothing in TheHive | `closed` (`complete_low_risk_analysis`, score 0), **two** rows in `SOC_Audit`, nothing in TheHive |  PASS |
| 2 | Ran a renamed copy of `curl.exe` from the user's Temp folder on SOC-WIN10-01; it connected to 8.8.8.8  | 100921, Executable from user Temp folder connected to 8.8.8.8:443 (level 12, added for the PoC) | `analyst_review`, alert in TheHive | `analyst_review` (`analyst_review_required`, score 44, verdict `medium`), one alert in TheHive with 8.8.8.8 attached | PASS |
| 3 | TODO | TODO | `malicious`, alert in TheHive with the IOCs attached | TODO | TODO |



TODO: two or three sentences on what the table shows. Say it plainly if something did not go as pl (see [Notes](#notes)).anned.
<!--First scenario summary -->
Scenario 1 reached the expected outcome: the benign file was closed automatically with a written reason and nothing reached TheHive. The run also showed that enrichment results can reach the decision in separate batches, which recorded the same alert twice in `SOC_Audit` (see [Issues found](#issues-found1)).

Scenario 2 also reached the expected outcome: the threat intelligence disagreed, so the workflow did not decide and sent the alert to an analyst. The default Wazuh rules do not detect a program in a user's Temp folder connecting to the internet, so we added rule `100921` for this behaviour.  The run also exposed two scoring weaknesses  (see [Notes](#notes)).

## What was running

| Item | Value |
|---|---|
| n8n workflow | `SOC - Wazuh alert triage` (ID `JqM02cALddRCz3a4`), published on 2026-11-13 12:07 (+01:00), version `5cb075fd` |
| Node code | `normalize-v1.2.js`, `score-v0.2.js`, `decision-v0.1.js`, `thehive-alert-v0.3.js` from [`soar/n8n/nodes/`](../soar/n8n/nodes/) <!-- confirm these are the versions in the live workflow --> |
| Scoring config | [`score-config.json`](../soar/n8n/nodes/score-config.json) |
| Wazuh integration | `custom-n8n`, two `<integration>` blocks: one forwards alerts at level 12 and above, one forwards selected rules by `rule_id` (added for this PoC, see below) |
| Cortex analyzers used | Hashes: `TeamCymruMHR_1_0`, `CIRCLHashlookup_1_1`, `VirusTotal_GetReport_3_1`. IPs: `AbuseIPDB_2_0`. Several types: `Maltiverse_Report_1_0`. |
| MISP | Attribute search on the lab instance (10.10.20.50) for every observable from the alert. |

Lab machines that take part:

| System | Lab address | Role here |
|---|---|---|
| Kali | 10.10.30.100 | Sends the test requests |
| SOC-LIN-01 (agent `006`) | 10.10.10.100 | Linux endpoint and test web server |
| SOC-WIN10-01 (agent `007`) | 10.10.10.150 | Windows endpoint <!-- delete the row if not used --> |
| Wazuh manager | 10.10.20.243 | Detects and forwards alerts to n8n |
| n8n | TODO | Runs the triage workflow |
| MISP | 10.10.20.50 | Threat intelligence lookup |
| Cortex and TheHive | 10.10.20.247 | Analyzers and the alert queue for the analyst |

All addresses are private lab ranges. API keys, the webhook token and the webhook URL are not on this page or in any screenshot.

### Wazuh integration for the PoC

The default integration forwards only alerts at level 12 and above. Scenario 1 uses rule 554 (level 5), so a second `<integration>` block was added to `ossec.conf` on the Wazuh manager. It forwards rule 554 regardless of its level:

~~~xml
<!-- Second block: forwards selected rules regardless of their level (added for the PoC) -->
<integration>
  <name>custom-n8n</name>
  <hook_url>https://<N8N_HOST>/webhook/<WEBHOOK_PATH></hook_url>
  <api_key><WEBHOOK_TOKEN></api_key>
  <rule_id>554</rule_id>
  <alert_format>json</alert_format>
</integration>
~~~

`<N8N_HOST>`, `<WEBHOOK_PATH>` and `<WEBHOOK_TOKEN>` are placeholders. The real values are kept only on the Wazuh manager.

Without this block the alert from scenario 1 would stay in Wazuh and never reach n8n.

## Before a run

A run only makes sense if these are true:

- The workflow is published and active. Runs from the editor with pinned data do not count here.
- The trigger raises a Wazuh alert that the integration forwards: **level 12 or higher**, or a rule listed in the `rule_id` block (rule 554 for scenario 1). Anything else never reaches n8n.
- The agent is in `soc_asset_inventory`. Without exactly one matching row the alert cannot be closed automatically.
- The alert carries at least one external IP, domain, URL or hash. With nothing to enrich, the decision is always `analyst_review`.
- Each run produces a new Wazuh alert ID. TheHive rejects a second alert with the same `sourceRef`.

For every run we wrote down the same four things: the Wazuh alert, the n8n execution, the Decision output, and where the alert ended up.

## Scenario 1: benign alert, closed automatically

**Why this one:** this is the path that takes work off the analyst.

### What we did

On SOC-LIN-01, the admin deployed the jQuery library from the official Ubuntu package to the web root. This is a routine change: the file comes from a signed distribution package and its hash is publicly known as legitimate. The package was installed a few minutes earlier, so only the copy into the monitored directory triggered the alert

~~~bash
date -Is 
sudo mkdir -p /var/www/html/js
sudo cp /usr/share/javascript/jquery/jquery.min.js /var/www/html/js/jquery.min.js
~~~

<details>
<summary>Screenshot: commands run on SOC-LIN-01</summary>

![Trigger command on SOC-LIN-01](images/endpoints/92-s1-trigger-command.png)

*Figure 1. Terminal on SOC-LIN-01: start time recorded with `date -Is` (22:45:30), then the file copied to the web root.*

</details>

### Wazuh alert

| Field | Value |
|---|---|
| Rule | 554, File added to the system. |
| Level | 5 |
| Agent | SOC-LIN-01 |
| Alert ID | 1794692751.963227 |
| Time | 2026-11-14T22:45:51.315+01:00 |

![Wazuh alert for scenario 1](images/wazuh/92-s1-alert-554.png)

*Figure 2. Wazuh Discover: rule 554 on SOC-LIN-01 at 22:45:51, 21 s after the file was copied to the web root.*

### n8n execution

Execution 13918, 2026-11-14 22:45:52 (+01:00), took 21.5 s.
![n8n execution 13918](images/n8n/92-s1-execution.png)

*Figure 3. n8n execution 13918: the alert passes normalization, deduplication and enrichment (MISP, Team Cymru, CIRCL), then ends at* Count - TheHive Skipped*;* Create an alert *did not run.*

### Enrichment

| Source | Observable | What came back |
|---|---|---|
| MISP | observables extracted from the alert | no matching attributes (`attribute_count: 0`) |
| Cortex: TeamCymruMHR_1_0 | SHA-256, SHA-1, MD5 of the file | No record found` (not in the malware hash registry) |
| Cortex: CIRCLHashlookup_1_1 | SHA-256 `03378a72…588fd | known file `jquery.min.js` (89 037 B), `hashlookup:trust: 100`, 12 parent packages |

![CIRCL Hashlookup result for scenario 1](images/n8n/92-s1-circl-hashlookup.png)

*Figure 4. CIRCL Hashlookup in Cortex knows the file: same SHA-256 as in the Wazuh alert, `hashlookup:trust: 100`, found in 12 public packages.*

### Score and decision

| Field | Value |
|---|---|
| `decision.score` | 0 |
| `decision.verdict` | `likely_false_positive` |
| `decision.coverage` | 1 |
| `decision.analysis_complete` | true |
| `decision.outcome` | closed |
| `decision.reason_code` | omplete_low_risk_analysis |
| Asset | 006 SOC-LIN-01, criticality `standard`, auto-close allowed `true`|

Reason recorded by the workflow: *"The complete analysis produced a likely-false-positive verdict and the asset inventory allows automatic closure."*

![Decision output for scenario 1](images/n8n/92-s1-decision.png)

*Figure 5. Decision node output: the workflow closed the alert as a likely false positive and recorded why.*

### Where it ended up

`SOC_Audit` has the decision for execution 13918: outcome `closed`, reason `complete_low_risk_analysis`, score 0, recorded at 2026-11-14T22:46:14+01:00. The workflow took the `TheHive skipped` branch (`Count - TheHive Skipped`), and TheHive (organisation `soclab`) has no new alert after 22:45 for alert ID `1794692751.963227`.

![SOC_Audit rows for scenario 1](images/n8n/92-s1-audit-row.png)

*Figure 6. SOC_Audit for execution 13918: the decision is recorded correctly* 

### Issues found1

- **Duplicate items after enrichment.** `Summary Enrichments` emits 2 items for one alert, which then go through Scoring and Decision. Result: two `SOC_Audit` rows (id 21 and 22) and two `thehive_skipped` counters for one alert. The decision is correct, but the funnel counters are inflated, and for a non-closed outcome this could create two TheHive alerts. TODO issue #
- **`alert_id` is `null` in `SOC_Audit`**, while the counter table has the correct ID (`1794692751.963227`). TODO issue #


## Scenario 2: unclear alert, sent to the analyst

**Why this one:** the workflow must not guess. When the evidence is incomplete or mixed, a person decides.

### What we did

On SOC-WIN10-01, a standard user ran a copy of `curl.exe`, renamed to `updater.exe`, from their Temp folder. The program opened an HTTPS connection to 8.8.8.8. An unknown program in a user's Temp folder that talks to the internet is a common sign of a dropper; here it is a harmless, signed tool. Wazuh cannot tell the two apart, so the decision depends on the enrichment.

The default Wazuh ruleset has no rule for this behaviour, so we added rule `100921` (level 12) to `local_rules.xml` on the manager. Its level is high enough for the default integration block, so `ossec.conf` did not need another change. See [Notes](#notes).

~~~bash
Get-Date -Format o

Copy-Item C:\Windows\System32\curl.exe "$env:TEMP\updater.exe" -Force
 & "$env:TEMP\updater.exe" -s -o NUL --max-time 10 https://8.8.8.8/
~~~

<details>
<summary>Screenshot: commands run on SOC-WIN-10-01</summary>

![Trigger command on SOC-WIN-10](images/endpoints/92-s2-trigger-command.png)

*Figure 7. PowerShell on SOC-WIN10-01, standard user: start time recorded with `Get-Date` (12:05:XX), then `updater.exe` from the Temp folder connects to 8.8.8.8 and returns HTTP XXX.*

</details>

### Wazuh alert

| Field | Value |
|---|---|
| Rule | 100921, Executable from user Temp folder connected to 8.8.8.8:443 |
| Level | 12 |
| Agent | SOC-WIN10-01 (`007`) |
| Alert ID | 1794740716.37121389 |
| Time | 2026-11-15T12:05:16.926+01:00 |

![Wazuh alert for scenario 2](images/wazuh/92-s2-alert-100921.png)

*Figure 8. Wazuh Discover: rule 100921 on SOC-WIN10-01 at 12:05:16. The alert names the program (`…\Temp\updater.exe`) and the destination (8.8.8.8:443); its level 12 is enough for the integration to forward it to n8n.*

### n8n execution

Execution 16668, started 2026-11-15 12:05:19 (+01:00), took 8.961s s.

![n8n execution for scenario 2](images/n8n/92-s2-execution.png)
*Figure 9. n8n execution 16668: the alert is new (1), MISP is queried (2) and AbuseIPDB is the only Cortex analyzer that runs, because 8.8.8.8 is the only external observable (3). The decision is `analyst_review` (4), so the alert and its observable are created in TheHive (5).*


### Enrichment

| Source | Observable | What came back |
|---|---|---|
| MISP | `Updater.exe` (file name) | Event 952, *OSINT - Operation AppleJeus: Lazarus hits cryptocurrency exchange with fake installer and macOS malware*, `to_ids: true` (the same attribute three times) |
| MISP | `8.8.8.8` | Four attributes: event 1331 (`to_ids: false`), event 1351 (`to_ids: false`, warninglist: public DNS resolver), event 1411 *Fake 7-Zip downloads are turning home PCs into proxy nodes* (`to_ids: true`), and the lab event 1686 *SOC-LAB test IOCs – benign* (`to_ids: false`, comment "Google DNS - known benign") |
| Cortex: `AbuseIPDB_2_0` | `8.8.8.8` | `whitelisted: true`, confidence score 0, Google LLC, Content Delivery Network; still 71 reports (24 in the last 7 days), mostly *Port Scan* |

The other analyzers (Maltiverse, Team Cymru, CIRCL, VirusTotal) did not run: the alert has no hash, domain or URL. The internal source IP, the host name, the user and the file name were not sent to Cortex.

![MISP result for scenario 2](images/n8n/92-s2-enrichment-misp.png)

*Figure 10. Summary Enrichments, MISP part: 8.8.8.8 matches four attributes, one of them in the lab event "SOC-LAB test IOCs – benign". None has `to_ids: true`.*

![AbuseIPDB result for scenario 2](images/n8n/92-s2-enrichment-abuseipdb.png)

*Figure 11. AbuseIPDB marks 8.8.8.8 as whitelisted (Google LLC, confidence 0), yet lists 71 reports, mostly port scans. `processing.status` is `complete`: every source answered.*

### Score and decision

| Field | Value |
|---|---|
| `decision.score` | 44 (rule level +24, MISP +30, AbuseIPDB −10) |
| `decision.verdict` | `medium` |
| `decision.coverage` | 1 |
| `decision.analysis_complete` | true |
| `decision.outcome` | `analyst_review` |
| `decision.reason_code` | `analyst_review_required` |
| `decision.malicious_signals` | none |
| `decision.has_benign_misp_tag` | false |
| Asset | 007 SOC-WIN10-01, `workstation`, criticality `standard`, auto-close allowed `true` |

Reason recorded by the workflow: *"Scoring verdict "medium" requires analyst review."*

The asset would allow automatic closure, but only a `likely_false_positive` verdict can be closed, so the asset policy was never applied. The analysis was complete: the alert went to an analyst because of the evidence, not because a source was missing.

![Scoring output for scenario 2](images/n8n/92-s2-scoring.png)

*Figure 12. Scoring output: 44 points, verdict `medium`, coverage 1 (1). The rule level adds 24 (2), AbuseIPDB subtracts 10 because 8.8.8.8 is whitelisted (3), and MISP adds 30 for an IDS-flagged attribute matching the file name `Updater.exe` (4). The evidence points in opposite directions.*

![Decision output for scenario 2](images/n8n/92-s2-decision.png)

*Figure 13. Decision output: the analysis is complete and the asset allows auto-close, but the `medium` verdict sends the alert to an analyst (`analyst_review_required`). No malicious signal was found.*



### Where it ended up

TheHive (organisation `soclab`) has a new alert `~286867456`, status *New*, unassigned:

| Field | Value |
|---|---|
| Title | Analyst review on SOC-WIN10-01 (IOC 8.8.8.8): Executable from user Temp folder connected to 8.8.8.8:443 |
| Severity | Medium (2) |
| TLP / PAP | AMBER / AMBER (no source marking, default for unclassified data) |
| Source / Reference | Wazuh / `1794740716.37121389` (the Wazuh alert ID) |
| Tags | `analysis:complete`, `auto-triage`, `decision:analyst_review`, `severity:medium`, `source:wazuh`, `verdict:medium` |
| Observables | 1: `8.8.8.8` (ip) |

The description gives the analyst the decision, the asset, the source alert and every MISP and Cortex result, so the conflict is visible without opening n8n. Exactly one alert was created for this Wazuh alert.

![TheHive alert for scenario 2](images/thehive/92-s2-thehive-alert.png)

*Figure 14. TheHive alert in `soclab`: the title names the host and the IOC (1), severity Medium with TLP and PAP AMBER (2), and the reference is the Wazuh alert ID (3). The description repeats the automated decision (4) and lists the conflicting evidence: a MISP report on Lazarus that matches the file name (5) and an AbuseIPDB whitelist entry for 8.8.8.8 (6). The user name is redacted.*

### Notes

We added rule `100921` to `local_rules.xml` on the Wazuh manager. The default ruleset has no detection for a program in a user's Temp folder that opens an outbound connection, a common sign of a dropper. The rule matches Sysmon network events (event ID 3) from an `.exe` in `AppData\Local\Temp` to a non-private address. Its level 12 is enough for the default integration block to forward the alert to n8n.

~~~xml
<group name="local,sysmon,soc_detection,">
  <rule id="100921" level="12">
    <if_group>sysmon_event3</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)appdata.+local.+temp.+\.exe$</field>
    <field name="win.eventdata.initiated">^true$</field>
    <field name="win.eventdata.destinationIp" type="pcre2" negate="yes">^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)</field>
    <description>Executable from user Temp folder connected to $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>
</group>
~~~


**What the run showed about scoring:**

- **A file-name match counts as much as a hash.** `Updater.exe` matched an attribute in a public report on the Lazarus group and added 30 points, the same as a hash match. Common file names are weak indicators and should get a separate, lower weight in `score-config.json`.
- **The `soc-lab:benign` tag never reaches the decision.** The tag is set on the MISP event, but the MISP node returns only attribute tags, so `has_benign_misp_tag` is `false`. The search should include event tags (`includeEventTags`).
- **The IOC verdict in the TheHive description uses AbuseIPDB only.** 8.8.8.8 is described as "benign" although event 1411 lists it with `to_ids: true`.
- **The MISP references list repeats the same attribute three times.**

## Scenario 3: confirmed malicious, prioritised in TheHive

**Why this one:** a real hit from threat intelligence has to reach the analyst with the evidence already attached.

### What we did

TODO. We used a public test artefact (WICAR / EICAR), not real malware.

~~~bash
TODO command
~~~

### Wazuh alert

| Field | Value |
|---|---|
| Rule | TODO |
| Level | TODO |
| Agent | TODO |
| Alert ID | TODO |
| Time | TODO |

<!-- ![Wazuh alert for scenario 3](images/poc/TODO-s3-wazuh-alert.png) -->

### n8n execution

Execution TODO id, started TODO, took TODO s.

<!-- ![n8n execution for scenario 3](images/poc/TODO-s3-n8n-execution.png) -->

### Enrichment

| Source | Observable | What came back |
|---|---|---|
| MISP | TODO | TODO |
| Cortex: TODO analyzer | TODO | TODO |

### Score and decision

| Field | Value |
|---|---|
| `decision.score` | TODO |
| `decision.verdict` | TODO |
| `decision.coverage` | TODO |
| `decision.analysis_complete` | TODO |
| `decision.outcome` | TODO |
| `decision.reason_code` | TODO |
| `decision.malicious_signals` | TODO |
| Asset | TODO |

<!-- ![Decision output for scenario 3](images/poc/TODO-s3-decision.png) -->

### Where it ended up

TODO: the TheHive alert (title, severity, observables, which of them are marked as IOC).

<!-- ![TheHive alert for scenario 3](images/poc/TODO-s3-thehive-alert.png) -->

### Notes

TODO

## How long it took

Time from the event on the machine to the final effect. Clocks in the lab are not perfectly in sync, so treat differences of a few seconds as noise.

| # | Event | Wazuh alert | n8n started | n8n finished | Total |
|---|---|---|---|---|---|
| 1 | TODO | TODO | TODO | TODO | TODO |
| 2 | TODO | TODO | TODO | TODO | TODO |
| 3 | TODO | TODO | TODO | TODO | TODO |

## What this does not prove

<!-- Keep what is true, delete the rest, add your own. -->

- These are three hand-picked alerts, not a load test. Alert volumes over a full day are in [`metrics/`](../metrics/README.md).
- The scoring thresholds are lab values and were not calibrated on real traffic.
- `closed` is recorded in `SOC_Audit` only. The workflow does not change the alert status in Wazuh.
- TODO

## Run it again

1. Check the list in [Before a run](#before-a-run).
2. Run the command from the scenario.
3. In n8n open **Executions** and pick the run that matches the time.
4. Compare the Decision output with the table in that scenario.
5. Check TheHive (scenarios 2 and 3) or the `SOC_Audit` table (scenario 1).

If no execution shows up, start with the integration log on the Wazuh manager. The usual suspects are in the troubleshooting tables of the [triage runbook](runbooks/n8n-triage.md).

## Related

- [n8n triage runbook](runbooks/n8n-triage.md): how every node is built and tested
- [ADR 0003](decisions/0003-n8n-triage-workflow.md): why the workflow looks the way it does
- [First end-to-end test](e2e-test.md): the five-node version from 31 October 2026 (#55)