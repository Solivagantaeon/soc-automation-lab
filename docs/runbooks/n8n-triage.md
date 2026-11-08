# Runbook: n8n triage workflow

How to build, test and fix every node of the  workflow. The reasons behind each choice are in ADR 0003.



<!--
How to fill in your stage:
- One subsection per node, in the order the nodes run. Copy the node template below.
- Screenshot every node's settings and one successful test. Save them as
  docs/images/n8n/<issue>-<node-name>.png and check them with scripts/check_images.py --ocr.
  No keys, tokens, webhook URLs or real usernames on screenshots.
- Settings table: write the value you typed or selected. For credentials, write only the credential name.
- "If it does not work": every problem you hit while building, with what fixed it.

Node template:

#### Node: <name in n8n>

**What it does:** one sentence.

**How to build it:**
1. ...
2. ...

![<what the screenshot shows>](../images/n8n/<issue>-<node-name>.png)

| Setting | Value |
|---|---|
| | |

**How to test it:** what you send, what you should see.

![<what the screenshot shows>](../images/n8n/<issue>-<node-name>-test.png)

**If it does not work:**

| What you see | Cause | Fix |
|---|---|---|
| | | |
-->

## 1. Webhook
**What it does:** Receives Wazuh alerts as JSON over an authenticated HTTP POST request and immediately acknowledges receipt.

**How to build it:**

1. Add a Webhook node to the n8n workflow.
2. Set **HTTP Method** to `POST`.
3. Set **Authentication** to `Header Auth` and select the existing `Wazuh webhook token` credential.
4. Set **Respond** to `Immediately`.
5. Publish the workflow and configure the Wazuh `custom-n8n` integration to send JSON alerts to the production Webhook URL.
6. Set the Wazuh integration threshold to level 12. This forwards alerts at level 12 and above.

**Wazuh manager integration:**

The Wazuh manager applies the alert-level filter before sending alerts to n8n. Its `custom-n8n` integration block selects JSON alerts at level 12 and above, then invokes the custom script to forward them to the Webhook. The n8n Webhook handles the incoming request; it does not set this threshold.

The sanitized [Wazuh integration template](../../detection/wazuh/integrations/n8n-integration.xml) shows the manager-side configuration. For the script installation, CA setup, and delivery verification steps, see the [Wazuh integrations README](../../detection/wazuh/integrations/README.md).

**Webhook node settings:**
| Setting | Value |
|---|---|
| HTTP Method | `POST` |
| Authentication | `Header Auth` |
| Credential | `Wazuh webhook token` |
| Respond | `Immediately` |
| Wazuh alert format | JSON |
| Wazuh minimum level | `12` |

![Webhook node settings: POST, Header Auth, and Respond Immediately](../images/n8n/66-webhook.png)



**How to test it:** Generate a long-URL test request from Kali to the lab web server. Wazuh should create rule `31115` at level `13`, and n8n should record a successful execution after receiving the alert.

To generate such test - Run this on Kali with `python3`:

```python
python3 - <<'PY'
from urllib.request import urlopen

url = "http://10.10.10.100/?probe=" + "A" * 8000

with urlopen(url, timeout=10) as response:
    print(f"HTTP {response.status}")
PY
```

![Wazuh recorded rule 31115 for the long-URL test](../images/n8n/66-webhook-wazuh-alert.png)

![Successful n8n execution for the test alert](../images/n8n/66-webhook-test.png)

![Webhook output showing the received Wazuh alert](../images/n8n/66-webhook-payload.png)


The test on 2026-11-02 produced the Wazuh alert at 23:36:28 and a successful n8n execution at 23:36:30, completed in 4.066 seconds.


**If it does not work:**

| What you see | Cause | Fix |
|---|---|---|
| Wazuh records the alert, but no n8n execution appears | The workflow is not published, or Wazuh is sending to the test URL | Publish the workflow and configure Wazuh to use the production Webhook URL |

## 2. Normalize

**Owner:** @84rtek

**What it does:** Converts raw Wazuh, Elasticsearch, and Shuffle-wrapper alert payloads into a common JSON structure and extracts observables for downstream processing.

**How to build it:**

1. Add a **Code** node immediately after the Webhook node in the Skeleton workflow.
2. Name the node `Normalize` (or keep the current node name if it is already referenced elsewhere in the workflow).
3. Set **Mode** to `Run Once for All Items`.
4. Set **Language** to `JavaScript`.
5. Copy the contents of [`normalize-v1.2.js`](../../soar/n8n/nodes/normalize-v1.2.js) into the Code node editor.
6. Connect the Code node output to the next workflow stage.
7. Save the workflow.

**Code node settings:**

| Setting | Value |
|---|---|
| Node type | `Code` |
| Mode | `Run Once for All Items` |
| Language | `JavaScript` |
| Implementation | Normalize v1.2 |

**Input formats:**

| Format | Recognition |
|---|---|
| Raw Wazuh | Unwrapped Wazuh alert JSON |
| Elasticsearch | Alert document containing `_source` |
| Shuffle wrapper | Payload containing `all_fields` |

**Normalized output:**

The node produces one normalized alert object per input item. Main fields include:

| Field | Purpose |
|---|---|
| `alert_id` | Original alert identifier |
| `timestamp` | Event timestamp |
| `source_format` | Detected input format: `raw`, `elasticsearch`, or `shuffle-wrapper` |
| `rule` | Rule ID, level, description, groups, and MITRE data |
| `agent` | Agent ID, name, and IP |
| `location`, `decoder` | Event source context |
| `syscheck`, `signature`, `command_line`, `full_log` | Additional event context when available |
| `observables` | Extracted observables with type, value, source field, and internal flag |
| `primary_observable` | Selected primary observable, or `-` when none is eligible |
| `dedup_key` | Key prepared for the separate Dedup stage |

**Observable types:**

| Type | Examples |
|---|---|
| `ip` | IPv4 and IPv6 addresses |
| `domain` | Domain names |
| `url` | Full URLs |
| `uri_path` | URI paths |
| `hash` | MD5, SHA1, SHA256 |
| `filename` | File names |
| `registry_key` | Windows registry paths |
| `user` | User names |
| `hostname` | Host names |
| `other` | Other retained values, including User-Agent |

Internal endpoint data, such as `agent.ip`, remains available in `observables` with `internal: true`. It is not automatically treated as an external IOC or selected as `primary_observable`. When no eligible IOC is present, the primary value is `-`.

The `dedup_key` is generated during normalization. This does not perform duplicate detection; that is the responsibility of the Dedup stage.

**How to test it:**

Use Webhook mock data (or the n8n node's pinned/mock input data) to execute the Code node against each of the six test scenarios below. These are functional tests of Normalize and do not test live Webhook delivery or Header Auth.

| Test | Input scenario | Expected result |
|---|---|---|
| 1 | Network / DNS / HTTP | Extract IP, domain, URL, filename, user, and User-Agent |
| 2 | Sysmon / hashes | Extract MD5, SHA1, SHA256, file path, command line, and user |
| 3 | Syscheck / Windows Registry | Extract registry path as `registry_key` |
| 4 | Raw Wazuh | Recognize `raw` format and extract external IP |
| 5 | Shuffle wrapper | Recognize `shuffle-wrapper` and extract SHA256 and filename |
| 6 | Alert without IOC | Preserve agent context and return `primary_observable: "-"` |

All six scenarios passed with Normalize v1.2.

Example expected output for the no-IOC scenario:

```json
{
  "source_format": "raw",
  "observables": [
    {
      "dataType": "ip",
      "data": "10.10.10.171",
      "field": "agent.ip",
      "internal": true
    },
    {
      "dataType": "other",
      "data": "SYSTEM",
      "field": "data.win.eventdata.user",
      "internal": true,
      "kind": "user"
    },
    {
      "dataType": "hostname",
      "data": "SOC-WIN11-AI",
      "internal": true
    }
  ],
  "primary_observable": "-",
  "dedup_key": "soc:dedup:100506::004:-"
}
```


**Evidence:**

The following screenshots show the Normalize configuration, its position in the workflow, and the mapping of the normalized primary observable into the MISP search node.

![Normalize Code node settings](../images/n8n/67-normalize-settings.png)

![Normalize node in the n8n workflow](../images/n8n/67-normalize-workflow.png)

![MISP search using the normalized primary observable](../images/n8n/67-normalize-misp-mapping.png)


Only include screenshots that have actually been captured and checked into the repository.

**If it does not work:**

| What you see | Cause | Fix |
|---|---|---|
| Code node reports an error when using `$input.all()` | The node is not configured to process all input items | Set Mode to `Run Once for All Items` |
| `source_format` is unexpected | Input payload does not match the expected raw, Elasticsearch, or Shuffle-wrapper structure | Inspect the incoming JSON and confirm its wrapper/field names |
| No IOC is found | The alert does not contain an eligible external observable, or the relevant field is not covered by the extractor | Inspect the original payload; keep internal agent context distinct from external IOC data |
| Registry path is treated as a filename | The input field is not recognized as a Windows registry path | Check the source field and the registry detection logic |



## 3. Dedup

**Owner:** @arturesturemkuros

**What it does:** Detects an alert that was already seen within the last 3 minutes and stops it before MISP and Cortex, so a repeated alert is not processed twice.

**How to build it:**

1. Open the workflow and remove the connections that leave the Normalize node (to the MISP search node and to Split Cortex Observables).
2. Add a **Code** node after Normalize and name it `Dedup`.
3. Set **Mode** to `Run Once for All Items` and **Language** to `JavaScript`.
4. Paste the code below into the editor.
5. Add an **If** node after Dedup and name it `New Alert?`.
6. In the condition, set the value to `{{ $json.is_duplicate }}` and the operator to **Boolean -> is false**.
7. Connect the **true** output to both the MISP search node and Split Cortex Observables. Leave the **false** output empty.
8. Save and publish the workflow.

```javascript
const WINDOW_MS = 3 * 60 * 1000; // dedup window, 3 minutes

const now = Date.now();
const store = $getWorkflowStaticData('global');
store.dedup = store.dedup ?? {};

// entries older than the window are removed
for (const [k, v] of Object.entries(store.dedup)) {
  if (now - v.first_seen > WINDOW_MS) delete store.dedup[k];
}

return $input.all().map(item => {
  const key = item.json.dedup_key;
  const hit = store.dedup[key]; // undefined when the key was not seen

  if (hit) {
    hit.count++;
    return { json: { ...item.json, is_duplicate: true,
      duplicate_count: hit.count, first_seen: hit.first_seen } };
  }

  store.dedup[key] = { first_seen: now, count: 1 };
  return { json: { ...item.json, is_duplicate: false, duplicate_count: 1 } };
});
```

**Dedup node settings:**

| Setting | Value |
|---|---|
| Node type | `Code` |
| Mode | `Run Once for All Items` |
| Language | `JavaScript` |
| Window (`WINDOW_MS`) | `7 * 60 * 1000` (7 minutes) |
| State | `$getWorkflowStaticData('global')`, key `dedup` |
| Input | `dedup_key` from Normalize |
| Output fields added | `is_duplicate`, `duplicate_count`, `first_seen` (duplicates only) |

**New Alert? node settings:**

| Setting | Value |
|---|---|
| Node type | `If` |
| Condition | `{{ $json.is_duplicate }}` -> Boolean -> is false |
| true output | MISP search node and Split Cortex Observables |
| false output | Not connected (duplicate, execution ends) |

**The key:**

Normalize builds the key as `soc:dedup:<rule.id>:<signature_id>:<agent.id>:<source_ip>:<primary_observable>`. The source IP includes private addresses. For web rules (groups `web`, `accesslog`, `web_scan`) with a source IP, the last element is `*`, so the path is not part of the key. Normalize also outputs `source_ip` and `dedup_mode` (`default` or `web-source`) to show which form was used.

**How to test it:**

Static data is not saved when the workflow is run manually, so a duplicate is only recognised inside one execution. Put all test alerts into one pinned Webhook output and run the workflow once.

1. Open the Webhook node, choose **Edit Output** and paste the seven test alerts (see the table).
2. Click **Execute workflow**.
3. Open the Dedup output and check `is_duplicate` and `duplicate_count` for every item.
4. Open New Alert? and check how many items went to each branch.

| Test | Input scenario | Expected result |
|---|---|---|
| 1 | New alert, public source IP | `is_duplicate: false`, `dedup_mode: default` |
| 2 | Same alert again | `is_duplicate: true`, `duplicate_count: 2` |
| 3 | Web rule, private source IP, path `/dvwa/admin` | `is_duplicate: false`, `dedup_mode: web-source` |
| 4 | Same web rule and source IP, other path | `is_duplicate: true`, same key as test 3 |
| 5 | Same web rule, different source IP | `is_duplicate: false`, different key |
| 6 | No observables, no source IP | `is_duplicate: false`, `primary_observable: "-"` |
| 7 | Same alert as test 6 again | `is_duplicate: true` |

Expected: **4 items on the true branch and 3 items on the false branch.**

The test was run on 2026-11-08 and gave this result. Window expiry was not tested, because it needs the active workflow. To test it, send the same alert twice to the production Webhook URL, wait longer than 3 minutes and send it again; the last one should pass as new.

**Evidence:**

The screenshots show the workflow with the new nodes, the Dedup output for a duplicate, and the New Alert? split.

![The n8n workflow with the Dedup and New Alert? nodes after Normalize](../images/n8n/68-dedup-workflow.png)

*Figure. Dedup and New Alert? placed between Normalize Alert and the MISP and Cortex branches.*

![Dedup output showing is_duplicate true and duplicate_count 2](../images/n8n/68-dedup-output.png)

*Figure. Dedup output for a repeated alert, with `is_duplicate: true` and `duplicate_count: 2`.*

![New Alert? output showing 4 items on true and 3 items on false](../images/n8n/68-dedup-if.png)

*Figure. New Alert? result for the seven test alerts: 4 items continue (true), 3 duplicates stop (false).*

**If it does not work:**

| What you see | Cause | Fix |
|---|---|---|
| Every alert is new, even an identical one sent in a separate run | Static data is not saved on manual runs | Put all test alerts into one pinned output and execute once, or test on the active workflow with the production Webhook URL |
| Duplicates are not recognised on the active workflow | The workflow is not published, or alerts are sent to the test URL | Publish the workflow and send to the production Webhook URL |
| New Alert? reports a type error | `is_duplicate` is missing, because the If node is not connected to the Dedup output | Connect Dedup to New Alert? and check the Dedup output |
| Web alerts are not merged and `dedup_mode` is `default` | The alert has no web group in `rule.groups`, or no source IP | Check `rule.groups` and `source_ip` in the Normalize output and add the group to `WEB_GROUPS` in Normalize |
| Dedup fails with a missing `dedup_key` | The node is not connected after Normalize, or Normalize failed | Check the connection and the Normalize output |
| Different events from one rule and agent are dropped | The alerts have no observables and no source IP, so they share one key | Known limitation; check the original alerts and consider adding a field to the key |
| An alert is dropped as a duplicate, but its first copy failed in a later stage | The key is stored before enrichment | Wait until the window ends and resend |

## 4. MISP and Cortex

**Owner:** @MKonrad-afk

## 5. Score

**Owner:** @arturesturemkuros

## 6. Decision

**Owner:** @arturesturemkuros

## 7. Failure handling

**Owner:** @p4chatek

## 8. TheHive

**Owner:** @Solivagantaeon

## 9. Audit

**Owner:** @Maartini22

## 10. Counters

**Owner:** @Maartini22

## Full test

**Owner:** @Solivagantaeon
