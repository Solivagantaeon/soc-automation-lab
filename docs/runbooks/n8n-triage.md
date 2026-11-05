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

**Owner:** @MKonrad-afk


## 2. Normalize

**Owner:** @84rtek

**What it does:** Converts raw Wazuh, Elasticsearch, and Shuffle-wrapper alert payloads into a common JSON structure and extracts observables for downstream processing.

**How to build it:**

1. Add a **Code** node immediately after the Webhook node in the Skeleton workflow.
2. Name the node `Normalize` (or keep the current node name if it is already referenced elsewhere in the workflow).
3. Set **Mode** to `Run Once for All Items`.
4. Set **Language** to `JavaScript`.
5. Paste the Normalize v1.2 JavaScript implementation into the code editor.
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

Add screenshots of the Code node configuration and representative test outputs to `docs/images/n8n/`. Suggested filenames:

- `67-normalize-settings.png` – Code node showing `Run Once for All Items` and JavaScript.
- `67-normalize-network-test.png` – Network / DNS / HTTP output.
- `67-normalize-hashes-test.png` – Sysmon hashes output.
- `67-normalize-registry-test.png` – Windows Registry output.
- `67-normalize-no-ioc-test.png` – No-IOC output showing `primary_observable: "-"`.

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
