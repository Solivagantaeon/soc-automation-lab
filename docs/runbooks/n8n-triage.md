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

**What it does:** Receives Wazuh alerts as JSON over an authenticated HTTP POST request and immediately acknowledges receipt.

**How to build it:**

1. Add a Webhook node to the n8n workflow.
2. Set **HTTP Method** to `POST`.
3. Set **Authentication** to `Header Auth` and select the existing `Wazuh webhook token` credential.
4. Set **Respond** to `Immediately`.
5. Publish the workflow and configure the Wazuh `custom-n8n` integration to send JSON alerts to the production Webhook URL.
6. Set the Wazuh integration threshold to level 12. This forwards alerts at level 12 and above.

**Configure the Wazuh manager:**

`custom-n8n` is the custom integration script installed on the Wazuh manager at `/var/ossec/integrations/custom-n8n`. Wazuh invokes it for alerts matching the integration block. The script forwards each alert as JSON to the n8n production Webhook, using the `<api_key>` value as the authentication token.

Use the sanitized [Wazuh integration template](../../detection/wazuh/integrations/n8n-integration.xml). Add its `<integration>` block to `/var/ossec/etc/ossec.conf`, inside the existing `<ossec_config>` element. On the Wazuh manager, replace `N8N_WEBHOOK_URL` with the production Webhook URL and `N8N_WEBHOOK_TOKEN` with the token configured in the n8n Header Auth credential.

The `<level>12</level>` setting is a minimum threshold, so Wazuh forwards alerts at level 12 and above. `<alert_format>json</alert_format>` sets the alert format to JSON. Keep the populated URL and token on the Wazuh manager; do not commit them.

After saving the configuration, restart the Wazuh manager and check its status:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

The status command should return:

```text
active
```

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

**Owner:** @

## 3. Dedup

**Owner:** @

## 4. MISP and Cortex

**Owner:** @

## 5. Score

**Owner:** @

## 6. Decision

**Owner:** @

## 7. Failure handling

**Owner:** @

## 8. TheHive

**Owner:** @

## 9. Audit

**Owner:** @

## 10. Counters

**Owner:** @

## Full test

**Owner:** @Solivagantaeon
