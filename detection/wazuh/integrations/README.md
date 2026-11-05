# Wazuh integrations

This directory contains integration files used by the Wazuh manager.

| File | Purpose |
|---|---|
| [`custom-n8n`](custom-n8n) | Custom executable that forwards matching Wazuh alerts to n8n. See [The `custom-n8n` integration](#the-custom-n8n-integration). |
| [`n8n-integration.xml`](n8n-integration.xml) | Sanitized manager-side configuration for n8n. See [n8n integration configuration](#n8n-integration-configuration). |
| [`shuffle-integration.xml`](shuffle-integration.xml) | Configuration template for the separate Shuffle integration. See [Shuffle integration configuration](#shuffle-integration-configuration). |

## The `custom-n8n` integration

`custom-n8n` is a custom integration script, not a built-in Wazuh integration. The `<name>custom-n8n</name>` setting tells Wazuh to run the `custom-n8n` executable for alerts that match the integration block.

Wazuh passes the alert file, API token, and Webhook URL to the script. The script reads the full alert as JSON and sends it to n8n in an HTTPS POST request. It sends the token in the `X-Wazuh-Token` header and writes the delivery result to `/var/ossec/logs/integrations.log`.

The script uses `/var/ossec/etc/n8n-ca.crt` to verify the n8n certificate when that file exists. If it does not exist, the script uses the system certificate store. The script uses Wazuh's embedded Python interpreter and the `requests` package.

Although this file contains Python code, it has no `.py` suffix because Wazuh expects the executable filename to match the `<name>` value in the integration block. The shebang (`#!/var/ossec/framework/python/bin/python3`) tells the system which interpreter to use. Keep the filename `custom-n8n` unless you also change the integration name and installed path.

## Configuration files

### n8n integration configuration

[`n8n-integration.xml`](n8n-integration.xml) contains the sanitized Wazuh `<integration>` block that invokes `custom-n8n`. It sends JSON alerts at level 12 and above. For installation, see [Install on the Wazuh manager](#install-on-the-wazuh-manager). The n8n node settings and lab test are documented in the [n8n triage runbook](../../../docs/runbooks/n8n-triage.md#1-webhook).

### Shuffle integration configuration

[`shuffle-integration.xml`](shuffle-integration.xml) is a separate Wazuh-to-Shuffle configuration. It uses the `shuffle` integration name and forwards JSON alerts at level 3 and above. It does not configure or invoke `custom-n8n`.

For the existing Shuffle setup, see the [Wazuh–Shuffle integration runbook](../../../docs/runbooks/wazuh-integration-shuffle.md).

## Install on the Wazuh manager

1. Copy the `custom-n8n` script to the Wazuh manager. Install it at the path expected by Wazuh, with the required owner and permissions:

   ```bash
   sudo install -o root -g wazuh -m 750 \
     /path/to/custom-n8n \
     /var/ossec/integrations/custom-n8n
   ```

2. If the n8n certificate is not trusted by the system certificate store, install the trusted CA certificate at `/var/ossec/etc/n8n-ca.crt`. The certificate must be available on the Wazuh manager; it is not included in this repository.

3. Add the block from [`n8n-integration.xml`](n8n-integration.xml) to `/var/ossec/etc/ossec.conf`, inside the existing `<ossec_config>` element. Replace the placeholders on the manager with the production Webhook URL and token. The configured minimum alert level is 12, and the alert format is JSON.

4. Restart the Wazuh manager and confirm that it is active:

   ```bash
   sudo systemctl restart wazuh-manager
   sudo systemctl is-active wazuh-manager
   ```

   The expected status is `active`.

Keep the populated Webhook URL and token in the manager configuration. Do not commit them to the repository.

## Verify delivery

Check `/var/ossec/logs/integrations.log` for a successful `custom-n8n: sent alert ...` entry. Then check n8n's execution history for a new successful production execution.

For the Webhook node settings and the end-to-end lab test, see the [n8n triage runbook](../../../docs/runbooks/n8n-triage.md#1-webhook).
