# Wazuh rules

Custom rules deployed to `/var/ossec/etc/rules/` on the Wazuh manager (`wazuh-master`, Wazuh 4.14.9).
The manager loads every file in that folder through `<rule_dir>etc/rules</rule_dir>` in `ossec.conf`,
so no `<include>` is needed.

| File | Purpose | Rules |
|---|---|---|
| [`local_rules.xml`](local_rules.xml) | Lab tests, enrichment test indicators, PoC detection | 7 |
| [`local_rules_noise_reduction.xml`](local_rules_noise_reduction.xml) | Noise reduction (v2) and Sysmon availability alerts | 30 |

The files in this folder are the files deployed on the manager. Rule IDs use the custom range
**100000-120000**. Comments and descriptions are in English; the logic of every rule is the same as
on the manager before the translation (checked by parsing both versions and comparing every element
except `<description>`).

## Detection and test rules (`local_rules.xml`)

| Rule | Level | Detects | Test | Evidence |
|---|---|---|---|---|
| 100001 | 5 | Example shipped with Wazuh: failed SSH login from 1.1.1.1 | - | - |
| 100900 | 12 | Any log line containing `SOC_TEST_CRITICAL` | `wazuh-logtest`, see [Test](#test) | - |
| 100901 | 7 | Any log line containing `SOC_TEST_MID` | `wazuh-logtest`, see [Test](#test) | - |
| 100910 | 13 | Sysmon DNS query (61650) for `wicar.org` or a subdomain - malware test domain | `Resolve-DnsName wicar.org` on a Windows agent | - |
| 100911 | 13 | Sysmon network connection (61605, 92101) to the MISP test IOC 199.34.228.69 | connection to that IP from a Windows agent | - |
| 100920 | 12 | SSH login attempt with the non-existent user `soc-poc-benign` (5710) - controlled benign event | `ssh soc-poc-benign@<linux-agent>` | - |
| 100921 | 12 | Executable in the user's `AppData\Local\Temp` opened an outbound connection to a non-private address (Sysmon EID 3), T1105 | renamed `curl.exe` in `%TEMP%` connecting to a public address | [PoC scenario 2](../../../docs/validation/poc-live-workflow.md), [alert](../../../docs/images/wazuh/92-s2-alert-100921.png) |

Rules 100910, 100911 and 100921 have level 12 or higher, so the `custom-n8n` integration (`<level>12</level>`)
forwards them to n8n.\

## Noise reduction (`local_rules_noise_reduction.xml`)

All rules below have `level="0"`: Wazuh drops the matching event before it reaches `alerts.json`.
Each one is scoped to the exact process, path or command line seen in the lab, so the same base rule
still fires for anything else. The comments in the file explain every choice.

| Section | Rules | Base rule(s) | Suppressed |
|---|---|---|---|
| 1. Windows logons/logoffs | 100100-100103 | 60106, 60137 | Network logons of machine accounts, service logons of built-in accounts, DWM/UMFD virtual accounts, network/service logoffs |
| 2. Event 4688 | 100110 | 67027 | Process creation already covered by Sysmon EID 1 |
| 3. Sysmon EID 7 | 100120-100125 | 92154, 92157 | `taskschd.dll` loaded by system processes, Defender, Edge Update, servicing, SoftLandingTask; signed DISM providers loaded by DismHost |
| 4. Sysmon EID 1 | 100130 | 92058 | `sdbinst.exe` started by Windows maintenance |
| 5. Windows system events | 100140, 100141 | 60642, 61104 | Software Protection restarts, start-type changes of update services |
| 6. Manager PAM | 100150 | 5501, 5502 | PAM sessions of `sudo` (duplicate of 5402) |
| 7. PowerShell test files | 100160 | 92200-92205 | `__PSScriptPolicyTest_*` files created at every PowerShell start |
| 8. Wazuh agent | 100170-100173 | Sysmon EID 1 group, 92052 | Exact SCA scan commands and the active-response restart, only with the agent as parent |
| 9. Installers/updates | 100175-100177 | 92207, 92217-92219 | Edge shortcuts, Windows Update downloads, servicing writes |
| 10. Sysmon EID 13 | 100180, 100181 | 92307 | Edge firewall rule and `elevation_service` ImagePath |
| 11. Registry FIM | 100185 | 594, 597, 598, 750-752 | Per-user service instances (`CDPUserSvc_<hex>`); other FIM exclusions are in [`agent.conf`](../agent-config/agent.conf) |
| 12. Suricata | 100186 | 86601 | `ET INFO ... azurewebsites .net` lookups from the DC, which is the lab DNS resolver |
| 14. OneDrive | 100922 | 92910 | OneDrive client/updater accessing `explorer.exe` (272 level-12 alerts in 8 s after a first logon) |

Compensating control (section 13): rules **100190** and **100191** (level 10, T1562.001) raise an alert when the
Sysmon service stops, so suppressing Sysmon noise cannot hide a disabled Sysmon.

The list at the end of the file names alerts that were reviewed and **deliberately not suppressed**
(e.g. 92213, tampering with Defender and Sysmon registry keys).

The alert counts in [`metrics/`](../../../metrics/README.md) were measured with v2 before rule 100922
was added; the SHA-256 given there is the file as deployed at that time.

## Deploy

On the Wazuh manager (commands as root, `sudo -i`). Copy the two files from the repository to the
manager first, e.g. `scp detection/wazuh/rules/*.xml <user>@<manager>:/tmp/`.

```bash
mkdir -p /root/rules-backup-$(date +%F)
cp -p /var/ossec/etc/rules/*.xml /root/rules-backup-$(date +%F)/
install -o root -g wazuh -m 660 /tmp/local_rules.xml /tmp/local_rules_noise_reduction.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-analysisd -t          # configuration test, no output = OK
systemctl restart wazuh-manager
systemctl is-active wazuh-manager          # active
```

Keep the backup outside `/var/ossec/etc/rules/`: the manager loads every file in that folder.

Repository = manager check:

```bash
sha256sum /var/ossec/etc/rules/local_rules*.xml     # compare with sha256sum on the repository files
```

## Test

```bash
echo 'Nov 24 12:00:00 soc-lin-01 soc-test: SOC_TEST_MID pipeline check' | /var/ossec/bin/wazuh-logtest
```

Expected in phase 3: `id: '100901'`, `level: '7'`, `description: 'SOC lab test: mid test event'`.
Replace `SOC_TEST_MID` with `SOC_TEST_CRITICAL` to test 100900 (level 12).

Windows rules (Sysmon, eventchannel) cannot be tested with a pasted log line: trigger the event on the
agent (see the Test column above) and look for the rule ID in *Threat Hunting* / *Discover*.
After changing noise reduction, compare the alert count per rule before and after in `metrics/`.
