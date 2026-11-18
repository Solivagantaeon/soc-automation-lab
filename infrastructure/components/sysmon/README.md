## 4. Sysmon — Windows endpoint telemetry

### 4.1 Purpose and deployment

Sysmon provides detailed Windows activity records, including process creation, process access, image loading, file creation and registry operations. Sysmon runs on the Windows hosts as a Windows service and writes to the `Microsoft-Windows-Sysmon/Operational` event channel. Wazuh agents collect matching Windows Event Channel records and forward them to Wazuh.

| Host | VM ID | Private IP | OS | Sysmon version | Wazuh agent |
|---|---|---|---|---|---|
| `SOC-DC01` | `101` | `10.10.10.200` | Windows Server 2022 | `15.22` | `4.14.9` |
| `SOC-WIN10-01` | `102` | `10.10.10.150` | Windows 10 | `15.15` | `4.14.9` |
| `SOC-WIN11-AI` | `103` | `10.10.10.171` | Windows 11 | `15.21` | `4.14.9` |

**Installation method:** native Sysmon Windows service, manually deployed with the `sysmon-modular` Balanced configuration. The Windows 10 host uses Sysmon schema 4.90; the domain controller and Windows 11 use schema 4.91. The deployment record, configuration hashes, and inspection commands are in [`../../../detection/sysmon/README.md`](../../../detection/sysmon/README.md).

### 4.2 Ports, authentication and APIs

- Sysmon itself logs locally and does **not** require an inbound network port or external REST API.
- The Event Log collection interface is `Microsoft-Windows-Sysmon/Operational` on each host.
- The Wazuh agent forwards selected events to `10.10.20.243:1514/TCP` using its enrolled agent identity/key.
- Managing the service or configuration requires appropriate Windows administrative privileges; a Sysmon application API key is not involved.

### 4.3 Startup and standalone verification

On an endpoint with an authorized PowerShell session:

```powershell
Get-Service Sysmon,Sysmon64 -ErrorAction SilentlyContinue
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
    Select-Object LogName, IsEnabled, RecordCount
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} -MaxEvents 3 | Select-Object TimeCreated, Id, ProviderName
```

Service administration uses Windows Services / PowerShell (`Start-Service` or `Restart-Service` on the installed service name). The Sysmon executable's `-s` option displays its installed event schema; use the endpoint's installation/runbook record for version-specific deployment and configuration commands.

**Independent check:** the local Sysmon Operational channel contains freshly generated Event ID 1 process-creation records, regardless of whether the Wazuh manager is available.

**Wazuh ingestion verification (18 October 2026):** the following queries returned Sysmon-channel Wazuh alerts in a 90-day search window:

```text
agent.name: "SOC-WIN10-01" AND data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"
agent.name: "SOC-WIN11-AI" AND data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"
```

| Host | Alert matches in 90-day window | Observed example |
|---|---:|---|
| `SOC-WIN10-01` | **63** | Sysmon Event ID 10, process access; Wazuh rule `92910` |
| `SOC-WIN11-AI` | **3,127** | Sysmon Event ID 1, process creation; Wazuh rule `92052` |

These are **Wazuh alerts matching the filter**, not total Sysmon event counts. The windows-to-Wazuh collection path is established by the event provider, channel, agent name and timestamp fields.

### 4.4 Problems and corrective procedures

**Sysmon Event ID 255 — telemetry reliability:** a seven-day Wazuh search on 18 October 2026 matched **73** Sysmon error alerts: **72** from `SOC-WIN11-AI` and **1** from `SOC-WIN10-01`.

- `QUEUE`: driver queue reported dropped events (including registry events and image loads). Dropped events are an observability gap, even if some other alerts are being collected normally.
- `IMAGE_LOAD`: Sysmon reported `Failed to find process image name` on Windows 11.
- **Investigation/correction:** review the active sysmon-modular configuration, reduce particularly noisy event selections where appropriate, review endpoint resource utilization and Sysmon diagnostic logs, then repeat Event ID 255 monitoring after changes. Do not treat this diagnostic as a malware verdict.

To reproduce the Wazuh-side error search:

```text
data.win.system.eventID: "255" AND (agent.name: "SOC-WIN10-01" OR agent.name: "SOC-WIN11-AI")
```

For process-access detection rule `92910`, a sample involving `OneDrive.exe` accessing `Explorer.EXE` was classified by the rule as possible process injection. It is a detection requiring triage, not proof of malicious process injection.

### 4.5 Evidence and related files

- Sysmon deployment notes: [`../../../detection/sysmon/README.md`](../../../detection/sysmon/README.md)
- Agent configuration: [`../../../detection/wazuh/agent-config/agent.conf`](../../../detection/wazuh/agent-config/agent.conf)
- Sanitized sample record: [`../../../samples/alerts/wazuh/sysmon-92213-exe-in-temp.json`](../../../samples/alerts/wazuh/sysmon-92213-exe-in-temp.json)

---
