# Sysmon

Endpoints use Sysmon 15.x with the **sysmon-modular** "Balanced" configuration
(https://github.com/olafhartong/sysmon-modular). Keep a reference to the exact upstream commit/config used
rather than copying the full file, plus any local overrides in this folder.

Wazuh agent channel:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
