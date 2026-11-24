## Suricata — network intrusion detection on OPNsense

### 3.1 Purpose and deployment

Suricata provides network IDS telemetry on the OPNsense firewall (Proxmox VM **901**). The firewall serves VLAN-segmented lab networks, including the VICTIM and SOC segments. IDS alerts are forwarded into Wazuh by the **Wazuh agent installed on OPNsense**; Suricata does not transmit alerts directly to the manager over its own listening service.

| Property | Configuration |
|---|---|
| Software | Suricata IDS integrated with OPNsense |
| Host | OPNsense, VM 901; agent hostname `opnsense` |
| Private SOC address | `10.10.20.1` |
| Installation method | OPNsense package/IDS service, managed using the firewall UI |
| Data source | Suricata IDS alert output read by the OPNsense Wazuh agent |
| Target platform | Wazuh manager `10.10.20.243` |

### 3.2 Ports, authentication and APIs

- **IDS inspection:** traffic is inspected on the configured interfaces; Suricata is not an API server requiring a dedicated inbound port for this integration.
- **Alert forwarding:** the OPNsense Wazuh agent communicates to `10.10.20.243:1514/TCP` with Wazuh agent authentication.
- **Firewall management:** OPNsense HTTPS management interface is administratively authenticated; access is limited to authorized lab networks.
- **API usage:** this collection path uses log/agent forwarding, not an application-specific Suricata REST API.

### 3.3 Startup and standalone verification

1. In OPNsense, open **Services → Intrusion Detection → Administration**.
2. Review the enabled IDS service and its selected interfaces, rule policies, and logging configuration.
3. Start or restart the IDS service only if operational maintenance requires it.
4. Open **Services → Intrusion Detection → Alerts** and inspect locally generated IDS alert records. This is the standalone test; it does not depend on Wazuh, Shuffle or TheHive.
5. As a separate integration test, check Wazuh Threat Hunting for Suricata-related alert rule `86601` and source agent `opnsense`.

### 3.4 Problems and resolution

- **Low-severity alert forwarding:** Suricata alert rule `86601` may be assigned a lower Wazuh level than host detections. Integration routing is based on relevant `rule_id` values rather than a simple global level threshold.
- **Separation of responsibilities:** OPNsense/Suricata produces the IDS events; the Wazuh agent delivers them; the Wazuh manager performs alert correlation. Each stage should be checked independently during troubleshooting.

### 3.5 Evidence and references

- Existing screenshot: [`docs/images/suricata/04-suricata-alert.png`](../../docs/images/suricata/04-suricata-alert.png)
- Network details: [lab setup](../../infrastructure/architecture/lab-setup.md)

---
