# Compliance mapping

This mapping is implementation guidance, not a certification claim. Control applicability must be validated for each deployment and standard edition.

| Capability | Implementation | Compliance intent |
|---|---|---|
| Asset inventory | `assets`, `observations` | IEC 62443-2-1 asset inventory; NERC CIP-002 BES Cyber System identification |
| Traceable activity | append-only hash-chained `audit_log`, authenticated inventory-read logging, integrity verification endpoint | IEC 62443-2-1 accountability; NERC CIP-007 system security management evidence |
| Role separation | `users.role` viewer/admin model | IEC 62443 identification, authentication, and least privilege intent |
| Vulnerability tracking | `cve_matches` | IEC 62443-2-1 patch and vulnerability management evidence |
| Communication records | `observations`, `protocol_events` | Supports network segmentation review and security monitoring evidence |
| Passive Modbus discovery | offline PCAP parser and authenticated ingestion API | Supports passive asset identification without transmitting to control devices |
| Offline vulnerability intelligence | NVD 2.0 import, CISA KEV overlay, CPE correlation | Supports vulnerability identification, prioritization, and air-gapped evidence updates |
| Auditor-facing dashboard | asset table, evidence panel, communication graph | Supports reviewable inventory, vulnerability, and observed-flow evidence |
| Portable compliance evidence | CycloneDX 1.7 with VEX and formula-safe CSV | Supports exchange with GRC, vulnerability, and audit tooling |
| Federated identity and role administration | OIDC validation, viewer/admin persistence, last-admin protection | Supports identification, authentication, least privilege, and accountable access changes |
| Passive DNP3 discovery | CRC-validated offline parser and outstation-address fingerprinting | Supports passive RTU/IED identification and communication evidence without polling field devices |
| Passive S7comm discovery | RFC 1006/COTP/S7 metadata and rack/slot evidence | Supports passive PLC identification and observed control-operation evidence without contacting PLCs |
| Passive OPC UA discovery | endpoint, security-policy, channel, and cleartext service metadata | Supports passive server/session/browse evidence without decrypting or manipulating OPC UA traffic |
| Store-and-forward evidence handling | sealed incoming PCAPs, replay-safe event IDs, retained archive | Supports controlled-zone transfer, evidence continuity, and repeatable collection in disconnected sites |
| Firmware configuration monitoring | administrator-approved baseline, passive version comparison, timestamped drift transitions | Supports authorized-change review, configuration monitoring, and patch-management evidence |
