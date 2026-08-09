# Threat model

This document records the baseline security assumptions for OT-Sentinel. It is not a substitute for
a site-specific risk assessment.

## Trust boundaries

- The TAP/SPAN interface is untrusted input. Protocol parsers use bounded frame lengths, reject
  inconsistent lengths, and never transmit responses.
- Capture files are sensitive evidence. The capture host restricts file permissions; transfer and
  retention remain controlled by the operator.
- The sensor-to-API boundary requires a dedicated secret and HTTPS outside the internal Compose
  network. Stable event IDs make delivery retry-safe.
- Browser and API users are untrusted until authenticated by OIDC or explicitly enabled bootstrap
  keys. Viewers cannot access administrative endpoints.
- Vulnerability feeds are untrusted structured input transferred through an approved staging path.
  Operators verify their recorded digest before import.

## Principal threats and controls

| Threat | Primary controls | Residual risk |
|---|---|---|
| Crafted packets exploit a parser | strict lengths, bounded protocol frames, metadata-only decoding, parser tests | Python/Scapy defects and untested protocol variants |
| Sensor accidentally affects field devices | fixed passive capture filter; no send, replay, or active-probe code path | host misconfiguration outside the application |
| Active discovery disrupts control equipment | global gate defaults off, disabled policies, CIDR allowlists, expiring approval, maintenance windows, target/rate caps, no executor shipped | a future executor must preserve every gate and undergo field safety validation |
| Duplicate or interrupted forwarding corrupts inventory | deterministic event IDs, database advisory locks, unique constraint | events from legacy sensors without IDs are not idempotent |
| Stolen credentials expose inventory | OIDC validation, role checks, no-store responses, secrets excluded from audit data | bootstrap keys require operator rotation and secure storage |
| Audit history is altered | append-only database trigger, serialized SHA-256 chain, verification endpoint | a privileged database administrator can replace both data and backups |
| Feed tampering creates false matches | offline digest workflow, schema validation, candidate confidence and review state | source-feed or staging-host compromise |
| Spool exhaustion stops monitoring | configurable ceiling, health file, packet-drop reporting, explicit retention | monitoring pauses until capacity is restored |

## Operational requirements

Run the backend behind TLS, disable bootstrap API keys after OIDC onboarding, restrict database and
spool access, monitor health and free space, retain immutable database backups, and test restoration
regularly. Review this model whenever a protocol parser, trust boundary, or active capability changes.
