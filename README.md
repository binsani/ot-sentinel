# OT-Sentinel

OT-Sentinel is an open-source, passive-by-default OT/ICS asset discovery and vulnerability-correlation platform. Version 0.3.0 includes passive discovery, multi-site inventory, vulnerability and firmware evidence, explainable risk scoring, communication anomaly detection, secure webhook and TLS Syslog integrations, compliance exports, and a verifiable append-only audit chain.

> **Safety:** OT-Sentinel observes mirrored network traffic. It must not transmit to field devices. Active probing is outside the current scope and must never be enabled implicitly.

## Start locally

1. Copy `.env.example` to `.env` and replace the password.
2. Run `docker compose up --build`.
3. Open the dashboard at `http://localhost:3000`; API documentation remains available at
   `http://localhost:8000/docs`.

The API container applies database migrations before starting. PostgreSQL is only exposed on the internal Compose network; the API is available on loopback by default.

## Capabilities

- Passive Modbus TCP, DNP3, S7comm, IEC 61850 MMS, and OPC UA metadata observation
- Rotating capture spool with disconnected authenticated forwarding and retry-safe event IDs
- Typed SQLAlchemy models, PostgreSQL constraints, and Alembic migrations
- NVD, CISA KEV, and CISA ICS-advisory reference correlation
- OIDC and viewer/admin role enforcement
- Asset inventory, vulnerability evidence, communication graph, feed status, and audit dashboard
- CycloneDX 1.7/VEX and formula-safe CSV exports
- Database-enforced append-only audit records with full-chain verification
- Air-gapped feed worker, container orchestration, CI, CodeQL, and dependency update policy
- Fail-closed active-probing policy evaluation with probing disabled and no executor shipped

## Passive sensor

The sensor passively captures only configured OT protocol ports from a TAP/SPAN interface into
rotating PCAP files, or parses existing PCAPs for Modbus TCP, DNP3, S7comm, IEC 61850 MMS,
and OPC UA metadata.
Capture and forwarding are separate commands for disconnected deployments. The authenticated
forwarder retries safely using deterministic event IDs, and archives delivered PCAPs rather than
deleting evidence. No sensor component transmits traffic to field devices.

```powershell
ot-sentinel-sensor capture --interface Ethernet --spool C:\ot-sentinel-spool
$env:SENSOR_INGEST_API_KEY = "replace-with-secret"
ot-sentinel-sensor forward --spool C:\ot-sentinel-spool --backend-url https://sentinel.example `
  --sensor-id tap-01 --site-id plant-a
```

DNP3/TCP offline parsing is also available with CRC validation, link-address extraction, transport
metadata, application function classification, and outstation-address fingerprinting. Control
operations are observed and labeled but never transmitted or replayed.

S7comm over RFC 1006 is parsed from offline captures for connection TSAPs, rack/slot hints,
negotiated PDU size, response/error metadata, and read/write function classification. Variable
payload values are intentionally not interpreted in this milestone.

## Offline vulnerability feeds

Apply migrations, then import previously downloaded official JSON feeds inside the backend
environment:

```text
python -m app.cve.cli --nvd /feeds/nvd-page.json --kev /feeds/known_exploited_vulnerabilities.json --correlate
```

NVD data is normalized locally; CISA KEV status is retained across later NVD refreshes. Matching
is deliberately conservative: vendor and model must match a vulnerable CPE, while absent firmware
produces a candidate rather than a confirmed result. Read-only inventory endpoints require the
`X-API-Key` viewer or admin credential.

## Dashboard

The React dashboard provides the asset inventory, per-asset vulnerability evidence, summary
counts, and a Cytoscape communication graph. It never persists API keys to browser storage. Graph
edges represent observed logical communications and must not be interpreted as physical cabling or
network-zone boundaries.

Authenticated users can export a formula-safe inventory CSV or a CycloneDX 1.7 JSON document. The
CycloneDX export represents observed devices as components and includes VEX analysis for correlated
CVEs. Export actions are appended to the audit chain.

OIDC bearer-token validation supports connected JWKS URLs and read-only local JWKS files for
air-gapped deployments. First-time OIDC users receive the viewer role; administrators manage roles
through the protected user API. Bootstrap keys can be disabled after initial provisioning. See
[`docs/authentication.md`](docs/authentication.md).

OPC UA TCP support records handshake limits, endpoint URLs, security policies, secure-channel
identifiers, and recognizable session/browse service IDs when `SecurityPolicy#None` is explicitly
observed. Protected message bodies remain opaque and are never decrypted.

## Phase 2 progress

Firmware drift monitoring is implemented. Administrators can establish a baseline from an observed
version, while later passive Modbus device-identification responses detect and audit divergence or
restoration. No firmware query is transmitted to field devices.

## Trademark notice

Modbus, DNP3, OPC UA, Siemens, and S7 are trademarks or names of their respective owners. OT-Sentinel is independent and is not affiliated with or endorsed by those owners.

Licensed under Apache-2.0. See [LICENSE](LICENSE).

Operational guidance is available in [`docs/architecture.md`](docs/architecture.md),
[`docs/deployment-airgapped.md`](docs/deployment-airgapped.md),
[`docs/threat-model.md`](docs/threat-model.md), and
[`docs/backup-restore.md`](docs/backup-restore.md). Site commissioning must follow
[`docs/field-acceptance.md`](docs/field-acceptance.md).
