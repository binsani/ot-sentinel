# Changelog

## 1.0.0 - 2026-08-10

- Added production Kubernetes manifests, external PostgreSQL/OIDC integration, restricted pod
  security contexts, migration jobs, ingress, and network policy.
- Added guarded PostgreSQL backup/restore tooling with checksum manifests, audit evidence, isolated
  restore rehearsal, and disaster-recovery guidance.
- Added administrator screens for webhook, TLS Syslog, communication baseline, and dry-run probing
  policy management.
- Added deterministic 10,000-asset performance validation; the release baseline completed 2,993
  requests with zero errors and 461.52 ms p95 latency.
- Expanded checksum-pinned real-PCAP validation with official CISA DNP3 and S7comm fixtures and
  strict source, license, commit, filename, and SHA-256 provenance checks.
- Added field-acceptance records, external security-assessment readiness guidance, and deterministic
  audit-evidence manifests.
- Added a CI/release-enforced passive-only gate and recorded a no-go decision for a v1.0 probe
  executor.
- Added v1.0 release packages, checksums, SBOM/provenance-enabled container publication, and version
  consistency enforcement.

## 0.3.0 - 2026-08-10

- Added explainable asset risk scoring from CVSS/KEV, observed peer exposure, and criticality.
- Added RFC 5424 Syslog forwarding over certificate-verified TLS with explicit destination CIDRs.
- Added immutable site communication baselines and new-edge anomaly detection.
- Added anomaly webhook/SIEM delivery, dashboard review, and audited acknowledgement.
- Added risk components and open anomaly evidence to CSV and CycloneDX exports.

## 0.2.0 - 2026-08-09

- Added passive firmware baselines, drift detection, and audited transitions.
- Added multi-site exposure summaries and site-scoped inventory filtering.
- Added signed HTTPS webhook alert rules with an asynchronous retry outbox.
- Added passive IEC 61850 MMS parsing and retry-safe ingestion.
- Added a fail-closed active-probing policy framework with no probe executor.

## 0.1.0 - 2026-08-09

- Initial passive OT asset inventory and vulnerability-correlation release.
