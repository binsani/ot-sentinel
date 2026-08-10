# Security assessment readiness

This guide prepares OT-Sentinel for an independent security assessment. It is not an assessment,
certification, penetration-test result, or claim of field acceptance.

## Recommended scope

- Backend authentication, authorization, audit integrity, exports, ingestion, and administrative APIs
- Frontend credential handling, browser security boundaries, and role-dependent behavior
- Passive sensor parsers, capture spool, retry behavior, and hostile-PCAP resource bounds
- Container, Compose, Kubernetes, migration, backup, restore, and release supply chain
- Offline vulnerability-feed handling, SIEM/webhook egress controls, and secret management
- Verification that no shipped component can probe, replay, or transmit toward field devices

## Rules of engagement

Assessment must occur in an isolated lab using synthetic devices or approved simulators. Production
OT networks and field devices are out of scope unless the asset owner provides separate written
authorization, targets, methods, maintenance window, stop conditions, and recovery ownership. Do
not import plant packet captures or credentials into third-party tooling. Denial-of-service,
protocol fuzzing, active scanning, credential attacks, and load testing require explicit limits and
an emergency stop contact even in the lab.

## Evidence package

Run `scripts/collect-audit-evidence.ps1` from a clean checkout of the assessed commit. It produces a
JSON manifest containing the commit and SHA-256 hashes of security design, deployment, dependency,
CI, release, backup, authentication, field-acceptance, and vulnerability-reporting artifacts. The
manifest deliberately states that field acceptance and external assessment are incomplete; only
signed site and assessor records may change those conclusions outside this generated file.

Provide the assessor with the release artifacts and attestations, SBOMs, CI/CodeQL results,
performance result, backup/restore rehearsal, real-PCAP provenance manifest, threat model, compliance
mapping, architecture, and a blank field-acceptance record. Share secrets or sensitive operational
evidence only through the site's approved controlled channel.

## Control-to-evidence index

| Control objective | Primary evidence | Verification focus |
|---|---|---|
| Passive-only collection | threat model, sensor code/tests, field acceptance FA-01/FA-02 | No transmit/replay path; capture-interface isolation |
| Parser resilience | protocol tests, pinned external corpus, CI/CodeQL | Bounds, malformed lengths, CRC handling, opaque encrypted payloads |
| Identity and least privilege | authentication guide, API tests, FA-09 | OIDC validation, viewer/admin denial, bootstrap-key retirement |
| Evidence integrity | audit-chain implementation/tests, backup manifest, FA-08 | Append-only enforcement, chain verification, isolated restore |
| Egress restriction | SIEM/webhook policy and tests | TLS, allowlists, SSRF resistance, secret redaction, retry limits |
| Supply-chain integrity | lockfiles, release workflow, SBOM/provenance | Pinned dependencies/actions, image attestations, reproducible source commit |
| Operational resilience | backup/restore, performance artifact, FA-03/FA-12 | Restore objectives, capacity assumptions, monitoring and stop conditions |
| Vulnerability response | `SECURITY.md`, GitHub private reporting | Intake confidentiality, triage ownership, remediation and disclosure process |

## Completion criteria

Readiness is complete when the assessor has a named sponsor, signed scope and rules of engagement,
an immutable evidence manifest for the assessed commit, isolated test infrastructure, reporting and
severity criteria, remediation ownership, retest expectations, and a protected report location.
The external-audit work item closes only after findings are dispositioned and the independent
assessor issues the final report. The field-acceptance work item closes separately for each site
after all required rows in the acceptance record are evidenced and signed.
