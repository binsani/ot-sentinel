# OT-Sentinel v1.0.0

OT-Sentinel v1.0.0 is the first production-packaged release of the passive OT/ICS asset discovery
and vulnerability-management platform.

Highlights include multi-protocol passive inventory, conservative vulnerability correlation,
firmware drift, explainable risk, communication anomaly baselines, authenticated administration,
TLS Syslog and signed webhook integrations, append-only audit evidence, Kubernetes deployment,
backup/restore rehearsal, large-inventory performance validation, and checksum-pinned external PCAP
coverage.

The release remains passive by design. It contains no probe executor, packet replay, or field-device
transmission path. CI and release builds enforce this boundary.

Known boundaries:

- Field acceptance is site-specific and is not conferred by this release.
- Independent external security assessment remains a separate operator activity.
- DNP3 object decoding and multi-frame reassembly, S7comm Plus, decrypted OPC UA payloads, and full
  IEC 61850 process-value decoding are outside the declared v1.0 scope.
- Bootstrap API keys are intended only for initial provisioning and must be disabled after OIDC
  onboarding in production.

Review `docs/release-checklist.md`, `docs/deployment-kubernetes.md`, and
`docs/field-acceptance.md` before deployment.
