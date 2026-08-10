# Field acceptance record template

Copy this file into the site's controlled change-record system. Do not commit completed records,
plant addresses, credentials, packet contents, or sensitive screenshots to the public repository.

## Identification

| Field | Recorded value |
|---|---|
| Site/change record | |
| Test date and maintenance window | |
| OT-Sentinel version and commit | |
| Deployment topology | Compose / Kubernetes / other: |
| Sensor host and approved interface identifier | |
| Operator | |
| OT asset owner approver | |
| Cybersecurity authority approver | |

## Acceptance results

Use `Pass`, `Fail`, or `Not applicable`. Every `Not applicable` result requires written rationale.

| ID | Requirement | Result | Evidence ID/hash | Notes |
|---|---|---|---|---|
| FA-01 | Monitoring interface is connected only to the approved TAP/SPAN receive path | | | |
| FA-02 | Independent observation confirms no field-bound frames originate from the sensor interface | | | |
| FA-03 | Capture health, packet-drop rate, spool capacity, and file permissions meet site thresholds | | | |
| FA-04 | Interrupted capture recovery preserves the sealed non-empty capture | | | |
| FA-05 | TLS store-and-forward succeeds using a dedicated short-lived sensor credential | | | |
| FA-06 | Delivery retry preserves observation and protocol-event identifiers | | | |
| FA-07 | Failed and delivered capture retention matches the approved policy | | | |
| FA-08 | Isolated database restore, migrations, audit-chain verification, and counts succeed | | | |
| FA-09 | Production OIDC viewer/admin separation succeeds and bootstrap keys are disabled | | | |
| FA-10 | TLS, security headers, database isolation, secret rotation, and backup monitoring pass | | | |
| FA-11 | Feed freshness, exports, SIEM delivery, and archive retention meet site requirements | | | |
| FA-12 | Representative inventory/load validation meets the site's documented performance budget | | | |
| FA-13 | No credentials, sensitive packet contents, or unnecessary plant identifiers enter evidence | | | |

## Deviations and residual risk

Record each failed or waived item, compensating control, risk owner, due date, and approval. Field
acceptance does not pass while an unapproved failure remains open.

## Evidence inventory

| Evidence ID | Description | SHA-256 | Controlled storage location | Retention |
|---|---|---|---|---|
| | | | | |

## Sign-off

By signing, the approvers confirm that the recorded checks were performed on the identified release
and deployment, evidence remains available in controlled storage, and residual risks are accepted by
the named authority.

| Role | Name | Signature/reference | Date |
|---|---|---|---|
| Operator | | | |
| OT asset owner | | | |
| Cybersecurity authority | | | |
