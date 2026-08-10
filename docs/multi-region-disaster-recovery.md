# Multi-region disaster recovery

OT-Sentinel supports a warm-infrastructure, dormant-application standby pattern. It does not claim
transparent active-active operation. A single PostgreSQL writer and a single active application
region are mandatory unless a separately validated database architecture provides equivalent
fencing and consistency guarantees.

## Deployment profiles

- `deploy/kubernetes/overlays/primary` runs the normal backend, frontend, workers, migration Job, and
  ingress in the designated primary region.
- `deploy/kubernetes/overlays/standby` renders every Deployment at zero replicas, suspends the
  migration Job, and removes ingress. It can pre-stage namespace, configuration, services, policy,
  and workload definitions without opening a second application writer.
- `deploy/kubernetes/overlays/recovery` is an active profile for the recovery region. Never apply it
  while the primary region can still write to the database.

Replace example hostnames, secret names, registries, and image tags with immutable, approved values.
Keep region secrets in the organization's secret manager and never copy plaintext secrets through
the repository or a failover ticket.

## Required external services

The database platform must provide encrypted cross-region backup or replication, point-in-time
recovery, monitored lag, documented promotion fencing, and an isolated restore target. Object
storage used for backup manifests must be immutable under a separate administrative boundary. OIDC,
DNS, ingress certificates, vulnerability-feed staging, SIEM destinations, and container registry
availability must be tested from the recovery region.

## Promotion procedure

1. Declare an incident and name the incident commander, database owner, application owner, OT asset
   owner, and cybersecurity authority. Record the release tag, source commit, last known audit-chain
   head, recovery point objective, and recovery time objective.
2. Stop observation forwarding to the primary API and preserve sensor spools. Do not discard or
   replay captures manually.
3. Prove the primary application and workers are unable to write. Fence its database credentials,
   ingress, and compute at independent control points. Absence of health checks alone is not proof.
4. Promote or restore the recovery database using the database provider's approved procedure.
   Record recovery timestamp, transaction position, backup manifest SHA-256, and operator identity.
5. Verify the restored audit chain and compare its head/counts to the most recent protected record.
   Stop on unexplained divergence.
6. Apply recovery-region secrets through the approved secret controller. Render and review the
   recovery overlay, pin image digests, then apply it. Run the migration Job once and wait for it to
   complete before application rollout.
7. Test administrator/viewer OIDC, inventory reads, audit writes, feed status, SIEM/webhook egress,
   exports, and backup creation using synthetic or approved data.
8. Change DNS or traffic management only after the application, database, and security owners sign
   the promotion checkpoint. Resume sensor forwarding gradually and monitor retry/idempotency,
   latency, error rate, database load, and spool drain.

## Failback

Failback is another controlled disaster-recovery event, not a DNS reversal. Rebuild the former
primary as a dormant standby, establish replication from the current writer, rehearse restore and
audit verification, fence the current writer, and repeat the promotion gates. Never operate both
regions as writers to shorten a maintenance window.

## Exercise evidence

At least annually and before a material database/topology change, conduct an isolated exercise and
retain: participant approvals, exact manifests and image digests, database recovery position,
replication lag, audit-chain results, RPO/RTO measurements, DNS/identity/integration checks, load
results, observed gaps, corrective owners, and final sign-off. A rendered overlay or CI check is
engineering evidence only; it is not proof that regional failover succeeded.
