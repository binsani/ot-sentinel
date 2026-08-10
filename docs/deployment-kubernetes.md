# Kubernetes production deployment

The manifests under `deploy/kubernetes/base` provide a production-oriented Kustomize base. They use
external PostgreSQL, OIDC, TLS ingress, non-root containers, read-only root filesystems, resource
limits, health probes, and separate background workers. They do not deploy a packet-capture sensor or
grant raw-network capabilities inside the cluster.

Before deployment:

1. Mirror the versioned backend and frontend images into the approved registry and pin immutable
   digests in every workload.
2. Provision PostgreSQL 16 with TLS, point-in-time recovery, encryption at rest, and restricted
   credentials. Do not use the Compose database in production.
3. Copy `deploy/kubernetes/secret-template.yaml` outside the repository, replace every placeholder,
   encrypt it with the organization's secret-management workflow, and never commit the result.
4. Replace the OIDC, ingress hostname, TLS secret, SIEM CIDRs, and image references.
5. Review the ingress controller and network policies for the cluster's CNI. The generic backend
   policy permits cluster namespaces because ingress-controller namespace labels vary.

Apply and verify:

```text
kubectl apply -f /secure/location/ot-sentinel-secrets.yaml
kubectl -n ot-sentinel delete job ot-sentinel-migrate --ignore-not-found
kubectl apply -k deploy/kubernetes/base
kubectl -n ot-sentinel wait --for=condition=complete job/ot-sentinel-migrate --timeout=5m
kubectl -n ot-sentinel rollout status deployment/ot-sentinel-backend
kubectl -n ot-sentinel rollout status deployment/ot-sentinel-frontend
kubectl -n ot-sentinel rollout status deployment/ot-sentinel-workers
```

Run the migration Job once per release before rolling application workloads. Back up PostgreSQL and
perform a restore rehearsal before every schema upgrade. Capture remains on a dedicated TAP/SPAN host;
only authenticated parsed observations cross into the cluster.
