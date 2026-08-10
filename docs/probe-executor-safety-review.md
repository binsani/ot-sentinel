# Probe executor safety review gate

## Current decision: no-go

OT-Sentinel v1.0 is a passive product. No probe executor is included, and policy evaluation always
returns `allowed: false`, `transmission_performed: false`, and `probe_executor_not_installed`.
Configuration defaults remain disabled in local, Compose, and Kubernetes deployments. The release
pipeline verifies these invariants and rejects raw-socket or packet-transmission capability in the
sensor.

The existing policy screens are dry-run planning controls. Approval of a policy does not authorize
network transmission and cannot make the current build transmission-capable.

## Evidence required before reconsideration

A future executor proposal must be a separately scoped product change and cannot be approved by a
normal feature review. Before implementation or field trials, it requires:

1. A named product owner, OT safety authority, and independent assessor.
2. A protocol-by-protocol hazard analysis covering device families, firmware, failure modes,
   broadcast effects, redundancy/failover interactions, and fragile or safety-instrumented systems.
3. A lab-only prototype and test plan using owned simulators or equipment, with no production or
   third-party targets.
4. Hard architectural separation from passive capture, a separate executable and identity, no
   shared default deployment, and no implicit installation or enablement.
5. Exact target manifests, deny-by-default network policy, destination-port constraints, expiring
   dual authorization, maintenance windows, global/site/device rate limits, concurrency limits,
   emergency stop, and restart-safe cancellation.
6. Tamper-evident request, authorization, per-target attempt, result, cancellation, and error logs
   that never contain credentials or unnecessary payload data.
7. Tests proving DNS cannot expand scope, redirects are rejected, IPv4/IPv6 normalization cannot
   bypass allowlists, approvals cannot be replayed, and partial failures fail closed.
8. Independent code review, penetration testing, device-compatibility testing, recovery drills, and
   signed residual-risk acceptance by the OT asset owner and cybersecurity authority.

## Mandatory release separation

If a proposal eventually passes safety review, the passive product must remain available without
executor code or dependencies. Executor artifacts need a distinct name, SBOM, signing identity,
deployment manifest, threat model, operator guide, and release approval. Enabling a policy in the
passive API must never install, start, or authorize that external component.

## Gate operation

`scripts/verify-passive-release.py` runs in CI and again for release tags. It verifies passive
deployment defaults, hard-coded API non-transmission results, absence of a probe-executor module,
absence of raw-socket/subprocess transmission paths in the sensor, and absence of Scapy send/request
primitives. This automated check is defense in depth; it does not replace human safety review.
