# Active probing policy framework

OT-Sentinel remains passive by default. Phase 2 provides policy creation and dry-run evaluation only;
it does not ship a probe executor and cannot transmit probe packets.

A future executor must satisfy every independent gate before any transmission:

1. `ACTIVE_PROBING_ENABLED` must be explicitly set to `true`; it defaults to `false`.
2. An administrator must create a site policy, which is disabled when created.
3. An administrator must enter the explicit approval phrase. Approval expires within 24 hours.
4. Every target must fall within an exact CIDR allowlist; default routes and special-use networks are
   rejected.
5. The requested protocol, target count, UTC maintenance window, and rate cap must pass.

The evaluation endpoint records an immutable audit event and always returns
`transmission_performed: false` and `probe_executor_not_installed`. Disabling a policy clears its
approval immediately.
