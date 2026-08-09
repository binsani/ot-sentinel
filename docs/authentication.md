# Authentication and role management

Authenticated asset-list, asset-detail, communication-graph, export, and administrative actions
are recorded in the append-only audit chain. Administrators can verify the complete chain with
`GET /api/v1/admin/audit/verify`. The response includes the verified entry count, prior head hash,
and the first invalid entry ID when integrity checking fails. The verification request is appended
as a new audit event after the snapshot is checked.

OT-Sentinel accepts signed OIDC bearer tokens for dashboard/API users. Tokens are validated against
a configured JWKS using a fixed `RS256`/`ES256` allowlist and must contain valid `exp`, `iat`, `iss`,
`sub`, and `aud` claims. The configured issuer and audience must match exactly.

## Connected identity provider

Set `OIDC_ISSUER`, `OIDC_AUDIENCE`, and `OIDC_JWKS_URL`. The backend caches signing keys briefly to
support rotation. Only configure an HTTPS JWKS URL controlled by the deployment administrator.

## Air-gapped identity provider

Set `OIDC_ISSUER`, `OIDC_AUDIENCE`, and `OIDC_JWKS_FILE`, then mount the provider's approved JWKS
file read-only into the backend container. Establish an operational process for key rotation before
tokens signed by a new key are issued.

## Roles and bootstrap

The first successful login creates an active viewer. A bootstrap administrator key can call
`PATCH /api/v1/admin/users/{user_id}` to promote a user. Viewer and administrator keys must be
distinct and at least 24 characters. After establishing at least one OIDC administrator, set
`BOOTSTRAP_API_KEYS_ENABLED=false` and restart the backend.

OT-Sentinel prevents disabling or demoting the last active persisted administrator. User creation,
role changes, activation changes, and compliance exports are written to the append-only audit log.

The current frontend accepts a bearer token directly; authorization-code flow and automatic browser
redirects depend on the selected corporate provider and remain deployment integration work.
