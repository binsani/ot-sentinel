# Backup and restore

Back up PostgreSQL with a tool compatible with the deployed major version, encrypt the output, and
store at least one immutable copy outside the appliance. Back up the sensor archive separately under
the site's packet-evidence retention policy; it may contain operationally sensitive addresses and
commands.

For restoration, create an isolated PostgreSQL instance, restore the dump, run `alembic upgrade head`,
start the API without exposing it to users, and call `GET /api/v1/admin/audit/verify`. Compare the
reported verified head hash with the value recorded at backup time. Then validate inventory counts,
recent observations, user roles, exports, and feed status before returning the service to production.

Perform a documented restoration exercise at least annually and after major database upgrades.

## Verified scripts

`scripts/backup-postgres.ps1` creates a PostgreSQL custom-format dump and a JSON manifest containing
its SHA-256 checksum, audit-chain head, and key table counts. It writes partial files first and only
renames them after both dump and evidence capture succeed. Optional retention removes only files that
match the script's timestamped backup naming pattern.

`scripts/restore-postgres.ps1` requires an exact confirmation phrase, verifies the checksum, and
refuses to restore into a database containing public user tables. After restoration it compares the
audit head and every recorded count with the manifest. It does not drop or overwrite an existing
database.

Use PostgreSQL client tools from the same major version as the server. Supply credentials through a
protected `.pgpass`, workload identity, or an ephemeral environment secret; do not place passwords in
shell history. Example commands intentionally use placeholders:

```text
pwsh ./scripts/backup-postgres.ps1 -DatabaseUrl $DATABASE_URL -OutputDirectory /secure/backups
pwsh ./scripts/restore-postgres.ps1 -DatabaseUrl $EMPTY_RESTORE_DATABASE_URL \
  -BackupFile /secure/backups/ot-sentinel-TIMESTAMP.dump \
  -ManifestFile /secure/backups/ot-sentinel-TIMESTAMP.manifest.json \
  -Confirmation 'RESTORE INTO VERIFIED EMPTY DATABASE'
```

After the script verifies the data, run the current migration Job, start the API in isolation, call
`GET /api/v1/admin/audit/verify`, and execute the field-acceptance checklist before cutover. Record
recovery point objective, recovery time, operator, database version, checksum, and audit head in the
exercise report.
