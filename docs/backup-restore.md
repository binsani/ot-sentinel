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
