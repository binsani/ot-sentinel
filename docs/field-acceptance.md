# Field acceptance procedure

These tests require site-controlled infrastructure and must be completed by an authorized operator.
Record the date, operator, software tag, sensor host, monitored interface, and evidence hashes in the
site change record. Never connect an unapproved interface to a production control network.

## TAP/SPAN validation

1. Install the OS packet-capture provider and grant capture permission only to the sensor service
   account. Do not run the complete sensor as an unrestricted administrator or root user.
2. Connect the selected interface only to the approved receive-only TAP or switch mirror output.
3. Start `ot-sentinel-sensor capture --interface INTERFACE --spool PATH --rotate-seconds 60`.
4. Confirm the switch reports no transmitted frames from the monitoring interface and independently
   verify that the sensor host sends no traffic through it.
5. Generate no test traffic toward field devices. Wait for ordinary operations to produce at least
   one sealed capture.
6. Confirm `health.json` is healthy, dropped packets remain within the site's threshold, PCAP files
   have restricted permissions, and only TCP ports 502, 20000, 102, and 4840 are present.
7. Stop capture cleanly, restart it, and verify recovery of a deliberately interrupted non-empty
   `.writing.pcap` in the controlled test spool.

## Store-and-forward validation

1. Use a dedicated short-lived sensor key and a TLS endpoint whose certificate chains to the site's
   approved trust store.
2. Forward a copied test capture and verify inventory, protocol events, and audit entries appear.
3. Interrupt delivery, restart it, and verify observation and protocol-event IDs are unchanged after
   retry.
4. Confirm the source file moves to `archive`, failures remain in `incoming`, and no credentials are
   written to logs or `health.json`.

## Production service validation

1. Restore a database backup into an isolated environment and run all migrations.
2. Verify the audit chain and compare its head hash with the backup record.
3. Authenticate as viewer and administrator through production OIDC; confirm viewer denial for all
   administration endpoints and disable bootstrap keys.
4. Verify TLS, security headers, secret rotation, database isolation, backup monitoring, spool free
   space alerts, feed freshness, CSV/CycloneDX exports, and archive retention.
5. Capture screenshots or machine-readable results without including access tokens, API keys, or
   sensitive packet contents.

Field acceptance passes only when every check is evidenced and signed off by the OT asset owner and
the site's cybersecurity authority.
