# Air-gapped deployment

The sensor supports store-and-forward operation. Run `capture` on the monitored TAP/SPAN host to
seal rotating files under `spool/incoming`, transfer those files through the approved boundary if
needed, and run `forward` where the authenticated API is reachable. Successfully delivered files
move to `spool/archive`; failed or interrupted deliveries remain ready for retry. Deterministic
event identifiers make replay idempotent at the API.

Production deployments must protect the spool and archive as sensitive network evidence, monitor
free space and packet-drop output, rotate the sensor key, use HTTPS, and establish an explicit
retention policy. The present Compose setup remains for development and evaluation only and must
not be placed directly on a production control network.
