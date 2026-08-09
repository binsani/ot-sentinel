# SIEM forwarding over TLS Syslog

OT-Sentinel forwards operational security events as RFC 5424 Syslog using RFC 6587 octet framing
over certificate-verified TLS. UDP and plaintext TCP are intentionally unsupported.

Destinations are disabled when created. Before an administrator can create or enable one,
`SIEM_ALLOWED_CIDRS` must explicitly contain every address returned by its DNS name. The worker
repeats resolution and allowlist validation immediately before delivery, connects to a validated IP,
and verifies the certificate against the configured hostname. An empty allowlist denies all delivery.

Firmware drift and new vulnerability matches enter a PostgreSQL outbox in the same transaction as
their inventory evidence. The independent `siem-worker` retries temporary failures with exponential
backoff, stops after five attempts, and records delivered or permanently failed outcomes in the
immutable audit chain. CISA KEV matches are sent at critical severity; destination severity thresholds
can suppress lower-priority events.

Enable the worker with the `siem` Compose profile after configuring the allowlist:

```text
docker compose --profile siem up -d siem-worker
```

Collector trust uses the operating system CA bundle. Deploy a private CA into the backend image or
host trust store when the collector certificate is issued by an internal authority.
