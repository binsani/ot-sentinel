# Performance testing

OT-Sentinel includes an opt-in API load test for large synthetic inventories. It exercises only
authenticated read endpoints; it does not contact sensors or field devices.

Run the **Performance validation** GitHub Actions workflow manually. Its defaults create 10,000
assets and 40,000 observations, run 16 concurrent clients for 60 seconds, and fail when the overall
95th-percentile latency exceeds 3 seconds or more than 0.5% of requests fail. The JSON result is
retained as a workflow artifact. Adjusting the inventory size or duration makes results unsuitable
for direct comparison with the defaults, so record those inputs with every acceptance result.

For a controlled local environment, create a fresh database whose name ends in `_performance` or
`_perf`, apply migrations, and set `DATABASE_URL`. Seeding requires the exact phrase below and
refuses a database that already contains assets:

```powershell
python scripts/seed-performance-data.py --assets 10000 --observations-per-asset 4 `
  --confirmation "SEED DISPOSABLE PERFORMANCE DATABASE"
$env:OT_SENTINEL_LOAD_API_KEY = "replace-with-viewer-key"
python scripts/load-test.py --duration 60 --concurrency 16 --output performance-results.json
```

Remote targets are rejected unless `--allow-remote` is explicit. Obtain authorization and schedule
a maintenance window before testing any shared environment. The runner has bounded concurrency and
duration, but its inventory, risk, graph, anomaly, and site-summary queries create real database and
audit-log load. Never point it at a production OT deployment during normal operations.

The default budget is an engineering regression threshold, not a universal capacity guarantee.
Field acceptance must repeat the test using representative hardware, network latency, retention,
site counts, and database tuning, then preserve the JSON output with the acceptance record.
