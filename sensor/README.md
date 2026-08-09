# Sensor

The sensor passively observes Modbus TCP, DNP3/TCP, S7comm, IEC 61850 MMS, and OPC UA metadata. It has two separate
operating modes so capture hosts do not need direct access to the application network:

- `capture` reads a TAP/SPAN interface and seals rotating PCAP files under `spool/incoming`.
- `forward` parses sealed files, sends authenticated observations, and moves successful files to
  `spool/archive`. Interrupted delivery is safe to retry.

```powershell
ot-sentinel-sensor capture --interface Ethernet --spool C:\ot-sentinel-spool
$env:SENSOR_INGEST_API_KEY = "replace-with-secret"
ot-sentinel-sensor forward --spool C:\ot-sentinel-spool --backend-url https://sentinel.example `
  --sensor-id tap-01 --site-id plant-a
```

Live capture requires an OS packet-capture provider and permission to open the selected interface.
Only the four documented TCP port filters are observed. The sensor contains no packet-transmission
or active-probing path.

Capture defaults to a 10 GiB spool ceiling and stops safely when reached. Override it with
`--max-spool-bytes`. Both modes maintain `health.json`; capture health includes dropped-packet and
recovered-file counts. Archive retention is unlimited unless the forwarder receives an explicit
`--archive-retention-days` value. Abandoned non-empty `.writing.pcap` files are sealed on restart.

The optional Compose `sensor` profile runs the unprivileged forwarder against a managed spool volume:

```sh
docker compose --profile sensor up -d
```

Compose deliberately does not grant host networking, raw-packet capabilities, or a physical capture
interface. Run `capture` on the explicitly approved TAP/SPAN host, then place sealed PCAP files in the
forwarder's incoming spool using the site's controlled transfer process.
