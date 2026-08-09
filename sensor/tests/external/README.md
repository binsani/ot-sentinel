# External capture fixtures

These integration fixtures are fetched from their original repositories and are not distributed
as part of OT-Sentinel. Each URL is pinned to an upstream commit and verified against the SHA-256
in `manifest.json` before use.

`modbus_write_single_coil.pcap` comes from `biero-el-corridor/Bettercap_ICS`, whose upstream
repository publishes GPL-3.0 license text. Its traffic predates this project and exercises the
PCAP-to-Modbus observation pipeline independently of OT-Sentinel's synthetic parser vectors.

Run `python scripts/fetch-test-captures.py` from any directory to populate this folder. Review the
upstream license before redistributing any downloaded fixture.

`opcua-encrypted.pcapng` comes from the Wireshark Foundation test-capture collection at a pinned
commit under GPL-2.0. OT-Sentinel reads only the unencrypted UA-TCP handshake and channel metadata;
encrypted application bodies remain opaque.
