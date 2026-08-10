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

`dnp3_example.pcap` comes from CISA's official ICSNPP-DNP3 parser test suite under BSD-3-Clause.
It exercises bidirectional DNP3 read, select, operate, response, confirm, and unsolicited-response
traffic. OT-Sentinel validates DNP3 link CRCs before exposing application metadata.

`cisa_snap7.pcap` and `cisa_s7ident.pcap` come from CISA's official ICSNPP-S7comm parser test suite
under BSD-3-Clause. They exercise classic S7comm connection negotiation, rack/slot hints, variable
reads and writes, upload flow, PLC stop observation, and response metadata. S7comm Plus traffic is
outside OT-Sentinel's declared parser scope and is not represented as supported by these fixtures.

The fetcher validates every manifest entry before network access. Filenames must be unique and
local, hashes must be complete SHA-256 values, and both capture and license URLs must contain the
same immutable 40-character upstream commit. A source repository and written provenance statement
are mandatory. Downloaded third-party files remain excluded from source control.
