# Protocol support

| Protocol | Status | Mode |
|---|---|---|
| Modbus TCP | Offline-PCAP parser and authenticated ingestion implemented | Passive only |
| DNP3 | Offline-PCAP link/transport/application metadata parser | Passive only |
| S7comm | Offline RFC 1006/COTP/S7comm metadata parser | Passive only |
| IEC 61850 MMS | Offline RFC 1006/COTP and BER MMS metadata parser | Passive only |
| OPC UA metadata | UA-TCP handshake, channel, and cleartext service metadata | Passive only |

Parser unit tests use deterministic protocol vectors. The Modbus, DNP3, S7comm, and encrypted OPC UA
metadata pipelines additionally run against third-party captures fetched from upstream repositories
at pinned commits and verified by SHA-256. The DNP3 fixture is from CISA's BSD-3-Clause ICSNPP test
suite; the S7comm fixtures are from CISA's corresponding BSD-3-Clause suite; the remaining fixtures
are GPL-licensed. External binaries are not bundled with the Apache-licensed project; provenance and
retrieval details live in `sensor/tests/external`. Deterministic framing tests remain mandatory in
CI alongside the independently sourced capture corpus.

The Modbus implementation parses existing captures and does not expose active capture or probing.
Real deployment captures still require site-specific acceptance using scrubbed evidence when the
operator is permitted to retain it; public fixtures cannot represent every vendor implementation.

The DNP3 parser verifies link-header and 16-byte user-block CRCs, extracts link addresses, and reads
transport/application metadata from first transport segments. Multi-frame application-fragment
reassembly and object/variation decoding are not yet implemented; such traffic remains recorded as
link and transport evidence rather than being guessed.

The S7comm parser validates TPKT lengths, COTP headers, and S7 parameter/data lengths. It records
connection TSAPs, structurally valid rack/slot hints, negotiated PDU sizes, ROSCTR values, errors,
and function classes. It does not decode variable payload values or support S7comm Plus (`0x72`).

IEC 61850 MMS support validates TPKT/COTP framing and bounded BER lengths, records MMS PDU type,
invoke ID, service tag, and visible object references. It does not decode process values or transmit
association requests. Application payload inspection distinguishes MMS from S7comm on shared TCP
port 102.

OPC UA support records Hello/Acknowledge limits, endpoint URLs, security policy URIs, channel/token
identifiers, and service IDs for complete messages explicitly associated with `SecurityPolicy#None`.
Encrypted or signed bodies and continuation chunks remain opaque. Capture messages are capped at
16 MiB for sensor memory safety; the cap is not an active protocol negotiation.
