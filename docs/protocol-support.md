# Protocol support

| Protocol | Status | Mode |
|---|---|---|
| Modbus TCP | Offline-PCAP parser and authenticated ingestion implemented | Passive only |
| DNP3 | Offline-PCAP link/transport/application metadata parser | Passive only |
| S7comm | Offline RFC 1006/COTP/S7comm metadata parser | Passive only |
| OPC UA metadata | UA-TCP handshake, channel, and cleartext service metadata | Passive only |

Parser unit tests use deterministic protocol vectors. The Modbus and encrypted OPC UA metadata PCAP
pipelines additionally run against third-party captures fetched from GPL-licensed upstream
repositories at pinned commits and verified by SHA-256. External binaries are not bundled with the
Apache-licensed project; provenance and retrieval details live in `sensor/tests/external`. Suitable
redistributable DNP3 and S7comm fixtures are still accepted when their provenance and license can be
verified; their deterministic framing and parser tests remain mandatory in CI.

The Modbus implementation parses existing captures and does not expose active capture or probing.
Real deployment captures still require a scrubbed, redistributable regression corpus before the
parser can be considered production-validated.

The DNP3 parser verifies link-header and 16-byte user-block CRCs, extracts link addresses, and reads
transport/application metadata from first transport segments. Multi-frame application-fragment
reassembly and object/variation decoding are not yet implemented; such traffic remains recorded as
link and transport evidence rather than being guessed.

The S7comm parser validates TPKT lengths, COTP headers, and S7 parameter/data lengths. It records
connection TSAPs, structurally valid rack/slot hints, negotiated PDU sizes, ROSCTR values, errors,
and function classes. It does not decode variable payload values or support S7comm Plus (`0x72`).

OPC UA support records Hello/Acknowledge limits, endpoint URLs, security policy URIs, channel/token
identifiers, and service IDs for complete messages explicitly associated with `SecurityPolicy#None`.
Encrypted or signed bodies and continuation chunks remain opaque. Capture messages are capped at
16 MiB for sensor memory safety; the cap is not an active protocol negotiation.
