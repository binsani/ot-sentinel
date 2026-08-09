# Architecture

The deployment separates a passive capture sensor in the OT zone from the API and PostgreSQL
service in an IT/DMZ zone. Sealed captures or parsed observations cross the boundary only through an
explicitly configured, authenticated channel. No component initiates traffic toward field devices.

The sensor capture and forwarding processes are deliberately separable. Capture writes rotating,
permission-restricted PCAPs; forwarding parses the supported protocols and submits stable event IDs.
The API serializes retries for each event ID, preventing duplicate observations after interruption.
Successful source captures are archived rather than silently removed.

Offline PCAP ingestion and vulnerability-feed import are now implemented. Feed acquisition remains
outside the OT trust zone: official JSON is downloaded and integrity-checked on a staging host,
then imported locally. The API does not require outbound internet connectivity.

The Compose sensor profile includes only the unprivileged forwarder. It receives no host networking
or raw-packet capability. Access to a physical TAP/SPAN interface must be granted explicitly on the
capture host and is never part of the default application deployment.
