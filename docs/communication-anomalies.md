# Communication graph anomaly detection

OT-Sentinel detects new communication edges without learning opaque behavioral models. An
administrator explicitly captures the currently observed source, destination, and protocol tuples
for one site as an immutable baseline. Capturing a replacement deactivates—but does not rewrite—the
previous snapshot.

The anomaly worker examines observations newer than the active baseline. A tuple absent from the
snapshot creates one open anomaly; later observations update its last-seen time and evidence count.
New anomalies enter the webhook and TLS Syslog outboxes at high severity. Administrators may
acknowledge an anomaly, with actor and timestamp retained in the database and audit chain.

Baseline capture is intentionally never automatic: operators should first observe a representative,
known-good maintenance and production cycle. Empty or incomplete baselines will correctly classify
ordinary traffic as new. Acknowledgement does not silently add an edge to the baseline; accepting new
normal behavior requires a deliberate replacement snapshot.
