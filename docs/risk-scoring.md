# Explainable asset risk scoring

OT-Sentinel calculates a deterministic 0–100 prioritization score from evidence already stored in
the platform. The score is not a prediction and does not replace an OT engineer's safety or impact
assessment.

| Component | Weight | Calculation |
|---|---:|---|
| Vulnerability | 50% | Highest active CVSS score multiplied by 10; CISA KEV evidence sets a floor of 90 |
| Network exposure | 25% | Ten points per distinct passively observed communication peer, capped at 100 |
| Criticality | 25% | Operator-assigned criticality 1–5 mapped linearly to 0–100 |

Bands are low below 25, medium from 25, high from 50, and critical from 75. API and dashboard
responses include every component and the underlying CVSS, KEV, peer-count, and criticality evidence.
Inventory and evidence changes are reflected on the next calculation; no hidden model state exists.
CSV and CycloneDX exports carry the same score, band, component breakdown, and open communication
anomaly count used by the dashboard.
