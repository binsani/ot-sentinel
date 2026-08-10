import uuid
from datetime import UTC, datetime

from app.exports import build_asset_csv, build_cyclonedx
from app.models import Asset, CveMatch, MatchStatus


def make_asset(*, site_id: str = "plant-a") -> Asset:
    now = datetime.now(UTC)
    return Asset(
        id=uuid.uuid4(),
        site_id=site_id,
        ip_address="192.0.2.10",
        vendor="Example Vendor",
        model="PLC 100",
        firmware_version="1.2.3",
        protocols=["modbus_tcp"],
        fingerprint={"cpe": "cpe:2.3:h:example:plc_100:1.2.3:*:*:*:*:*:*:*"},
        criticality=3,
        first_seen=now,
        last_seen=now,
    )


def test_cyclonedx_export_links_vulnerability_to_asset() -> None:
    asset = make_asset()
    match = CveMatch(
        asset_id=asset.id,
        cve_id="CVE-2026-1234",
        source="nvd",
        status=MatchStatus.CONFIRMED,
        confidence=0.95,
        cvss_score=9.8,
        severity="CRITICAL",
        exploitable=True,
        patch_available=True,
        matched_on={},
        advisory={},
        last_evaluated_at=datetime.now(UTC),
    )
    document = build_cyclonedx([asset], [match])
    assert document["specVersion"] == "1.7"
    assert document["components"][0]["bom-ref"] == f"urn:uuid:{asset.id}"
    vulnerability = document["vulnerabilities"][0]
    assert vulnerability["analysis"]["state"] == "exploitable"
    assert vulnerability["affects"] == [{"ref": f"urn:uuid:{asset.id}"}]


def test_csv_export_neutralizes_spreadsheet_formulas() -> None:
    output = build_asset_csv([make_asset(site_id="=cmd|test")])
    assert "'=cmd|test" in output


def test_exports_include_risk_and_anomaly_evidence() -> None:
    asset = make_asset()
    risks = {
        asset.id: {
            "score": 72.5,
            "band": "high",
            "components": {
                "vulnerability": 90.0,
                "network_exposure": 50.0,
                "criticality": 50.0,
            },
        }
    }
    anomaly_counts = {asset.id: 2}
    document = build_cyclonedx([asset], [], risks, anomaly_counts)
    properties = {item["name"]: item["value"] for item in document["components"][0]["properties"]}
    assert properties["ot-sentinel:risk-score"] == "72.5"
    assert properties["ot-sentinel:risk-band"] == "high"
    assert properties["ot-sentinel:open-communication-anomalies"] == "2"

    output = build_asset_csv([asset], risks, anomaly_counts)
    assert "risk_score,risk_band" in output
    assert "72.5,high,90.0,50.0,50.0,2" in output
