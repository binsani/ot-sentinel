import csv
import io
import json
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import append_audit_log
from app.auth import Principal, require_viewer
from app.database import get_session
from app.models import Asset, CveMatch, MatchStatus

router = APIRouter(
    prefix="/api/v1/exports",
    tags=["compliance exports"],
)


@router.get("/cyclonedx")
def export_cyclonedx(
    site_id: str | None = None,
    principal: Principal = Depends(require_viewer),
    session: Session = Depends(get_session),
) -> Response:
    assets = _assets(session, site_id)
    matches = _matches(session, [asset.id for asset in assets])
    document = build_cyclonedx(assets, matches)
    _audit_export(session, "cyclonedx", site_id, len(assets), principal.subject)
    return Response(
        content=json.dumps(document, separators=(",", ":")),
        media_type="application/vnd.cyclonedx+json; version=1.7",
        headers={"Content-Disposition": 'attachment; filename="ot-sentinel.cdx.json"'},
    )


@router.get("/assets.csv")
def export_assets_csv(
    site_id: str | None = None,
    principal: Principal = Depends(require_viewer),
    session: Session = Depends(get_session),
) -> Response:
    assets = _assets(session, site_id)
    content = build_asset_csv(assets)
    _audit_export(session, "asset-csv", site_id, len(assets), principal.subject)
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="ot-sentinel-assets.csv"'},
    )


def build_cyclonedx(assets: list[Asset], matches: list[CveMatch]) -> dict[str, Any]:
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    components = [_component(asset) for asset in assets]
    grouped: dict[str, list[CveMatch]] = defaultdict(list)
    for match in matches:
        grouped[match.cve_id].append(match)
    vulnerabilities = [_vulnerability(cve_id, rows) for cve_id, rows in sorted(grouped.items())]
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "OT-Sentinel",
                        "version": "0.1.0",
                    }
                ]
            },
            "properties": [
                {"name": "ot-sentinel:collection-mode", "value": "passive"},
                {"name": "ot-sentinel:inventory-scope", "value": "observed-assets"},
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def build_asset_csv(assets: list[Asset]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(
        [
            "asset_id",
            "site_id",
            "ip_address",
            "mac_address",
            "hostname",
            "vendor",
            "model",
            "firmware_version",
            "protocols",
            "criticality",
            "first_seen",
            "last_seen",
        ]
    )
    for asset in assets:
        writer.writerow(
            [
                str(asset.id),
                _csv_safe(asset.site_id),
                str(asset.ip_address),
                str(asset.mac_address or ""),
                _csv_safe(asset.hostname or ""),
                _csv_safe(asset.vendor or ""),
                _csv_safe(asset.model or ""),
                _csv_safe(asset.firmware_version or ""),
                ";".join(asset.protocols),
                asset.criticality,
                asset.first_seen.isoformat(),
                asset.last_seen.isoformat(),
            ]
        )
    return output.getvalue()


def _component(asset: Asset) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "device",
        "bom-ref": f"urn:uuid:{asset.id}",
        "name": asset.model or asset.hostname or f"OT asset {asset.ip_address}",
        "properties": [
            {"name": "ot-sentinel:asset-id", "value": str(asset.id)},
            {"name": "ot-sentinel:site-id", "value": asset.site_id},
            {"name": "ot-sentinel:ip-address", "value": str(asset.ip_address)},
            {"name": "ot-sentinel:protocols", "value": ",".join(asset.protocols)},
            {"name": "ot-sentinel:first-seen", "value": asset.first_seen.isoformat()},
            {"name": "ot-sentinel:last-seen", "value": asset.last_seen.isoformat()},
        ],
    }
    if asset.vendor:
        component["manufacturer"] = {"name": asset.vendor}
    if asset.firmware_version:
        component["version"] = asset.firmware_version
    cpe = asset.fingerprint.get("cpe")
    if isinstance(cpe, str) and cpe.startswith("cpe:2.3:"):
        component["cpe"] = cpe
    return component


def _vulnerability(cve_id: str, matches: list[CveMatch]) -> dict[str, Any]:
    representative = max(matches, key=lambda item: item.cvss_score or -1)
    if any(match.exploitable is True and match.status != MatchStatus.REJECTED for match in matches):
        state = "exploitable"
        detail = "Listed by CISA as known exploited and matched to an observed asset."
    elif any(match.status != MatchStatus.REJECTED for match in matches):
        state = "in_triage"
        detail = (
            "Fingerprint correlation requires operational review before exploitability is asserted."
        )
    else:
        state = "false_positive"
        detail = "All current asset correlations have been rejected or invalidated."
    result: dict[str, Any] = {
        "id": cve_id,
        "source": {
            "name": "National Vulnerability Database",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        },
        "analysis": {"state": state, "detail": detail},
        "affects": [
            {"ref": f"urn:uuid:{match.asset_id}"}
            for match in matches
        ],
    }
    if representative.cvss_score is not None:
        result["ratings"] = [
            {
                "source": {"name": "National Vulnerability Database"},
                "score": representative.cvss_score,
                "severity": (representative.severity or "unknown").lower(),
            }
        ]
    if any(match.patch_available for match in matches):
        result["analysis"]["response"] = ["update"]
    return result


def _csv_safe(value: str) -> str:
    return f"'{value}" if value.startswith(("=", "+", "-", "@")) else value


def _assets(session: Session, site_id: str | None) -> list[Asset]:
    statement = select(Asset).order_by(Asset.site_id, Asset.ip_address)
    if site_id:
        statement = statement.where(Asset.site_id == site_id)
    return list(session.scalars(statement))


def _matches(session: Session, asset_ids: list[uuid.UUID]) -> list[CveMatch]:
    if not asset_ids:
        return []
    return list(session.scalars(select(CveMatch).where(CveMatch.asset_id.in_(asset_ids))))


def _audit_export(
    session: Session,
    export_type: str,
    site_id: str | None,
    count: int,
    actor_subject: str,
) -> None:
    append_audit_log(
        session,
        action="report.exported",
        object_type="report",
        object_id=export_type,
        details={"site_id": site_id, "asset_count": count},
        actor_subject=actor_subject,
    )
    session.commit()
