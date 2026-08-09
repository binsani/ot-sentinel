import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.audit import append_audit_log
from app.auth import Principal, require_viewer
from app.database import get_session
from app.models import Asset, CveMatch, MatchStatus, Observation

router = APIRouter(
    prefix="/api/v1/assets",
    tags=["asset inventory"],
)


@router.get("")
def list_assets(
    site_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require_viewer),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    statement = select(Asset).order_by(Asset.last_seen.desc()).limit(limit).offset(offset)
    if site_id:
        statement = statement.where(Asset.site_id == site_id)
    assets = list(session.scalars(statement))
    _audit_inventory_read(
        session,
        principal,
        action="assets.viewed",
        object_type="asset_collection",
        object_id=None,
        details={"site_id": site_id, "limit": limit, "offset": offset, "count": len(assets)},
    )
    return [_asset_dict(asset) for asset in assets]


@router.get("/graph/communications")
def communication_graph(
    site_id: str | None = None,
    limit: int = Query(default=500, ge=1, le=2000),
    principal: Principal = Depends(require_viewer),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    statement = (
        select(
            Observation.source_ip,
            Observation.destination_ip,
            Observation.protocol,
            func.sum(Observation.packet_count).label("packet_count"),
            func.sum(Observation.byte_count).label("byte_count"),
            func.max(Observation.observed_at).label("last_seen"),
        )
        .join(Asset, Asset.id == Observation.asset_id)
        .group_by(Observation.source_ip, Observation.destination_ip, Observation.protocol)
        .order_by(func.max(Observation.observed_at).desc())
        .limit(limit)
    )
    if site_id:
        statement = statement.where(Asset.site_id == site_id)
    rows = session.execute(statement).all()
    node_ids = {str(row.source_ip) for row in rows} | {str(row.destination_ip) for row in rows}
    result = {
        "nodes": [{"id": node_id, "label": node_id} for node_id in sorted(node_ids)],
        "edges": [
            {
                "id": f"{row.source_ip}|{row.destination_ip}|{row.protocol}",
                "source": str(row.source_ip),
                "target": str(row.destination_ip),
                "protocol": row.protocol,
                "packet_count": int(row.packet_count),
                "byte_count": int(row.byte_count),
                "last_seen": row.last_seen,
            }
            for row in rows
        ],
    }
    _audit_inventory_read(
        session,
        principal,
        action="communication_graph.viewed",
        object_type="communication_graph",
        object_id=None,
        details={"site_id": site_id, "limit": limit, "edge_count": len(rows)},
    )
    return result


@router.get("/sites/summary")
def site_summary(
    principal: Principal = Depends(require_viewer),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    vulnerability_totals = (
        select(
            Asset.site_id.label("site_id"),
            func.count(CveMatch.id).label("vulnerability_matches"),
            func.count(func.distinct(CveMatch.asset_id)).label("vulnerable_assets"),
        )
        .join(CveMatch, CveMatch.asset_id == Asset.id)
        .where(CveMatch.status != MatchStatus.REJECTED)
        .group_by(Asset.site_id)
        .subquery()
    )
    rows = session.execute(
        select(
            Asset.site_id,
            func.count(Asset.id).label("asset_count"),
            func.max(Asset.last_seen).label("last_seen"),
            func.sum(
                case(
                    (
                        Asset.firmware_baseline.is_not(None)
                        & Asset.firmware_version.is_not(None)
                        & (Asset.firmware_baseline != Asset.firmware_version),
                        1,
                    ),
                    else_=0,
                )
            ).label("firmware_drift_count"),
            func.coalesce(
                vulnerability_totals.c.vulnerability_matches, 0
            ).label("vulnerability_matches"),
            func.coalesce(vulnerability_totals.c.vulnerable_assets, 0).label(
                "vulnerable_assets"
            ),
        )
        .outerjoin(vulnerability_totals, vulnerability_totals.c.site_id == Asset.site_id)
        .group_by(
            Asset.site_id,
            vulnerability_totals.c.vulnerability_matches,
            vulnerability_totals.c.vulnerable_assets,
        )
        .order_by(func.count(Asset.id).desc(), Asset.site_id)
    ).all()
    result = [
        {
            "site_id": row.site_id,
            "asset_count": int(row.asset_count),
            "last_seen": row.last_seen,
            "firmware_drift_count": int(row.firmware_drift_count),
            "vulnerability_matches": int(row.vulnerability_matches),
            "vulnerable_assets": int(row.vulnerable_assets),
        }
        for row in rows
    ]
    _audit_inventory_read(
        session,
        principal,
        action="sites.viewed",
        object_type="site_collection",
        object_id=None,
        details={"count": len(result)},
    )
    return result


@router.get("/{asset_id}")
def get_asset(
    asset_id: uuid.UUID,
    principal: Principal = Depends(require_viewer),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")
    result = _asset_dict(asset)
    result["vulnerabilities"] = [
        {
            "cve_id": match.cve_id,
            "status": match.status.value,
            "confidence": match.confidence,
            "cvss_score": match.cvss_score,
            "severity": match.severity,
            "known_exploited": match.exploitable,
            "patch_available": match.patch_available,
            "matched_on": match.matched_on,
            "advisory": match.advisory,
        }
        for match in session.scalars(
            select(CveMatch)
            .where(CveMatch.asset_id == asset.id)
            .order_by(CveMatch.cvss_score.desc().nullslast())
        )
    ]
    _audit_inventory_read(
        session,
        principal,
        action="asset.viewed",
        object_type="asset",
        object_id=str(asset.id),
        details={"vulnerability_count": len(result["vulnerabilities"])},
    )
    return result


def _audit_inventory_read(
    session: Session,
    principal: Principal,
    *,
    action: str,
    object_type: str,
    object_id: str | None,
    details: dict[str, Any],
) -> None:
    append_audit_log(
        session,
        action=action,
        object_type=object_type,
        object_id=object_id,
        details=details,
        actor_subject=principal.subject,
    )
    session.commit()


def _asset_dict(asset: Asset) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "site_id": asset.site_id,
        "ip_address": str(asset.ip_address),
        "mac_address": str(asset.mac_address) if asset.mac_address else None,
        "hostname": asset.hostname,
        "vendor": asset.vendor,
        "model": asset.model,
        "firmware_version": asset.firmware_version,
        "firmware_baseline": asset.firmware_baseline,
        "firmware_baseline_set_at": asset.firmware_baseline_set_at,
        "firmware_baseline_set_by": asset.firmware_baseline_set_by,
        "firmware_drift_detected_at": asset.firmware_drift_detected_at,
        "firmware_drift": bool(
            asset.firmware_baseline
            and asset.firmware_version
            and asset.firmware_baseline != asset.firmware_version
        ),
        "protocols": asset.protocols,
        "fingerprint": asset.fingerprint,
        "criticality": asset.criticality,
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
    }
