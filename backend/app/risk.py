from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.audit import append_audit_log
from app.auth import Principal, require_viewer
from app.database import get_session
from app.models import Asset, CveMatch, MatchStatus, Observation

router = APIRouter(prefix="/api/v1/assets/risk", tags=["asset risk"])


@dataclass(frozen=True, slots=True)
class RiskInputs:
    criticality: int
    max_cvss: float | None
    known_exploited: bool
    peer_count: int


def calculate_risk(inputs: RiskInputs) -> dict[str, Any]:
    vulnerability = max(0.0, min(100.0, (inputs.max_cvss or 0.0) * 10.0))
    if inputs.known_exploited:
        vulnerability = max(vulnerability, 90.0)
    exposure = min(100.0, max(0, inputs.peer_count) * 10.0)
    criticality = max(0.0, min(100.0, (inputs.criticality - 1) * 25.0))
    score = round(0.5 * vulnerability + 0.25 * exposure + 0.25 * criticality, 1)
    band = (
        "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    )
    return {
        "score": score,
        "band": band,
        "components": {
            "vulnerability": round(vulnerability, 1),
            "network_exposure": round(exposure, 1),
            "criticality": round(criticality, 1),
        },
        "evidence": {
            "max_cvss": inputs.max_cvss,
            "known_exploited": inputs.known_exploited,
            "observed_peer_count": inputs.peer_count,
            "asset_criticality": inputs.criticality,
        },
    }


@router.get("/summary")
def risk_summary(
    site_id: str | None = None,
    limit: int = Query(default=500, ge=1, le=2000),
    principal: Principal = Depends(require_viewer),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    asset_statement = select(Asset).order_by(Asset.last_seen.desc()).limit(limit)
    if site_id:
        asset_statement = asset_statement.where(Asset.site_id == site_id)
    assets = list(session.scalars(asset_statement))
    asset_ids = [asset.id for asset in assets]
    if not asset_ids:
        return []
    vulnerability_rows = session.execute(
        select(
            CveMatch.asset_id,
            func.max(CveMatch.cvss_score).label("max_cvss"),
            func.max(case((CveMatch.exploitable.is_(True), 1), else_=0)).label("known_exploited"),
        )
        .where(CveMatch.asset_id.in_(asset_ids), CveMatch.status != MatchStatus.REJECTED)
        .group_by(CveMatch.asset_id)
    ).all()
    vulnerability_by_asset = {
        row.asset_id: (
            float(row.max_cvss) if row.max_cvss is not None else None,
            bool(row.known_exploited),
        )
        for row in vulnerability_rows
    }
    peer = case(
        (Observation.source_ip == Asset.ip_address, Observation.destination_ip),
        else_=Observation.source_ip,
    )
    peer_rows = session.execute(
        select(Observation.asset_id, func.count(func.distinct(peer)).label("peer_count"))
        .join(Asset, Asset.id == Observation.asset_id)
        .where(Observation.asset_id.in_(asset_ids))
        .group_by(Observation.asset_id)
    ).all()
    peers_by_asset = {row.asset_id: int(row.peer_count) for row in peer_rows}
    result = []
    for asset in assets:
        max_cvss, known_exploited = vulnerability_by_asset.get(asset.id, (None, False))
        risk = calculate_risk(
            RiskInputs(
                criticality=asset.criticality,
                max_cvss=max_cvss,
                known_exploited=known_exploited,
                peer_count=peers_by_asset.get(asset.id, 0),
            )
        )
        result.append(
            {
                "asset_id": str(asset.id),
                "site_id": asset.site_id,
                "ip_address": str(asset.ip_address),
                "vendor": asset.vendor,
                "model": asset.model,
                **risk,
            }
        )
    result.sort(key=lambda item: (-item["score"], item["site_id"], item["ip_address"]))
    append_audit_log(
        session,
        action="asset_risk.viewed",
        object_type="risk_summary",
        object_id=None,
        details={"site_id": site_id, "count": len(result)},
        actor_subject=principal.subject,
    )
    session.commit()
    return result
