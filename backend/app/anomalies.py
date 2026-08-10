import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.alerting import enqueue_alert
from app.audit import append_audit_log
from app.auth import Principal, require_admin, require_viewer
from app.database import get_session
from app.models import (
    Asset,
    GraphAnomaly,
    GraphBaseline,
    GraphBaselineEdge,
    Observation,
)

router = APIRouter(prefix="/api/v1/anomalies", tags=["communication anomalies"])
BASELINE_CONFIRMATION = "CAPTURE CURRENT COMMUNICATIONS AS BASELINE"


class BaselineCreate(BaseModel):
    site_id: str = Field(min_length=1, max_length=128)
    confirmation: str


@router.post("/baselines", status_code=status.HTTP_201_CREATED)
def capture_baseline(
    data: BaselineCreate,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    if data.confirmation != BASELINE_CONFIRMATION:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="explicit baseline confirmation is required",
        )
    session.execute(
        update(GraphBaseline)
        .where(GraphBaseline.site_id == data.site_id, GraphBaseline.active.is_(True))
        .values(active=False)
    )
    edges = session.execute(
        select(
            Observation.source_ip,
            Observation.destination_ip,
            Observation.protocol,
        )
        .join(Asset, Asset.id == Observation.asset_id)
        .where(Asset.site_id == data.site_id)
        .group_by(
            Observation.source_ip,
            Observation.destination_ip,
            Observation.protocol,
        )
    ).all()
    captured_at = datetime.now(UTC)
    baseline = GraphBaseline(
        site_id=data.site_id,
        active=True,
        captured_at=captured_at,
        captured_by=principal.subject,
        edge_count=len(edges),
    )
    session.add(baseline)
    session.flush()
    session.add_all(
        [
            GraphBaselineEdge(
                baseline_id=baseline.id,
                source_ip=row.source_ip,
                destination_ip=row.destination_ip,
                protocol=row.protocol,
            )
            for row in edges
        ]
    )
    append_audit_log(
        session,
        action="communication_baseline.captured",
        object_type="graph_baseline",
        object_id=str(baseline.id),
        details={"site_id": data.site_id, "edge_count": len(edges)},
        actor_subject=principal.subject,
    )
    session.commit()
    return baseline_dict(baseline)


@router.get("/baselines")
def list_baselines(
    principal: Principal = Depends(require_viewer),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    rows = session.scalars(select(GraphBaseline).order_by(GraphBaseline.captured_at.desc()))
    return [baseline_dict(row) for row in rows]


@router.get("")
def list_anomalies(
    site_id: str | None = None,
    anomaly_status: str = Query(default="open", pattern="^(open|acknowledged|all)$"),
    principal: Principal = Depends(require_viewer),
    session: Session = Depends(get_session),
) -> list[dict[str, Any]]:
    statement = select(GraphAnomaly).order_by(GraphAnomaly.last_seen.desc()).limit(500)
    if site_id:
        statement = statement.where(GraphAnomaly.site_id == site_id)
    if anomaly_status != "all":
        statement = statement.where(GraphAnomaly.status == anomaly_status)
    rows = list(session.scalars(statement))
    append_audit_log(
        session,
        action="communication_anomalies.viewed",
        object_type="graph_anomaly_collection",
        object_id=None,
        details={"site_id": site_id, "status": anomaly_status, "count": len(rows)},
        actor_subject=principal.subject,
    )
    session.commit()
    return [anomaly_dict(row) for row in rows]


@router.post("/{anomaly_id}/acknowledge")
def acknowledge_anomaly(
    anomaly_id: uuid.UUID,
    principal: Principal = Depends(require_admin),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    anomaly = session.scalar(
        select(GraphAnomaly).where(GraphAnomaly.id == anomaly_id).with_for_update()
    )
    if anomaly is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="anomaly not found")
    anomaly.status = "acknowledged"
    anomaly.acknowledged_at = datetime.now(UTC)
    anomaly.acknowledged_by = principal.subject
    append_audit_log(
        session,
        action="communication_anomaly.acknowledged",
        object_type="graph_anomaly",
        object_id=str(anomaly.id),
        details={},
        actor_subject=principal.subject,
    )
    session.commit()
    return anomaly_dict(anomaly)


def analyze_active_baselines(session: Session) -> int:
    created = 0
    baselines = list(
        session.scalars(
            select(GraphBaseline).where(GraphBaseline.active.is_(True)).with_for_update()
        )
    )
    for baseline in baselines:
        known_edges = set(
            session.execute(
                select(
                    GraphBaselineEdge.source_ip,
                    GraphBaselineEdge.destination_ip,
                    GraphBaselineEdge.protocol,
                ).where(GraphBaselineEdge.baseline_id == baseline.id)
            ).all()
        )
        observed = session.execute(
            select(
                Observation.source_ip,
                Observation.destination_ip,
                Observation.protocol,
                func.min(Observation.observed_at).label("first_seen"),
                func.max(Observation.observed_at).label("last_seen"),
                func.count(Observation.id).label("observation_count"),
            )
            .join(Asset, Asset.id == Observation.asset_id)
            .where(
                Asset.site_id == baseline.site_id,
                Observation.observed_at > baseline.captured_at,
            )
            .group_by(
                Observation.source_ip,
                Observation.destination_ip,
                Observation.protocol,
            )
        ).all()
        for row in observed:
            edge = (row.source_ip, row.destination_ip, row.protocol)
            if edge in known_edges:
                continue
            anomaly = session.scalar(
                select(GraphAnomaly).where(
                    GraphAnomaly.baseline_id == baseline.id,
                    GraphAnomaly.source_ip == row.source_ip,
                    GraphAnomaly.destination_ip == row.destination_ip,
                    GraphAnomaly.protocol == row.protocol,
                )
            )
            if anomaly is not None:
                anomaly.last_seen = row.last_seen
                anomaly.observation_count = int(row.observation_count)
                continue
            anomaly = GraphAnomaly(
                baseline_id=baseline.id,
                site_id=baseline.site_id,
                source_ip=row.source_ip,
                destination_ip=row.destination_ip,
                protocol=row.protocol,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                observation_count=int(row.observation_count),
            )
            session.add(anomaly)
            session.flush()
            enqueue_alert(
                session,
                event_type="communication_anomaly",
                site_id=baseline.site_id,
                payload={
                    "anomaly_id": str(anomaly.id),
                    "source_ip": str(row.source_ip),
                    "destination_ip": str(row.destination_ip),
                    "protocol": row.protocol,
                    "first_seen": row.first_seen.isoformat(),
                },
            )
            created += 1
    session.commit()
    return created


def baseline_dict(row: GraphBaseline) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "site_id": row.site_id,
        "active": row.active,
        "captured_at": row.captured_at,
        "captured_by": row.captured_by,
        "edge_count": row.edge_count,
    }


def anomaly_dict(row: GraphAnomaly) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "baseline_id": str(row.baseline_id),
        "site_id": row.site_id,
        "source_ip": str(row.source_ip),
        "destination_ip": str(row.destination_ip),
        "protocol": row.protocol,
        "status": row.status,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "observation_count": row.observation_count,
        "acknowledged_at": row.acknowledged_at,
        "acknowledged_by": row.acknowledged_by,
    }
