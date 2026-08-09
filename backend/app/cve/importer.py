from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.audit import append_audit_log
from app.cve.nvd import parse_nvd_page
from app.models import Vulnerability


def import_nvd_document(session: Session, document: dict[str, Any]) -> int:
    records = parse_nvd_page(document)
    for record in records:
        statement = insert(Vulnerability).values(**record)
        statement = statement.on_conflict_do_update(
            index_elements=[Vulnerability.cve_id],
            set_={
                **{
                    key: statement.excluded[key]
                    for key in record
                    if key not in {"cve_id", "known_exploited", "remediation"}
                },
                "imported_at": datetime.now(UTC),
            },
        )
        session.execute(statement)
    append_audit_log(
        session,
        action="vulnerability_feed.imported",
        object_type="vulnerability_catalog",
        object_id="nvd",
        details={"record_count": len(records)},
        actor_subject="system:cve-import",
    )
    session.commit()
    return len(records)


def apply_cisa_kev_document(session: Session, document: dict[str, Any]) -> int:
    updated = 0
    for item in document.get("vulnerabilities", []):
        cve_id = item.get("cveID")
        if not isinstance(cve_id, str):
            continue
        vulnerability = session.scalar(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        )
        if vulnerability is None:
            continue
        vulnerability.known_exploited = True
        vulnerability.remediation = item.get("requiredAction")
        updated += 1
    append_audit_log(
        session,
        action="vulnerability_feed.enriched",
        object_type="vulnerability_catalog",
        object_id="cisa-kev",
        details={"record_count": updated},
        actor_subject="system:cve-import",
    )
    session.commit()
    return updated
