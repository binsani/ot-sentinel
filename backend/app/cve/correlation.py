import re
from datetime import UTC, datetime
from typing import Any

from packaging.version import InvalidVersion, Version
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.alerting import enqueue_alert
from app.models import Asset, CveMatch, MatchStatus, Vulnerability


def correlate_assets(session: Session) -> int:
    count = 0
    assets = session.scalars(
        select(Asset).where(Asset.vendor.is_not(None), Asset.model.is_not(None))
    )
    vulnerabilities = session.scalars(select(Vulnerability)).all()
    for asset in assets:
        existing_cves = set(
            session.scalars(select(CveMatch.cve_id).where(CveMatch.asset_id == asset.id))
        )
        matched_cves: set[str] = set()
        for vulnerability in vulnerabilities:
            result = match_asset(asset, vulnerability.cpe_matches)
            if result is None:
                continue
            confidence, matched_on = result
            matched_cves.add(vulnerability.cve_id)
            patch_available = any(
                any(
                    str(tag).casefold() in {"patch", "vendor advisory"}
                    for tag in reference.get("tags", [])
                )
                for reference in vulnerability.references
            )
            cisa_ics_advisories = [
                reference.get("url")
                for reference in vulnerability.references
                if _is_cisa_ics_advisory(reference.get("url"))
            ]
            statement = insert(CveMatch).values(
                asset_id=asset.id,
                cve_id=vulnerability.cve_id,
                source="nvd",
                status=MatchStatus.CONFIRMED if confidence >= 0.9 else MatchStatus.CANDIDATE,
                confidence=confidence,
                cvss_score=vulnerability.cvss_score,
                severity=vulnerability.severity,
                exploitable=vulnerability.known_exploited,
                patch_available=patch_available,
                matched_on=matched_on,
                advisory={
                    "description": vulnerability.description,
                    "cisa_ics_advisories": cisa_ics_advisories,
                },
                last_evaluated_at=datetime.now(UTC),
            )
            statement = statement.on_conflict_do_update(
                constraint="uq_cve_matches_asset_cve",
                set_={
                    "status": statement.excluded.status,
                    "confidence": statement.excluded.confidence,
                    "cvss_score": statement.excluded.cvss_score,
                    "severity": statement.excluded.severity,
                    "exploitable": statement.excluded.exploitable,
                    "patch_available": statement.excluded.patch_available,
                    "matched_on": statement.excluded.matched_on,
                    "advisory": statement.excluded.advisory,
                    "last_evaluated_at": statement.excluded.last_evaluated_at,
                },
            )
            session.execute(statement)
            if vulnerability.cve_id not in existing_cves:
                enqueue_alert(
                    session,
                    event_type="vulnerability_match",
                    site_id=asset.site_id,
                    payload={
                        "asset_id": str(asset.id),
                        "ip_address": str(asset.ip_address),
                        "cve_id": vulnerability.cve_id,
                        "severity": vulnerability.severity,
                        "cvss_score": vulnerability.cvss_score,
                        "known_exploited": vulnerability.known_exploited,
                    },
                )
            count += 1
        stale = update(CveMatch).where(
            CveMatch.asset_id == asset.id,
            CveMatch.source == "nvd",
            CveMatch.status != MatchStatus.REJECTED,
        )
        if matched_cves:
            stale = stale.where(CveMatch.cve_id.not_in(matched_cves))
        session.execute(
            stale.values(
                status=MatchStatus.REJECTED,
                confidence=0,
                last_evaluated_at=datetime.now(UTC),
            )
        )
    session.commit()
    return count


def match_asset(
    asset: Asset, matches: list[dict[str, Any]]
) -> tuple[float, dict[str, Any]] | None:
    vendor = _normalize(asset.vendor or "")
    model = _normalize(asset.model or "")
    for match in matches:
        parts = _split_cpe(match.get("criteria", ""))
        if len(parts) < 6 or _normalize(parts[3]) != vendor or _normalize(parts[4]) != model:
            continue
        cpe_version = parts[5]
        if not asset.firmware_version:
            return 0.7, {"criteria": match["criteria"], "vendor": vendor, "model": model}
        if _version_matches(asset.firmware_version, cpe_version, match):
            return 0.95, {
                "criteria": match["criteria"],
                "vendor": vendor,
                "model": model,
                "firmware_version": asset.firmware_version,
            }
    return None


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _is_cisa_ics_advisory(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return "cisa.gov/news-events/ics-advisories/" in value.casefold()


def _split_cpe(value: str) -> list[str]:
    parts: list[str] = []
    current = ""
    escaped = False
    for character in value:
        if escaped:
            current += character
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append(current)
            current = ""
        else:
            current += character
    parts.append(current)
    return parts


def _version_matches(version: str, cpe_version: str, match: dict[str, Any]) -> bool:
    if cpe_version not in {"*", "-"}:
        return _normalize(version) == _normalize(cpe_version)
    try:
        candidate = Version(version)
        if "versionStartIncluding" in match:
            if candidate < Version(str(match["versionStartIncluding"])):
                return False
        if "versionStartExcluding" in match:
            if candidate <= Version(str(match["versionStartExcluding"])):
                return False
        if "versionEndIncluding" in match:
            if candidate > Version(str(match["versionEndIncluding"])):
                return False
        if "versionEndExcluding" in match:
            if candidate >= Version(str(match["versionEndExcluding"])):
                return False
        return True
    except InvalidVersion:
        return False
