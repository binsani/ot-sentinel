from collections.abc import Iterator
from datetime import datetime
from typing import Any


def parse_nvd_page(document: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for wrapper in document.get("vulnerabilities", []):
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        score, severity = _best_metric(cve.get("metrics", {}))
        references = [
            {"url": item.get("url"), "tags": item.get("tags", [])}
            for item in cve.get("references", [])
            if item.get("url")
        ]
        records.append(
            {
                "cve_id": cve_id,
                "source_identifier": cve.get("sourceIdentifier"),
                "description": _english_description(cve.get("descriptions", [])),
                "published_at": _datetime(cve.get("published")),
                "modified_at": _datetime(cve.get("lastModified")),
                "cvss_score": score,
                "severity": severity,
                "cpe_matches": list(_walk_cpe_matches(cve.get("configurations", []))),
                "references": references,
                "known_exploited": False,
                "remediation": None,
                "raw": cve,
            }
        )
    return records


def _english_description(items: list[dict[str, Any]]) -> str:
    for item in items:
        if item.get("lang") == "en":
            return str(item.get("value", ""))
    return ""


def _datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _best_metric(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return (float(score) if score is not None else None, severity)
    return None, None


def _walk_cpe_matches(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        for match in value.get("cpeMatch", []):
            if match.get("vulnerable", False) and match.get("criteria"):
                yield {
                    key: match[key]
                    for key in (
                        "criteria",
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    )
                    if key in match
                }
        for child in value.values():
            yield from _walk_cpe_matches(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_cpe_matches(child)

