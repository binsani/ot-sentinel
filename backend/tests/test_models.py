from app import models  # noqa: F401
from app.database import Base


def test_core_tables_are_registered() -> None:
    assert {
        "assets",
        "observations",
        "protocol_events",
        "cve_matches",
        "users",
        "audit_log",
        "vulnerabilities",
    } <= set(Base.metadata.tables)
