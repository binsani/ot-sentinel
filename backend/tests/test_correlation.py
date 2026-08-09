from datetime import UTC, datetime

from app.cve.correlation import _is_cisa_ics_advisory, match_asset
from app.models import Asset


def asset(version: str | None = "1.5") -> Asset:
    now = datetime.now(UTC)
    return Asset(
        site_id="test",
        ip_address="192.0.2.1",
        vendor="Example Vendor",
        model="PLC-100",
        firmware_version=version,
        protocols=["modbus_tcp"],
        fingerprint={},
        first_seen=now,
        last_seen=now,
    )


def test_exact_version_is_confirmed() -> None:
    result = match_asset(
        asset("1.5"),
        [{"criteria": "cpe:2.3:h:example_vendor:plc_100:1.5:*:*:*:*:*:*:*"}],
    )
    assert result is not None
    assert result[0] == 0.95


def test_version_range_matches() -> None:
    result = match_asset(
        asset("1.5"),
        [
            {
                "criteria": "cpe:2.3:h:example_vendor:plc_100:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "1.0",
                "versionEndExcluding": "2.0",
            }
        ],
    )
    assert result is not None
    assert result[0] == 0.95


def test_missing_firmware_is_only_candidate() -> None:
    result = match_asset(
        asset(None),
        [{"criteria": "cpe:2.3:h:example_vendor:plc_100:1.5:*:*:*:*:*:*:*"}],
    )
    assert result is not None
    assert result[0] == 0.7


def test_different_model_does_not_match() -> None:
    result = match_asset(
        asset(),
        [{"criteria": "cpe:2.3:h:example_vendor:different_plc:1.5:*:*:*:*:*:*:*"}],
    )
    assert result is None


def test_identifies_official_cisa_ics_advisory_reference() -> None:
    assert _is_cisa_ics_advisory(
        "https://www.cisa.gov/news-events/ics-advisories/icsa-26-001-01"
    )
    assert not _is_cisa_ics_advisory("https://example.test/icsa-26-001-01")
