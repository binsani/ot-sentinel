from app.cve.nvd import parse_nvd_page


def test_parse_nvd_v2_shape() -> None:
    document = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1234",
                    "sourceIdentifier": "example@example.invalid",
                    "published": "2026-01-01T00:00:00.000Z",
                    "lastModified": "2026-01-02T00:00:00.000Z",
                    "descriptions": [
                        {"lang": "es", "value": "descripción"},
                        {"lang": "en", "value": "Example vulnerability"},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:h:vendor:plc:1.0:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [{"url": "https://example.invalid", "tags": ["Patch"]}],
                }
            }
        ]
    }
    record = parse_nvd_page(document)[0]
    assert record["cve_id"] == "CVE-2026-1234"
    assert record["description"] == "Example vulnerability"
    assert record["cvss_score"] == 9.8
    assert record["cpe_matches"][0]["criteria"].startswith("cpe:2.3:h:vendor")

