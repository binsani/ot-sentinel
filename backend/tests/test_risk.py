from app.risk import RiskInputs, calculate_risk


def test_risk_score_is_explainable_and_weighted() -> None:
    result = calculate_risk(
        RiskInputs(criticality=5, max_cvss=8.0, known_exploited=False, peer_count=5)
    )
    assert result["score"] == 77.5
    assert result["band"] == "critical"
    assert result["components"] == {
        "vulnerability": 80.0,
        "network_exposure": 50.0,
        "criticality": 100.0,
    }


def test_known_exploited_floors_vulnerability_component() -> None:
    result = calculate_risk(
        RiskInputs(criticality=1, max_cvss=4.0, known_exploited=True, peer_count=0)
    )
    assert result["components"]["vulnerability"] == 90.0
    assert result["score"] == 45.0
    assert result["band"] == "medium"


def test_risk_inputs_are_bounded() -> None:
    result = calculate_risk(
        RiskInputs(criticality=10, max_cvss=50.0, known_exploited=False, peer_count=999)
    )
    assert result["score"] == 100.0
    assert all(value <= 100 for value in result["components"].values())
