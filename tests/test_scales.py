import pytest

from ratm import scales


@pytest.mark.parametrize(
    ("impact", "likelihood", "expected"),
    [
        ("Low", "Very Low", 1),
        ("Medium", "Low", 4),
        ("High", "High", 12),
        ("High", None, None),
        (None, "Low", None),
        ("Critical", "Low", None),
        ("High", "Unlikely", None),
    ],
)
def test_risk_score(impact, likelihood, expected) -> None:
    assert scales.risk_score(impact, likelihood) == expected


def test_capec_severity_clamps_to_impact_scale() -> None:
    assert scales.CAPEC_SEVERITY_TO_IMPACT["Very High"] == "High"
    assert scales.CAPEC_SEVERITY_TO_IMPACT["Very Low"] == "Low"
    assert set(scales.CAPEC_SEVERITY_TO_IMPACT.values()) <= set(scales.IMPACT_SCORES)


def test_default_statuses_are_valid() -> None:
    assert scales.DEFAULT_THREAT_STATUS in scales.THREAT_STATUSES
    assert scales.DEFAULT_MITIGATION_STATUS in scales.MITIGATION_STATUSES
