"""Tests for the model code: the Ratm builders, Threat, Mitigation, and Report."""

import pytest

from ratm import CAPECInfo, Mitigation, Ratm, Report, Scenario, Threat, ThreatActor


@pytest.fixture()
def tm() -> Ratm:
    tm = Ratm(load_capec_info=False)
    tm.define_properties(
        "reads_input",
        "sanitizes_input",
        ("loads_resources", "Loads resources", (), tuple),
        ("verifies_resources", "Verifies resources", (), tuple),
    )
    tm.Mitigation("M-SANITIZE", title="Sanitize input", property="sanitizes_input")
    tm.Mitigation(
        "M-VERIFY",
        title="Verify resources",
        property="verifies_resources.deps",
        status="proposed",
    )
    tm.Mitigation("M-DOCS", title="Document the risk", status="optional")
    tm.ThreatActor("Nation state", description="Well-resourced adversary")
    tm.ThreatActor("Any")
    return tm


def make_scenario(tm: Ratm) -> Scenario:
    a = tm.Component(name="A", reads_input=True, sanitizes_input=True)
    b = tm.Component(name="B", reads_input=True)
    scenario = Scenario(name="S1")
    scenario.Dataflow(name="A to B", source=a, sink=b)
    return scenario


# -- Mitigation and ThreatActor entities


def test_mitigation_to_dict() -> None:
    mit = Mitigation("M1", title="T", property="verifies_resources.deps")
    assert mit.property_names == ["verifies_resources"]
    assert mit.to_dict() == {
        "id": "M1",
        "title": "T",
        "description": "",
        "status": "implemented",
        "property": "verifies_resources.deps",
    }
    assert Mitigation("M2", title="T").property_names == []
    assert Mitigation("M3", title="T", property="a != b").property_names == ["a", "b"]
    assert Mitigation("M4", title="T", property="!is_exposed").property_names == [
        "is_exposed"
    ]


def test_threat_actor_to_dict() -> None:
    assert ThreatActor("Any").to_dict() == {"name": "Any", "description": ""}
    assert ThreatActor("Troll", description="Bored").to_dict() == {
        "name": "Troll",
        "description": "Bored",
    }


def test_ratm_rejects_duplicate_ids(tm: Ratm) -> None:
    tm.Threat("T1", requirements=["reads_input"])
    with pytest.raises(ValueError, match="T1"):
        tm.Threat("T1", requirements=["reads_input"])
    with pytest.raises(ValueError, match="M-DOCS"):
        tm.Mitigation("M-DOCS", title="again")
    with pytest.raises(ValueError, match="Any"):
        tm.ThreatActor("Any")


# -- Threat


def test_threat_matches_ignores_mitigations(tm: Ratm) -> None:
    """Only the requirements decide whether a threat applies."""
    threat = tm.Threat("T1", requirements=["reads_input"], mitigations=["M-SANITIZE"])
    a = tm.Component(name="A", reads_input=True, sanitizes_input=True)
    assert threat.matches(a) is True


def test_threat_labels_and_scores() -> None:
    threat = Threat("T1", requirements=["x"], impact="High", likelihood="Low")
    assert threat.impact_label == "High"
    assert threat.likelihood_label == "Low"
    assert threat.risk_score == 6
    # Residual values default to the base ones.
    assert threat.residual_impact_label == "High"
    assert threat.residual_likelihood_label == "Low"
    assert threat.residual_risk_score == 6
    threat.residual_likelihood = "Very Low"
    assert threat.residual_risk_score == 3


def test_threat_falls_back_to_capec_info() -> None:
    threat = Threat(
        "CAPEC-1",
        requirements=["x"],
        capec_info=CAPECInfo(
            description="d", severity="Very High", likelihood="Medium"
        ),
    )
    assert threat.impact_label == "High"
    assert threat.likelihood_label == "Medium"
    assert threat.risk_score == 9
    assert Threat("T2", requirements=["x"]).risk_score is None


def test_threat_to_dict_shape() -> None:
    threat = Threat(
        "T1",
        requirements=["reads_input"],
        mitigations=["M-SANITIZE"],
        capec_info=CAPECInfo(
            description="Bad input", severity="Medium", likelihood="Low"
        ),
        status="partially mitigated",
        impact="High",
        residual_impact="Medium",
        residual_risk="Some input paths remain unsanitized",
        further_mitigations=["M-VERIFY"],
        children=["T2"],
        threat_actors=["Any"],
        comment="c",
    )
    data = threat.to_dict()
    assert data["SID"] == "T1"
    assert data["status"] == "partially mitigated"
    assert data["impact"] == "High"
    assert data["severity"] == "Medium"  # the original CAPEC severity is still included
    assert data["likelihood"] == "Low"
    assert data["residual_impact"] == "Medium"
    assert data["residual_likelihood"] == "Low"
    assert data["residual_risk"] == "Some input paths remain unsanitized"
    assert data["children"] == ["T2"]
    assert data["threat_actors"] == ["Any"]
    assert data["mapping"] == {
        "requirements": ["reads_input"],
        "mitigations": ["M-SANITIZE"],
        "further_mitigations": ["M-VERIFY"],
    }


# -- Report


def test_report_emits_entities_and_all_findings(tm: Ratm) -> None:
    tm.Threat(
        "T1",
        requirements=["reads_input"],
        mitigations=["M-SANITIZE"],
        status="mitigated",
        impact="Low",
        likelihood="Low",
        threat_actors=["Any"],
    )
    scenario = make_scenario(tm)
    report = tm.Report([scenario]).generate()
    assert set(report) == {
        "properties",
        "components",
        "scenarios",
        "threats",
        "mitigations",
        "threat_actors",
    }
    assert report["threat_actors"]["Nation state"]["description"] == (
        "Well-resourced adversary"
    )
    targets = sorted(f["target"] for f in report["scenarios"][0]["findings"])
    # A sanitizes its input but the finding is still reported.
    assert targets == ["A", "B"]


def test_report_without_entities_still_generates() -> None:
    a = Threat("T1", requirements=["x"])
    scenario = Scenario(name="S1", dataflows=[])
    report = Report([scenario], threats=[a]).generate()
    assert report["mitigations"] == {}
    assert report["threat_actors"] == {}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"mitigations": ["NOPE"]}, "T1.*mitigation.*NOPE"),
        ({"further_mitigations": ["NOPE"]}, "T1.*mitigation.*NOPE"),
        ({"threat_actors": ["Nobody"]}, "T1.*actor.*Nobody"),
        ({"children": ["T-MISSING"]}, "T1.*child.*T-MISSING"),
        ({"children": ["T1"]}, "T1.*child.*T1"),
        ({"status": "fixed"}, "T1.*status.*fixed"),
        ({"impact": "Critical"}, "T1.*impact.*Critical"),
        ({"likelihood": "Unlikely"}, "T1.*likelihood.*Unlikely"),
        ({"residual_impact": "None"}, "T1.*residual impact.*None"),
        ({"residual_likelihood": "Rare"}, "T1.*residual likelihood.*Rare"),
    ],
)
def test_report_validates_threats(tm: Ratm, kwargs, message) -> None:
    tm.Threat("T1", requirements=["reads_input"], **kwargs)
    scenario = make_scenario(tm)
    with pytest.raises(ValueError, match=message):
        tm.Report([scenario]).generate()


def test_report_validates_mitigation_status(tm: Ratm) -> None:
    tm.Mitigation("M-BAD", title="Bad", status="done")
    with pytest.raises(ValueError, match="M-BAD.*status.*done"):
        tm.Report([make_scenario(tm)]).generate()


def test_report_validates_mitigation_property(tm: Ratm) -> None:
    tm.Mitigation("M-BAD", title="Bad", property="no_such_prop.item")
    with pytest.raises(ValueError, match="M-BAD.*property.*no_such_prop"):
        tm.Report([make_scenario(tm)]).generate()


def test_report_validates_duplicate_threat_ids() -> None:
    threats = [Threat("T1", requirements=["x"]), Threat("T1", requirements=["y"])]
    with pytest.raises(ValueError, match="T1"):
        Report([Scenario(name="S1", dataflows=[])], threats=threats).generate()


def test_report_accepts_unknown_labels_when_none(tm: Ratm) -> None:
    tm.Threat("T1", requirements=["reads_input"])
    report = tm.Report([make_scenario(tm)]).generate()
    threat = report["threats"][0]
    assert threat["impact"] == ""
    assert threat["likelihood"] == ""
    assert threat["status"] == "unmanaged"
