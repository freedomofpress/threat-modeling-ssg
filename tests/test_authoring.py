"""Tests for the model code: the Ratm builders, Threat, Mitigation, and Report."""

import inspect
import json

import pytest

from ratm import CAPECInfo, Mitigation, Ratm, Report, Scenario, Threat, ThreatActor
from ratm.ssg.models import Component as SiteComponent
from ratm.ssg.models import _token_props, _token_satisfied


@pytest.fixture()
def tm() -> Ratm:
    tm = Ratm(load_capec_info=False)
    tm.define_properties(
        "reads_input",
        "sanitizes_input",
        ("loads_resources", "Loads resources", (), tuple),
        ("verifies_resources", "Verifies resources", (), tuple),
    )
    tm.Mitigation("M-SANITIZE", title="Sanitize input")
    tm.Mitigation(
        "M-VERIFY",
        title="Verify resources",
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
    mit = Mitigation("M1", title="T", source=("model.py", 3))
    assert mit.to_dict() == {
        "id": "M1",
        "title": "T",
        "description": "",
        "status": "implemented",
        "source": {"file": "model.py", "line": 3},
    }


def test_threat_actor_to_dict() -> None:
    assert ThreatActor("Any", source=("model.py", 7)).to_dict() == {
        "name": "Any",
        "description": "",
        "source": {"file": "model.py", "line": 7},
    }
    assert ThreatActor("Troll", description="Bored").to_dict()["description"] == "Bored"


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


def test_capec_likelihood_off_the_scale_is_unknown(tm: Ratm) -> None:
    """CAPEC allows "Unknown" likelihood, which must not fail the author's build."""
    tm.Threat(
        "CAPEC-9",
        requirements=["reads_input"],
        capec_info=CAPECInfo(description="d", severity="High", likelihood="Unknown"),
    )
    threat = tm.Report([make_scenario(tm)]).generate()["threats"][0]
    assert threat["impact"] == "High"
    assert threat["likelihood"] == ""


# -- Source locations


def test_builders_record_repo_relative_source(tm: Ratm) -> None:
    line = inspect.currentframe().f_lineno + 1
    threat = tm.Threat("T-SRC", requirements=["reads_input"])
    assert threat.source == ("tests/test_authoring.py", line)
    line = inspect.currentframe().f_lineno + 1
    comp = tm.Component(name="C-SRC", reads_input=True)
    assert comp.source == ("tests/test_authoring.py", line)
    # The fixture registers these, so their source is this file.
    assert tm.mitigations["M-DOCS"].source[0] == "tests/test_authoring.py"
    assert tm.threat_actors["Any"].source[0] == "tests/test_authoring.py"


def test_source_is_the_model_code_that_called_a_helper(tm: Ratm) -> None:
    def register(model):
        return model.Threat("T-HELPER", requirements=["reads_input"])

    threat = register(tm)
    # The source is the call inside the helper, not a line inside ratm.
    assert threat.source[0] == "tests/test_authoring.py"
    assert threat.source[1] == register.__code__.co_firstlineno + 1


# -- "Any of" requirements


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("reads_input | sanitizes_input", True),
        ("sanitizes_input | reads_input", True),
        ("sanitizes_input | is_exposed", False),
        ("sanitizes_input|reads_input", True),
        ("loads_resources.images | loads_resources.deps", True),
        ("loads_resources.images | verifies_resources.images", False),
        ("!reads_input | is_exposed", False),
        ("!sanitizes_input | is_exposed", True),
        ("reads_input == is_exposed | reads_input", True),
    ],
)
def test_any_of_requirements_agree_across_layers(token, expected) -> None:
    """The model code decides findings and the site re-checks tokens, so the two must agree."""
    tm = Ratm(load_capec_info=False)
    tm.define_properties(
        "reads_input",
        "sanitizes_input",
        "is_exposed",
        ("loads_resources", "Loads resources", (), tuple),
        ("verifies_resources", "Verifies resources", (), tuple),
    )
    comp = tm.Component(name="C", reads_input=True, loads_resources=("deps",))
    assert bool(comp.matches(token)) is expected
    # Go through JSON, as a real report does, so tuples become lists.
    properties = json.loads(json.dumps(comp.to_dict()["properties"]))
    site_comp = SiteComponent(name="C", properties=properties)
    assert _token_satisfied(site_comp, token) is expected


def test_any_of_threat_applies_to_either_component() -> None:
    tm = Ratm(load_capec_info=False)
    tm.define_properties(("element_ids", "Legacy ids", (), tuple))
    tm.Threat("T1", requirements=["element_ids.DFD1 | element_ids.DFD2"])
    a = tm.Component(name="A", element_ids=("DFD1",))
    b = tm.Component(name="B", element_ids=("DFD2",))
    c = tm.Component(name="C", element_ids=("DFD3",))
    scenario = Scenario(name="S")
    scenario.Dataflow(name="A to B", source=a, sink=b)
    scenario.Dataflow(name="B to C", source=b, sink=c)
    report = tm.Report([scenario]).generate()
    targets = sorted(f["target"] for f in report["scenarios"][0]["findings"])
    assert targets == ["A", "B"]
    assert _token_props("element_ids.DFD1 | !other") == ["element_ids", "other"]
