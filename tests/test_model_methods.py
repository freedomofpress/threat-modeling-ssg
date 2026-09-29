import pytest

from ratm.ssg.models import (
    Component,
    Finding,
    Flow,
    Mitigation,
    Property,
    Scenario,
    Threat,
    ThreatActor,
    ThreatMapping,
    ThreatModel,
    _token_props,
    _token_satisfied,
)


@pytest.fixture()
def model_factory():
    def _make(
        threats, components, scenarios, properties=None, mitigations=None, actors=None
    ):
        return ThreatModel(
            threats=threats,
            components=components,
            scenarios=scenarios,
            properties=properties or {},
            mitigations=mitigations or {},
            threat_actors=actors or {},
        )

    return _make


FLOW_A_B = Flow(id="1", name="A to B", source="A", sink="B")


def test_component_threats(model_factory) -> None:
    model = model_factory(
        threats={"T1": Threat(SID="T1"), "T2": Threat(SID="T2")},
        components={
            "A": Component(name="A", component_class="Process"),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[
                    Finding(target="A", threat_id="T1"),
                    Finding(target="B", threat_id="T2"),
                ],
                flows=[FLOW_A_B],
            )
        ],
    )
    analysis = model.analyze()
    assert analysis["components_to_threats"].get("A", set()) == {"T1"}
    assert analysis["components_to_threats"].get("B", set()) == {"T2"}


def test_threat_affected_components(model_factory) -> None:
    model = model_factory(
        threats={"T1": Threat(SID="T1"), "T2": Threat(SID="T2")},
        components={
            "A": Component(name="A", component_class="Process"),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[
                    Finding(target="A", threat_id="T1"),
                    Finding(target="B", threat_id="T1"),
                ],
                flows=[FLOW_A_B],
            )
        ],
    )
    analysis = model.analyze()
    assert analysis["threats_to_components"].get("T1", set()) == {"A", "B"}
    assert analysis["threats_to_components"].get("T2", set()) == set()


def test_threat_linked_scenarios(model_factory) -> None:
    model = model_factory(
        threats={"T1": Threat(SID="T1"), "T2": Threat(SID="T2")},
        components={
            "A": Component(name="A", component_class="Process"),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[Finding(target="A", threat_id="T1")],
                flows=[FLOW_A_B],
            ),
            Scenario(
                name="S2",
                findings=[Finding(target="B", threat_id="T2")],
                flows=[Flow(id="1", name="B to A", source="B", sink="A")],
            ),
        ],
    )
    analysis = model.analyze()
    assert analysis["threats_to_scenarios"].get("T1", []) == ["S1"]
    assert analysis["threats_to_scenarios"].get("T2", []) == ["S2"]


def test_threat_mapping_base_props() -> None:
    mapping = ThreatMapping(
        requirements=["loads_resources.images", "reads_input"],
        mitigations=["M-VERIFY", "M-TRUST"],
    )
    assert mapping.requirement_props == {"loads_resources", "reads_input"}
    assert mapping.mitigations == ["M-VERIFY", "M-TRUST"]


def test_threat_mapping_for_prop() -> None:
    mapping = ThreatMapping(
        requirements=["loads_resources.images", "loads_resources.deps", "reads_input"],
    )
    assert mapping.requirements_for_prop("loads_resources") == [
        "loads_resources.images",
        "loads_resources.deps",
    ]
    assert mapping.requirements_for_prop("reads_input") == ["reads_input"]
    assert mapping.requirements_for_prop("other") == []


def test_property_requiring_threats(model_factory) -> None:
    """Active threats that have the property in their requirements show up for the property page."""
    model = model_factory(
        threats={
            "T-active": Threat(
                SID="T-active",
                mapping=ThreatMapping(
                    requirements=["loads_resources.system"],
                    mitigations=["verifies_resources.system"],
                ),
            ),
            "T-inactive": Threat(
                SID="T-inactive",
                mapping=ThreatMapping(
                    requirements=["loads_resources.images"],
                    mitigations=["verifies_resources.images"],
                ),
            ),
        },
        components={
            "A": Component(
                name="A",
                component_class="Process",
                properties={"loads_resources": ["system"]},
            ),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[Finding(target="A", threat_id="T-active")],
                flows=[FLOW_A_B],
            )
        ],
        properties={
            "loads_resources": Property(name="Loads resources", type="list"),
        },
    )
    analysis = model.analyze()
    requiring = [
        tid
        for tid, t in model.threats.items()
        if tid in analysis["threat_counter"]
        and "loads_resources" in t.mapping.requirement_props
    ]
    assert requiring == ["T-active"]


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("is_exposed", True),
        ("!is_exposed", False),
        ("encrypts_secrets", False),
        ("!encrypts_secrets", True),
        ("loads_resources.deps", True),
        ("loads_resources.source", False),
        ("!loads_resources.source", True),
        ("requires_credentials == uses_strong_credentials", False),
        ("requires_credentials != uses_strong_credentials", True),
    ],
)
def test_token_satisfied(token, expected) -> None:
    component = Component(
        name="A",
        component_class="Process",
        properties={
            "is_exposed": True,
            "loads_resources": ["deps"],
            "requires_credentials": True,
        },
    )
    assert _token_satisfied(component, token) is expected


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("is_exposed", ["is_exposed"]),
        ("!encrypts_secrets", ["encrypts_secrets"]),
        ("verifies_resources.deps", ["verifies_resources"]),
        (
            "requires_credentials != uses_strong_credentials",
            ["requires_credentials", "uses_strong_credentials"],
        ),
    ],
)
def test_token_props(token, expected) -> None:
    assert _token_props(token) == expected


def test_mapping_props_cover_negated_and_compared_tokens() -> None:
    mapping = ThreatMapping(
        requirements=[
            "stores_secrets",
            "!encrypts_secrets",
            "requires_credentials != uses_strong_credentials",
        ],
    )
    assert mapping.requirement_props == {
        "stores_secrets",
        "encrypts_secrets",
        "requires_credentials",
        "uses_strong_credentials",
    }
    assert mapping.requirements_for_prop("encrypts_secrets") == ["!encrypts_secrets"]


SANITIZE = Mitigation(
    id="M-SANITIZE", title="Sanitize input", property="sanitizes_input"
)
DOCS = Mitigation(id="M-DOCS", title="Document it", status="optional")


def test_property_mitigation_state_split_by_component(model_factory) -> None:
    """A property-bearing mitigation reports where it is implemented and where it is missing."""
    model = model_factory(
        threats={
            "T1": Threat(
                SID="T1",
                mapping=ThreatMapping(
                    requirements=["reads_input"], mitigations=["M-SANITIZE"]
                ),
            ),
        },
        components={
            "A": Component(
                name="A",
                component_class="Process",
                properties={"reads_input": True, "sanitizes_input": True},
            ),
            "B": Component(
                name="B",
                component_class="Process",
                properties={"reads_input": True, "sanitizes_input": False},
            ),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[
                    Finding(target="A", threat_id="T1"),
                    Finding(target="B", threat_id="T1"),
                ],
                flows=[FLOW_A_B],
            )
        ],
        properties={
            "reads_input": Property(name="Reads input", type="bool"),
            "sanitizes_input": Property(name="Sanitizes input", type="bool"),
        },
        mitigations={"M-SANITIZE": SANITIZE, "M-DOCS": DOCS},
    )
    states = model.property_mitigation_state("sanitizes_input")
    assert [st["mitigation"].id for st in states] == ["M-SANITIZE"]
    assert [tid for tid, _ in states[0]["threats"]] == ["T1"]
    assert [name for name, _ in states[0]["implemented_on"]] == ["A"]
    assert [name for name, _ in states[0]["missing_on"]] == ["B"]
    assert model.property_mitigation_state("reads_input") == []


def test_property_mitigation_state_dotted(model_factory) -> None:
    verify = Mitigation(
        id="M-VERIFY", title="Verify", property="verifies_resources.system"
    )
    model = model_factory(
        threats={
            "T1": Threat(
                SID="T1",
                mapping=ThreatMapping(
                    requirements=["loads_resources.system"], mitigations=["M-VERIFY"]
                ),
            ),
        },
        components={
            "Covered": Component(
                name="Covered",
                component_class="Process",
                properties={
                    "loads_resources": ["system"],
                    "verifies_resources": ["system"],
                },
            ),
            "Affected": Component(
                name="Affected",
                component_class="Process",
                properties={
                    "loads_resources": ["system"],
                    "verifies_resources": ["updates"],
                },
            ),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[
                    Finding(target="Covered", threat_id="T1"),
                    Finding(target="Affected", threat_id="T1"),
                ],
                flows=[
                    Flow(
                        id="1",
                        name="Covered to Affected",
                        source="Covered",
                        sink="Affected",
                    )
                ],
            )
        ],
        properties={
            "loads_resources": Property(name="Loads resources", type="list"),
            "verifies_resources": Property(name="Verifies resources", type="list"),
        },
        mitigations={"M-VERIFY": verify},
    )
    (state,) = model.property_mitigation_state("verifies_resources")
    assert [name for name, _ in state["implemented_on"]] == ["Covered"]
    assert [name for name, _ in state["missing_on"]] == ["Affected"]


def test_mitigation_implemented_on() -> None:
    comp = Component(name="X", properties={"sanitizes_input": True})
    assert SANITIZE.implemented_on(comp) is True
    assert SANITIZE.implemented_on(Component(name="Y", properties={})) is False
    assert DOCS.implemented_on(comp) is None
    assert SANITIZE.property_names == ["sanitizes_input"]
    assert DOCS.property_names == []


def test_component_mitigation_states_and_potential(model_factory) -> None:
    threat = Threat(
        SID="T1",
        mapping=ThreatMapping(
            requirements=["reads_input"], mitigations=["M-SANITIZE", "M-DOCS"]
        ),
    )
    model = model_factory(
        threats={"T1": threat},
        components={},
        scenarios=[],
        mitigations={"M-SANITIZE": SANITIZE, "M-DOCS": DOCS},
    )
    missing = Component(name="X", properties={"reads_input": True})
    states = model.component_mitigation_states(missing, threat)
    assert [(st["mitigation"].id, st["implemented"]) for st in states] == [
        ("M-SANITIZE", False),
        ("M-DOCS", None),
    ]
    # Only property-bearing mitigations that are missing count as potential.
    assert [m.id for m in model.component_potential_mitigations(missing, {"T1"})] == [
        "M-SANITIZE"
    ]
    covered = Component(name="Y", properties={"sanitizes_input": True})
    assert model.component_potential_mitigations(covered, {"T1"}) == []


def test_threat_mitigations_and_mitigation_threats(model_factory) -> None:
    model = model_factory(
        threats={
            "T1": Threat(
                SID="T1",
                mapping=ThreatMapping(
                    mitigations=["M-SANITIZE"], further_mitigations=["M-DOCS"]
                ),
            ),
            "T2": Threat(SID="T2", mapping=ThreatMapping(mitigations=["M-DOCS"])),
        },
        components={},
        scenarios=[],
        mitigations={"M-SANITIZE": SANITIZE, "M-DOCS": DOCS},
    )
    t1 = model.threats["T1"]
    assert [m.id for m in model.threat_mitigations(t1)] == ["M-SANITIZE"]
    assert [m.id for m in model.threat_mitigations(t1, further=True)] == ["M-DOCS"]
    mitigating, proposing = model.mitigation_threats("M-DOCS")
    assert [tid for tid, _ in mitigating] == ["T2"]
    assert [tid for tid, _ in proposing] == ["T1"]


def test_threat_impact_and_scores() -> None:
    assert Threat.model_validate({"SID": "T", "impact": "Low"}).impact == "Low"
    threat = Threat(SID="T", impact="High", likelihood="Medium")
    assert threat.impact_label == "High"
    assert threat.risk_score == 9
    assert threat.residual_risk_score == 9
    threat = Threat(
        SID="T",
        impact="High",
        likelihood="Medium",
        residual_impact="Low",
        residual_likelihood="Very Low",
    )
    assert threat.residual_risk_score == 1
    unknown = Threat(SID="T", impact="Critical")
    assert unknown.impact_label == "Unknown"
    assert unknown.likelihood_label == "Unknown"
    assert unknown.risk_score is None
    assert Threat(SID="T", status="partially mitigated").status_slug == (
        "partially-mitigated"
    )
    assert Threat(SID="CAPEC-1").is_capec is True
    assert Threat(SID="T").is_capec is False


def test_analysis_distributions_and_actors(model_factory) -> None:
    model = model_factory(
        threats={
            "T1": Threat(
                SID="T1", impact="High", status="mitigated", threat_actors=["Any"]
            ),
            "T2": Threat(SID="T2", impact="Low", status="unmanaged"),
            "T3": Threat(SID="T3", status="unmanaged", threat_actors=["Any", "Troll"]),
        },
        components={
            "A": Component(name="A", component_class="Process"),
            "B": Component(name="B", component_class="Process"),
        },
        scenarios=[
            Scenario(
                name="S1",
                findings=[
                    Finding(target="A", threat_id="T1"),
                    Finding(target="B", threat_id="T2"),
                ],
                flows=[FLOW_A_B],
            )
        ],
        actors={"Any": ThreatActor(name="Any"), "Troll": ThreatActor(name="Troll")},
    )
    analysis = model.analyze()
    assert analysis["impact_distribution"] == {"High": 1, "Low": 1}
    assert analysis["status_distribution"] == {"unmanaged": 1, "mitigated": 1}
    # Actor mapping covers every defined threat, active or not.
    assert analysis["actors_to_threats"] == {"Any": ["T1", "T3"], "Troll": ["T3"]}


def test_parent_threats(model_factory) -> None:
    model = model_factory(
        threats={
            "T1": Threat(SID="T1", children=["T2", "T3"]),
            "T2": Threat(SID="T2", children=["T3"]),
            "T3": Threat(SID="T3"),
        },
        components={},
        scenarios=[],
    )
    assert model.parent_threats("T3") == ["T1", "T2"]
    assert model.parent_threats("T1") == []


def test_entity_lists_are_keyed() -> None:
    model = ThreatModel.model_validate(
        {
            "threats": [{"SID": "T1"}],
            "components": {},
            "scenarios": [],
            "properties": {},
            "mitigations": [{"id": "M1", "title": "t"}],
            "threat_actors": [{"name": "Any"}],
        }
    )
    assert list(model.threats) == ["T1"]
    assert list(model.mitigations) == ["M1"]
    assert list(model.threat_actors) == ["Any"]
    # Missing entity maps still load (older reports).
    old = ThreatModel.model_validate(
        {"threats": [], "components": {}, "scenarios": [], "properties": {}}
    )
    assert old.mitigations == {} and old.threat_actors == {}
