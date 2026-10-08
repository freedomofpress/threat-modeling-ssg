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


SANITIZE = Mitigation(id="M-SANITIZE", title="Sanitize input")
DOCS = Mitigation(id="M-DOCS", title="Document it", status="optional")


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
    # Status counts include every defined threat, as the register's status filter does,
    # and put the statuses most in need of attention first, so unmanaged comes before
    # mitigated.
    assert analysis["status_distribution"] == {"unmanaged": 2, "mitigated": 1}
    assert list(analysis["status_distribution"]) == ["unmanaged", "mitigated"]
    # The actor mapping includes every defined threat, even ones no scenario finds.
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


def test_threats_by_risk_order() -> None:
    """Residual risk first, then base risk, then id with numbers compared by value (T2
    before T10). Unknown risk last."""
    model = ThreatModel(
        threats={
            "T10": Threat(SID="T10", impact="High", likelihood="High"),
            "T2": Threat(SID="T2", impact="High", likelihood="High"),
            "T3": Threat(
                SID="T3",
                impact="High",
                likelihood="High",
                residual_likelihood="Very Low",
            ),
            "T4": Threat(SID="T4", impact="Low", likelihood="Low"),
            "T5": Threat(SID="T5"),
            "T1": Threat(SID="T1"),
        },
        components={},
        scenarios=[],
        properties={},
    )
    assert [tid for tid, _ in model.threats_by_risk()] == [
        "T2",
        "T10",
        "T3",
        "T4",
        "T1",
        "T5",
    ]
    assert [tid for tid, _ in model.threats_by_risk(["T4", "T3"])] == ["T3", "T4"]


def test_threat_open_and_bands() -> None:
    threat = Threat(
        SID="T",
        status="partially mitigated",
        impact="High",
        likelihood="High",
        residual_likelihood="Low",
    )
    assert threat.is_open is True
    assert threat.risk_band == "high"
    assert threat.residual_risk_band == "medium"
    assert Threat(SID="T", status="accepted").is_open is False
    assert Threat(SID="T").risk_band is None


def test_backlog_ranks_proposed_mitigations_by_threat_risk(model_factory) -> None:
    model = model_factory(
        threats={
            "T1": Threat(
                SID="T1",
                status="unmanaged",
                impact="High",
                likelihood="High",
                mapping=ThreatMapping(further_mitigations=["M-LOW", "M-HIGH"]),
            ),
            "T2": Threat(
                SID="T2",
                status="accepted",
                impact="Low",
                likelihood="Low",
                mapping=ThreatMapping(further_mitigations=["M-LOW"]),
            ),
            "T3": Threat(
                SID="T3",
                impact="Medium",
                likelihood="Low",
                mapping=ThreatMapping(mitigations=["M-LOW"]),
            ),
        },
        components={},
        scenarios=[],
        mitigations={
            "M-LOW": Mitigation(id="M-LOW", title="Low", status="proposed"),
            "M-HIGH": Mitigation(id="M-HIGH", title="High", status="proposed"),
            "M-DONE": Mitigation(id="M-DONE", title="Done"),
            "M-UNUSED": Mitigation(id="M-UNUSED", title="Unused", status="proposed"),
        },
    )
    backlog = model.backlog()
    # Both reach risk 12 through T1. M-LOW covers more open threats, so it wins the tie.
    # The implemented mitigation is not in the backlog.
    assert [row["mitigation"].id for row in backlog] == ["M-LOW", "M-HIGH", "M-UNUSED"]
    assert backlog[1]["open_count"] == 1
    low = backlog[0]
    # Threats that list it in place or as a further mitigation, highest risk first.
    assert [tid for tid, _ in low["threats"]] == ["T1", "T3", "T2"]
    assert low["top_risk"] == 12
    assert low["open_count"] == 2
    assert backlog[2]["threats"] == [] and backlog[2]["top_risk"] is None


def test_open_risk_summary() -> None:
    model = ThreatModel(
        threats={
            "T1": Threat(SID="T1", status="unmanaged", impact="Low", likelihood="Low"),
            "T2": Threat(
                SID="T2",
                status="partially mitigated",
                impact="High",
                likelihood="High",
                residual_likelihood="Low",
            ),
            "T3": Threat(
                SID="T3", status="mitigated", impact="High", likelihood="High"
            ),
        },
        components={},
        scenarios=[],
        properties={},
    )
    # Highest risk after mitigations among open threats only: T2's 6, not T3's 12.
    assert model.open_risk(["T1", "T2", "T3", "missing"]) == {
        "total": 3,
        "open": 2,
        "top_risk": 6,
    }
    assert model.open_risk(["T3"]) == {"total": 1, "open": 0, "top_risk": None}


# -- Tags


def tagged_model(model_factory, threat_components):
    """A model where A and B are tagged "Legacy", C is not, and threat Tn is found on
    the components listed for it in threat_components."""
    components = {
        "A": Component(name="A", tags=["Legacy"]),
        "B": Component(name="B", tags=["Legacy", "Lab"]),
        "C": Component(name="C"),
    }
    findings = [
        Finding(target=comp, threat_id=tid)
        for tid, comps in threat_components.items()
        for comp in comps
    ]
    flows = [
        Flow(id="1", name="A to B", source="A", sink="B"),
        Flow(id="2", name="B to C", source="B", sink="C"),
    ]
    threats = {tid: Threat(SID=tid) for tid in threat_components}
    return model_factory(
        threats=threats,
        components=components,
        scenarios=[Scenario(name="S1", flows=flows, findings=findings)],
    )


def test_threat_takes_the_tags_all_its_components_share(model_factory) -> None:
    model = tagged_model(model_factory, {"T1": ["A", "B"], "T2": ["A", "C"]})
    model.resolve_tags()
    assert model.threats["T1"].tags == ["Legacy"]
    assert model.threats["T2"].tags == []


def test_threat_keeps_its_own_tags(model_factory) -> None:
    model = tagged_model(model_factory, {"T1": ["C"], "T2": []})
    model.threats["T1"].tags = ["Legacy"]
    model.threats["T2"].tags = ["Lab"]
    model.resolve_tags()
    assert model.threats["T1"].tags == ["Legacy"]
    # Found on no component, so nothing is inherited.
    assert model.threats["T2"].tags == ["Lab"]


def test_mitigation_takes_the_tags_all_its_threats_share(model_factory) -> None:
    model = tagged_model(model_factory, {"T1": ["A"], "T2": ["B"], "T3": ["C"]})
    model.threats["T1"].mapping.mitigations = ["M-OLD", "M-BOTH"]
    model.threats["T2"].mapping.further_mitigations = ["M-OLD"]
    model.threats["T3"].mapping.mitigations = ["M-BOTH"]
    model.mitigations = {
        "M-OLD": Mitigation(id="M-OLD"),
        "M-BOTH": Mitigation(id="M-BOTH"),
        "M-UNUSED": Mitigation(id="M-UNUSED"),
    }
    model.resolve_tags()
    assert model.mitigations["M-OLD"].tags == ["Legacy"]
    assert model.mitigations["M-BOTH"].tags == []
    assert model.mitigations["M-UNUSED"].tags == []


def test_resolve_tags_twice_gives_the_same_tags(model_factory) -> None:
    model = tagged_model(model_factory, {"T1": ["A", "B"]})
    model.resolve_tags()
    model.resolve_tags()
    assert model.threats["T1"].tags == ["Legacy"]
