from collections import Counter, defaultdict
from typing import Any, TextIO

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    model_validator,
)

from .. import scales


class SiteConfig(BaseModel):
    title: str = "Threat Model Report"
    logo: str | None = None
    github_repo: str | None = None
    hide_components_with_category: list[str] = []


class ThreatMapping(BaseModel):
    requirements: list[str] = []
    # Mitigation ids. Look them up in ThreatModel.mitigations.
    mitigations: list[str] = []
    further_mitigations: list[str] = []

    @property
    def requirement_props(self) -> set[str]:
        return {prop for k in self.requirements for prop in _token_props(k)}

    def requirements_for_prop(self, base_prop: str) -> list[str]:
        """All requirement tokens referring to base_prop."""
        return [k for k in self.requirements if base_prop in _token_props(k)]


class Mitigation(BaseModel):
    id: str
    title: str = ""
    description: str = ""
    status: str = scales.DEFAULT_MITIGATION_STATUS


class ThreatActor(BaseModel):
    name: str
    description: str = ""


class Threat(BaseModel):
    SID: str
    comment: str = ""
    description: str = ""
    details: str = ""
    example: str = ""
    impact: str = ""
    likelihood: str = ""
    residual_impact: str = ""
    residual_likelihood: str = ""
    residual_risk: str = ""
    status: str = scales.DEFAULT_THREAT_STATUS
    threat_actors: list[str] = []
    children: list[str] = []
    mapping: ThreatMapping = Field(default_factory=ThreatMapping)

    @property
    def impact_label(self) -> str:
        return self.impact if self.impact in scales.IMPACT_SCORES else scales.UNKNOWN

    @property
    def likelihood_label(self) -> str:
        if self.likelihood in scales.LIKELIHOOD_SCORES:
            return self.likelihood
        return scales.UNKNOWN

    @property
    def residual_impact_label(self) -> str:
        if self.residual_impact in scales.IMPACT_SCORES:
            return self.residual_impact
        return self.impact_label

    @property
    def residual_likelihood_label(self) -> str:
        if self.residual_likelihood in scales.LIKELIHOOD_SCORES:
            return self.residual_likelihood
        return self.likelihood_label

    @property
    def risk_score(self) -> int | None:
        return scales.risk_score(self.impact_label, self.likelihood_label)

    @property
    def residual_risk_score(self) -> int | None:
        return scales.risk_score(
            self.residual_impact_label, self.residual_likelihood_label
        )

    @property
    def status_slug(self) -> str:
        return self.status.replace(" ", "-")

    @property
    def is_capec(self) -> bool:
        return self.SID.startswith("CAPEC-")

    def applies_to(self, component: "Component") -> bool:
        """True if the component has all the requirement properties for this threat."""
        return bool(self.mapping.requirements) and all(
            _token_satisfied(component, tok) for tok in self.mapping.requirements
        )


class Component(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str = ""
    component_class: str = Field(alias="class", default="")
    description: str | None = ""
    inBoundary: str | None = Field(alias="in_boundary", default=None)
    properties: dict[str, Any] = {}
    _key: str | None = PrivateAttr(default=None)

    def get_property(self, name):
        return self.properties.get(name, False)


class Finding(BaseModel):
    target: str
    threat_id: str


class Flow(BaseModel):
    id: str
    name: str
    is_response: bool = False
    response_to: str | None = None
    sink: str
    source: str


class Scenario(BaseModel):
    description: str = ""
    name: str
    file: str = ""
    findings: list[Finding] = []
    flows: list[Flow] = []
    components: list[str] = []
    dfd: str = ""
    mermaid: str = ""
    url: str | None = None

    @property
    def linked_component_names(self) -> set:
        """Component names that appear in at least one flow (source or sink)."""
        return {flow.source for flow in self.flows} | {flow.sink for flow in self.flows}


class Property(BaseModel):
    description: str = ""
    name: str
    type: str
    _key: str | None = PrivateAttr(default=None)


def _token_props(token: str) -> list[str]:
    """The property names a requirement/mitigation token refers to."""
    token = token.strip()
    for operator in ("!=", "=="):
        if operator in token:
            left, right = token.split(operator, 1)
            return [left.strip(), right.strip()]
    return [token.removeprefix("!").split(".", 1)[0]]


def _token_satisfied(component: Component, token: str) -> bool:
    """Check if a single requirement/mitigation token is satisfied by the component.

    Mirrors ComponentProperties.matches() on the report side: negation ('!is_exposed'),
    comparison ('requires_credentials != uses_strong_credentials'), sub-resources
    ('verifies_resources.deps') and plain truthiness ('is_physical')."""
    token = token.strip()
    if token.startswith("!"):
        return not _token_satisfied(component, token[1:])
    for operator in ("!=", "=="):
        if operator in token:
            left, right = (part.strip() for part in token.split(operator, 1))
            equal = component.properties.get(left) == component.properties.get(right)
            return not equal if operator == "!=" else equal
    if "." in token:
        prop, item = token.split(".", 1)
        value = component.properties.get(prop)
        return item in value if isinstance(value, list) else bool(value)
    return bool(component.properties.get(token))


class ThreatModel(BaseModel):
    threats: dict[str, Threat]
    components: dict[str, Component]
    scenarios: list[Scenario]
    properties: dict[str, Property]
    mitigations: dict[str, Mitigation] = {}
    threat_actors: dict[str, ThreatActor] = {}
    _analysis: dict[str, Any] | None = PrivateAttr(default=None)
    _scenario_by_name: dict[str, Scenario] | None = PrivateAttr(default=None)
    _parents: dict[str, list[str]] | None = PrivateAttr(default=None)

    @model_validator(mode="before")
    @classmethod
    def threats_list_to_dict(cls, data: Any) -> Any:
        for key, id_field in (
            ("threats", "SID"),
            ("mitigations", "id"),
            ("threat_actors", "name"),
        ):
            if isinstance(data.get(key), list):
                data[key] = {item[id_field]: item for item in data[key]}
        return data

    @model_validator(mode="after")
    def assign_keys(self) -> "ThreatModel":
        for key, component in self.components.items():
            component._key = key
            if not component.name:
                component.name = key
        for key, prop in self.properties.items():
            prop._key = key
        return self

    @classmethod
    def load_report(cls, file: TextIO) -> "ThreatModel":
        return cls.model_validate_json(file.read())

    def prepare_scenarios(self, config: SiteConfig) -> None:
        from .graphs import generate_dataflow, generate_sequence

        for scenario in self.scenarios:
            if config.github_repo and scenario.file:
                scenario.url = f"{config.github_repo}/blob/main/{scenario.file}"
            scenario.dfd = generate_dataflow(scenario, self.components)
            scenario.mermaid = generate_sequence(scenario)

    def scenario_by_name(self) -> dict[str, Scenario]:
        if self._scenario_by_name is None:
            self._scenario_by_name = {s.name: s for s in self.scenarios}
        return self._scenario_by_name

    def analyze(self) -> dict[str, Any]:
        """Analyze the threat model and return useful statistics."""
        if self._analysis is not None:
            return self._analysis

        threat_counter: Counter[str] = Counter()
        threats_to_components: defaultdict[str, set[str]] = defaultdict(set)
        threats_to_scenarios: defaultdict[str, list[str]] = defaultdict(list)
        components_to_threats: defaultdict[str, set[str]] = defaultdict(set)
        components_to_scenarios: defaultdict[str, list[str]] = defaultdict(list)

        for scenario in self.scenarios:
            linked = scenario.linked_component_names
            for finding in scenario.findings:
                tid, target = finding.threat_id, finding.target
                components_to_threats[target].add(tid)
                if scenario.name not in components_to_scenarios[target]:
                    components_to_scenarios[target].append(scenario.name)
                if target in linked:
                    threat_counter[tid] += 1
                    threats_to_components[tid].add(target)
                    if scenario.name not in threats_to_scenarios[tid]:
                        threats_to_scenarios[tid].append(scenario.name)

        active = [self.threats[tid] for tid in threat_counter if tid in self.threats]
        impact_counter = Counter(t.impact_label for t in active)
        impact_distribution = {
            label: impact_counter[label]
            for label in scales.IMPACT_ORDER
            if impact_counter[label]
        }
        status_counter = Counter(t.status for t in active)
        status_distribution = {
            status: status_counter[status]
            for status in scales.THREAT_STATUSES
            if status_counter[status]
        }

        # Include every defined threat, not only those found in a scenario, so an
        # actor's page lists all of that actor's threats.
        actors_to_threats: defaultdict[str, list[str]] = defaultdict(list)
        for tid, threat in self.threats.items():
            for actor in threat.threat_actors:
                actors_to_threats[actor].append(tid)

        self._analysis = {
            "threat_counter": threat_counter,
            "threats_by_frequency": threat_counter.most_common(),
            "threats_to_components": dict(threats_to_components),
            "threats_to_scenarios": dict(threats_to_scenarios),
            "components_to_threats": dict(components_to_threats),
            "components_to_scenarios": dict(components_to_scenarios),
            "impact_distribution": impact_distribution,
            "status_distribution": status_distribution,
            "actors_to_threats": dict(actors_to_threats),
        }
        return self._analysis

    def threat_mitigations(
        self, threat: Threat, further: bool = False
    ) -> list[Mitigation]:
        """Return the mitigations a threat lists. Unknown ids are skipped."""
        ids = (
            threat.mapping.further_mitigations
            if further
            else threat.mapping.mitigations
        )
        return [self.mitigations[mid] for mid in ids if mid in self.mitigations]

    def mitigation_threats(
        self, mitigation_id: str
    ) -> tuple[list[tuple[str, Threat]], list[tuple[str, Threat]]]:
        """Return two lists of threats naming this mitigation.

        The first lists it as in place, the second as a further mitigation.
        """
        mitigating = [
            (tid, t)
            for tid, t in sorted(self.threats.items())
            if mitigation_id in t.mapping.mitigations
        ]
        proposing = [
            (tid, t)
            for tid, t in sorted(self.threats.items())
            if mitigation_id in t.mapping.further_mitigations
        ]
        return mitigating, proposing

    def parent_threats(self, threat_id: str) -> list[str]:
        """Return the ids of the threats that list threat_id as a child."""
        if self._parents is None:
            parents: defaultdict[str, list[str]] = defaultdict(list)
            for tid, threat in self.threats.items():
                for child in threat.children:
                    parents[child].append(tid)
            self._parents = {child: sorted(tids) for child, tids in parents.items()}
        return self._parents.get(threat_id, [])
