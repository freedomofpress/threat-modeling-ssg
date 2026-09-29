from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any, TextIO

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator


class SiteConfig(BaseModel):
    title: str = "Threat Model Report"
    logo: str | None = None
    github_repo: str | None = None
    hide_components_with_category: list[str] = []


class ThreatMapping(BaseModel):
    requirements: list[str] = []
    mitigations: list[str] = []

    @property
    def requirement_props(self) -> set[str]:
        return {prop for k in self.requirements for prop in _token_props(k)}

    @property
    def mitigation_props(self) -> set[str]:
        return {prop for k in self.mitigations for prop in _token_props(k)}

    def requirements_for_prop(self, base_prop: str) -> list[str]:
        """All requirement tokens referring to base_prop."""
        return [k for k in self.requirements if base_prop in _token_props(k)]

    def mitigations_for_prop(self, base_prop: str) -> list[str]:
        """All mitigation tokens referring to base_prop."""
        return [k for k in self.mitigations if base_prop in _token_props(k)]


class Threat(BaseModel):
    SID: str
    comment: str = ""
    description: str = ""
    details: str = ""
    example: str = ""
    severity: str = ""
    likelihood: str = ""
    mapping: ThreatMapping = Field(default_factory=ThreatMapping)

    def applies_to(self, component: "Component") -> bool:
        """True if the component has all the requirement properties for this threat."""
        return bool(self.mapping.requirements) and all(
            _token_satisfied(component, tok) for tok in self.mapping.requirements
        )

    def is_mitigated(self, component: "Component") -> bool:
        """True if at least one mitigation token is satisfied by the component."""
        return any(_token_satisfied(component, tok) for tok in self.mapping.mitigations)


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
    _analysis: dict[str, Any] | None = PrivateAttr(default=None)
    _scenario_by_name: dict[str, Scenario] | None = PrivateAttr(default=None)

    @model_validator(mode="before")
    @classmethod
    def threats_list_to_dict(cls, data: Any) -> Any:
        if isinstance(data.get("threats"), list):
            data["threats"] = {t["SID"]: t for t in data["threats"]}
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

        severity_order = ["Very High", "High", "Medium", "Low", "Unknown"]
        severity_counter = Counter(
            self.threats[tid].severity or "Unknown"
            for tid in threat_counter
            if tid in self.threats
        )
        severity_distribution = {
            s: severity_counter[s] for s in severity_order if severity_counter[s]
        }
        for s, c in severity_counter.items():
            severity_distribution.setdefault(s, c)

        self._analysis = {
            "threat_counter": threat_counter,
            "threats_by_frequency": threat_counter.most_common(),
            "threats_to_components": dict(threats_to_components),
            "threats_to_scenarios": dict(threats_to_scenarios),
            "components_to_threats": dict(components_to_threats),
            "components_to_scenarios": dict(components_to_scenarios),
            "severity_distribution": severity_distribution,
        }
        return self._analysis

    def threat_unimplemented_mitigations(
        self, component: Component, threat: Threat
    ) -> list[str]:
        """Mitigation tokens from threat.mapping.mitigations not yet satisfied by component."""
        return [
            tok
            for tok in threat.mapping.mitigations
            if not _token_satisfied(component, tok)
        ]

    def component_unimplemented_mitigations(
        self, component: Component, threat_ids: Iterable[str]
    ) -> list[str]:
        missing: set[str] = set()
        for tid in threat_ids:
            threat = self.threats.get(tid)
            if threat:
                missing.update(
                    prop
                    for tok in threat.mapping.mitigations
                    if not _token_satisfied(component, tok)
                    for prop in _token_props(tok)
                )
        return sorted(missing)

    def property_mitigation_state(
        self, prop_key: str
    ) -> tuple[
        list[tuple[str, Threat]], list[tuple[str, Threat]], list[dict[str, Any]]
    ]:
        analysis = self.analyze()
        active_threat_ids = [
            tid for tid in analysis["threat_counter"] if tid in self.threats
        ]

        mitigated_threats: list[tuple[str, Threat]] = []
        would_be_mitigated_threats: list[tuple[str, Threat]] = []
        benefit_components: dict[str, dict[str, Any]] = {}

        for tid in active_threat_ids:
            threat = self.threats[tid]
            tokens = threat.mapping.mitigations_for_prop(prop_key)
            if not tokens:
                continue

            affected_components = analysis["threats_to_components"].get(tid, set())
            if not affected_components:
                mitigated_threats.append((tid, threat))
                continue

            missing = [
                (name, comp)
                for name in affected_components
                if (comp := self.components.get(name)) is not None
                and not any(_token_satisfied(comp, tok) for tok in tokens)
            ]
            if not missing:
                mitigated_threats.append((tid, threat))
                continue

            would_be_mitigated_threats.append((tid, threat))
            for comp_name, comp in missing:
                entry = benefit_components.setdefault(
                    comp_name,
                    {
                        "name": comp_name,
                        "comp": comp,
                        "current_value": comp.properties.get(prop_key),
                        "threats": [],
                    },
                )
                entry["threats"].append((tid, threat))

        mitigated_threats.sort(key=lambda item: item[0])
        would_be_mitigated_threats.sort(key=lambda item: item[0])

        benefit_components_list = list(benefit_components.values())
        benefit_components_list.sort(
            key=lambda item: (
                0 if item["current_value"] is False else 1,
                item["name"].lower(),
            )
        )

        return mitigated_threats, would_be_mitigated_threats, benefit_components_list
