from collections import Counter, defaultdict
from collections.abc import Iterable
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
    # Branch used by "Defined in" links to files in github_repo.
    github_branch: str = "main"
    hide_components_with_category: list[str] = []


class SourceRef(BaseModel):
    """Where an item is defined in the model's repository."""

    file: str
    line: int | None = None


class ThreatMapping(BaseModel):
    requirements: list[str] = []
    # Mitigation ids. Look them up in ThreatModel.mitigations.
    mitigations: list[str] = []
    further_mitigations: list[str] = []
    # Components and boundaries the threat is listed for, by name.
    components: list[str] = []

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
    source: SourceRef | None = None


class ThreatActor(BaseModel):
    name: str
    description: str = ""
    source: SourceRef | None = None


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
    source: SourceRef | None = None

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
    def risk_band(self) -> str | None:
        return scales.risk_band(self.risk_score)

    @property
    def residual_risk_band(self) -> str | None:
        return scales.risk_band(self.residual_risk_score)

    @property
    def is_open(self) -> bool:
        """True while the threat still needs work (see scales.OPEN_STATUSES)."""
        return self.status in scales.OPEN_STATUSES

    @property
    def risk_order(self) -> tuple:
        """Sort key: highest residual risk first, then highest risk, then id.

        Unknown scores sort after every known one. The id comes last so no two threats
        tie, which keeps the order the same on every build.
        """
        unknown = 1
        return (
            -self.residual_risk_score if self.residual_risk_score else unknown,
            -self.risk_score if self.risk_score else unknown,
            scales.natural_key(self.SID),
        )

    @property
    def status_slug(self) -> str:
        return self.status.replace(" ", "-")

    @property
    def is_capec(self) -> bool:
        return self.SID.startswith("CAPEC-")


class Component(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str = ""
    component_class: str = Field(alias="class", default="")
    description: str | None = ""
    inBoundary: str | None = Field(alias="in_boundary", default=None)
    properties: dict[str, Any] = {}
    source: SourceRef | None = None
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
    line: int | None = None
    findings: list[Finding] = []
    flows: list[Flow] = []
    components: list[str] = []
    dfd: str = ""
    mermaid: str = ""
    url: str | None = None

    @property
    def source(self) -> SourceRef | None:
        return SourceRef(file=self.file, line=self.line) if self.file else None

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
    """The property names that one requirement refers to."""
    if "|" in token:
        names = [name for part in token.split("|") for name in _token_props(part)]
        return list(dict.fromkeys(names))
    token = token.strip()
    for operator in ("!=", "=="):
        if operator in token:
            left, right = token.split(operator, 1)
            return [left.strip(), right.strip()]
    return [token.removeprefix("!").split(".", 1)[0]]


def source_url(config: SiteConfig, source: SourceRef | None) -> str | None:
    """Link to a definition in the repository, if the site knows the repository."""
    if not (config.github_repo and source):
        return None
    anchor = f"#L{source.line}" if source.line else ""
    return f"{config.github_repo}/blob/{config.github_branch}/{source.file}{anchor}"


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
                scenario.url = source_url(config, scenario.source)
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
        # Count every defined threat, so each count matches the register filtered to
        # that status.
        status_counter = Counter(t.status for t in self.threats.values())
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

    def threats_by_risk(
        self, threat_ids: Iterable[str] | None = None
    ) -> list[tuple[str, Threat]]:
        """Return (id, threat) pairs in risk order, for the given ids or all threats."""
        ids = self.threats if threat_ids is None else threat_ids
        pairs = [(tid, self.threats[tid]) for tid in ids if tid in self.threats]
        return sorted(pairs, key=lambda item: item[1].risk_order)

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
        by_risk = self.threats_by_risk()
        mitigating = [
            (tid, t) for tid, t in by_risk if mitigation_id in t.mapping.mitigations
        ]
        proposing = [
            (tid, t)
            for tid, t in by_risk
            if mitigation_id in t.mapping.further_mitigations
        ]
        return mitigating, proposing

    def open_risk(self, threat_ids: Iterable[str]) -> dict[str, Any]:
        """Summarize a group of threats: how many, how many are open, and the highest
        risk after mitigations among the open ones."""
        threats = [self.threats[tid] for tid in set(threat_ids) if tid in self.threats]
        open_scores = [
            t.residual_risk_score
            for t in threats
            if t.is_open and t.residual_risk_score
        ]
        return {
            "total": len(threats),
            "open": sum(t.is_open for t in threats),
            "top_risk": max(open_scores) if open_scores else None,
        }

    def backlog(self) -> list[dict[str, Any]]:
        """Proposed mitigations, ranked by the highest risk they would reduce.

        Each entry lists the threats naming the mitigation (in place or as a further
        mitigation) in risk order, the highest risk after mitigations among them, and
        how many are open. Ties fall back to the open count, then the mitigation id.
        """
        rows = []
        for mid, mit in self.mitigations.items():
            if mit.status != "proposed":
                continue
            mitigating, proposing = self.mitigation_threats(mid)
            threats = sorted(
                {tid: t for tid, t in mitigating + proposing}.items(),
                key=lambda item: item[1].risk_order,
            )
            scores = [
                t.residual_risk_score for _, t in threats if t.residual_risk_score
            ]
            rows.append(
                {
                    "mitigation": mit,
                    "threats": threats,
                    "top_risk": max(scores) if scores else None,
                    "open_count": sum(t.is_open for _, t in threats),
                }
            )
        rows.sort(
            key=lambda row: (
                -(row["top_risk"] or 0),
                -row["open_count"],
                scales.natural_key(row["mitigation"].id),
            )
        )
        return rows

    def parent_threats(self, threat_id: str) -> list[str]:
        """Return the ids of the threats that list threat_id as a child."""
        if self._parents is None:
            parents: defaultdict[str, list[str]] = defaultdict(list)
            for tid, threat in self.threats.items():
                for child in threat.children:
                    parents[child].append(tid)
            self._parents = {
                child: sorted(tids, key=scales.natural_key)
                for child, tids in parents.items()
            }
        return self._parents.get(threat_id, [])
