from . import scales
from .components import Component, Mitigation, Property, Scenario, Threat, ThreatActor


class Report:
    def __init__(
        self,
        scenarios: list[Scenario],
        components: list[Component] | None = None,
        threats: list[Threat] | None = None,
        properties: list[Property] | None = None,
        mitigations: list[Mitigation] | None = None,
        threat_actors: list[ThreatActor] | None = None,
    ):
        self.scenarios = scenarios
        self.threats = list(threats or [])
        self.properties = list(properties or [])
        self.mitigations = list(mitigations or [])
        self.threat_actors = list(threat_actors or [])
        self.components = components or self.populate_components(scenarios)

    def populate_components(self, scenarios: list[Scenario]):
        """Iterate all scenarios and retrieve their components."""
        components = {}
        for scenario in scenarios:
            for component in scenario.iter_components():
                components[component.name] = component
        return components.values()

    def components_to_dict(self):
        return {comp.name: comp.to_dict() for comp in self.components}

    def properties_to_dict(self):
        return {prop.name: prop.to_dict() for prop in self.properties}

    def scenarios_to_dict(self):
        return [scenario.to_dict() for scenario in self.scenarios]

    def threats_to_dict(self):
        return [threat.to_dict() for threat in self.threats]

    def mitigations_to_dict(self):
        return {mit.id: mit.to_dict() for mit in self.mitigations}

    def threat_actors_to_dict(self):
        return {actor.name: actor.to_dict() for actor in self.threat_actors}

    def validate(self):
        """Check cross-references and labels, raising ValueError on the first problem."""
        threat_ids = _unique_ids("threat", [t.id for t in self.threats])
        mitigation_ids = _unique_ids("mitigation", [m.id for m in self.mitigations])
        actor_names = _unique_ids("threat actor", [a.name for a in self.threat_actors])
        property_names = {prop.name for prop in self.properties}

        for mit in self.mitigations:
            if mit.status not in scales.MITIGATION_STATUSES:
                raise ValueError(
                    f"Mitigation {mit.id} has unknown status '{mit.status}'"
                )
            # Only meaningful when the model defines properties at all.
            if property_names:
                for name in mit.property_names:
                    if name not in property_names:
                        raise ValueError(
                            f"Mitigation {mit.id} property '{mit.property}' refers"
                            f" to undefined property '{name}'"
                        )

        for threat in self.threats:
            prefix = f"Threat {threat.id}"
            if threat.status not in scales.THREAT_STATUSES:
                raise ValueError(f"{prefix} has unknown status '{threat.status}'")
            _check_label(prefix, "impact", threat.impact_label, scales.IMPACT_SCORES)
            _check_label(
                prefix, "likelihood", threat.likelihood_label, scales.LIKELIHOOD_SCORES
            )
            _check_label(
                prefix, "residual impact", threat.residual_impact, scales.IMPACT_SCORES
            )
            _check_label(
                prefix,
                "residual likelihood",
                threat.residual_likelihood,
                scales.LIKELIHOOD_SCORES,
            )
            for mid in [*threat.mitigations, *threat.further_mitigations]:
                if mid not in mitigation_ids:
                    raise ValueError(f"{prefix} refers to unknown mitigation '{mid}'")
            for name in threat.threat_actors:
                if name not in actor_names:
                    raise ValueError(
                        f"{prefix} refers to unknown threat actor '{name}'"
                    )
            for cid in threat.children:
                if cid == threat.id or cid not in threat_ids:
                    raise ValueError(f"{prefix} refers to invalid child threat '{cid}'")

    def generate(self):
        self.validate()

        for scenario in self.scenarios:
            scenario.populate_findings(self.threats)

        report = {}
        report["properties"] = self.properties_to_dict()
        report["components"] = self.components_to_dict()
        report["scenarios"] = self.scenarios_to_dict()
        report["threats"] = self.threats_to_dict()
        report["mitigations"] = self.mitigations_to_dict()
        report["threat_actors"] = self.threat_actors_to_dict()
        return report


def _unique_ids(kind: str, ids: list[str]) -> set[str]:
    seen = set()
    for item in ids:
        if item in seen:
            raise ValueError(f"Duplicate {kind} id '{item}'")
        seen.add(item)
    return seen


def _check_label(prefix: str, field: str, value: str | None, scale: dict) -> None:
    if value is not None and value not in scale:
        raise ValueError(f"{prefix} has unknown {field} '{value}'")
