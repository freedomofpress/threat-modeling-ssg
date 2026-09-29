import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

from .. import scales
from .graphs import generate_highlighted_dataflow
from .models import Component, SiteConfig, Threat, ThreatModel
from .utils import display_token, slugify, view


@view("/index.html", log="Generating index.html...")
def summary_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    return {"config": config, "model": model, "analysis": model.analyze()}


@view("/threats.html", log="Generating threats.html...")
def threats_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    all_props = list(model.properties)
    impact_tables = []
    for impact in scales.IMPACT_ORDER:
        threats = sorted(
            (tid, t) for tid, t in model.threats.items() if t.impact_label == impact
        )
        if not threats:
            continue
        props = [
            p
            for p in all_props
            if any(t.mapping.requirements_for_prop(p) for _, t in threats)
        ]
        impact_tables.append({"impact": impact, "threats": threats, "props": props})
    return {
        "config": config,
        "model": model,
        "analysis": model.analyze(),
        "impact_tables": impact_tables,
    }


@view(
    "/threat_{threat_id}.html",
    template="threat.html",
    log=lambda count: f"Generating {count} threat pages...",
)
def threat_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    analysis = model.analyze()
    scenario_by_name = model.scenario_by_name()
    for threat_id, threat in model.threats.items():
        scenario_names = analysis["threats_to_scenarios"].get(threat_id, [])
        affected_components = sorted(
            analysis["threats_to_components"].get(threat_id, set())
        )
        threat_scenario_data = []
        for scenario_name in scenario_names:
            scenario = scenario_by_name.get(scenario_name)
            if not scenario:
                continue
            linked = scenario.linked_component_names
            affected_in_scenario = [
                f.target
                for f in scenario.findings
                if f.threat_id == threat_id and f.target in linked
            ]
            if not affected_in_scenario:
                continue
            highlighted_dfd = (
                generate_highlighted_dataflow(scenario.dfd, set(affected_in_scenario))
                if scenario.dfd
                else None
            )
            threat_scenario_data.append(
                {
                    "scenario": scenario,
                    "affected_components": affected_in_scenario,
                    "highlighted_dfd": highlighted_dfd,
                }
            )
        mitigations = []
        for mit in model.threat_mitigations(threat):
            per_component = None
            if mit.property:
                per_component = [
                    (name, mit.implemented_on(model.components[name]))
                    for name in affected_components
                    if name in model.components
                ]
            mitigations.append({"mitigation": mit, "per_component": per_component})
        yield {
            "config": config,
            "model": model,
            "threat_id": threat_id,
            "threat": threat,
            "components": affected_components,
            "scenarios": scenario_names,
            "frequency": analysis["threat_counter"].get(threat_id, 0),
            "threat_scenario_data": threat_scenario_data,
            "mitigations": mitigations,
            "further_mitigations": model.threat_mitigations(threat, further=True),
            "children": [(cid, model.threats.get(cid)) for cid in threat.children],
            "parents": [
                (pid, model.threats[pid]) for pid in model.parent_threats(threat_id)
            ],
        }


@view(
    "/component_{component_name}.html",
    template="component.html",
    log=lambda count: f"Generating {count} component pages...",
)
def component_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    analysis = model.analyze()
    for name, component in model.components.items():
        threat_ids = sorted(analysis["components_to_threats"].get(name, set()))
        scenario_names = list(
            dict.fromkeys(
                s.name
                for s in model.scenarios
                if name in s.linked_component_names or name in s.components
            )
        )
        yield {
            "config": config,
            "model": model,
            "comp_name": name,
            "component": component,
            "threats": threat_ids,
            "scenarios": scenario_names,
            "potential_mitigations": model.component_potential_mitigations(
                component, threat_ids
            ),
            "threat_mitigations": {
                tid: model.component_mitigation_states(component, model.threats[tid])
                for tid in threat_ids
                if tid in model.threats
            },
            "component_name": slugify(name),
        }


_PLURAL_CLASSES = {
    "Actor": "Actors",
    "Boundary": "Boundaries",
    "Component": "Components",
}


@view("/components.html", log="Generating components.html...")
def components_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    prop_keys = list(model.properties)
    members_by_class: dict[str, list] = {}
    for name, component in sorted(
        model.components.items(), key=lambda x: x[1].component_class
    ):
        if component.component_class in config.hide_components_with_category:
            continue
        members_by_class.setdefault(component.component_class, []).append(
            (name, component)
        )
    class_tables = [
        {
            "label": _PLURAL_CLASSES.get(cls, cls),
            "members": members,
            "props": [
                key
                for key in prop_keys
                if any(
                    comp.get_property(key) not in (False, None) for _, comp in members
                )
            ],
        }
        for cls, members in members_by_class.items()
    ]
    return {"config": config, "model": model, "class_tables": class_tables}


@view(
    "/property_{prop_slug}.html",
    template="property.html",
    log=lambda count: f"Generating {count} property pages...",
)
def property_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    analysis = model.analyze()
    for prop_key, prop in model.properties.items():
        requiring_threats = sorted(
            (
                (tid, t)
                for tid, t in model.threats.items()
                if tid in analysis["threat_counter"]
                and prop_key in t.mapping.requirement_props
            ),
            key=lambda x: x[0],
        )
        slug = slugify(prop_key)
        yield {
            "config": config,
            "prop": prop_key,
            "prop_slug": slug,
            "data": {
                "label": prop.name,
                "display_label": display_token(prop_key).title(),
                "slug": slug,
                "mitigation_states": model.property_mitigation_state(prop_key),
                "requiring_threats": requiring_threats,
            },
        }


@view(
    "/scenario_{scenario_name}.html",
    template="scenario.html",
    log=lambda count: f"Generating {count} scenario pages...",
)
def scenario_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    for scenario in model.scenarios:
        yield {
            "config": config,
            "model": model,
            "scenario": scenario,
            "scenario_name": slugify(scenario.name),
        }


@view("/scenarios.html", log="Generating scenarios.html...")
def scenarios_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    return {"config": config, "model": model}


def _threat_sort_key(item: tuple[str, Threat]) -> tuple[int, int]:
    """Highest impact first, then by the number in the id."""
    tid, threat = item
    match = re.search(r"\d+", tid)
    return (
        scales.IMPACT_ORDER.index(threat.impact_label),
        int(match.group()) if match else 0,
    )


def _risk_sort_key(item: tuple[str, Threat]) -> tuple[int, str]:
    """Highest risk first, unknown risk last."""
    tid, threat = item
    return (-(threat.risk_score or 0), tid)


@view("/threats_components.html", log="Generating threats_components.html...")
def threats_components_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    analysis = model.analyze()

    active_threats = sorted(
        (
            (tid, t)
            for tid, t in model.threats.items()
            if tid in analysis["threat_counter"]
        ),
        key=_threat_sort_key,
    )

    affected: dict[str, Component] = {}
    status: dict[str, dict[str, dict]] = {}
    for tid, threat in active_threats:
        status[tid] = {}
        for comp_name, comp in model.components.items():
            if not threat.applies_to(comp):
                continue
            affected[comp_name] = comp
            status[tid][comp_name] = {
                "states": [
                    st
                    for st in model.component_mitigation_states(comp, threat)
                    if st["implemented"] is not None
                ],
            }

    sorted_components = sorted(
        affected.items(), key=lambda x: (x[1].component_class, x[0])
    )

    return {
        "config": config,
        "model": model,
        "active_threats": active_threats,
        "sorted_components": sorted_components,
        "component_classes": Counter(
            comp.component_class or "Other" for _, comp in sorted_components
        ),
        "status": status,
    }


@view("/mitigations.html", log="Generating mitigations.html...")
def mitigations_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    rows = []
    for mid in sorted(model.mitigations):
        mitigating, proposing = model.mitigation_threats(mid)
        rows.append((model.mitigations[mid], mitigating, proposing))
    return {"config": config, "model": model, "rows": rows}


@view(
    "/mitigation_{mitigation_id}.html",
    template="mitigation.html",
    log=lambda count: f"Generating {count} mitigation pages...",
)
def mitigation_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    analysis = model.analyze()
    for mid, mitigation in model.mitigations.items():
        mitigating, proposing = model.mitigation_threats(mid)
        component_states = None
        if mitigation.property:
            affected = sorted(
                {
                    name
                    for tid, _ in mitigating
                    for name in analysis["threats_to_components"].get(tid, set())
                }
            )
            component_states = [
                (
                    name,
                    model.components[name],
                    mitigation.implemented_on(model.components[name]),
                )
                for name in affected
                if name in model.components
            ]
        yield {
            "config": config,
            "model": model,
            "mitigation_id": mid,
            "mitigation": mitigation,
            "threats": mitigating,
            "further_threats": proposing,
            "component_states": component_states,
        }


@view("/threat_actors.html", log="Generating threat_actors.html...")
def threat_actors_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    analysis = model.analyze()
    rows = [
        (actor, analysis["actors_to_threats"].get(name, []))
        for name, actor in sorted(model.threat_actors.items())
    ]
    return {"config": config, "model": model, "rows": rows}


@view(
    "/threat_actor_{actor_slug}.html",
    template="threat_actor.html",
    log=lambda count: f"Generating {count} threat actor pages...",
)
def threat_actor_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    analysis = model.analyze()
    for name, actor in model.threat_actors.items():
        threats = sorted(
            (
                (tid, model.threats[tid])
                for tid in analysis["actors_to_threats"].get(name, [])
                if tid in model.threats
            ),
            key=_risk_sort_key,
        )
        yield {
            "config": config,
            "model": model,
            "actor": actor,
            "actor_slug": slugify(name),
            "threats": threats,
        }
