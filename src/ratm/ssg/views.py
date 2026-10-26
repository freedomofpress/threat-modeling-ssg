import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

from .graphs import generate_highlighted_dataflow
from .models import Component, SiteConfig, ThreatModel, _token_satisfied
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
    severity_tables = []
    for severity in ["Very High", "High", "Medium", "Low", "Unknown"]:
        threats = sorted(
            (tid, t)
            for tid, t in model.threats.items()
            if (t.severity or "Unknown") == severity
        )
        if not threats:
            continue
        props = [
            p
            for p in all_props
            if any(
                t.mapping.requirements_for_prop(p) or t.mapping.mitigations_for_prop(p)
                for _, t in threats
            )
        ]
        severity_tables.append(
            {"severity": severity, "threats": threats, "props": props}
        )
    return {
        "config": config,
        "model": model,
        "analysis": model.analyze(),
        "severity_tables": severity_tables,
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
        yield {
            "config": config,
            "model": model,
            "threat_id": threat_id,
            "threat": threat,
            "components": affected_components,
            "scenarios": scenario_names,
            "frequency": analysis["threat_counter"].get(threat_id, 0),
            "threat_scenario_data": threat_scenario_data,
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
            "unimplemented_mitigations": model.component_unimplemented_mitigations(
                component, threat_ids
            ),
            "threat_unimplemented": {
                tid: model.threat_unimplemented_mitigations(
                    component, model.threats[tid]
                )
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
        mitigated_threats, would_be_mitigated_threats, benefit_components = (
            model.property_mitigation_state(prop_key)
        )
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
                "mitigated_threats": mitigated_threats,
                "would_be_mitigated_threats": would_be_mitigated_threats,
                "benefit_components": benefit_components,
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


@view("/threats_components.html", log="Generating threats_components.html...")
def threats_components_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    analysis = model.analyze()

    severity_order = {"Very High": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}

    def sort_key(item: tuple[str, Any]) -> tuple[int, int]:
        tid, threat = item
        sev = severity_order.get(threat.severity or "Unknown", 4)
        match = re.search(r"\d+", tid)
        return (sev, int(match.group()) if match else 0)

    active_threats = sorted(
        (
            (tid, t)
            for tid, t in model.threats.items()
            if tid in analysis["threat_counter"]
        ),
        key=sort_key,
    )

    affected: dict[str, Component] = {}
    status: dict[str, dict[str, dict]] = {}
    for tid, threat in active_threats:
        status[tid] = {}
        for comp_name, comp in model.components.items():
            if not threat.applies_to(comp):
                continue
            affected[comp_name] = comp
            satisfied, missing = [], []
            for tok in threat.mapping.mitigations:
                (satisfied if _token_satisfied(comp, tok) else missing).append(tok)
            status[tid][comp_name] = {
                "mitigated": bool(satisfied),
                "satisfied": satisfied,
                "missing": missing,
            }

    sorted_components = sorted(
        affected.items(), key=lambda x: (x[1].component_class, x[0])
    )

    return {
        "config": config,
        "active_threats": active_threats,
        "sorted_components": sorted_components,
        "component_classes": Counter(
            comp.component_class or "Other" for _, comp in sorted_components
        ),
        "status": status,
    }
