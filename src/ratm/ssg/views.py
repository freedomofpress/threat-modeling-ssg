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
    analysis = model.analyze()
    # The highest residual risks that still need work and apply to at least one
    # component in a scenario.
    top_open = [
        {
            "tid": tid,
            "threat": threat,
            "components": sorted(
                analysis["threats_to_components"].get(tid, set()),
                key=scales.natural_key,
            ),
        }
        for tid, threat in model.threats_by_risk()
        if threat.is_open and tid in analysis["threat_counter"]
    ][:10]
    return {
        "config": config,
        "model": model,
        "analysis": analysis,
        "top_open": top_open,
        "open_count": sum(t.is_open for t in model.threats.values()),
    }


@view("/threats.html", log="Generating threats.html...")
def threats_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    """The risk register: every threat in risk order, sortable and filterable."""
    analysis = model.analyze()
    rows = []
    for tid, threat in model.threats_by_risk():
        components = sorted(
            analysis["threats_to_components"].get(tid, set()), key=scales.natural_key
        )
        rows.append({"tid": tid, "threat": threat, "components": components})
    id_rank = {
        tid: rank
        for rank, tid in enumerate(sorted(model.threats, key=scales.natural_key))
    }
    return {
        "config": config,
        "model": model,
        "rows": rows,
        "id_rank": id_rank,
        "status_rank": {s: i for i, s in enumerate(scales.THREAT_STATUSES)},
        "impact_scores": scales.IMPACT_SCORES,
        "likelihood_scores": scales.LIKELIHOOD_SCORES,
        "statuses": [
            s
            for s in scales.THREAT_STATUSES
            if any(t.status == s for t in model.threats.values())
        ],
        "actors": sorted(
            {a for t in model.threats.values() for a in t.threat_actors},
            key=scales.natural_key,
        ),
    }


@view("/threat_rules.html", log="Generating threat_rules.html...")
def threat_rules_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    """Model internals: which component properties each threat's rule uses."""
    all_props = list(model.properties)
    impact_tables = []
    for impact in scales.IMPACT_ORDER:
        threats = sorted(
            ((tid, t) for tid, t in model.threats.items() if t.impact_label == impact),
            key=lambda item: scales.natural_key(item[0]),
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
        "listed_only": sum(
            1 for t in model.threats.values() if not t.mapping.requirements
        ),
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
            "status_descriptions": scales.THREAT_STATUSES,
            "threat_scenario_data": threat_scenario_data,
            "mitigations": model.threat_mitigations(threat),
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
        threats = model.threats_by_risk(
            analysis["components_to_threats"].get(name, set())
        )
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
            "threats": threats,
            # Findings never target a boundary, so its page lists the threats that name
            # it, or a boundary around it, instead.
            "boundary_threats": model.listed_threats(name)
            if component.component_class == "Boundary"
            else [],
            "scenarios": scenario_names,
            "component_name": slugify(name),
        }


# Components carry the threats, so they come first. Boundaries rarely do.
_CLASS_ORDER = {"Component": 0, "Actor": 1, "Boundary": 2}

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
    """Components grouped by class, the ones carrying the most open risk first."""
    analysis = model.analyze()
    groups: dict[str, list] = {}
    for name, component in model.components.items():
        if component.component_class in config.hide_components_with_category:
            continue
        summary = model.open_risk(analysis["components_to_threats"].get(name, set()))
        groups.setdefault(component.component_class, []).append(
            {"name": name, "component": component, **summary}
        )
    class_lists = [
        {
            "label": _PLURAL_CLASSES.get(cls, cls),
            "members": sorted(
                members,
                key=lambda row: (
                    -(row["top_risk"] or 0),
                    -row["open"],
                    -row["total"],
                    scales.natural_key(row["name"]),
                ),
            ),
        }
        for cls, members in sorted(
            groups.items(),
            key=lambda item: (_CLASS_ORDER.get(item[0], len(_CLASS_ORDER)), item[0]),
        )
    ]
    return {"config": config, "model": model, "class_lists": class_lists}


@view("/component_properties.html", log="Generating component_properties.html...")
def component_properties_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    """Model internals: which properties each component has."""
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
        requiring_threats = model.threats_by_risk(
            tid
            for tid, t in model.threats.items()
            if tid in analysis["threat_counter"]
            and prop_key in t.mapping.requirement_props
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
        # One row per (threat, component) finding, highest risk first.
        findings = sorted(
            (
                {
                    "tid": f.threat_id,
                    "threat": model.threats[f.threat_id],
                    "target": f.target,
                }
                for f in scenario.findings
                if f.threat_id in model.threats
            ),
            key=lambda row: (
                row["threat"].risk_order,
                scales.natural_key(row["target"]),
            ),
        )
        yield {
            "config": config,
            "model": model,
            "scenario": scenario,
            "summary": model.open_risk(f.threat_id for f in scenario.findings),
            "findings": findings,
            "scenario_name": slugify(scenario.name),
        }


@view("/scenarios.html", log="Generating scenarios.html...")
def scenarios_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    return {
        "config": config,
        "model": model,
        "summaries": {
            s.name: model.open_risk(f.threat_id for f in s.findings)
            for s in model.scenarios
        },
    }


def _threat_sort_key(item: tuple[str, Threat]) -> tuple:
    """Highest impact first, then by id with its numbers compared."""
    tid, threat = item
    return (scales.IMPACT_ORDER.index(threat.impact_label), scales.natural_key(tid))


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

    # Names of the components each threat applies to, from the findings, so listed
    # components and requirement matches both count. A cell is filled when the component
    # is in its threat's set.
    applies: dict[str, set[str]] = {
        tid: set(analysis["threats_to_components"].get(tid, set()))
        for tid, _ in active_threats
    }
    affected: dict[str, Component] = {
        name: model.components[name]
        for names in applies.values()
        for name in names
        if name in model.components
    }

    sorted_components = sorted(
        affected.items(), key=lambda x: (x[1].component_class, x[0])
    )

    return {
        "config": config,
        "model": model,
        "active_threats": active_threats,
        "status_legend": [
            status
            for status in scales.THREAT_STATUSES
            if any(t.status == status for _, t in active_threats)
        ],
        "sorted_components": sorted_components,
        "component_classes": Counter(
            comp.component_class or "Other" for _, comp in sorted_components
        ),
        "applies": applies,
    }


@view("/mitigations.html", log="Generating mitigations.html...")
def mitigations_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    rows = []
    for rank, mid in enumerate(sorted(model.mitigations, key=scales.natural_key)):
        mitigating, proposing = model.mitigation_threats(mid)
        rows.append(
            {
                "mitigation": model.mitigations[mid],
                "rank": rank,
                "mitigating": mitigating,
                "proposing": proposing,
            }
        )
    return {
        "config": config,
        "model": model,
        "rows": rows,
        "statuses": [
            s
            for s in scales.MITIGATION_STATUSES
            if any(m.status == s for m in model.mitigations.values())
        ],
    }


@view("/backlog.html", log="Generating backlog.html...")
def backlog_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    """Proposed mitigations, ranked by the highest risk they would reduce."""
    return {"config": config, "model": model, "rows": model.backlog()}


@view(
    "/mitigation_{mitigation_id}.html",
    template="mitigation.html",
    log=lambda count: f"Generating {count} mitigation pages...",
)
def mitigation_view(
    config: SiteConfig,
    model: ThreatModel,
) -> Iterable[dict[str, Any]]:
    for mid, mitigation in model.mitigations.items():
        mitigating, proposing = model.mitigation_threats(mid)
        yield {
            "config": config,
            "model": model,
            "mitigation_id": mid,
            "mitigation": mitigation,
            "threats": mitigating,
            "further_threats": proposing,
            "status_descriptions": scales.MITIGATION_STATUSES,
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
        threats = model.threats_by_risk(analysis["actors_to_threats"].get(name, []))
        yield {
            "config": config,
            "model": model,
            "actor": actor,
            "actor_slug": slugify(name),
            "threats": threats,
        }


@view("/internals.html", log="Generating internals.html...")
def internals_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    """Model internals: authoring aids kept out of the reader-facing pages."""
    return {"config": config, "model": model}


@view("/guide.html", log="Generating guide.html...")
def guide_view(
    config: SiteConfig,
    model: ThreatModel,
) -> dict[str, Any]:
    """How to read the model: statuses, the risk scale, and residual risk."""
    impacts = sorted(scales.IMPACT_SCORES, key=scales.IMPACT_SCORES.get, reverse=True)
    likelihoods = sorted(scales.LIKELIHOOD_SCORES, key=scales.LIKELIHOOD_SCORES.get)
    return {
        "config": config,
        "model": model,
        "threat_statuses": [
            (s, description, s in scales.OPEN_STATUSES)
            for s, description in scales.THREAT_STATUSES.items()
        ],
        "mitigation_statuses": list(scales.MITIGATION_STATUSES.items()),
        "impacts": [(i, scales.IMPACT_SCORES[i]) for i in impacts],
        "likelihoods": [(lk, scales.LIKELIHOOD_SCORES[lk]) for lk in likelihoods],
        "risk_score": scales.risk_score,
        "bands": scales.RISK_BANDS,
    }
