"""The DOT source generated for scenario diagrams."""

import json

from ratm import Ratm
from ratm.components import Scenario
from ratm.ssg.graphs import generate_highlighted_dataflow
from ratm.ssg.models import SiteConfig, ThreatModel

# Characters with a meaning in DOT strings or in Graphviz HTML-like labels.
BOUNDARY = 'R&D <lab> "east"'
COMPONENT = 'Build "fast" \\ server'
FLOW = 'Push "release" \\ tag'


def dfd() -> str:
    tm = Ratm(load_capec_info=False)
    tm.define_properties("reads_input")
    zone = tm.Boundary(name=BOUNDARY)
    box = tm.Component(name=COMPONENT, boundary=zone)
    other = tm.Component(name="Other")
    scenario = Scenario(name="S", description="d")
    scenario.Dataflow(name=FLOW, source=other, sink=box)
    report = tm.Report([scenario]).generate()
    model = ThreatModel.model_validate(json.loads(json.dumps(report)))
    model.prepare_scenarios(SiteConfig())
    return model.scenarios[0].dfd


def test_boundary_names_are_escaped_as_html() -> None:
    assert "label = <<i>R&amp;D &lt;lab&gt; &quot;east&quot;</i>>;" in dfd()


def test_component_and_flow_names_are_escaped_as_dot_strings() -> None:
    source = dfd()
    assert 'label = "Build \\"fast\\"\\n\\\\ server";' in source
    assert 'tooltip = "Build \\"fast\\" \\\\ server";' in source
    assert 'label = "1. Push \\"release\\"\\n\\\\ tag";' in source


def test_components_with_escaped_names_can_be_highlighted() -> None:
    highlighted = generate_highlighted_dataflow(dfd(), {COMPONENT})
    assert highlighted.count('class = "highlighted"') == 1
