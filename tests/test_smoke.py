"""End-to-end: author a model, generate the report, load it, and render every view."""

import json
import runpy
from pathlib import Path

import pytest

from ratm import Ratm, Scenario
from ratm.ssg.cli import build_env
from ratm.ssg.models import SiteConfig, ThreatModel
from ratm.ssg.utils import render_views

DEMO = Path(__file__).parent.parent / "demo" / "model.py"


def author_model() -> dict:
    tm = Ratm(load_capec_info=False)
    tm.define_properties(
        "reads_input",
        "sanitizes_input",
        "is_exposed",
        ("loads_resources", "Loads resources", (), tuple),
        ("verifies_resources", "Verifies resources", (), tuple),
    )
    tm.Mitigation(
        "M-SANITIZE",
        title="Sanitize input",
        property="sanitizes_input",
    )
    tm.Mitigation("M-VERIFY", title="Verify deps", property="verifies_resources.deps")
    tm.Mitigation("M-DOCS", title="Document the risk", status="optional")
    tm.Mitigation("M-WAF", title="Add a WAF", status="proposed")
    tm.ThreatActor("Nation state", description="Well resourced")
    tm.ThreatActor("Any")
    tm.Threat(
        "T-INPUT",
        requirements=["reads_input"],
        mitigations=["M-SANITIZE", "M-DOCS"],
        further_mitigations=["M-WAF"],
        status="partially mitigated",
        impact="High",
        likelihood="Medium",
        residual_likelihood="Low",
        residual_risk="Legacy parsers remain",
        threat_actors=["Nation state", "Any"],
        children=["T-DEPS"],
        comment="Input handling",
    )
    tm.Threat(
        "T-DEPS",
        requirements=["loads_resources.deps"],
        mitigations=["M-VERIFY"],
        status="mitigated",
        impact="Medium",
        likelihood="Low",
        threat_actors=["Any"],
    )
    tm.Threat("T-BARE", requirements=["is_exposed"], status="out of scope")
    net = tm.Boundary(name="Net", is_exposed=True)
    web = tm.Component(
        name="Web app",
        boundary=net,
        reads_input=True,
        sanitizes_input=True,
        loads_resources=("deps",),
    )
    worker = tm.Component(name="Worker", reads_input=True, loads_resources=("deps",))
    scenario = Scenario(name="Handle request", description="A request comes in")
    scenario.Dataflow(name="Request", source=web, sink=worker)
    return tm.Report([scenario]).generate()


def render(report: dict, out: Path) -> ThreatModel:
    model = ThreatModel.model_validate(json.loads(json.dumps(report)))
    config = SiteConfig(title="Smoke")
    model.prepare_scenarios(config)
    render_views(build_env(), out, {"config": config, "model": model})
    return model


def test_render_all_views(tmp_path: Path) -> None:
    render(author_model(), tmp_path)
    names = {p.name for p in tmp_path.iterdir()}
    expected = {
        "index.html",
        "threats.html",
        "threats_components.html",
        "components.html",
        "scenarios.html",
        "mitigations.html",
        "threat_actors.html",
        "threat_T-INPUT.html",
        "threat_T-DEPS.html",
        "mitigation_M-SANITIZE.html",
        "mitigation_M-DOCS.html",
        "threat_actor_Nation_state.html",
        "threat_actor_Any.html",
        "property_sanitizes_input.html",
        "component_Web_app.html",
        "scenario_Handle_request.html",
    }
    assert expected <= names, expected - names


def test_threat_page_contents(tmp_path: Path) -> None:
    render(author_model(), tmp_path)
    page = (tmp_path / "threat_T-INPUT.html").read_text()
    assert "partially mitigated" in page
    assert "capec.mitre.org" not in page
    assert "Legacy parsers remain" in page
    for needle in (
        "mitigation_M-SANITIZE.html",
        "mitigation_M-WAF.html",
        "threat_actor_Nation_state.html",
        "threat_T-DEPS.html",
    ):
        assert needle in page, needle
    # risk 9 (High x Medium) and residual 6 (High x Low)
    assert '<div class="count-box__value">9</div>' in page
    assert "residual: 6" in page
    child = (tmp_path / "threat_T-DEPS.html").read_text()
    assert "threat_T-INPUT.html" in child


def test_mitigation_and_actor_pages(tmp_path: Path) -> None:
    render(author_model(), tmp_path)
    mit = (tmp_path / "mitigation_M-SANITIZE.html").read_text()
    assert "threat_T-INPUT.html" in mit
    assert "Web app" in mit and "Worker" in mit
    listing = (tmp_path / "mitigations.html").read_text()
    assert "mitigation_M-WAF.html" in listing and "proposed" in listing
    actor = (tmp_path / "threat_actor_Any.html").read_text()
    assert "threat_T-INPUT.html" in actor and "threat_T-DEPS.html" in actor


def test_summary_and_matrix(tmp_path: Path) -> None:
    render(author_model(), tmp_path)
    matrix = (tmp_path / "threats_components.html").read_text()
    assert "status--partially-mitigated" in matrix
    prop = (tmp_path / "property_sanitizes_input.html").read_text()
    assert "Worker" in prop and "mitigation_M-SANITIZE.html" in prop


@pytest.mark.skipif(not DEMO.exists(), reason="demo model missing")
def test_demo_round_trip(tmp_path: Path) -> None:
    namespace = runpy.run_path(str(DEMO), run_name="demo")
    tm = namespace["tm"]
    scenarios = [namespace[n] for n in ("release", "authoring", "publishing")]
    report = tm.Report(scenarios).generate()
    assert report["mitigations"], "the demo should define mitigations"
    assert report["threat_actors"], "the demo should define threat actors"
    model = render(report, tmp_path)
    assert (tmp_path / "mitigations.html").exists()
    assert model.analyze()["status_distribution"]
