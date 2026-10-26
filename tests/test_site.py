"""Author a model, generate the report, then render and check the site."""

import json
from pathlib import Path

from ratm import Ratm
from ratm.components import CAPECInfo, Scenario
from ratm.ssg.cli import build_env
from ratm.ssg.models import SiteConfig, ThreatModel
from ratm.ssg.utils import render_views


def author_model(description: str = "A request comes in") -> dict:
    tm = Ratm(load_capec_info=False)
    tm.define_properties("reads_input", "sanitizes_input", "is_exposed")
    tm.Threat(
        "T-INPUT",
        requirements=["reads_input"],
        mitigations=[],
        capec_info=CAPECInfo(description="Unsanitized input", severity="High"),
    )
    net = tm.Boundary(name="Net", is_exposed=True)
    web = tm.Component(name="Web app", boundary=net, reads_input=True)
    worker = tm.Component(name="Worker", reads_input=True)
    scenario = Scenario(name="Handle request", description=description)
    scenario.Dataflow(name="Request", source=web, sink=worker)
    return tm.Report([scenario]).generate()


def render(report: dict, out: Path) -> ThreatModel:
    model = ThreatModel.model_validate(json.loads(json.dumps(report)))
    config = SiteConfig(title="Site")
    model.prepare_scenarios(config)
    render_views(build_env(), out, {"config": config, "model": model})
    return model


def test_scenario_without_description_loads_on_the_site(tmp_path: Path) -> None:
    report = author_model(description=None)
    assert report["scenarios"][0]["description"] == ""
    render(report, tmp_path)
    assert (tmp_path / "scenario_Handle_request.html").is_file()


def test_scenario_names_with_punctuation_get_portable_page_names(
    tmp_path: Path,
) -> None:
    # Characters such as : ? and " are not allowed in Windows file names, and
    # actions/upload-artifact rejects them, so page names must not contain them.
    tm = Ratm(load_capec_info=False)
    tm.define_properties("reads_input")
    tm.Threat("T1", requirements=["reads_input"], mitigations=[])
    box = tm.Component(name="Box", reads_input=True)
    other = tm.Component(name="Other")
    scenario = Scenario(name='Workstation: boot & "updates"?', description="d")
    scenario.Dataflow(name="Flow", source=other, sink=box)
    render(tm.Report([scenario]).generate(), tmp_path)

    page = "scenario_Workstation__boot____updates__.html"
    assert (tmp_path / page).is_file()
    for path in tmp_path.rglob("*"):
        assert not set(path.name) & set('"<>|*?:'), path.name
    link = f'href="{page}"'
    for linking in (
        "index.html",
        "scenarios.html",
        "component_Box.html",
        "threat_T1.html",
    ):
        assert link in (tmp_path / linking).read_text(), linking
