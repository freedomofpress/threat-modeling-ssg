"""Author a model, generate the report, then render and check the site."""

import html
import json
import re
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
        mitigations=["sanitizes_input"],
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


def diagram_sources(page: str) -> list[str]:
    """The diagram text as diagrams.js reads it: the decoded textContent."""
    return [
        html.unescape(raw)
        for raw in re.findall(
            r'<pre class="diagram-source" hidden>(.*?)</pre>', page, re.DOTALL
        )
    ]


def test_model_text_is_escaped(tmp_path: Path) -> None:
    report = author_model()
    tricky = 'Use "safe" <b>parser</b> & friends'
    threat = next(t for t in report["threats"] if t["SID"] == "T-INPUT")
    threat["description"] = tricky
    report["scenarios"][0]["description"] = tricky
    model = render(report, tmp_path)

    escaped = "Use &#34;safe&#34; &lt;b&gt;parser&lt;/b&gt; &amp; friends"
    for name in ("threat_T-INPUT.html", "threats.html", "scenarios.html"):
        assert escaped in (tmp_path / name).read_text(), name

    for page_path in tmp_path.glob("*.html"):
        page = page_path.read_text()
        assert "<b>" not in page, page_path.name
        # Text escaped twice, or HTML from the templates shown as literal text.
        for needle in ("&amp;amp;", "&amp;#34;", "&amp;#x", "&lt;span", "&lt;a "):
            assert needle not in page, (page_path.name, needle)

    # In the page, the diagram source is escaped. Decoding it must give back exactly the
    # DOT and Mermaid text, since that is what diagrams.js passes to Viz and Mermaid.
    scenario = model.scenarios[0]
    page = (tmp_path / "scenario_Handle_request.html").read_text()
    assert "label = &lt;&lt;i&gt;Net&lt;/i&gt;&gt;;" in page
    assert diagram_sources(page) == [scenario.dfd, scenario.mermaid]
    assert "label = <<i>Net</i>>;" in scenario.dfd

    # The matrix check marks are the characters ✓ and ✗. Written as &#x2713; entities,
    # they would be escaped and shown as literal text.
    matrix = (tmp_path / "threats_components.html").read_text()
    assert "✓" in matrix or "✗" in matrix
