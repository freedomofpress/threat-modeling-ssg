"""End-to-end: author a model, generate the report, load it, and render every view."""

import filecmp
import html
import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from ratm import Ratm, Scenario
from ratm.ssg.cli import build_env
from ratm.ssg.models import SiteConfig, ThreatModel
from ratm.ssg.utils import render_views

ROOT = Path(__file__).parent.parent
DEMO = ROOT / "demo" / "model.py"


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
    )
    tm.Mitigation("M-VERIFY", title="Verify deps")
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
        "threat_rules.html",
        "internals.html",
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
    assert "Legacy parsers remain" in page
    for needle in (
        "mitigation_M-SANITIZE.html",
        "mitigation_M-WAF.html",
        "threat_actor_Nation_state.html",
        "threat_T-DEPS.html",
    ):
        assert needle in page, needle
    # The risk line shows risk 9 (High x Medium) and residual risk 6 (High x Low).
    assert (
        'High impact × Medium likelihood = <span class="risk"><span class="risk-value">9'
        in page
    )
    assert (
        'High impact × Low likelihood = <span class="risk"><span class="risk-value">6'
        in page
    )
    # The risk line comes before the details, notes, and matching rules.
    order = [
        page.index('class="risk-line"'),
        page.index("<h2>Mitigations</h2>"),
        page.index("<h2>Notes</h2>"),
        page.index("How this threat is matched"),
    ]
    assert order == sorted(order)
    child = (tmp_path / "threat_T-DEPS.html").read_text()
    assert "threat_T-INPUT.html" in child


def test_register_lists_threats_in_risk_order(tmp_path: Path) -> None:
    render(author_model(), tmp_path)
    page = (tmp_path / "threats.html").read_text()
    assert 'id="register"' in page and "data-sortable" in page
    # Residual 6 (High x Low), then 4 (Medium x Low), then unknown.
    order = [
        page.index(f'href="threat_{tid}.html"')
        for tid in ("T-INPUT", "T-DEPS", "T-BARE")
    ]
    assert order == sorted(order)
    # Filter values for the status select, including the open group.
    assert 'data-status="partially mitigated|open"' in page
    assert '<option value="open">' in page


def test_mitigation_and_actor_pages(tmp_path: Path) -> None:
    render(author_model(), tmp_path)
    mit = (tmp_path / "mitigation_M-SANITIZE.html").read_text()
    assert "threat_T-INPUT.html" in mit
    listing = (tmp_path / "mitigations.html").read_text()
    assert "mitigation_M-WAF.html" in listing and "proposed" in listing
    actor = (tmp_path / "threat_actor_Any.html").read_text()
    assert "threat_T-INPUT.html" in actor and "threat_T-DEPS.html" in actor


def test_summary_leads_with_open_risk(tmp_path: Path) -> None:
    render(author_model(), tmp_path)
    index = (tmp_path / "index.html").read_text()
    # Status counts link to the register filtered to that status.
    assert 'href="threats.html?status=partially%20mitigated"' in index
    assert 'href="threats.html?status=open"' in index
    # Top open risks lists T-INPUT, which is open and applies. T-DEPS is mitigated and
    # T-BARE is out of scope, so neither is listed.
    top = index[index.index("Top open risks") :]
    assert 'href="threat_T-INPUT.html"' in top
    assert 'href="threat_T-DEPS.html"' not in top
    assert "dfd-container" not in index


def test_summary_and_matrix(tmp_path: Path) -> None:
    render(author_model(), tmp_path)
    matrix = (tmp_path / "threats_components.html").read_text()
    # The legend also uses this class, so match the cell markup itself.
    assert '<td class="prop-cell status--partially-mitigated"' in matrix
    assert '<span class="tag tag--text">Sanitize input</span>' in matrix
    prop = (tmp_path / "property_reads_input.html").read_text()
    assert "threat_T-INPUT.html" in prop


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
    report["mitigations"]["M-SANITIZE"]["title"] = tricky
    model = render(report, tmp_path)

    escaped = "Use &#34;safe&#34; &lt;b&gt;parser&lt;/b&gt; &amp; friends"
    for name in (
        "threat_T-INPUT.html",
        "threats.html",
        "scenario_Handle_request.html",
        "mitigation_M-SANITIZE.html",
        "mitigations.html",
        "component_Web_app.html",
    ):
        assert escaped in (tmp_path / name).read_text(), name
    # Escaped in link text too, from a macro on the component page and from an include
    # on the scenario page.
    link = f'<a href="mitigation_M-SANITIZE.html">{escaped}</a>'
    assert link in (tmp_path / "component_Web_app.html").read_text()
    assert link in (tmp_path / "scenario_Handle_request.html").read_text()

    for page_path in tmp_path.glob("*.html"):
        page = page_path.read_text()
        assert "<b>" not in page, page_path.name
        # Double escaping, or macro output escaped as text.
        for needle in ("&amp;amp;", "&amp;#34;", "&lt;span", "&lt;a "):
            assert needle not in page, (page_path.name, needle)

    # In the page, the diagram source is escaped. Decoding it must give back exactly the
    # DOT and Mermaid text, since that is what diagrams.js passes to Viz and Mermaid.
    scenario = model.scenarios[0]
    page = (tmp_path / "scenario_Handle_request.html").read_text()
    assert "label = &lt;&lt;i&gt;Net&lt;/i&gt;&gt;;" in page
    assert diagram_sources(page) == [scenario.dfd, scenario.mermaid]
    assert "label = <<i>Net</i>>;" in scenario.dfd
    # The summary page has no diagrams, but the scenario index and threat pages do.
    for name in ("scenarios.html", "threat_T-INPUT.html"):
        sources = diagram_sources((tmp_path / name).read_text())
        assert sources, name
        assert all(s.startswith(("digraph tm {", "sequenceDiagram")) for s in sources)
        assert any("label = <<i>Net</i>>;" in s for s in sources), name


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


def build_demo_site(out: Path, hash_seed: int) -> None:
    """Run `demo/model.py | ratm -o out` under a fixed string hash seed."""
    env = {
        **os.environ,
        "PYTHONHASHSEED": str(hash_seed),
        "PYTHONPATH": os.pathsep.join(
            filter(None, [str(ROOT / "src"), os.environ.get("PYTHONPATH")])
        ),
    }
    # ratm loads config.toml from the current directory. Run from `out` so a config.toml
    # wherever the tests run cannot change the build.
    report = subprocess.run(
        [sys.executable, str(DEMO)],
        env=env,
        cwd=out,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    subprocess.run(
        [sys.executable, "-c", "from ratm.ssg.cli import main; main()", "-o", "."],
        input=report,
        env=env,
        cwd=out,
        capture_output=True,
        text=True,
        check=True,
    )


def differing_files(a: Path, b: Path) -> list[str]:
    cmp = filecmp.dircmp(a, b)
    assert not cmp.left_only and not cmp.right_only
    _, differ, errors = filecmp.cmpfiles(a, b, cmp.common_files, shallow=False)
    differ += errors
    for sub in cmp.common_dirs:
        differ += [f"{sub}/{name}" for name in differing_files(a / sub, b / sub)]
    return differ


@pytest.mark.skipif(not DEMO.exists(), reason="demo model missing")
def test_builds_are_reproducible(tmp_path: Path) -> None:
    # Python randomizes string hashing in each process, and that decides the order in
    # which a set of strings is iterated. Two builds in this process would always match,
    # so build in separate processes with different PYTHONHASHSEED values and compare
    # the output. Without sorting, seeds 0 and 1 reorder the component tables on the
    # demo's threat pages, and seed 2 reorders a component page's threat table.
    builds = []
    for seed in (0, 1, 2):
        out = tmp_path / f"seed{seed}"
        out.mkdir()
        build_demo_site(out, seed)
        builds.append(out)
    assert (builds[0] / "threat_RATM-4-EXEC.html").exists()
    for other in builds[1:]:
        assert differing_files(builds[0], other) == [], other.name
