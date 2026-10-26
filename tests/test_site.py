"""Author a model, generate the report, then render and check the site."""

import filecmp
import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from ratm import Ratm
from ratm.components import CAPECInfo, Scenario
from ratm.ssg.cli import build_env
from ratm.ssg.models import SiteConfig, ThreatModel
from ratm.ssg.utils import render_views

ROOT = Path(__file__).parent.parent
DEMO = ROOT / "demo" / "model.py"


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
    # the output.
    builds = []
    for seed in (0, 1, 2):
        out = tmp_path / f"seed{seed}"
        out.mkdir()
        build_demo_site(out, seed)
        builds.append(out)
    assert (builds[0] / "threat_RATM-4-EXEC.html").exists()
    for other in builds[1:]:
        assert differing_files(builds[0], other) == [], other.name


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
