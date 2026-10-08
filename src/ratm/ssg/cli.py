import shutil
import sys
import tomllib
from pathlib import Path

import click
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import scales
from . import views  # noqa: F401 — registers @view decorators
from .models import SiteConfig, ThreatModel, source_url
from .utils import (
    display_token,
    mitigation_href,
    property_href,
    render_views,
    slugify,
    status_slug,
    threat_actor_href,
)

TEMPLATES_DIR = Path(__file__).parent / "templates"


def load_config(filename="config.toml"):
    config_path = Path(filename)
    if config_path.exists():
        print("Loading config.toml...")
        with open(config_path, "rb") as f:
            return SiteConfig.model_validate(tomllib.load(f))
    return SiteConfig()


def copy_assets(assets_dst):
    assets_src = TEMPLATES_DIR / "assets"
    if assets_dst.exists():
        shutil.rmtree(assets_dst)
    shutil.copytree(assets_src, assets_dst)


def build_env() -> Environment:
    # Escape model text in all .html templates. This also escapes the hidden diagram
    # sources, which diagrams.js reads through textContent. That turns the entities back
    # into the original characters.
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["basename"] = lambda p: Path(p).name
    env.filters["slugify"] = slugify
    env.filters["display"] = display_token
    env.filters["property_href"] = property_href
    env.filters["mitigation_href"] = mitigation_href
    env.filters["threat_actor_href"] = threat_actor_href
    env.filters["status_slug"] = status_slug
    env.filters["risk_band"] = scales.risk_band
    env.globals["source_url"] = source_url

    # FIXME: These are a bit hackish, but work.
    env.filters["sort_by_class"] = lambda d: sorted(
        d.items(), key=lambda x: x[1].component_class
    )
    env.filters["implemented"] = lambda d: sorted(
        ((k, v) for k, v in d.items() if v is not False),
        key=lambda item: 0 if not isinstance(item[1], bool) else 1,
    )
    return env


@click.command()
@click.option(
    "-o",
    "--output",
    "output_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default="output",
    show_default=True,
    help="Output directory for the generated files",
)
def main(output_dir):
    config = load_config()

    model = ThreatModel.load_report(sys.stdin)

    env = build_env()

    output_dir.mkdir(parents=True, exist_ok=True)

    model.prepare_site(config)

    copy_assets(output_dir / "assets")

    if config.logo:
        logo_src = Path(config.logo)
        if logo_src.is_file():
            shutil.copy(logo_src, output_dir / logo_src.name)
            config.logo = logo_src.name
        else:
            print(f"Warning: logo '{config.logo}' not found")
            config.logo = None

    render_views(
        env,
        output_dir,
        {
            "config": config,
            "model": model,
        },
    )

    print(f"\nDone! Generated files in {output_dir}/")
