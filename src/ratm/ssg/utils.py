from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ViewSpec:
    path_template: str
    template: str
    func: Callable[..., Mapping[str, Any] | Iterable[Mapping[str, Any]]]
    log: str | Callable[[int], str] | None = None


VIEWS: list[ViewSpec] = []


def view(
    path: str,
    template: str | None = None,
    *,
    log: str | Callable[[int], str] | None = None,
):
    path_template = path.lstrip("/")
    template_name = template or path_template

    def decorator(func: Callable[..., Mapping[str, Any] | Iterable[Mapping[str, Any]]]):
        VIEWS.append(
            ViewSpec(
                path_template=path_template,
                template=template_name,
                func=func,
                log=log,
            )
        )
        return func

    return decorator


def _call_view(func: Callable[..., Any], data: dict[str, Any]) -> Any:
    sig = inspect.signature(func)
    kwargs = {}
    for name, param in sig.parameters.items():
        if name in data:
            kwargs[name] = data[name]
        elif param.default is inspect._empty:
            raise KeyError(f"Missing view input '{name}' for {func.__name__}()")
    return func(**kwargs)


def _normalize_items(
    result: Mapping[str, Any] | Iterable[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    if isinstance(result, Mapping):
        return [result]
    return list(result)


def render_views(env, output_dir, data: dict[str, Any]) -> None:
    for spec in VIEWS:
        items = _normalize_items(_call_view(spec.func, data))
        if spec.log:
            if callable(spec.log):
                print(spec.log(len(items)))
            else:
                print(spec.log)
        template = env.get_template(spec.template)
        for item in items:
            output_path = spec.path_template.format(**item)
            html = template.render(**item)
            (output_dir / output_path).write_text(html)


def slugify(value: str) -> str:
    return re.sub(r"[^\w]", "_", value)


def _strip_family(part: str) -> str:
    negated = part.startswith("!")
    if negated:
        part = part[1:]
    if part.startswith(("ctx_", "mit_")):
        part = part[4:]
    return ("!" if negated else "") + part


def display_token(token: str) -> str:
    stripped = ".".join(_strip_family(part) for part in str(token).split("."))
    return stripped.replace("_", " ").replace("!", "not ")


def property_href(token: str) -> str:
    base = str(token).replace("!", "").split(".")[0]
    return f"property_{slugify(base)}.html"


def status_slug(value: str) -> str:
    return str(value).replace(" ", "-")


def mitigation_href(mitigation_id: str) -> str:
    return f"mitigation_{mitigation_id}.html"


def threat_actor_href(name: str) -> str:
    return f"threat_actor_{slugify(name)}.html"
