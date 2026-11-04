import html
import re
from collections import defaultdict

from .models import Component, Scenario

FONT_NAME = "Arial"
FONT_SIZE_GRAPH = 14
FONT_SIZE_NODE = 14
FONT_SIZE_EDGE = 12
FONT_SIZE_BOUNDARY = 10

NODE_SHAPES = {
    "Actor": "square",
    "Process": "circle",
    "ExternalEntity": "square",
    "Datastore": "cylinder",
    "Server": "box",
}


def dot_string(text: str) -> str:
    """Escape text for a double-quoted DOT string."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def generate_dataflow(scenario: Scenario, components: dict[str, Component]) -> str:
    """Generate a Graphviz DOT diagram from scenario components and flows."""

    def slug(name: str) -> str:
        return re.sub(r"[^\w]", "_", name)

    def node_id(comp: Component) -> str:
        return f"{comp.component_class.lower()}_{slug(comp.name)}_{slug(comp.inBoundary or '')}"

    def wrap_label(text: str, width: int = 16) -> str:
        words, lines, current = text.split(), [], []
        for w in words:
            if current and sum(len(x) for x in current) + len(current) + len(w) > width:
                lines.append(" ".join(current))
                current = [w]
            else:
                current.append(w)
        if current:
            lines.append(" ".join(current))
        return "\\n".join(lines)

    boundaries = {
        name: comp
        for name, comp in components.items()
        if comp.component_class == "Boundary"
    }
    all_nodes = {
        name: comp
        for name, comp in components.items()
        if name in scenario.linked_component_names
        and comp.component_class != "Boundary"
    }
    # Filter out components not linked to any flow
    nodes = [
        node
        for name, node in all_nodes.items()
        if name in scenario.linked_component_names
    ]

    # Build boundary nesting tree
    boundary_children: dict = defaultdict(list)
    root_boundaries: list = []
    for name, b in boundaries.items():
        if b.inBoundary and b.inBoundary in boundaries:
            boundary_children[b.inBoundary].append(name)
        else:
            root_boundaries.append(name)

    nodes_by_boundary: dict = defaultdict(list)
    for n in nodes:
        nodes_by_boundary[n.inBoundary or ""].append(n)

    lines: list = []

    def emit_node(comp: Component, indent: str) -> None:
        _id = node_id(comp)
        shape = NODE_SHAPES.get(comp.component_class, "circle")
        label = wrap_label(dot_string(comp.name))
        lines.extend(
            [
                f"{indent}{_id} [",
                f"{indent}    shape = {shape};",
                f"{indent}    color = black;",
                f"{indent}    fontcolor = black;",
                f'{indent}    label = "{label}";',
                f'{indent}    URL = "component_{slug(comp.name)}.html";',
                f'{indent}    tooltip = "{dot_string(comp.name)}";',
                f"{indent}    margin = 0.02;",
                f"{indent}]",
                "",
            ]
        )

    def boundary_has_content(name: str) -> bool:
        if nodes_by_boundary.get(name):
            return True
        return any(
            boundary_has_content(child) for child in boundary_children.get(name, [])
        )

    def emit_boundary(name: str, indent: str = "    ") -> None:
        if not boundary_has_content(name):
            return
        lines.extend(
            [
                f"{indent}subgraph cluster_boundary_{slug(name)} {{",
                f"{indent}    graph [",
                f"{indent}        fontsize = {FONT_SIZE_BOUNDARY};",
                f"{indent}        fontcolor = black;",
                f"{indent}        style = dashed;",
                f"{indent}        color = firebrick2;",
                # Graphviz reads <...> as an HTML-like label (here, for the italics), so
                # the name is escaped as HTML.
                f"{indent}        label = <<i>{html.escape(name)}</i>>;",
                f"{indent}    ]",
                "",
            ]
        )
        for child in boundary_children.get(name, []):
            emit_boundary(child, indent + "    ")
        for comp in nodes_by_boundary.get(name, []):
            emit_node(comp, indent + "    ")
        lines.extend([f"{indent}}}", ""])

    lines.extend(
        [
            "digraph tm {",
            "    graph [",
            f"        fontname = {FONT_NAME};",
            f"        fontsize = {FONT_SIZE_GRAPH};",
            "    ]",
            "    node [",
            f"        fontname = {FONT_NAME};",
            f"        fontsize = {FONT_SIZE_NODE};",
            "    ]",
            "    edge [",
            f"        fontname = {FONT_NAME};",
            f"        fontsize = {FONT_SIZE_EDGE};",
            "    ]",
            "    nodesep = 1;",
            "",
        ]
    )

    for b_name in root_boundaries:
        emit_boundary(b_name)

    for component in nodes_by_boundary.get("", []):
        emit_node(component, "    ")

    name_to_id = {component.name: node_id(component) for component in nodes}

    for i, flow in enumerate(scenario.flows, 1):
        src = name_to_id.get(flow.source)
        snk = name_to_id.get(flow.sink)
        if src and snk:
            label = wrap_label(dot_string(f"{i}. {flow.name}"), width=20)
            lines.extend(
                [
                    (
                        f"    {src} -> {snk} ["
                        "        color = black;"
                        "        fontcolor = black;"
                        "        dir = forward;"
                        f'        label = "{label}";'
                        "    ]"
                        ""
                    )
                ]
            )

    lines.append("}")
    return "\n".join(lines)


def generate_highlighted_dataflow(dfd: str, highlight_components: set) -> str:
    """Modify a DOT graph string to highlight specific components by label."""
    if not highlight_components or not dfd:
        return dfd

    def highlighter(match):
        node_id = match.group(1)
        attrs = match.group(2)
        label_match = re.search(r'label\s*=\s*"((?:[^"\\]|\\.)*)"', attrs)
        # Undo dot_string(), and turn wrap_label()'s line breaks into spaces.
        label = (
            re.sub(
                r"\\(.)",
                lambda m: " " if m.group(1) == "n" else m.group(1),
                label_match.group(1),
            )
            if label_match
            else None
        )
        if label and label in highlight_components:
            indent_match = re.search(r"^(\s+)\S", attrs, re.MULTILINE)
            indent = indent_match.group(1) if indent_match else "        "
            stripped = attrs.rstrip()
            trailing = attrs[len(stripped) :]
            attrs = (
                f'{stripped}\n{indent}style = "filled";\n'
                f'{indent}fillcolor = "#c0392b";\n{indent}fontcolor = "white";\n'
                f'{indent}class = "highlighted";{trailing}'
            )
        return f"{node_id} [{attrs}]"

    pattern = re.compile(
        r"\b((?:\w+)_\w+)\s*\[([^\[\]]+)\]",
        re.DOTALL,
    )
    return pattern.sub(highlighter, dfd)


def generate_sequence(scenario: Scenario) -> str:
    if not scenario.flows:
        return ""

    def alias(name: str) -> str:
        return re.sub(r"[^\w]", "_", name)

    seen: set = set()
    participants: list = []
    for flow in scenario.flows:
        for name in (flow.source, flow.sink):
            if name not in seen:
                participants.append(name)
                seen.add(name)

    lines = ["sequenceDiagram"]
    for name in participants:
        lines.append(f"    participant {alias(name)} as {name}")
        lines.append(
            f"    link {alias(name)}: Component @ component_{alias(name)}.html"
        )
    lines.append("")
    for i, flow in enumerate(scenario.flows, 1):
        arrow = "-->>" if flow.is_response else "->>"
        lines.append(
            f"    {alias(flow.source)}{arrow}{alias(flow.sink)}: {i}. {flow.name}"
        )

    return "\n".join(lines)
