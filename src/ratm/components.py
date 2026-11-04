import csv
import dataclasses
import functools
import hashlib
import pathlib
from dataclasses import dataclass


@functools.cache
def load_capec_db(capec_db_path: pathlib.Path):
    with capec_db_path.open() as opened:
        # Strip a stray single quote in the downloaded CSV
        csv_content = opened.read().lstrip("'").split("\n")

        reader = csv.DictReader(csv_content, dialect="unix")
        return {threat["ID"]: threat for threat in reader}


@dataclass
class Property:
    """Information about a component property."""

    name: str
    description: str = None
    default: object = None
    type: type = bool

    @classmethod
    def create_many(cls, *args):
        properties = []
        for arg in args:
            if isinstance(arg, str):
                properties.append(cls(arg))
            elif isinstance(arg, tuple):
                properties.append(cls(*arg))

        return properties

    def to_dict(self):
        default = self.default
        if self.type is bool and self.default is None:
            default = False

        return {
            "name": self.name,
            "description": self.description or "",
            "default": default,
            "type": self.type.__name__,
        }


@dataclass
class ComponentProperties:
    """Name/value pairs of properties."""

    def item_in_prop(self, prop: str, item: str):
        prop_value = getattr(self, prop)
        return item in prop_value
        # if not isinstance(prop_value, (tuple, list)):
        #     raise ValueError(f"Bad expression: {prop}")
        # return item in prop_value

    def prop_is_thruthy(self, prop: str):
        return bool(getattr(self, prop.strip()))

    def props_are_equal(self, prop_left: str, prop_right: str):
        return getattr(self, prop_left.strip()) == getattr(self, prop_right.strip())

    def matches(self, expr: str):
        if expr.startswith("!"):
            # Check if the component property is missing, False, or empty list.
            prop = expr.removeprefix("!")
            return not self.prop_is_thruthy(prop)
        elif "==" in expr:
            (prop_left, prop_right) = expr.split("==", 1)
            return self.props_are_equal(prop_left, prop_right)
        elif "!=" in expr:
            (prop_left, prop_right) = expr.split("!=", 1)
            return not self.props_are_equal(prop_left, prop_right)
        elif "." in expr:
            (prop, item) = expr.split(".", 1)
            return self.item_in_prop(prop, item)
        else:
            return self.prop_is_thruthy(expr)

    def to_nondefault_dict(self):
        """Get only the non-default properties in dict format."""
        uniq = {}
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if value == field.default:
                continue
            uniq[field.name] = value
        return uniq


@dataclass
class Component:
    """A component in the threat model that is neither and actor or boundary."""

    name: str
    # FIXME: Do we need it?
    # id: str = None
    description: str = None
    boundary: "Boundary" = None
    properties: ComponentProperties = None
    type: str = "Component"

    def with_properties(
        self, component_properties_cls=ComponentProperties, **properties
    ):
        self.properties = component_properties_cls(**properties)
        return self

    @property
    def combined_properties(self):
        """Present a unified view of the component's and boundary's properties.

        The inheritance logic is the following:
        1. If the component is in a boundary, the boundary properties are the
           base ones.
           - If the boundary does not have properties, ignore it.
        2. If the component has non-default properties, these take precedence
           over the boundary ones.
        """
        if self.type == "Boundary":
            return self.properties

        boundary_properties = None if not self.boundary else self.boundary.properties

        if not boundary_properties:
            return self.properties

        changes = self.properties.to_nondefault_dict()
        return dataclasses.replace(boundary_properties, **changes)

    def matches(self, expr: str):
        combined = self.combined_properties
        if combined:
            return combined.matches(expr)

    def to_dict(self):
        return {
            "class": self.type,
            "description": self.description or "",
            "in_boundary": self.boundary.name if self.boundary else None,
            "name": self.name,
            "properties": self.combined_properties.to_nondefault_dict(),
        }


@dataclass
class Actor(Component):
    "An entity which takes decisions and initiates actions."

    type: str = "Actor"


@dataclass
class Boundary(Component):
    """A boundary which may contain components, actors, or other boundaries."""

    type: str = "Boundary"


@dataclass
class Dataflow:
    """A connection between two components."""

    name: str
    source: Component | None
    sink: Component | None
    id: str = None
    is_response: bool = False
    response_to: "Dataflow" = None
    data: Component = None
    description: str | None = None
    labels: list[str] | None = None

    def __post_init__(self):
        if self.id is None:
            self.id = hashlib.sha256(self.name.encode()).hexdigest()

    def to_dict(self):
        if isinstance(self.data, Component):
            data = [self.data]
        elif not self.data:
            data = []
        else:
            data = self.data

        return {
            # FIXME: Improve this dictionary.
            "id": self.id,
            "name": self.name,
            "description": self.description or "",
            "source": self.source.name if self.source else None,
            "sink": self.sink.name if self.sink else None,
            "is_response": self.is_response,
            "response_to": self.response_to.name if self.response_to else None,
            "data": sorted({d.name for d in data}),
        }

    def iter_components(self):
        if self.sink:
            yield self.sink
        if self.source:
            yield self.source
        if self.data:
            if isinstance(self.data, list):
                yield from self.data
            else:
                yield self.data


@dataclass
class CAPECInfo:
    """CAPEC information for a threat."""

    description: str
    likelihood: str = None
    details: str = None
    severity: str = None
    example: str = None
    prerequisites: str = None
    mitigations: str = None
    # FIXME: Should this become a list?
    references: str = None

    @classmethod
    def from_capec_entry(cls, entry: dict):
        capec_id = entry["ID"]
        reference = f"https://capec.mitre.org/data/definitions/{capec_id}.html"
        return cls(
            description=entry["Name"],
            likelihood=entry["Likelihood Of Attack"],
            details=entry["Description"],
            severity=entry["Typical Severity"],
            prerequisites=entry["Prerequisites"].strip(":"),
            mitigations=entry["Mitigations"].strip(":"),
            example=entry["Example Instances"].strip(":"),
            references=reference,
        )

    def to_dict(self):
        info = dataclasses.asdict(self)
        return {k: v if v else "" for k, v in info.items()}


@dataclass
class Threat:
    """The requirements and mitigations for a threat, alongside its info."""

    id: str
    requirements: list[str]
    mitigations: list[str]
    capec_info: CAPECInfo = None
    comment: str = None

    def populate_capec_info(self, capec_db_path: str):
        capec_threats = load_capec_db(capec_db_path)
        capec_id = self.id.removeprefix("CAPEC-")
        if capec_id not in capec_threats:
            raise RuntimeError(
                "Could not retrieve information from CAPEC database"
                f" for CAPEC threat '{self.id}'"
            )
        entry = capec_threats[capec_id]
        self.capec_info = CAPECInfo.from_capec_entry(entry)

    def matches(self, component: Component):
        if not self.requirements:
            raise ValueError(f"Threat {self} does not have requirements")

        for req in self.requirements:
            if not component.matches(req):
                return False

        for mit in self.mitigations:
            if component.matches(mit):
                return False

        return True

    def to_dict(self):
        info = self.capec_info.to_dict() if self.capec_info else CAPECInfo("").to_dict()
        info["SID"] = self.id
        info["comment"] = self.comment or ""
        info["mapping"] = {}
        info["mapping"]["requirements"] = self.requirements
        info["mapping"]["mitigations"] = self.mitigations
        return info


@dataclass
class Finding:
    """An association between threat and component."""

    target: str
    threat_id: str


@dataclass
class Scenario:
    """A scenario that shows how components may interact with each other."""

    name: str
    dataflows: list[Dataflow] | None = None
    description: str = None
    findings: list[Finding] | None = None

    def copy_from_label(self, label, name, description=None):
        new_flows = []
        for flow in self.dataflows:
            if flow.labels and label in flow.labels:
                new_flows.append(flow)
        return self.__class__(name=name, dataflows=new_flows, description=description)

    def iter_components(self):
        """Iterate the components referenced by a scenario."""
        visited = set()
        for flow in self.dataflows:
            for component in flow.iter_components():
                if component.name not in visited:
                    yield component
                    visited.add(component.name)

    def populate_findings(self, threats: list[Threat]):
        findings = []
        components = list(self.iter_components())
        for threat in threats:
            for component in components:
                if threat.matches(component):
                    finding = Finding(threat_id=threat.id, target=component.name)
                    findings.append(finding)

        self.findings = findings

    def to_dict(self):
        return {
            # FIXME: Improve this dictionary
            "file": "",
            "description": self.description or "",
            "name": self.name,
            "flows": [f.to_dict() for f in self.dataflows],
            "findings": [dataclasses.asdict(f) for f in self.findings],
        }

    def Dataflow(self, dataflow_cls=Dataflow, *args, **kwargs):
        cur_id = len(self.dataflows or [])
        kwargs.setdefault("id", str(cur_id + 1))
        dataflow = dataflow_cls(*args, **kwargs)
        if self.dataflows is None:
            self.dataflows = [dataflow]
        else:
            self.dataflows.append(dataflow)
        return dataflow
