import dataclasses

from . import components, report


class Ratm:
    component_cls = components.Component
    property_cls = components.Property
    report_cls = report.Report
    component_properties_cls = components.ComponentProperties
    threat_cls = components.Threat
    mitigation_cls = components.Mitigation
    threat_actor_cls = components.ThreatActor

    def __init__(
        self,
        component_cls=component_cls,
        property_cls=property_cls,
        report_cls=report_cls,
        component_properties_cls=component_properties_cls,
        threat_cls=threat_cls,
        load_capec_info=False,
        capec_db_path=None,
    ):
        self.component_cls = component_cls
        self.property_cls = property_cls
        self.report_cls = report_cls
        self.properties = {}
        self.components = {}
        self.threats = {}
        self.mitigations = {}
        self.threat_actors = {}
        self.component_properties_cls = components.ComponentProperties
        self.load_capec_info = load_capec_info
        self.capec_db_path = capec_db_path

    def recreate_component_properties_cls(self):
        fields = []
        for prop in self.properties.values():
            fields.append(
                (prop.name, prop.type, dataclasses.field(default=prop.default))
            )
        self.component_properties_cls = dataclasses.make_dataclass(
            "_ComponentPropertiesGenerated",
            fields,
            bases=(components.ComponentProperties,),
        )

    def Property(self, *args, **kwargs):
        """Property builder."""
        if self.components:
            raise RuntimeError(
                "You must define all the component properties first, before"
                " creating new components"
            )

        prop = self.property_cls(*args, **kwargs)
        self.properties[prop.name] = prop
        self.recreate_component_properties_cls()

        return prop

    def Component(self, component_cls=None, *args, **kwargs):
        """Component builder."""
        if component_cls is None:
            component_cls = self.component_cls

        fields = dataclasses.fields(self.component_properties_cls)
        fields_set = {f.name for f in fields}
        kwargs_set = {key for key in kwargs}
        props_set = kwargs_set & fields_set
        props = {name: kwargs.pop(name) for name in props_set}

        component = component_cls(*args, **kwargs).with_properties(
            self.component_properties_cls, **props
        )
        if component.name in self.components:
            raise ValueError(
                f"A component with name {component.name} is already registered"
            )
        self.components[component.name] = component

        return component

    def Actor(self, *args, **kwargs):
        return self.Component(components.Actor, *args, **kwargs)

    def Boundary(self, *args, **kwargs):
        return self.Component(components.Boundary, *args, **kwargs)

    def define_properties(self, *prop_args):
        props = []
        for prop_arg in prop_args:
            if isinstance(prop_arg, str):
                prop = self.Property(prop_arg)
            else:
                prop = self.Property(*prop_arg)
            props.append(prop)
        return props

    def populate_capec_info(self, threat, capec_db_path: str):
        if threat.capec_info:
            # This threat somehow already has CAPEC info, skipping it...
            return
        if not threat.id.startswith("CAPEC-"):
            # This threat is a custom one, skipping it...
            return
        threat.populate_capec_info(capec_db_path)

    def Threat(self, *args, **kwargs):
        threat = self.threat_cls(*args, **kwargs)
        if threat.id in self.threats:
            raise ValueError(f"A threat with id {threat.id} is already registered")
        self.threats[threat.id] = threat

        if self.load_capec_info:
            self.populate_capec_info(threat, self.capec_db_path)

        return threat

    def Mitigation(self, *args, **kwargs):
        mitigation = self.mitigation_cls(*args, **kwargs)
        if mitigation.id in self.mitigations:
            raise ValueError(
                f"A mitigation with id {mitigation.id} is already registered"
            )
        self.mitigations[mitigation.id] = mitigation
        return mitigation

    def ThreatActor(self, *args, **kwargs):
        actor = self.threat_actor_cls(*args, **kwargs)
        if actor.name in self.threat_actors:
            raise ValueError(
                f"A threat actor with name {actor.name} is already registered"
            )
        self.threat_actors[actor.name] = actor
        return actor

    def Report(self, scenarios: list[components.Scenario]):
        return report.Report(
            scenarios=scenarios,
            components=self.components.values(),
            threats=self.threats.values(),
            properties=self.properties.values(),
            mitigations=self.mitigations.values(),
            threat_actors=self.threat_actors.values(),
        )
