from ratm import Ratm
from ratm.components import CAPECInfo, Scenario

# [ Demo threat model ]
# ------------------------------------------------------------
# Exemple usage of ratm, describing its very own threat model.
# This is a simplistic example to showcase how the tool works
# and what can be accomplished with it.
#
# RATM is a tool that:
#
# - Let developers use python to define their threat model
# - Compiles the threat model and publishes it on a static site generator
# ------------------------------------------------------------

# create a threat model object that will be used afterwards
tm = Ratm(load_capec_info=False)

# A list of properties: (name, description, default, type)
tm.define_properties(
    ("loads_resources", "Loads resources external to the program.", (), tuple),
    ("verifies_resources", "Verifies the resources before use.", (), tuple),
    ("uses_network", "The component uses the network stack"),
    ("is_exposed", "The component is considered exposed to the attacker"),
    ("is_physical", "The component is a physical one"),
    ("requires_credentials", "The component requires credentials to connect"),
    (
        "uses_strong_credentials",
        "The credentials are strong (2FA with OTP, certificates)",
    ),
    ("publishes_code", "The component publishes code"),
    ("stores_secrets", "The component keeps secrets (tokens, keys) at rest"),
    ("encrypts_secrets", "The secrets at rest are encrypted"),
    ("executes_code", "The component runs code it did not author itself"),
)


# -- Mitigations
#
# Each mitigation is its own object with an id, a title, and a status: "implemented",
# "optional", or "proposed".
#
# When a control is a component property, put it in the threat's requirements instead,
# as RATM-3-SECRETS does with "!encrypts_secrets". The threat then applies only to
# components without the control.

tm.Mitigation(
    "MIT-VERIFY-DEPS",
    title="Pin and hash-check dependencies",
    description="Lockfiles with hashes make the registry unable to swap a package.",
)
tm.Mitigation(
    "MIT-STRONG-CREDS",
    title="Hardware-backed or short-lived credentials",
)
tm.Mitigation(
    "MIT-ENCRYPT-SECRETS",
    title="Encrypt tokens at rest",
    status="proposed",
)
tm.Mitigation(
    "MIT-VERIFY-SOURCE",
    title="Verify the origin of executed code",
    status="proposed",
)
tm.Mitigation(
    "MIT-CSP",
    title="Content Security Policy on the report",
    description="Restricts what the vendored scripts may load or connect to.",
    status="optional",
)

# -- Threat actors
#
# Each threat lists its actors by name. A name that was not registered with
# tm.ThreatActor fails the build.

tm.ThreatActor(
    "Registry impersonator",
    description="Whoever can answer for PyPI or NPM: a MITM or a compromised mirror.",
)
tm.ThreatActor(
    "Malicious maintainer",
    description="Someone with publish rights on a dependency.",
)
tm.ThreatActor("Any", description="No particular capability required.")

# -- Threats
#
# You can define your own threats, naming them and providing:
#
# - a list of requirements, that need to be true for this threat to apply
# - a list of mitigation ids that are in place, and optionally `further_mitigations`
#   that are being considered
# - a `status`: unmanaged, accepted, transferred, mitigated, avoided, inform, partially
#   mitigated, or out of scope. The status says how the threat is handled. Mitigations
#   never remove a threat from the report. It is listed for every component that matches
#   its requirements.
# - `impact` (Low, Medium, or High) and `likelihood` (Very Low, Low, Medium, or High).
#   Risk is impact times likelihood. `residual_impact` and `residual_likelihood` give
#   the values with the mitigations in place, and `residual_risk` explains what is left.
# - `threat_actors`, and `children` listing smaller threats that make up this one.
#
# Threats which are not CAPEC ones can carry their own description and details for the
# report to display. When `impact` or `likelihood` is not given, the CAPEC severity and
# likelihood are used instead.

# In this example, we use sub-resources, using the dot separator.
tm.Threat(
    "RATM-1-DEPS",
    requirements=["loads_resources.deps"],
    mitigations=["MIT-VERIFY-DEPS"],
    status="partially mitigated",
    impact="High",
    likelihood="Medium",
    residual_likelihood="Low",
    residual_risk="The ratm package itself still installs its npm assets unpinned.",
    threat_actors=["Registry impersonator", "Malicious maintainer"],
    comment="Check that every component that explicitly loads packages verify them",
    capec_info=CAPECInfo(
        description="Unverified dependencies",
        details=(
            "A component installing packages without checking their integrity"
            " runs whatever the registry (or someone impersonating it) serves."
        ),
    ),
)

# Requirements can compare two properties with == and !=.
tm.Threat(
    "RATM-2-WEAKCREDS",
    requirements=["requires_credentials != uses_strong_credentials"],
    mitigations=["MIT-STRONG-CREDS"],
    status="inform",
    impact="Medium",
    likelihood="Low",
    threat_actors=["Any"],
    comment="Anything asking for credentials should ask for strong ones",
    capec_info=CAPECInfo(
        description="Weak credentials on an authenticated component",
        details=(
            "Credentials that are neither hardware-backed nor short-lived can be"
            " replayed by whoever gets a copy of them."
        ),
    ),
)

# Requirements can also be negated, with a leading "!".
tm.Threat(
    "RATM-3-SECRETS",
    requirements=["stores_secrets", "!encrypts_secrets"],
    further_mitigations=["MIT-ENCRYPT-SECRETS"],
    status="accepted",
    impact="High",
    likelihood="Low",
    residual_risk="Accepted until the token can be scoped to a single project.",
    threat_actors=["Any"],
    comment="Secrets kept on disk should not be readable as-is",
    capec_info=CAPECInfo(
        description="Secrets stored unencrypted",
        details=(
            "A publishing token written in cleartext can be read by any process"
            " running as the same user."
        ),
    ),
)

tm.Threat(
    "RATM-4-EXEC",
    requirements=["executes_code"],
    mitigations=["MIT-CSP"],
    further_mitigations=["MIT-VERIFY-SOURCE"],
    status="unmanaged",
    impact="High",
    likelihood="Medium",
    threat_actors=["Malicious maintainer"],
    children=["RATM-1-DEPS"],
    comment="Running someone else's code means trusting where it came from",
    capec_info=CAPECInfo(
        description="Execution of unverified code",
        details=(
            "Both the generator and the browser rendering the report end up"
            " executing code nobody reviewed at that point."
        ),
    ),
)


# -- Boundaries

THE_INTERNET = tm.Boundary(
    name="Internet",
    # Define your own properties here
    uses_network=True,
    is_exposed=True,
)

DEV_HOST = tm.Boundary(
    name="Dev host",
    uses_network=True,
    is_physical=True,
)

USER_HOST = tm.Boundary(
    name="User host",
    # You can define an array of resources loaded by a boundary
    loads_resources=["system", "files"],
)

# -- Actors

USER = tm.Actor(
    name="User",
    description="Someone reading a published threat model report.",
    boundary=USER_HOST,
)
DEV = tm.Actor(
    name="Developer",
    description="The person writing the model and publishing the report.",
    boundary=DEV_HOST,
)

# -- Components

DEV_MACHINE = tm.Component(
    name="Dev machine",
    description="The laptop where the model is written, built and published from.",
    is_physical=True,
    boundary=DEV_HOST,
    # The publishing token lives here, in cleartext.
    stores_secrets=True,
    executes_code=True,
)

BROWSER = tm.Component(
    name="Browser of the visitor of the threat model",
    description="Renders the generated report, diagrams included.",
    boundary=USER_HOST,
    uses_network=True,
    # The report ships mermaid and viz-js, and runs them on model-authored strings.
    executes_code=True,
)

PYPI = tm.Component(
    name="PyPI servers",
    description="Where the ratm package is released.",
    boundary=THE_INTERNET,
    requires_credentials=True,
    uses_strong_credentials=True,
    publishes_code=True,
)

NPM = tm.Component(
    name="NPM servers",
    description="Where the vendored JavaScript dependencies come from.",
    boundary=THE_INTERNET,
    requires_credentials=True,
    uses_strong_credentials=True,
    publishes_code=True,
)

RATM_PACKAGE = tm.Component(
    name="ratm python package",
    description="The ratm distribution, vendoring its JavaScript assets.",
    boundary=DEV_HOST,
    loads_resources=["deps"],
)

MODEL_SCRIPT = tm.Component(
    name="Threat model script",
    description="The model.py describing the system under study.",
    boundary=DEV_HOST,
    # Its dependencies are pinned and hash-checked by uv.lock, unlike the ones above.
    loads_resources=["deps"],
    verifies_resources=["deps"],
)

GENERATED_REPORT = tm.Component(
    name="Generated report",
    description="The static site written to output/, before it gets published.",
    boundary=DEV_HOST,
)

PAGES = tm.Component(
    name="Static site host",
    description="Serves the published report to anyone with the URL.",
    boundary=THE_INTERNET,
    requires_credentials=True,
    is_exposed=True,
)

# -- Scenarios
# 1. Publishing to PyPI servers (building npm packages)
# 2. Authoring a model and generating the report locally
# 3. Publishing the generated report and having it read

release = Scenario(name="Release", description="Build and release the ratm package")

release.Dataflow(
    name="Kick off release build",
    description="A dev decides to build and release",
    source=DEV,
    sink=DEV_MACHINE,
)

release.Dataflow(
    name="Gather JS deps",
    description="Get JavaScript dependencies from NPM",
    source=DEV_MACHINE,
    sink=NPM,
)

release.Dataflow(
    name="Gather python deps",
    description="Get python dependencies from PyPI",
    source=DEV_MACHINE,
    sink=PYPI,
)
release.Dataflow(
    name="Vendorize JS deps",
    description="Vendorize the JS dependencies in the python package",
    source=DEV_MACHINE,
    sink=RATM_PACKAGE,
)

release.Dataflow(
    name="Publish on PyPI",
    description="Publish the local package on PyPI",
    source=RATM_PACKAGE,
    sink=PYPI,
)

authoring = Scenario(
    name="Authoring the model",
    description="Describe a system in python and render it locally",
)

authoring.Dataflow(
    name="Write the threat model",
    description="The dev describes components, threats and scenarios",
    source=DEV,
    sink=MODEL_SCRIPT,
)

run_model = authoring.Dataflow(
    name="Run the model script",
    description="`uv run demo/model.py` executes the model as plain python",
    source=DEV_MACHINE,
    sink=MODEL_SCRIPT,
)

# A flow can be marked as the response to another one: the sequence diagram
# then draws it as a return arrow.
authoring.Dataflow(
    name="Emit the JSON report",
    description="The script prints the compiled model on stdout",
    source=MODEL_SCRIPT,
    sink=DEV_MACHINE,
    is_response=True,
    response_to=run_model,
)

authoring.Dataflow(
    name="Generate the static site",
    description="The JSON report is piped into ratm",
    source=DEV_MACHINE,
    sink=RATM_PACKAGE,
)

authoring.Dataflow(
    name="Write the report files",
    description="Templates and vendored assets are rendered to output/",
    source=RATM_PACKAGE,
    sink=GENERATED_REPORT,
)

publishing = Scenario(
    name="Publishing the report",
    description="Push the generated report online and have someone read it",
)

publishing.Dataflow(
    name="Trigger the publication",
    description="The dev decides the report is ready to be shared",
    source=DEV,
    sink=DEV_MACHINE,
)

upload = publishing.Dataflow(
    name="Upload the generated site",
    description="The report files are pushed to the hosting platform",
    source=GENERATED_REPORT,
    sink=PAGES,
)

publishing.Dataflow(
    name="Deployment status",
    description="The host reports whether the deployment succeeded",
    source=PAGES,
    sink=DEV_MACHINE,
    is_response=True,
    response_to=upload,
)

publishing.Dataflow(
    name="Open the report URL",
    description="A reader follows a link to the published model",
    source=USER,
    sink=BROWSER,
)

fetch = publishing.Dataflow(
    name="Fetch the report",
    description="The browser requests the published pages and assets",
    source=BROWSER,
    sink=PAGES,
)

publishing.Dataflow(
    name="Serve the report",
    description="HTML, diagrams and the vendored JS bundles are served back",
    source=PAGES,
    sink=BROWSER,
    is_response=True,
    response_to=fetch,
)

# And finally, your scenarios

if __name__ == "__main__":
    report = tm.Report(
        [
            release,
            authoring,
            publishing,
        ]
    )
    out = report.generate()
    import json

    print(json.dumps(out, indent=4, sort_keys=True))
