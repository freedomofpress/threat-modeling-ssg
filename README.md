# Rage Against Threat Modeling

_"Some of those that work forces,</br>
are the same that burn ~crosses~ 0-days"_

`ratm` is a tool that helps you think about your threat model, generating a static site and graphs that help you navigate them.

It takes its inspiration on [PyTM](https://github.com/OWASP/pytm), but simplifying how things work, by removing dependencies to Java utilities.

This tool actually came out as a way to do the threat modeling of [dangerzone](https://dangerzone.rocks).

## Run the demo

We include a short demo showcasing how to define components, threats, boundaries and scenarios. Here is how to generate a static site out of it:

```bash
uv run demo/model.py | uvx ratm
```

## Model format

A model is a Python script that uses the `Ratm` builders. `demo/model.py` is a commented example. The script prints a report, and `ratm` turns that report into the site.

**Properties** describe components (`tm.define_properties(...)`). A threat's `requirements` are expressions over them: `prop`, `!prop`, `prop.item`, `a == b`, `a != b`.

**Threats** (`tm.Threat(id, requirements=[...], ...)`):

| Field | Meaning |
|---|---|
| `mitigations` | ids of the mitigations in place |
| `further_mitigations` | ids of mitigations being considered |
| `status` | `unmanaged`, `accepted`, `transferred`, `mitigated`, `avoided`, `inform`, `partially mitigated`, or `out of scope`. The default is `unmanaged`. |
| `impact` | `Low` (1), `Medium` (2), or `High` (3) |
| `likelihood` | `Very Low` (1), `Low` (2), `Medium` (3), or `High` (4) |
| `residual_impact`, `residual_likelihood` | the values with the mitigations in place. They default to `impact` and `likelihood`. |
| `residual_risk` | a note on the risk that remains |
| `threat_actors` | names of threat actors registered with `tm.ThreatActor` |
| `children` | ids of smaller threats that make up this one |
| `capec_info`, `comment` | description and details. If `impact` or `likelihood` is not given, the CAPEC severity and likelihood are used instead. CAPEC's five severity levels are mapped onto the three impact levels. |

Risk is impact times likelihood. The status says how the team is handling the threat. Mitigations never remove a threat from the report. It is listed for every component that matches its requirements.

**Mitigations** (`tm.Mitigation(id, title=..., ...)`) have a `description` and a `status` (`implemented`, `optional`, or `proposed`). When a control is a component property, put it in the threat's requirements instead, for example `!encrypts_secrets`, so the threat applies only to components without it.

**Threat actors** (`tm.ThreatActor(name, description=...)`) must be registered before a threat can name them.

Generating the report fails with an error naming the problem when:

- a threat names an unknown mitigation, threat actor, or child threat, or lists itself as a child
- a status is not one of the values above
- an impact or likelihood is given but is not on its scale
- two threats, mitigations, or threat actors share an id or name

## Source links

Each threat, mitigation, threat actor, component, and scenario page shows the file and line of the model script that defines it, for example "Defined in demo/model.py:42". ratm records this when the model script creates the object. The path is relative to the git checkout that holds the script, or to the current directory when the script is not in a checkout. Failing both, it is just the file name.

To link those lines to the code, set `github_repo` in the site config to the repository the model script lives in, and `github_branch` if it is not `main`:

```toml
github_repo = "https://github.com/example/threat-model"
github_branch = "main"
```

`ratm` reads `config.toml` from the current directory, or the file passed with `--config`. A link then points to `<github_repo>/blob/<github_branch>/<file>#L<line>`. Without `github_repo`, the file and line are shown as plain text.
