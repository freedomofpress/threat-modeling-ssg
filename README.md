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

A model is a Python script using the `Ratm` builders. `demo/model.py` is a commented walkthrough. The report it prints is what `ratm` renders.

**Properties** describe components (`tm.define_properties(...)`). A threat's `requirements` are expressions over them: `prop`, `!prop`, `prop.item`, `a == b`, `a != b`.

**Threats** (`tm.Threat(id, requirements=[...], ...)`):

| Field | Meaning |
|---|---|
| `mitigations` | ids of the mitigations in place |
| `further_mitigations` | ids of mitigations being considered |
| `status` | `unmanaged`, `accepted`, `transferred`, `mitigated`, `avoided`, `inform`, `partially mitigated`, `out of scope` (default `unmanaged`) |
| `impact` | `Low` (1), `Medium` (2), `High` (3) |
| `likelihood` | `Very Low` (1), `Low` (2), `Medium` (3), `High` (4) |
| `residual_impact`, `residual_likelihood` | values once mitigations are applied, defaulting to the base ones |
| `residual_risk` | free-text note on what remains |
| `threat_actors` | names of registered threat actors |
| `children` | ids of threats this one decomposes into |
| `capec_info`, `comment` | description and details. CAPEC severity and likelihood fill `impact` / `likelihood` when those are not given |

Risk is impact times likelihood. The status is authoritative. A threat is reported for every component matching its requirements, and the status says how the team is handling it.

**Mitigations** (`tm.Mitigation(id, title=..., ...)`): `description`, `status` (`implemented`, `optional`, `proposed`), and an optional `property` expression. When `property` is set, the report shows per component whether the mitigation is in place.

**Threat actors** (`tm.ThreatActor(name, description=...)`) are a controlled vocabulary. A threat naming an unknown actor fails the build, as does an unknown mitigation or child id, an invalid label, or a duplicate id.

