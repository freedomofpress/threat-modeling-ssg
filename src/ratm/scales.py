"""Vocabularies shared by the authoring layer and the static site generator.

Labels are matched exactly. The tool never guesses at a misspelled label. Scores are
computed from labels on demand and never serialised in the report.
"""

THREAT_STATUSES = (
    "unmanaged",
    "accepted",
    "transferred",
    "mitigated",
    "avoided",
    "inform",
    "partially mitigated",
    "out of scope",
)
DEFAULT_THREAT_STATUS = "unmanaged"

MITIGATION_STATUSES = ("implemented", "optional", "proposed")
DEFAULT_MITIGATION_STATUS = "implemented"

IMPACT_SCORES = {"Low": 1, "Medium": 2, "High": 3}
LIKELIHOOD_SCORES = {"Very Low": 1, "Low": 2, "Medium": 3, "High": 4}

UNKNOWN = "Unknown"
IMPACT_ORDER = ("High", "Medium", "Low", UNKNOWN)

# CAPEC's "Typical Severity" has five levels. Clamp it onto the three-level impact scale
# so CAPEC-sourced threats need no manual relabelling.
CAPEC_SEVERITY_TO_IMPACT = {
    "Very Low": "Low",
    "Low": "Low",
    "Medium": "Medium",
    "High": "High",
    "Very High": "High",
}


def risk_score(impact: str | None, likelihood: str | None) -> int | None:
    """Impact score times likelihood score, or None if either label is unknown."""
    if impact not in IMPACT_SCORES or likelihood not in LIKELIHOOD_SCORES:
        return None
    return IMPACT_SCORES[impact] * LIKELIHOOD_SCORES[likelihood]
