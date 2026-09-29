"""Status names and risk scales shared by the model code and the site generator.

Labels must match exactly. A misspelled label is an error, not a guess. Scores are
worked out from the labels when needed and are not written to the report JSON.
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

# CAPEC's "Typical Severity" has five levels. Map them onto the three impact levels so
# threats taken from CAPEC need no manual relabelling.
CAPEC_SEVERITY_TO_IMPACT = {
    "Very Low": "Low",
    "Low": "Low",
    "Medium": "Medium",
    "High": "High",
    "Very High": "High",
}


def risk_score(impact: str | None, likelihood: str | None) -> int | None:
    """Return impact score times likelihood score.

    Return None if either label is not on its scale.
    """
    if impact not in IMPACT_SCORES or likelihood not in LIKELIHOOD_SCORES:
        return None
    return IMPACT_SCORES[impact] * LIKELIHOOD_SCORES[likelihood]
