"""Status names and risk scales shared by the model code and the site generator.

Labels must match exactly. A misspelled label is an error, not a guess. Scores are
worked out from the labels when needed and are not written to the report JSON.
"""

import re

# Dictionary insertion order puts statuses most in need of attention first.
THREAT_STATUSES = {
    "unmanaged": "No decision has been made about this threat yet.",
    "partially mitigated": "Some controls are in place, but the risk is still too high.",
    "accepted": "The team has decided to live with this risk.",
    "transferred": "Someone else handles this risk, such as an upstream project.",
    "inform": "Handled by telling users how to protect themselves.",
    "avoided": "The feature that caused the risk was left out or removed.",
    "mitigated": "Controls in place bring the risk down to an acceptable level.",
    "out of scope": "Outside what this threat model covers.",
}
DEFAULT_THREAT_STATUS = "unmanaged"

# Statuses that still need work. The site ranks and counts these as open risk.
OPEN_STATUSES = ("unmanaged", "partially mitigated")

MITIGATION_STATUSES = {
    "implemented": "In place.",
    "optional": "Available, but it has to be turned on or chosen.",
    "proposed": "Not in place yet. Being considered.",
}
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


# Score ranges for the low, medium, and high risk levels. The only possible scores are
# 1, 2, 3, 4, 6, 8, 9, and 12.
RISK_BANDS = (("low", 1, 3), ("medium", 4, 6), ("high", 8, 12))


def risk_band(score: int | None) -> str | None:
    """Return "low", "medium", or "high" for a risk score, or None if unknown."""
    if score is None:
        return None
    for name, low, high in RISK_BANDS:
        if low <= score <= high:
            return name
    return None


def natural_key(value: str) -> tuple:
    """Sort key that orders the numbers inside ids by value, so MITIG2 < MITIG10."""
    pairs = tuple(
        (text, int(digits) if digits else -1)
        for text, digits in re.findall(r"(\D*)(\d*)", value)
        if text or digits
    )
    # "a01" and "a1" have the same numbers, so fall back to the id text to keep their
    # order fixed.
    return pairs, value
