"""Risk Engine for institutional vulnerability prioritization.

The risk score combines:
  - CVSS v3 base score (the published severity of the vulnerability itself)
  - CISA KEV status (a +25 boost when the CVE is on the Known Exploited list)
  - Asset criticality (LOW=0, MEDIUM=10, HIGH=20, CRITICAL=30)
  - Internet exposure (an additional +15 if the asset is reachable from
    the public internet)

The combined score is a 0-100 number mapped to a label:

    >= 80   CRITICAL
    >= 60   HIGH
    >= 30   MEDIUM
    >= 10   LOW
    else    INFO

The function is intentionally pure: it takes a ``RiskInputs`` dataclass
and returns a ``RiskResult``. There is no I/O, no DB, no clock — so it
is trivially testable and we can rely on it everywhere (sync jobs, scan
completion, API handlers) without mocking.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
class AssetCriticality:
    """Allowed criticality levels. Stored as a constant rather than an
    Enum so the scorer stays dependency-free and easy to call from
    background jobs."""

    LOW: Final = "LOW"
    MEDIUM: Final = "MEDIUM"
    HIGH: Final = "HIGH"
    CRITICAL: Final = "CRITICAL"

    ALL: Final = (LOW, MEDIUM, HIGH, CRITICAL)


_CRITICALITY_WEIGHT: Final[dict[str, int]] = {
    AssetCriticality.LOW: 0,
    AssetCriticality.MEDIUM: 10,
    AssetCriticality.HIGH: 20,
    AssetCriticality.CRITICAL: 30,
}

# KEV boost — being on the Known Exploited Vulnerabilities catalog means
# there is active exploitation in the wild. This is the single largest
# driver of "patch this now" so we give it meaningful weight.
KEV_BOOST: Final = 25

# Internet exposure boost — public-facing assets are an order of magnitude
# more likely to be probed. Capped at +15 so a high CVSS on an internal
# asset still scores higher than a low CVSS on an exposed one.
INTERNET_EXPOSURE_BOOST: Final = 15

# CVSS v3 max is 10.0; we multiply by 10 so a 9.8 CVSS becomes 98 points
# in the base contribution. This keeps the base term on the same 0-100
# scale as everything else.
CVSS_MULTIPLIER: Final = 10.0

# Score is clamped to [0, 100] so a single bug cannot push it above 100
# even with every factor maxed.
SCORE_MIN: Final = 0
SCORE_MAX: Final = 100

# Label thresholds, sorted high-to-low.
_LABEL_THRESHOLDS: Final[tuple[tuple[int, str], ...]] = (
    (80, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (10, "LOW"),
)


@dataclass(frozen=True)
class RiskInputs:
    """Everything the scorer needs to produce a risk number.

    ``cvss_v3`` is the published CVSS v3 base score (0.0 - 10.0) or
    ``None`` when the upstream feed did not include one.
    ``in_kev`` is true when the CVE appears on the CISA Known Exploited
    Vulnerabilities catalog.
    ``asset_criticality`` is one of LOW / MEDIUM / HIGH / CRITICAL. An
    unknown value falls back to LOW to keep the score conservative.
    ``internet_exposed`` is true when the asset is reachable from the
    public internet (no VPN, no IP allowlist).
    """

    cvss_v3: float | None
    in_kev: bool
    asset_criticality: str
    internet_exposed: bool


@dataclass(frozen=True)
class RiskResult:
    """The scorer's output: a numeric score plus a human label.

    ``contributions`` is a debug-friendly dict that names each input's
    contribution. We persist it (when available) so a security analyst
    can answer "why is this scored CRITICAL?" without re-running the
    formula by hand.
    """

    score: int
    label: str
    contributions: dict[str, int]


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------
def _cvss_term(cvss_v3: float | None) -> int:
    """CVSS contributes up to 100 points (10.0 CVSS * 10). Missing or
    out-of-range CVSS becomes 0 — we never invent a score."""
    if cvss_v3 is None:
        return 0
    try:
        v = float(cvss_v3)
    except (TypeError, ValueError):
        return 0
    if v <= 0:
        return 0
    if v >= 10.0:
        return int(10.0 * CVSS_MULTIPLIER)
    return int(v * CVSS_MULTIPLIER)


def _criticality_term(asset_criticality: str) -> int:
    """Unknown criticality defaults to LOW so an unscored asset does
    not silently inflate the score."""
    return _CRITICALITY_WEIGHT.get(asset_criticality, 0)


def _label_for(score: int) -> str:
    """Map a 0-100 score to a label. The threshold list is sorted
    high-to-low so the first match wins."""
    for threshold, label in _LABEL_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFO"


def score(inputs: RiskInputs) -> RiskResult:
    """Compute the institutional risk score for one (CVE, asset) pair.

    Example:
        >>> score(RiskInputs(cvss_v3=9.8, in_kev=True,
        ...                  asset_criticality="HIGH",
        ...                  internet_exposed=True))
        RiskResult(score=100, label='CRITICAL',
                   contributions={'cvss': 98, 'kev': 25,
                                  'criticality': 20, 'exposure': 15})
    """
    cvss_term = _cvss_term(inputs.cvss_v3)
    kev_term = KEV_BOOST if inputs.in_kev else 0
    crit_term = _criticality_term(inputs.asset_criticality)
    exposure_term = INTERNET_EXPOSURE_BOOST if inputs.internet_exposed else 0

    raw = cvss_term + kev_term + crit_term + exposure_term
    clamped = max(SCORE_MIN, min(SCORE_MAX, raw))

    return RiskResult(
        score=clamped,
        label=_label_for(clamped),
        contributions={
            "cvss": cvss_term,
            "kev": kev_term,
            "criticality": crit_term,
            "exposure": exposure_term,
        },
    )


def is_valid_criticality(value: str) -> bool:
    """Return True if ``value`` is one of the known criticality levels.
    Used by API schemas to validate user input without coupling to the
    scorer internals."""
    return value in AssetCriticality.ALL
