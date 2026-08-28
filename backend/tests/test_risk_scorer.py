"""Unit tests for the Risk Engine scorer.

The scorer is a pure function; these tests cover every factor at min/max
and the boundary cases between label buckets. If any of these break, the
institutional risk math has changed — that is a deliberate event, not
something to fix silently.
"""

from __future__ import annotations

import pytest

from app.services.risk import (
    AssetCriticality,
    RiskInputs,
    is_valid_criticality,
    score,
)
from app.services.risk.scorer import (
    CVSS_MULTIPLIER,
    INTERNET_EXPOSURE_BOOST,
    KEV_BOOST,
    SCORE_MAX,
    _CRITICALITY_WEIGHT,
)


# ---------------------------------------------------------------------------
# CVSS term
# ---------------------------------------------------------------------------
def test_no_cvss_yields_zero_base():
    r = score(RiskInputs(None, False, AssetCriticality.LOW, False))
    assert r.contributions["cvss"] == 0


def test_zero_cvss_yields_zero_base():
    r = score(RiskInputs(0.0, False, AssetCriticality.LOW, False))
    assert r.contributions["cvss"] == 0


def test_max_cvss_yields_hundred_base():
    r = score(RiskInputs(10.0, False, AssetCriticality.LOW, False))
    assert r.contributions["cvss"] == int(10.0 * CVSS_MULTIPLIER)


def test_above_max_cvss_clamped_to_hundred_base():
    # Defensive: a corrupt CVSS value of 11.0 should not produce a 110
    # point base contribution. The scorer clamps at 10.0 worth of points.
    r = score(RiskInputs(11.0, False, AssetCriticality.LOW, False))
    assert r.contributions["cvss"] == int(10.0 * CVSS_MULTIPLIER)


def test_cvss_9_8_typical_critical():
    r = score(RiskInputs(9.8, False, AssetCriticality.LOW, False))
    assert r.contributions["cvss"] == 98


def test_string_cvss_is_parsed():
    # Some upstream feeds return CVSS as a string. We tolerate that.
    r = score(RiskInputs("7.5", False, AssetCriticality.LOW, False))
    assert r.contributions["cvss"] == 75


def test_garbage_cvss_falls_back_to_zero():
    r = score(RiskInputs("not a number", False, AssetCriticality.LOW, False))
    assert r.contributions["cvss"] == 0


# ---------------------------------------------------------------------------
# KEV
# ---------------------------------------------------------------------------
def test_kev_boost_only_when_true():
    on = score(RiskInputs(0.0, True, AssetCriticality.LOW, False))
    off = score(RiskInputs(0.0, False, AssetCriticality.LOW, False))
    assert on.contributions["kev"] == KEV_BOOST
    assert off.contributions["kev"] == 0


# ---------------------------------------------------------------------------
# Criticality
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "level,expected",
    [
        (AssetCriticality.LOW, 0),
        (AssetCriticality.MEDIUM, 10),
        (AssetCriticality.HIGH, 20),
        (AssetCriticality.CRITICAL, 30),
    ],
)
def test_criticality_weights(level, expected):
    r = score(RiskInputs(None, False, level, False))
    assert r.contributions["criticality"] == expected
    # And the table is internally consistent with the constants.
    assert _CRITICALITY_WEIGHT[level] == expected


def test_unknown_criticality_treated_as_low():
    r = score(RiskInputs(None, False, "MEGA-IMPORTANT", False))
    assert r.contributions["criticality"] == 0


def test_is_valid_criticality_round_trip():
    for level in AssetCriticality.ALL:
        assert is_valid_criticality(level)
    assert not is_valid_criticality("URGENT")
    assert not is_valid_criticality("")
    assert not is_valid_criticality("low")  # case-sensitive on purpose


# ---------------------------------------------------------------------------
# Exposure
# ---------------------------------------------------------------------------
def test_exposure_boost_only_when_true():
    on = score(RiskInputs(0.0, False, AssetCriticality.LOW, True))
    off = score(RiskInputs(0.0, False, AssetCriticality.LOW, False))
    assert on.contributions["exposure"] == INTERNET_EXPOSURE_BOOST
    assert off.contributions["exposure"] == 0


# ---------------------------------------------------------------------------
# Label buckets
# ---------------------------------------------------------------------------
def test_label_info_when_zero_or_minimal():
    r = score(RiskInputs(0.5, False, AssetCriticality.LOW, False))
    # cvss=5, no KEV, LOW crit, internal => 5 points => INFO
    assert r.score == 5
    assert r.label == "INFO"


def test_label_low_at_threshold():
    # cvss=1.0 -> 10, no KEV, MEDIUM -> 10, total 20 => LOW
    r = score(RiskInputs(1.0, False, AssetCriticality.MEDIUM, False))
    assert r.score == 20
    assert r.label == "LOW"


def test_label_medium_at_threshold():
    # cvss=2.0 -> 20, no KEV, HIGH -> 20, total 40 => MEDIUM
    r = score(RiskInputs(2.0, False, AssetCriticality.HIGH, False))
    assert r.score == 40
    assert r.label == "MEDIUM"


def test_label_high_at_threshold():
    # cvss=4.0 -> 40, no KEV, HIGH -> 20, total 60 => HIGH
    r = score(RiskInputs(4.0, False, AssetCriticality.HIGH, False))
    assert r.score == 60
    assert r.label == "HIGH"


def test_label_critical_at_threshold():
    # cvss=6.0 -> 60, no KEV, CRITICAL -> 30, total 90 => CRITICAL
    r = score(RiskInputs(6.0, False, AssetCriticality.CRITICAL, False))
    assert r.score == 90
    assert r.label == "CRITICAL"


# ---------------------------------------------------------------------------
# Realistic scenarios (the spec's worked example)
# ---------------------------------------------------------------------------
def test_kev_high_criticality_internet_exposed_is_critical():
    """The headline scenario from the spec: CVSS 8.5, KEV yes, asset HIGH,
    internet exposed. Should be CRITICAL."""
    r = score(RiskInputs(8.5, True, AssetCriticality.HIGH, True))
    # 85 + 25 + 20 + 15 = 145, clamped to 100
    assert r.score == SCORE_MAX
    assert r.label == "CRITICAL"


def test_internal_high_cvss_kev_is_critical():
    """CVSS 9.0 + KEV + HIGH criticality, no internet. Should still be
    CRITICAL because KEV forces urgency."""
    r = score(RiskInputs(9.0, True, AssetCriticality.HIGH, False))
    # 90 + 25 + 20 + 0 = 135 -> clamped 100
    assert r.score == SCORE_MAX
    assert r.label == "CRITICAL"


def test_internal_low_criticality_low_cvss_is_info():
    """An internal asset with a 3.5 CVSS, no KEV. Should be MEDIUM, not
    CRITICAL — the institutional context matters."""
    r = score(RiskInputs(3.5, False, AssetCriticality.LOW, False))
    # 35 + 0 + 0 + 0 = 35 => MEDIUM
    assert r.score == 35
    assert r.label == "MEDIUM"


# ---------------------------------------------------------------------------
# Clamping and immutability
# ---------------------------------------------------------------------------
def test_score_clamped_to_max():
    r = score(RiskInputs(10.0, True, AssetCriticality.CRITICAL, True))
    assert r.score == SCORE_MAX


def test_score_clamped_to_min():
    r = score(RiskInputs(-5.0, False, AssetCriticality.LOW, False))
    assert r.score == 0
    assert r.label == "INFO"


def test_result_is_immutable():
    """RiskResult is a frozen dataclass — analysts can't accidentally
    mutate a shared risk number on its way to the DB."""
    r = score(RiskInputs(5.0, False, AssetCriticality.LOW, False))
    with pytest.raises(Exception):
        r.score = 42  # type: ignore[misc]


def test_inputs_is_immutable():
    inputs = RiskInputs(5.0, False, AssetCriticality.LOW, False)
    with pytest.raises(Exception):
        inputs.cvss_v3 = 9.0  # type: ignore[misc]
