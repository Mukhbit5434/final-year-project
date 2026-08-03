"""The clean-capture ceiling: a value counts as elevated only when it exceeds the
highest value seen across the machine's clean captures, times MARGIN.

This replaced a median-times-constant rule that flagged the fresh-boot capture
against its own baseline - psxview.not_in_pslist reaches 33 on a clean fresh boot,
and 3x the median of 2 is only 6. These tests pin the ceiling behaviour so that
regression cannot come back.
"""
import json

import numpy as np
import pytest

from app.forensics import baseline


@pytest.fixture
def seven_cap(monkeypatch):
    """A baseline carrying an observed-max block, the multi-capture format."""
    data = {
        "label": "test", "captures": ["c1", "c2", "c3", "c4", "c5", "c6", "c7"],
        "features": {"psxview.not_in_pslist": 2.0, "malfind.ninjections": 6.0},
        "all_features": {"svcscan.nservices": 635.0, "pslist.nproc": 81.0},
        "max": {"psxview.not_in_pslist": 33.0, "malfind.ninjections": 9.0,
                "svcscan.nservices": 636.0, "pslist.nproc": 92.0},
    }
    monkeypatch.setattr(baseline, "_data", data)
    return data


def test_ceiling_is_observed_max_times_margin(seven_cap):
    assert baseline.ceiling("psxview.not_in_pslist") == pytest.approx(33.0 * 1.2)
    assert baseline.ceiling("malfind.ninjections") == pytest.approx(9.0 * 1.2)


def test_the_fresh_boot_peak_does_not_flag_itself(seven_cap):
    # 33 is the clean maximum; it must not read as elevated against a ceiling of 39.6.
    assert baseline.compare({"psxview.not_in_pslist": 33.0}) == {
        "psxview.not_in_pslist": False}


def test_a_value_above_the_ceiling_is_elevated(seven_cap):
    assert baseline.compare({"psxview.not_in_pslist": 40.0}) == {
        "psxview.not_in_pslist": True}
    assert baseline.compare({"malfind.ninjections": 11.0}) == {
        "malfind.ninjections": True}


def test_a_value_just_under_the_ceiling_is_not(seven_cap):
    assert baseline.compare({"malfind.ninjections": 10.0})[  # 9 * 1.2 = 10.8
        "malfind.ninjections"] is False


def test_phrase_names_the_clean_capture_count_and_max(seven_cap):
    hot = baseline.phrase("psxview.not_in_pslist", 50.0)
    assert "exceeds the highest value (33)" in hot
    assert "7 clean captures of this machine" in hot
    assert "substantially elevated" in hot

    ok = baseline.phrase("psxview.not_in_pslist", 5.0)
    assert "within the highest value (33)" in ok
    assert "consistent with this machine" in ok


def test_volumetric_uses_the_clean_maximum_not_a_multiplier(seven_cap):
    names = ["svcscan.nservices", "pslist.nproc"]
    # 800 services against a clean max of 636 -> elevated; process count normal.
    vec = np.array([800.0, 85.0])
    raised, note = baseline.volumetric_context(vec, names, {})
    assert [r["feature"] for r in raised] == ["svcscan.nservices"]
    assert "clean maximum of 636" in note
    assert "additional software rather than compromise" in note


def test_a_single_capture_baseline_still_loads_via_fallback(monkeypatch):
    """An older baseline with no max block falls back to its own value times the
    margin, so the app does not break if pointed at the pre-multi-capture file."""
    monkeypatch.setattr(baseline, "_data",
                        {"features": {"malfind.ninjections": 10.0}})
    assert baseline.ceiling("malfind.ninjections") == pytest.approx(12.0)
    assert baseline.compare({"malfind.ninjections": 20.0}) == {
        "malfind.ninjections": True}


def test_the_injection_demo_scenario_reaches_high_against_the_live_ceilings():
    """30 injected regions trips ninjections (ceiling 10.8), uniqueInjections (5.4)
    and commitCharge, giving Process Injection elevated -> High. This is the
    demonstrable true positive on the reference machine."""
    from pathlib import Path

    from app.forensics import mitre, severity
    baseline.load(Path(__file__).resolve().parent.parent /
                  "baselines" / "clean_win10_x64.json")
    try:
        obs = {"malfind.ninjections": 30.0, "malfind.uniqueInjections": 15.0,
               "malfind.commitCharge": 3000.0}
        elev = baseline.compare(obs)
        assert all(elev.values()), "all three malfind features should clear the ceiling"
        standout = mitre.match([f for f, hi in elev.items() if hi], "memory")
        sev, _ = severity.for_memory(elev, standout, probability=0.5,
                                     model_reliable=True, baselined=True)
        assert sev == "High"
    finally:
        baseline._data = None


def test_spawn_and_kill_alone_does_not_clear_the_psxview_ceiling():
    """The fresh-boot peak of 33 sets the not_in_pslist ceiling to ~40, so 15-20
    spawned-and-killed processes do NOT register - recorded so the demo does not
    rely on a second technique that will not fire on this machine."""
    from pathlib import Path
    baseline.load(Path(__file__).resolve().parent.parent /
                  "baselines" / "clean_win10_x64.json")
    try:
        assert baseline.compare({"psxview.not_in_pslist": 20.0}) == {
            "psxview.not_in_pslist": False}
    finally:
        baseline._data = None


def test_the_committed_baseline_is_the_seven_capture_one():
    """Guards against a stray single-capture baseline being committed again."""
    from pathlib import Path
    data = json.loads((Path(__file__).resolve().parent.parent /
                       "baselines" / "clean_win10_x64.json").read_text())
    assert len(data.get("captures", [])) == 7
    assert data.get("max"), "the live baseline must carry the observed-max block"
    assert data["max"]["psxview.not_in_pslist"] == 33.0
