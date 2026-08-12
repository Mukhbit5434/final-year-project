"""Configuration counts as context, never as an indicator."""
import json

import numpy as np
import pytest

from app import report
from app.db import db
from app.forensics import baseline, mitre
from app.models import MEMORY, Job

NAMES = ["svcscan.nservices", "pslist.nproc", "malfind.ninjections"]
REF = {"svcscan.nservices": 600.0, "pslist.nproc": 60.0, "malfind.ninjections": 16.0}


@pytest.fixture
def loaded(tmp_path, monkeypatch):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"label": "t", "features": {"malfind.ninjections": 16.0},
                                "all_features": REF}))
    baseline.load(path)
    yield
    baseline._data = None


def test_no_context_when_counts_are_normal(loaded):
    vec = np.array([610.0, 61.0, 1.0])
    raised, note = baseline.volumetric_context(vec, NAMES, {})
    assert raised == [] and note is None


def test_elevated_counts_alone_are_worded_as_installed_software(loaded):
    vec = np.array([2400.0, 61.0, 1.0])
    raised, note = baseline.volumetric_context(vec, NAMES, {"malfind.ninjections": False})

    assert [r["feature"] for r in raised] == ["svcscan.nservices"]
    assert raised[0]["factor"] == 4.0
    assert "consistent with additional software rather than compromise" in note
    assert "does not contribute to severity" in note


def test_wording_changes_when_a_behavioural_indicator_is_also_elevated(loaded):
    vec = np.array([2400.0, 61.0, 99.0])
    _, note = baseline.volumetric_context(vec, NAMES, {"malfind.ninjections": True})
    assert "additional software" not in note
    assert "Read alongside the behavioural indicators" in note


def test_volumetric_context_is_silent_without_a_baseline():
    baseline._data = None
    assert baseline.volumetric_context(np.array([9e9, 9e9, 9e9]), NAMES, {}) == ([], None)


def test_no_memory_tag_maps_to_a_volumetric_feature():
    """A MITRE tag asserts a technique was observed. "More services than the
    baseline" is evidence of installed software, so the T1543.003 services row was
    removed on 2026-08-02 and must not come back."""
    mapped = {f for e in mitre.TAGS if e["pipeline"] == "memory"
              for f in e.get("features", [])}
    assert not (mapped & set(baseline.VOLUMETRIC)), "volumetric features must not tag"
    assert not any(f.startswith("svcscan.") for f in mapped)


def test_volumetric_features_cannot_reach_severity(loaded):
    """Structural, not incidental: severity is fed from the behavioural dict, and
    matching volumetric features against the memory tags yields nothing at all."""
    assert mitre.match(list(baseline.VOLUMETRIC), "memory") == []


def test_the_note_is_stored_but_no_longer_displayed(client, signed_in, db, analyst):
    """CLAUDE.md §18, seventh pass: the "Configuration context" box was removed from
    both the PDF and the web page. `job.volumetric["note"]` is still computed and
    stored on every real memory job exactly as before (baseline.volumetric_context()
    is untouched) - this just confirms the display is genuinely gone, not that the
    computation stopped."""
    from tests.test_report import text_of

    note = ("Configuration counts are elevated (service and driver count 2400 against "
            "baseline 600) with no behavioural indicators present; consistent with "
            "additional software rather than compromise. This does not contribute to "
            "severity.")
    job = Job(user=analyst, filename="v.raw", stored_name="vol1.raw", sha256="f" * 64,
              size_bytes=1024, artifact=MEMORY, status="COMPLETED", ood_count=21,
              volumetric={"raised": [{"feature": "svcscan.nservices"}], "note": note})
    db.session.add(job)
    db.session.commit()

    assert job.volumetric["note"] == note, "still computed and stored, unaffected"

    assert "consistent with additional software" not in text_of(
        report.render(job, compress=False))
    body = client.get(f"/jobs/{job.id}").get_data(as_text=True)
    assert "Configuration context" not in body
    assert "consistent with additional software" not in body
