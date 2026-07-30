import json

import pytest

from app.config import Config
from app.extractors import memory as ex

NAMES = json.loads((Config.MODELS_DIR / "memory" / "feature_list.json").read_text())

# What a live acquisition produced on the first x64 capture: the process list was
# read while Windows was modifying it, so one EPROCESS came back structurally
# torn. Magnet RAM Capture, WinPmem and DumpIt can all do this; the dataset's
# VirtualBox snapshots were atomic and never did.
TORN = {"PID": 88804946376740, "PPID": 4294967295123, "ImageFileName": "�",
        "Threads": 333494799, "Handles": None, "Wow64": None}

SANE = [{"PID": 4, "PPID": 0, "Threads": 120, "Wow64": False},
        {"PID": 88, "PPID": 4, "Threads": 12, "Wow64": True},
        {"PID": 92, "PPID": 4, "Threads": 8, "Wow64": False}]


def test_a_torn_row_is_detected():
    assert ex.torn_rows(SANE) == []
    assert ex.torn_rows(SANE + [TORN]) == [TORN]


def test_a_torn_row_does_not_poison_the_thread_average():
    clean = ex.from_pslist(SANE, 1000)["pslist.avg_threads"]
    withtorn = ex.from_pslist(SANE + [TORN], 1000)["pslist.avg_threads"]
    assert clean == pytest.approx(140 / 3)
    assert withtorn == clean, "implausible thread counts must be excluded"


def test_a_torn_row_still_counts_toward_nproc():
    # Ground truth on the x64 capture: Get-Process reported 67 and volatility
    # returned 67 rows, one of them torn. The process is real; only its fields
    # are unreadable, so dropping the row would put the count 1 below truth.
    out = ex.from_pslist(SANE + [TORN], 1000)
    assert out["pslist.nproc"] == 4


def test_a_torn_ppid_does_not_inflate_the_parent_count():
    assert ex.from_pslist(SANE + [TORN], 1000)["pslist.nppid"] == 2


def test_torn_rows_are_disclosed_as_a_gap():
    parts = [{n: 0.0 for n in NAMES}]
    _, gaps = ex.assemble(parts, NAMES, (), torn=1)
    entry = next(g for g in gaps if g["field"] == "pslist.avg_threads")
    assert entry["confidence"] == "inferred"
    assert "torn" in entry["reason"]
    assert "nproc" in entry["reason"]


def test_no_gap_is_recorded_when_nothing_was_torn():
    parts = [{n: 0.0 for n in NAMES}]
    _, gaps = ex.assemble(parts, NAMES, (), torn=0)
    assert not any(g["field"] == "pslist.avg_threads" for g in gaps)