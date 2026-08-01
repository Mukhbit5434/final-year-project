"""The refusal gate, exercised failing.

It passed on the first real run, which proves the happy path and nothing else.
These drive each gate to refuse. The expectations are monkeypatched down to toy
numbers so the tests need neither the 19 MB CSV nor a real split.

Verified against the real CSV as well (2026-08-02): wrong outer n_splits, wrong
inner n_splits, random_state=0, collapsed benign group keys and a one-row dedup
error were each refused, and a group-ignoring random split - which produced the
exactly correct row counts - was caught by class balance and by 2,277 shared
groups between train and test.
"""
import numpy as np
import pytest

import scripts.malmem_holdout as mh


@pytest.fixture
def toy(monkeypatch):
    """10 rows: 6 train, 2 val, 2 test, one benign and one malicious in test."""
    monkeypatch.setattr(mh, "EXPECTED", {"train": 6, "val": 2, "test": 2})
    monkeypatch.setattr(mh, "DEDUPED_ROWS", 10)
    monkeypatch.setattr(mh, "EXPECTED_TEST_CLASSES", {"benign": 1, "malware": 1})

    rows = [{"r": str(i)} for i in range(10)]
    y = np.array([0, 1] * 5)
    groups = np.array([f"g{i}" for i in range(10)], dtype=object)
    train, val, test = np.arange(6), np.arange(6, 8), np.arange(8, 10)
    return rows, y, groups, train, val, test


def test_a_correct_split_passes(toy):
    rows, y, groups, train, val, test = toy
    assert mh.check(rows, train, val, test, y, groups) == []


def test_wrong_row_counts_refuse(toy):
    rows, y, groups, train, val, test = toy
    train = np.arange(5)
    fails = mh.check(rows, train, val, test, y, groups)
    assert any("row counts" in f for f in fails)


def test_wrong_dedup_total_refuses(toy):
    rows, y, groups, train, val, test = toy
    fails = mh.check(rows[:-1], train, val, test, y, groups)
    assert any("after dedup" in f for f in fails)


def test_wrong_test_class_balance_refuses(toy):
    rows, y, groups, train, val, test = toy
    y = y.copy()
    y[8] = y[9] = 1
    fails = mh.check(rows, train, val, test, y, groups)
    assert any("test classes" in f for f in fails)


def test_group_leakage_between_train_and_test_refuses(toy):
    """The whole reason the split is group-aware: 10 dumps per malware sample, so
    a shared group means near-identical sibling captures on both sides."""
    rows, y, groups, train, val, test = toy
    groups = groups.copy()
    groups[8] = groups[0]
    fails = mh.check(rows, train, val, test, y, groups)
    assert any("train/test share" in f for f in fails)


def test_every_gate_can_fire_at_once(toy):
    rows, y, groups, train, val, test = toy
    groups = groups.copy()
    groups[8] = groups[0]
    y = y.copy()
    y[8] = y[9] = 1
    fails = mh.check(rows[:-1], np.arange(5), val, test, y, groups)
    assert len(fails) >= 4


def test_benign_rows_each_get_their_own_group():
    """Benign Category is the bare string "Benign" for every row, so keying on it
    alone puts the entire benign half in one group and one fold."""
    rows = [{"Category": "Benign"}, {"Category": "Benign"},
            {"Category": "Trojan-Zeus-abc-1.raw"}, {"Category": "Trojan-Zeus-abc-7.raw"}]
    keys = mh.group_keys(rows)
    assert keys[0] != keys[1]
    assert keys[2] == keys[3] == "Trojan-Zeus-abc", "the -N.raw suffix must be stripped"


def test_dedupe_drops_whole_row_duplicates_and_keeps_the_first():
    rows = [{"a": "1", "b": "x"}, {"a": "1", "b": "x"}, {"a": "1", "b": "y"}]
    out = mh.dedupe(rows)
    assert len(out) == 2
    assert out[0]["b"] == "x" and out[1]["b"] == "y"
