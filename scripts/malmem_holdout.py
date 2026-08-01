"""Pull genuinely held-out CIC-MalMem-2022 rows out of the test split.

The demo needs a labelled row the memory model has never seen. The training split
is reproducible, so rather than trusting a row picked by hand this reproduces the
split exactly and refuses to emit anything unless it lands on the numbers recorded
in models/memory/metadata.json.

    scripts\\malmem_holdout.py --csv data\\Obfuscated-MalMem2022.csv

Two details are not derivable from the metadata and were supplied by the person
who ran the original training:

  * dedup is a plain drop_duplicates() across ALL columns of the whole frame,
    applied BEFORE group keys are built, then the index is reset
  * benign rows all carry Category == "Benign" with nothing to tell them apart,
    so each benign row is its own group, keyed by post-dedup positional index.
    Keying on Category alone collapses them into one group and drops the entire
    benign half into a single fold.

No pandas (CLAUDE.md 16): csv plus numpy plus sklearn only.
"""
import argparse
import csv
import json
import re
import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RANDOM_STATE = 42
DEDUPED_ROWS = 58062
EXPECTED = {"train": 41456, "val": 8288, "test": 8318}
EXPECTED_TEST_CLASSES = {"benign": 4174, "malware": 4144}

SUFFIX = re.compile(r"-\d+\.raw$", re.IGNORECASE)


def read_rows(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def dedupe(rows):
    """drop_duplicates() over every column, keeping first, then reset the index."""
    seen, out = set(), []
    for row in rows:
        key = tuple(row.values())
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def group_keys(rows):
    """Category minus the -N.raw suffix; every benign row its own group.

    Benign Category values are indistinguishable, so grouping on the string alone
    would place all ~29k benign rows in one group and StratifiedGroupKFold would
    have to put them entirely on one side of the split.
    """
    keys = []
    for i, row in enumerate(rows):
        category = (row.get("Category") or "").strip()
        if category.lower().startswith("benign"):
            keys.append(f"benign_{i}")
        else:
            keys.append(SUFFIX.sub("", category))
    return np.array(keys, dtype=object)


def labels(rows):
    y = np.array([1 if (r.get("Class") or "").strip().lower() in ("malware", "1")
                  else 0 for r in rows], dtype=np.int64)
    return y


def split(n, y, groups):
    """Two stage, first fold each time - see metadata.json split.*_rows."""
    idx = np.arange(n)

    outer = StratifiedGroupKFold(n_splits=7, shuffle=True, random_state=RANDOM_STATE)
    rest_i, test_i = next(outer.split(idx, y, groups))

    inner = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=RANDOM_STATE)
    sub_train, sub_val = next(inner.split(rest_i, y[rest_i], groups[rest_i]))

    return rest_i[sub_train], rest_i[sub_val], test_i


def check(rows, train_i, val_i, test_i, y, groups):
    """-> list of failures. Emitting a row that might be from train is the one
    outcome worse than emitting nothing."""
    bad = []

    got = {"train": len(train_i), "val": len(val_i), "test": len(test_i)}
    if got != EXPECTED:
        bad.append(f"row counts {got} != recorded {EXPECTED}")

    if len(rows) != DEDUPED_ROWS:
        bad.append(f"{len(rows)} rows after dedup, expected {DEDUPED_ROWS}")

    n_benign = int((y[test_i] == 0).sum())
    n_malware = int((y[test_i] == 1).sum())
    if {"benign": n_benign, "malware": n_malware} != EXPECTED_TEST_CLASSES:
        bad.append(f"test classes benign={n_benign} malware={n_malware} != "
                   f"{EXPECTED_TEST_CLASSES}")

    g_train, g_val, g_test = (set(groups[i]) for i in (train_i, val_i, test_i))
    for a, b, name in ((g_train, g_test, "train/test"), (g_val, g_test, "val/test"),
                       (g_train, g_val, "train/val")):
        shared = a & b
        if shared:
            bad.append(f"{name} share {len(shared)} group(s), e.g. {list(shared)[:3]}")

    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Obfuscated-MalMem2022.csv")
    ap.add_argument("--out", default=str(ROOT / "data" / "holdout"))
    ap.add_argument("--force", action="store_true",
                    help="write the rows even if verification fails (do not)")
    args = ap.parse_args()

    from app.inference import memory as model
    model.load(ROOT / "models", ROOT / "reference_data")
    names = model.names()

    raw = read_rows(args.csv)
    rows = dedupe(raw)
    print(f"csv rows          {len(raw):,}  ->  {len(rows):,} after dedup")

    missing = [n for n in names if n not in rows[0]]
    if missing:
        raise SystemExit(f"CSV lacks {len(missing)} feature column(s), e.g. {missing[:4]}")

    y = labels(rows)
    groups = group_keys(rows)
    print(f"groups            {len(set(groups)):,} distinct "
          f"({(y == 0).sum():,} benign rows, {(y == 1).sum():,} malicious)")

    train_i, val_i, test_i = split(len(rows), y, groups)
    print(f"split             train {len(train_i):,} / val {len(val_i):,} / "
          f"test {len(test_i):,}")

    failures = check(rows, train_i, val_i, test_i, y, groups)
    if failures:
        print("\nVERIFICATION FAILED")
        for f in failures:
            print(f"  - {f}")
        if not args.force:
            raise SystemExit("\nemitting nothing: a row that might be from train is "
                             "worse than no row at all")
    else:
        print("\nverified: row counts, test class balance, dedup total and group "
              "disjointness all match metadata.json")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    for want, tag in ((1, "malicious"), (0, "benign")):
        pick = test_i[y[test_i] == want][0]
        row = rows[pick]
        vec = np.array([float(row[n]) for n in names], dtype=np.float32)
        prob, malicious = model.predict(vec)
        ood_count, _ = model.ood(vec)

        np.save(out / f"malmem_test_{tag}.npy", vec)
        (out / f"malmem_test_{tag}.json").write_text(json.dumps({
            "source": "CIC-MalMem-2022 test split, held out from training",
            "csv_row_after_dedup": int(pick),
            "category": row.get("Category"),
            "class": row.get("Class"),
            "group": str(groups[pick]),
            "split_reproduced": not failures,
            "model_probability": float(prob),
            "model_verdict": "malware" if malicious else "benign",
            "ood_features": int(ood_count),
        }, indent=2))

        print(f"\n{tag:>9}  row {pick}  {row.get('Category')}")
        print(f"           p={prob:.6f}  verdict={'MALWARE' if malicious else 'BENIGN'}"
              f"  ood={ood_count}/55")

    print(f"\nwrote 4 files to {out}")


if __name__ == "__main__":
    main()
