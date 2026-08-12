"""Build the multi-capture baseline from the seven extracted vectors.

Reads data/baseline_vectors/*.npy, computes median and IQR per feature across the
seven, and writes a candidate baseline JSON WITHOUT touching the committed one.
Reports which features are stable and which vary. Nothing here overwrites
baselines/clean_win10_x64.json - that is a separate, deliberate step once the
numbers are approved.

    scripts\\baseline_build.py
"""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

VEC = ROOT / "data" / "baseline_vectors"
CANDIDATE = ROOT / "data" / "baseline_candidate.json"


def main():
    from app.inference import memory as model
    model.load(ROOT / "models", ROOT / "reference_data")
    names = model.names()

    order = ["clean_1_freshboot", "clean_2_idle", "clean_3_browser", "clean_4_apps",
             "clean_5_afterclose", "clean_6_pair_a", "clean_7_pair_b"]
    mats = []
    used = []
    for name in order:
        p = VEC / f"{name}.npy"
        if p.exists():
            mats.append(np.load(p))
            used.append(name)
    if len(mats) < 2:
        raise SystemExit(f"only {len(mats)} vectors present; run baseline_extract first")
    M = np.vstack(mats)
    print(f"stacked {M.shape[0]} captures x {M.shape[1]} features: {', '.join(used)}\n")

    median = np.median(M, axis=0)
    q1 = np.percentile(M, 25, axis=0)
    q3 = np.percentile(M, 75, axis=0)
    mn = M.min(axis=0)
    mx = M.max(axis=0)

    features, all_features = {}, {}
    rows = []
    for i, n in enumerate(names):
        med = float(median[i])
        iqr = float(q3[i] - q1[i])
        spread = mx[i] / mn[i] if mn[i] > 0 else (float("inf") if mx[i] > 0 else 1.0)
        all_features[n] = round(med, 4)
        rows.append((n, med, iqr, float(mn[i]), float(mx[i]), spread))

    from app.forensics import baseline as bl
    behavioural = [n for n in names if n in _behavioural_names()]
    for n in behavioural:
        i = names.index(n)
        features[n] = round(float(median[i]), 4)

    print(f"{'feature':<36}{'median':>10}{'IQR':>9}{'min':>9}{'max':>9}{'max/min':>9}")
    print("-- most variable")
    for n, med, iqr, lo, hi, spread in sorted(rows, key=lambda r: -r[5])[:12]:
        print(f"{n:<36}{med:>10.1f}{iqr:>9.1f}{lo:>9.1f}{hi:>9.1f}{spread:>9.2f}")
    print("-- most stable (nonzero)")
    stable = [r for r in rows if r[3] > 0]
    for n, med, iqr, lo, hi, spread in sorted(stable, key=lambda r: r[5])[:12]:
        print(f"{n:<36}{med:>10.1f}{iqr:>9.1f}{lo:>9.1f}{hi:>9.1f}{spread:>9.2f}")

    candidate = {
        "label": "clean Windows 10 x64 reference machine, 7-capture baseline",
        "os": "Windows 10 21H2, build 19044.7548, x64",
        "captured": "2026-08-03",
        "captures": used,
        "capture_tool": "Magnet RAM Capture (live acquisition, flat raw)",
        "method": "median (features/all_features) and observed max per feature across "
                  "seven captures spanning boot/idle/browser/apps/after-close states "
                  "plus one 15-30s pair. Severity uses the max times MARGIN (1.2) as the "
                  "ceiling - the highest value seen on a clean capture of this machine, "
                  "not a percentile seven samples cannot support.",
        "ground_truth": "services held at 253 and drivers 363-364 across all seven; "
                        "process count varied 73-92 by state (60 on the volatile fresh "
                        "boot, where Get-Process ran ~40s before acquisition finished).",
        "features": features,
        "all_features": all_features,
        "max": {n: round(float(mx[i]), 4) for i, n in enumerate(names)},
        "iqr": {n: round(float(q3[i] - q1[i]), 4) for i, n in enumerate(names)},
        "min": {n: round(float(mn[i]), 4) for i, n in enumerate(names)},
    }
    CANDIDATE.write_text(json.dumps(candidate, indent=2))
    print(f"\nwrote candidate to {CANDIDATE}")
    print("review it, then replace baselines/clean_win10_x64.json to make it live")


def _behavioural_names():
    from app.forensics.meanings import BEHAVIOURAL
    return set(BEHAVIOURAL)


if __name__ == "__main__":
    main()
