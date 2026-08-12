"""Extract the seven clean baseline captures once, save vectors and a summary.

Extraction is the expensive part (minutes each), so this runs it exactly once per
dump, writes the 55-vector to data/baseline_vectors/, and records everything steps
2-4 of the baseline build need: the ground-truth features, OOD count, probability
and per-plugin timings. Analysis then works off the saved vectors, never the dumps.

    scripts\\baseline_extract.py
"""
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DUMPS = [
    ("clean_1_freshboot", 80, 253, 364),
    ("clean_2_idle", 73, 253, 363),
    ("clean_3_browser", 90, 253, 363),
    ("clean_4_apps", 92, 253, 364),
    ("clean_5_afterclose", 80, 253, 363),
    ("clean_6_pair_a", 83, 253, 363),
    ("clean_7_pair_b", None, None, None),
]

OUT = ROOT / "data" / "baseline_vectors"


def main():
    from volatility3.framework import constants
    constants.OFFLINE = True

    from app.extractors import memory as ex
    from app.inference import memory as model

    model.load(ROOT / "models", ROOT / "reference_data")
    names = model.names()
    OUT.mkdir(parents=True, exist_ok=True)

    idx = {n: i for i, n in enumerate(names)}
    summary = []

    for name, gt_proc, gt_svc, gt_drv in DUMPS:
        dump = ROOT / "sample" / "memory" / f"{name}.raw"
        if not dump.exists():
            print(f"MISSING {dump}", flush=True)
            continue

        print(f"\n=== {name}  (this takes minutes)", flush=True)
        t0 = time.time()
        try:
            out = ex.extract(str(dump), names)
        except Exception as e:
            print(f"  FAILED: {type(e).__name__}: {e}", flush=True)
            summary.append({"name": name, "error": f"{type(e).__name__}: {e}"})
            continue
        wall = time.time() - t0

        vec = np.asarray(out["vec"], dtype=np.float32)
        np.save(OUT / f"{name}.npy", vec)

        assert vec.shape == (55,), f"{name}: expected 55 features, got {vec.shape}"
        assert not np.isnan(vec).any() and not np.isinf(vec).any(), f"{name}: NaN/Inf"

        prob, malicious = model.predict(vec)
        ood_count, ood_fields = model.ood(vec)

        proc = float(vec[idx["pslist.nproc"]])
        svc = float(vec[idx["svcscan.nservices"]])
        drv = float(vec[idx["svcscan.kernel_drivers"]])

        row = {
            "name": name, "wall_seconds": round(wall, 1),
            "bits": out["bits"], "torn_rows": out.get("torn_process_rows", 0),
            "pslist.nproc": proc, "gt_proc": gt_proc,
            "svcscan.nservices": svc, "gt_services": gt_svc,
            "svcscan.kernel_drivers": drv, "gt_drivers": gt_drv,
            "probability": float(prob), "verdict": "malware" if malicious else "benign",
            "ood_count": int(ood_count), "ood_fields": ood_fields,
            "plugin_seconds": out.get("plugin_seconds", {}),
        }
        summary.append(row)
        print(f"  {wall:.0f}s  proc={proc:.0f} (gt {gt_proc})  "
              f"svc={svc:.0f} (gt {gt_svc})  drv={drv:.0f} (gt {gt_drv})  "
              f"p={prob:.4f}  ood={ood_count}/55", flush=True)

    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nwrote {len([s for s in summary if 'error' not in s])} vectors + summary "
          f"to {OUT}", flush=True)


if __name__ == "__main__":
    main()
