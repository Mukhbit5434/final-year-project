import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import Config
from app.extractors import memory as extractor
from app.inference import memory as model


def main():
    ap = argparse.ArgumentParser(
        description="Extract the 55 memory features and show each against its training range")
    ap.add_argument("dump")
    ap.add_argument("--json", type=Path, help="also write the raw result here")
    args = ap.parse_args()

    names = json.loads((Config.MODELS_DIR / "memory" / "feature_list.json").read_text())
    ref = np.load(Config.REFERENCE_DIR / "memory_sample.npy")
    lo, hi = ref.min(0), ref.max(0)

    started = time.time()
    out = extractor.extract(
        args.dump, names,
        progress=lambda key, plugin: print(f"  running {plugin} ...", flush=True))
    took = time.time() - started

    print(f"\nextraction took {took / 60:.1f} minutes")
    print("plugin rows:", ", ".join(f"{k}={v}" for k, v in out["plugin_rows"].items()))

    vec = out["vec"]
    print(f"\n{'#':>3} {'feature':42s} {'extracted':>14s} {'training min':>13s} "
          f"{'training max':>13s}  flag")
    outside = 0
    for i, name in enumerate(names):
        v = vec[i]
        off = v < lo[i] or v > hi[i]
        outside += off
        print(f"{i:3d} {name:42s} {v:14.4f} {lo[i]:13.4f} {hi[i]:13.4f}  "
              f"{'OUT' if off else ''}")

    print(f"\n{outside} of 55 features fall outside the range observed in training.")

    model.load(Config.MODELS_DIR, Config.REFERENCE_DIR)
    count, fields = model.ood(vec)
    prob, verdict = model.predict(vec)
    dominant = model.dominant_ood(vec)

    print(f"\nmodel probability : {prob:.4f}  (threshold {model.threshold():.4f})")
    print(f"raw verdict       : {'malicious' if verdict else 'benign'}")
    print(f"out-of-distribution: {count} of 55")
    if dominant:
        print(f"\n  Model verdict: not reliable for this capture. {len(dominant)} of the "
              f"{len(model.DOMINANT)} features this model depends on most fall outside "
              f"the range it was trained on:")
        for name in dominant:
            a, b = model.training_range(name)
            print(f"    {name:38s} extracted {vec[names.index(name)]:10.1f}  "
                  f"trained on [{a:g}, {b:g}]")

    print(f"\nextraction gaps ({len(out['gaps'])}):")
    for g in out["gaps"]:
        print(f"  {g['confidence']:9s} {g['field']:42s} {g['reason'][:70]}")

    if args.json:
        args.json.write_text(json.dumps(
            {"vec": vec, "gaps": out["gaps"], "plugin_rows": out["plugin_rows"],
             "ood_count": count, "ood_fields": fields, "probability": prob,
             "seconds": took}, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())