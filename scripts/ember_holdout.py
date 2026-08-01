"""Pull a labelled row out of EMBER 2018's test set and vectorise it.

The disk model is the validated one - 0.9940 ROC-AUC against the official
baseline's 0.9964 - but every artifact we can run end to end is known-clean, so
the detection path has never been shown on real malware. This closes that: the
EMBER test set ships *raw feature objects* with labels, and
PEFeatureExtractor.process_raw_features turns one straight into the 2,381 vector.

No PE binary is opened, no malware is handled, and lief never parses anything.

    scripts\\ember_holdout.py --tar data\\ember_dataset_2018_2.tar.bz2

test_features.jsonl is the held-out half of the published split; label 1 is
malicious, 0 benign, -1 unlabelled (those are skipped).
"""
import argparse
import json
import sys
import tarfile
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MEMBER = "ember2018/test_features.jsonl"


def rows(tar_path, wanted, limit):
    """Stream the member; it is ~1 GB expanded and we need two lines out of it."""
    found = {}
    with tarfile.open(tar_path, "r:bz2") as tar:
        member = None
        for m in tar:
            if m.name.endswith("test_features.jsonl"):
                member = m
                break
        if member is None:
            raise SystemExit(f"{MEMBER} not found in {tar_path}")

        print(f"streaming {member.name} ({member.size / 1024**2:.0f} MB expanded)")
        handle = tar.extractfile(member)
        for i, line in enumerate(handle):
            if i >= limit:
                break
            obj = json.loads(line)
            label = obj.get("label")
            if label in wanted and label not in found:
                found[label] = (i, obj)
                if len(found) == len(wanted):
                    break
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tar", default=str(ROOT / "data" / "ember_dataset_2018_2.tar.bz2"))
    ap.add_argument("--out", default=str(ROOT / "data" / "holdout"))
    ap.add_argument("--scan-limit", type=int, default=20000,
                    help="lines to read before giving up on finding both classes")
    args = ap.parse_args()

    from scripts.patch_ember import load_features
    from app.inference import disk as model

    model.load(ROOT / "models", ROOT / "reference_data")
    features = load_features()
    extractor = features.PEFeatureExtractor(feature_version=2)

    found = rows(args.tar, {0, 1}, args.scan_limit)
    if len(found) < 2:
        raise SystemExit(f"only found labels {sorted(found)} in the first "
                         f"{args.scan_limit} lines; raise --scan-limit")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    for label, tag in ((1, "malicious"), (0, "benign")):
        line_no, obj = found[label]
        vec_2381 = np.array(extractor.process_raw_features(obj), dtype=np.float32)
        if len(vec_2381) != 2381:
            raise SystemExit(f"expected 2381 features, got {len(vec_2381)}")

        vec_150 = model.subset(vec_2381)
        prob, malicious = model.predict(vec_150)
        correct = bool(malicious) == bool(label)

        np.save(out / f"ember_test_{tag}.npy", vec_150)
        (out / f"ember_test_{tag}.json").write_text(json.dumps({
            "source": "EMBER 2018 test_features.jsonl, the published held-out split",
            "line": line_no,
            "sha256": obj.get("sha256"),
            "label": label,
            "appeared_in": obj.get("appeared"),
            "model_probability": float(prob),
            "model_verdict": "malware" if malicious else "benign",
            "agrees_with_label": correct,
            "note": "vectorised from the published raw features; no PE was parsed",
        }, indent=2))

        print(f"\n{tag:>9}  line {line_no}  sha256={str(obj.get('sha256'))[:16]}…")
        print(f"           p={prob:.6f}  verdict={'MALWARE' if malicious else 'BENIGN'}"
              f"  label={label}  {'CORRECT' if correct else 'WRONG'}")

    print(f"\nwrote 4 files to {out}")


if __name__ == "__main__":
    main()
