"""Push a single pre-extracted feature vector through the real inference path.

The web app only accepts artifacts, which means the two demos that need *labelled*
data - a CIC-MalMem-2022 row and an EMBER test row - have no way in. This is that
way in. It runs the same loaders, the same thresholds, the same LIME explainer and
the same tag/severity code the job layer uses; nothing here is a reimplementation.

    scripts\\predict_vector.py memory --csv malmem.csv --row 12
    scripts\\predict_vector.py disk   --npy ember_row.npy
    scripts\\predict_vector.py memory --reference 41       (see the caveat below)

--reference pulls a row out of reference_data/. Those rows are *unlabelled training
samples*, so they demonstrate that the pipeline works and how the model separates -
they are not a verified true positive and must never be presented as one.
"""
import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MODELS = ROOT / "models"
REFERENCE = ROOT / "reference_data"


def _from_csv(path, row_index, names):
    """A CIC-MalMem-2022 export, matched by column name.

    Never positional: the released CSV carries a Category column and its own
    ordering, and hard rule 2 says the order comes from feature_list.json.
    """
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not 0 <= row_index < len(rows):
        raise SystemExit(f"row {row_index} out of range; the file holds {len(rows)}")

    row = rows[row_index]
    missing = [n for n in names if n not in row]
    if missing:
        raise SystemExit(f"CSV is missing {len(missing)} feature column(s), "
                         f"e.g. {missing[:4]}")

    label = row.get("Class") or row.get("Category") or "not stated"
    return np.array([float(row[n]) for n in names], dtype=np.float32), label


def _memory(vec, label):
    from app import explain
    from app.forensics import baseline, meanings, mitre
    from app.inference import memory as model

    prob, malicious = model.predict(vec)
    count, fields = model.ood(vec)
    dominant = model.dominant_ood(vec)
    reliable = not dominant
    names = model.names()

    print(f"\n  probability      {prob:.6f}   threshold {model.threshold():.6f}")
    print(f"  model verdict    {'MALWARE' if malicious else 'BENIGN'}")
    print(f"  stated label     {label}")
    print(f"  out of range     {count} of 55 features")
    if dominant:
        print(f"  dominant OOD     {', '.join(dominant)}")
        print("  -> the four features this model leans on are outside their training "
              "range;\n     the score is not trustworthy for this input (CLAUDE.md 5.4a)")
    else:
        print("  -> in distribution: the score is being read inside the range the "
              "model was fitted on")

    observed = meanings.observed(vec, names)
    elevated = baseline.compare(observed)
    matched = mitre.match(list(observed), "memory")

    print("\n  severity         not scored")
    print("  basis            severity needs a capture of the reference machine; a "
          "bare vector\n                   carries no provenance, so it is suppressed "
          "rather than guessed")

    print(f"\n  observed indicators ({len(observed)}):")
    for feature, value in sorted(observed.items(), key=lambda kv: -kv[1])[:8]:
        print(f"    {feature:<38} {value:>10.2f}   {baseline.phrase(feature, value)}")

    _tags(matched)
    if malicious and reliable:
        _lime(explain.memory_findings(vec))


def _disk(vec_150, label):
    from app import explain
    from app.forensics import mitre, severity
    from app.inference import disk as model

    prob, malicious = model.predict(vec_150)
    names = model.names()

    print(f"\n  probability      {prob:.6f}   threshold {model.threshold():.6f}")
    print(f"  model verdict    {'MALWARE' if malicious else 'BENIGN'}")
    print(f"  stated label     {label}")

    described = explain.disk_findings(vec_150) if malicious else []
    values = dict(zip(names, (float(x) for x in vec_150)))
    matched = mitre.match([d["feature"] for d in described], "disk", values)
    sev, note = severity.for_disk(prob, matched, model.threshold())
    print(f"\n  severity         {sev}\n  basis            {note}")

    _tags(matched)
    _lime(described)


def _tags(matched):
    if not matched:
        print("\n  no indicator categories matched")
        return
    print(f"\n  indicator tags ({len(matched)}):")
    for m in matched:
        print(f"    {m['tag']:<38} {m['mitre_id']:<12} {m['confidence']}")


def _lime(described):
    if not described:
        return
    print("\n  what drove the classification:")
    for d in described[:6]:
        print(f"    {d['feature']:<34} {d['why'][:90]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pipeline", choices=["memory", "disk"])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--csv", help="CIC-MalMem-2022 style CSV, matched by column name")
    src.add_argument("--npy", help=".npy holding one vector (55, 150 or 2381 long)")
    src.add_argument("--reference", type=int, metavar="N",
                     help="row N of reference_data/ - unlabelled training sample")
    ap.add_argument("--row", type=int, default=0, help="row index within --csv")
    args = ap.parse_args()

    from app import explain
    from app.forensics import baseline
    from app.inference import disk, memory

    memory.load(MODELS, REFERENCE)
    disk.load(MODELS, REFERENCE)
    explain.init(MODELS, REFERENCE)
    model = memory if args.pipeline == "memory" else disk
    names = model.names()

    label = "not stated"
    if args.csv:
        vec, label = _from_csv(args.csv, args.row, names)
        source = f"{Path(args.csv).name} row {args.row}"
    elif args.npy:
        vec = np.load(args.npy).astype(np.float32).reshape(-1)
        source = Path(args.npy).name
        sidecar = Path(args.npy).with_suffix(".json")
        if sidecar.exists():
            meta = json.loads(sidecar.read_text())
            label = meta.get("class") or meta.get("label")
            label = {0: "benign", 1: "malware"}.get(label, label)
            source += f"  ({meta.get('source', 'labelled')})"
    else:
        sample = np.load(REFERENCE / f"{args.pipeline}_sample.npy")
        if not 0 <= args.reference < len(sample):
            raise SystemExit(f"row out of range; the sample holds {len(sample)}")
        vec = sample[args.reference].astype(np.float32)
        source = f"reference_data/{args.pipeline}_sample.npy row {args.reference}"
        label = "UNLABELLED training sample"

    if args.pipeline == "disk" and len(vec) == 2381:
        vec = disk.subset(vec)
    if len(vec) != len(names):
        raise SystemExit(f"expected {len(names)} features, got {len(vec)}")

    print(f"\n{args.pipeline} pipeline  <-  {source}")
    print("=" * 72)
    if args.pipeline == "memory":
        if not baseline.loaded():
            baseline.load(ROOT / "baselines" / "clean_win10_x64.json")
        _memory(vec, label)
    else:
        _disk(vec, label)

    if args.reference is not None:
        print("\n  NOTE: reference_data rows are unlabelled samples of the *training*"
              "\n  distribution. This demonstrates the inference path, not a verified"
              "\n  true positive. Use --csv with a labelled held-out row for that.")
    print()


if __name__ == "__main__":
    main()
