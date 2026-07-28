import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import Config
from app.extractors import disk as extractor
from app.inference import disk as model


def main():
    ap = argparse.ArgumentParser(description="Scan a disk image and report flagged PE files")
    ap.add_argument("image")
    ap.add_argument("--max-files", type=int, default=Config.MAX_PE_FILES)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--no-predict", action="store_true")
    args = ap.parse_args()

    info = extractor.ewf_metadata(args.image)
    if info:
        print("acquisition:", ", ".join(f"{k}={v}" for k, v in info.items()))

    started = time.time()
    out = extractor.scan(args.image, max_files=args.max_files, workers=args.workers,
                         progress=lambda n, p: print(f"  [{n}] {p}", flush=True))
    took = time.time() - started

    print(f"\nvolumes      : {', '.join(out['volumes'])}")
    print(f"files examined: {out['examined']:,}")
    print(f"PE files     : {out['pe_found']} found, {len(out['files'])} vectorized")
    print(f"skipped      : {len(out['skipped'])}")
    print(f"elapsed      : {took:.1f}s")

    if out["skipped"]:
        print("\nskipped:")
        for s in out["skipped"][:20]:
            print(f"  {s['reason']:44s} {s['path']}")
        if len(out["skipped"]) > 20:
            print(f"  ... and {len(out['skipped']) - 20} more")

    if args.no_predict or not out["files"]:
        return 0

    model.load(Config.MODELS_DIR, Config.REFERENCE_DIR)
    rows = []
    for rec in out["files"]:
        prob, flagged = model.predict(model.subset(rec["vec"]))
        rows.append((prob, flagged, rec))
    rows.sort(key=lambda r: -r[0])

    flagged = [r for r in rows if r[1]]
    print(f"\nthreshold {model.threshold():.6f} -> {len(flagged)} of {len(rows)} flagged\n")
    print(f"{'prob':>7}  {'':1}  {'size':>9}  path")
    for prob, is_flagged, rec in rows[:40]:
        mark = "!" if is_flagged else " "
        print(f"{prob:7.4f}  {mark}  {rec['file_size']:9,}  {rec['path']}")
        if is_flagged:
            print(f"{'':12}sha256 {rec['file_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())