import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# metadata.json records what the models were actually trained/saved under.
# xgboost/lightgbm/sklearn mismatches can change prediction output, so they are
# checked against it; the rest just need to import.
PINNED = ("xgboost", "lightgbm", "sklearn")
OPTIONAL = ("numpy", "scipy", "lime", "flask", "sqlalchemy", "reportlab",
            "lief", "pytsk3", "pyewf", "volatility3")

ok = True


def line(status, name, detail=""):
    global ok
    if status == "FAIL":
        ok = False
    print(f"  [{status:4}] {name:14} {detail}")


def version(mod):
    for attr in ("__version__", "version", "VERSION"):
        v = getattr(mod, attr, None)
        if isinstance(v, str):
            return v
    return "?"


def check_libs():
    expected = {}
    for pipeline in ("memory", "disk"):
        meta = json.loads((ROOT / "models" / pipeline / "metadata.json").read_text())
        expected.update(meta.get("library_versions", {}))

    print("\npinned libraries (must match models/*/metadata.json):")
    for name in PINNED:
        try:
            mod = importlib.import_module(name)
        except ImportError as e:
            line("FAIL", name, f"not installed ({e})")
            continue
        got, want = version(mod), expected.get(name)
        if want is None:
            line("OK", name, got)
        elif got == want:
            line("OK", name, got)
        else:
            line("WARN", name, f"{got} != {want} recorded at training time")

    print("\nother libraries:")
    for name in OPTIONAL:
        try:
            mod = importlib.import_module(name)
        except ImportError as e:
            line("FAIL", name, str(e))
        else:
            line("OK", name, version(mod))


def check_artifacts():
    import numpy as np

    print("\nmodel artifacts:")
    mem_feats = json.loads((ROOT / "models/memory/feature_list.json").read_text())
    sel = json.loads((ROOT / "models/disk/feature_list_selected.json").read_text())
    full = json.loads((ROOT / "models/disk/feature_list_full_2381.json").read_text())
    line("OK" if len(mem_feats) == 55 else "FAIL", "memory feats", f"{len(mem_feats)} (want 55)")
    line("OK" if len(sel) == 150 else "FAIL", "disk selected", f"{len(sel)} (want 150)")
    line("OK" if len(full) == 2381 else "FAIL", "disk full", f"{len(full)} (want 2381)")

    pos = {n: i for i, n in enumerate(full)}
    missing = [n for n in sel if n not in pos]
    if missing:
        line("FAIL", "subset map", f"{len(missing)} selected names absent from full list")
    else:
        idx = [pos[n] for n in sel]
        # non-monotonic on purpose - sorting it silently mispredicts (hard rule 18)
        line("OK" if idx != sorted(idx) else "FAIL", "subset map",
             f"150 indices in [{min(idx)},{max(idx)}], non-monotonic={idx != sorted(idx)}")

    for pipeline, want_thr in (("memory", 0.2336726188659668), ("disk", 0.5010602922493019)):
        meta = json.loads((ROOT / "models" / pipeline / "metadata.json").read_text())
        thr = meta["threshold"]
        line("OK" if thr == want_thr else "FAIL", f"{pipeline} thresh", repr(thr))

    print("\nreference data:")
    mem = np.load(ROOT / "reference_data/memory_sample.npy")
    disk = np.load(ROOT / "reference_data/disk_sample.npy")
    for name, arr, cols in (("memory_sample", mem, 55), ("disk_sample", disk, 150)):
        clean = not (np.isnan(arr).any() or np.isinf(arr).any())
        good = arr.shape[1] == cols and clean
        line("OK" if good else "FAIL", name,
             f"{arr.shape} {arr.dtype} finite={clean} range=[{arr.min():.4g},{arr.max():.4g}]")

    # 3 all-zero but 4 zero-variance: callbacks.ngeneric is constant 8.0, not 0.
    # Asserting "3 zero-variance" is the wrong check and fails at boot.
    zero = [mem_feats[i] for i in range(mem.shape[1]) if not mem[:, i].any()]
    const = [mem_feats[i] for i in range(mem.shape[1]) if mem[:, i].std() == 0]
    line("OK" if len(zero) == 3 else "FAIL", "all-zero cols", f"{len(zero)} {zero}")
    line("OK" if len(const) == 4 else "FAIL", "constant cols", f"{len(const)} {const}")


def main():
    print(f"python {sys.version.split()[0]}  ({sys.executable})")
    check_libs()
    check_artifacts()

    print("\nember:")
    sys.path.insert(0, str(ROOT / "scripts"))
    import patch_ember
    try:
        st = patch_ember.state()
    except RuntimeError as e:
        line("FAIL", "features.py", str(e))
        return 0 if ok else 1
    for name, s in st.items():
        line("OK" if s == "patched" else "FAIL", f"patch:{name}", s)

    try:
        ext = patch_ember.load_features().PEFeatureExtractor(feature_version=2)
    except Exception as e:
        line("FAIL", "extractor", f"{type(e).__name__}: {e}")
    else:
        # end-to-end proof that lief 1.0 + the patch actually vectorize a real PE
        vec = ext.feature_vector(Path(sys.executable).read_bytes())
        line("OK" if len(vec) == 2381 else "FAIL", "extractor",
             f"python.exe -> {len(vec)} features (want 2381)")

    print("\nRESULT:", "OK" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())