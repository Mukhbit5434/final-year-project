import importlib.util
import sys
from pathlib import Path

# Both patches exist because ember 2018 targets lief 0.9.0 and we run lief 1.0.0
# (the version that produced the training features - see models/disk/metadata.json).
# Neither changes a feature value; they only make extraction run at all.
PATCHES = (
    (
        # elastic/ember PR #109. FeatureHasher(input_type="string") wants an
        # iterable of iterables; ember passes a bare string, so every sample dies
        # with "ValueError: Samples can not be a single string".
        "featurehasher",
        'FeatureHasher(50, input_type="string").transform([raw_obj[\'entry\']]).toarray()[0]',
        'FeatureHasher(50, input_type="string").transform([[raw_obj[\'entry\']]]).toarray()[0]',
    ),
    (
        # lief 1.0 dropped bad_format/bad_file/pe_error/parser_error/read_out_of_bound,
        # so building this tuple raises AttributeError before any parsing happens.
        # Resolve whatever the installed lief still exposes; RuntimeError always
        # applies. Catch-set only - parse behaviour is unchanged.
        "lief_errors",
        """        lief_errors = (lief.bad_format, lief.bad_file, lief.pe_error, lief.parser_error, lief.read_out_of_bound,
                       RuntimeError)""",
        """        lief_errors = tuple(
            exc for exc in (getattr(lief, n, None) for n in (
                "bad_format", "bad_file", "pe_error", "parser_error", "read_out_of_bound"))
            if isinstance(exc, type) and issubclass(exc, BaseException)
        ) + (RuntimeError,)""",
    ),
    (
        # np.int was removed in numpy 1.24. Pinning numpy back is not an option -
        # xgboost 3.2.0 and sklearn 1.6.1 both require newer. int is what the
        # alias always meant, so the dtype is unchanged.
        "np_int",
        "output = np.zeros((16, 16), dtype=np.int)",
        "output = np.zeros((16, 16), dtype=int)",
    ),
)


def features_path():
    # find_spec rather than import: ember/__init__.py pulls in pandas and
    # lightgbm, and the patch must work even if those are half-installed.
    spec = importlib.util.find_spec("ember")
    if spec is None or not spec.origin:
        raise RuntimeError("ember is not installed")
    return Path(spec.origin).parent / "features.py"


def state():
    """-> {patch_name: 'patched' | 'unpatched' | 'unknown'}"""
    src = features_path().read_text(encoding="utf-8")
    out = {}
    for name, broken, fixed in PATCHES:
        out[name] = "patched" if fixed in src else "unpatched" if broken in src else "unknown"
    return out


def verify():
    """Called at app startup. Patching happens at install time, not here -
    rewriting site-packages while workers are running is a race, and fails
    outright on read-only or service-account installs."""
    bad = {k: v for k, v in state().items() if v != "patched"}
    if bad:
        raise RuntimeError(f"ember/features.py not ready: {bad}; run scripts/patch_ember.py")


def load_features():
    """Load ember/features.py standalone, bypassing ember/__init__.py.

    __init__ drags in pandas, lightgbm and sklearn.model_selection for ember's
    training helpers, none of which we use - and pandas' C extensions are
    blocked outright by Windows Application Control on the target machine.
    features.py itself needs only re/lief/hashlib/numpy/os/json.
    """
    verify()
    spec = importlib.util.spec_from_file_location("ember_features", features_path())
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ember_features"] = mod
    spec.loader.exec_module(mod)
    return mod


def apply():
    p = features_path()
    src = p.read_text(encoding="utf-8")
    rc = 0
    for name, broken, fixed in PATCHES:
        if fixed in src:
            print(f"{name}: already patched")
        elif broken in src:
            src = src.replace(broken, fixed)
            print(f"{name}: patched")
        else:
            print(f"{name}: target text not found - ember upstream may have changed",
                  file=sys.stderr)
            rc = 1
    p.write_text(src, encoding="utf-8")
    print(f"wrote {p}")
    return rc


if __name__ == "__main__":
    sys.exit(apply())