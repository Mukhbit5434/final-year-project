import importlib.util
import sys
from pathlib import Path

PATCHES = (
    (
        "featurehasher",
        'FeatureHasher(50, input_type="string").transform([raw_obj[\'entry\']]).toarray()[0]',
        'FeatureHasher(50, input_type="string").transform([[raw_obj[\'entry\']]]).toarray()[0]',
    ),
    (
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
        "np_int",
        "output = np.zeros((16, 16), dtype=np.int)",
        "output = np.zeros((16, 16), dtype=int)",
    ),
)


def features_path():
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