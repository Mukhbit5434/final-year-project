import json
import logging

from . import disk, memory

log = logging.getLogger(__name__)

_loaded = False


def init(models_dir, reference_dir):
    """Load both pipelines once, at startup. Deliberately not a shared loader
    class - XGBoost and LightGBM disagree on how to load, how to predict and what
    a feature name is, and papering over that is how the two get swapped."""
    global _loaded

    n_mem = memory.load(models_dir, reference_dir)
    n_disk = disk.load(models_dir, reference_dir)
    _check_versions(models_dir)

    log.info("models loaded: memory %d features (threshold %.6f), "
             "disk %d of 2381 features (threshold %.6f)",
             n_mem, memory.threshold(), n_disk, disk.threshold())
    _loaded = True


def loaded():
    return _loaded


def _check_versions(models_dir):
    import lightgbm
    import sklearn
    import xgboost

    running = {"xgboost": xgboost.__version__, "lightgbm": lightgbm.__version__,
               "sklearn": sklearn.__version__}
    for pipeline in ("memory", "disk"):
        meta = json.loads((models_dir / pipeline / "metadata.json").read_text())
        for lib, want in meta.get("library_versions", {}).items():
            got = running.get(lib)
            if got and got != want:
                # Loud but not fatal: a patch bump is usually harmless, a major
                # one can change split evaluation. Someone has to look.
                log.warning("%s %s is installed but the %s model was saved under %s",
                            lib, got, pipeline, want)