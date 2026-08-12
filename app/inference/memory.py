import json

import numpy as np
import xgboost as xgb

TREES = (0, 173)

DOMINANT = ("svcscan.nservices", "handles.nmutant",
            "svcscan.shared_process_services", "svcscan.kernel_drivers")

_booster = None
_names = None
_threshold = None
_lo = None
_hi = None


class ModelError(RuntimeError):
    pass


def load(models_dir, reference_dir):
    global _booster, _names, _threshold, _lo, _hi

    here = models_dir / "memory"
    _names = json.loads((here / "feature_list.json").read_text())
    meta = json.loads((here / "metadata.json").read_text())
    _threshold = meta["threshold"]

    if _threshold == 0.5:
        raise ModelError("memory threshold read as 0.5 - metadata.json is wrong")

    _booster = xgb.Booster()
    _booster.load_model(str(here / "xgboost_model.json"))

    n = _booster.num_features()
    if n != len(_names) or n != 55:
        raise ModelError(f"memory model has {n} features, feature_list.json has {len(_names)}")

    ref = np.load(reference_dir / "memory_sample.npy")
    if ref.shape[1] != 55:
        raise ModelError(f"memory_sample.npy has {ref.shape[1]} columns, expected 55")
    if not np.isfinite(ref).all():
        raise ModelError("memory_sample.npy contains NaN or Inf")

    zeros = int(sum(1 for i in range(55) if not ref[:, i].any()))
    flat = int(sum(1 for i in range(55) if ref[:, i].std() == 0))
    if (zeros, flat) != (3, 4):
        raise ModelError(f"memory_sample.npy has {zeros} all-zero and {flat} "
                         f"zero-variance columns, expected 3 and 4")

    _lo, _hi = ref.min(0), ref.max(0)
    _check_reference(ref)
    return len(_names)


def _check_reference(ref):
    """The only check that catches a permuted column order. Both classes were
    balanced 50/50 in training, so correct ordering gives a bimodal split near
    the threshold; a scramble squashes everything into the middle."""
    p = predict_batch(ref)
    above = float((p >= _threshold).mean())
    mid = float(((p > 0.05) & (p < 0.95)).mean())
    if not 0.45 <= above <= 0.55 or mid > 0.05:
        raise ModelError(
            f"memory reference distribution looks wrong: {above:.3f} above threshold "
            f"(expect ~0.49), {mid:.3f} in the 0.05-0.95 band (expect ~0.001). "
            "A permuted feature order is the usual cause.")


def predict_batch(mat):
    mat = np.ascontiguousarray(mat, dtype=np.float32)
    return _booster.inplace_predict(mat, iteration_range=TREES)


def predict(vec):
    if len(vec) != 55:
        raise ModelError(f"expected a 55-length vector, got {len(vec)}")
    p = float(predict_batch(np.asarray(vec).reshape(1, -1))[0])
    return p, p >= _threshold


def ood(vec):
    """-> (count, [names]) of features outside the range seen in training.

    Mandatory on every memory result (hard rule 17). CIC-MalMem-2022 came from a
    single VM build, so on a real dump most features land outside it and the tree
    ensemble is extrapolating."""
    vec = np.asarray(vec, dtype=np.float64)
    outside = (vec < _lo) | (vec > _hi)
    return int(outside.sum()), [_names[i] for i in np.flatnonzero(outside)]


def dominant_ood(vec):
    """Which of the four features the model actually leans on are out of range."""
    _, names = ood(vec)
    return [n for n in DOMINANT if n in names]


def names():
    return list(_names)


def threshold():
    return _threshold


def training_range(name):
    i = _names.index(name)
    return float(_lo[i]), float(_hi[i])