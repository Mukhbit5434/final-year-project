import json

import lightgbm as lgb
import numpy as np

_booster = None
_selected = None
_idx = None
_threshold = None

FULL_DIM = 2381
SELECTED_DIM = 150


class ModelError(RuntimeError):
    pass


def load(models_dir, reference_dir):
    global _booster, _selected, _idx, _threshold

    here = models_dir / "disk"
    _selected = json.loads((here / "feature_list_selected.json").read_text())
    full = json.loads((here / "feature_list_full_2381.json").read_text())
    meta = json.loads((here / "metadata.json").read_text())
    _threshold = meta["threshold"]

    if _threshold == 0.5:
        raise ModelError("disk threshold read as 0.5 - metadata.json is wrong")
    if len(full) != FULL_DIM:
        raise ModelError(f"full feature list has {len(full)} names, expected {FULL_DIM}")

    _booster = lgb.Booster(model_file=str(here / "lightgbm_model.txt"))

    n = _booster.num_feature()
    if n != len(_selected) or n != SELECTED_DIM:
        raise ModelError(f"disk model has {n} features, selected list has {len(_selected)}")

    pos = {name: i for i, name in enumerate(full)}
    missing = [name for name in _selected if name not in pos]
    if missing:
        raise ModelError(f"{len(missing)} selected features absent from the 2381 list: "
                         f"{missing[:3]}")

    _idx = [pos[name] for name in _selected]
    if _idx == sorted(_idx):
        raise ModelError("subset indices came out sorted; the selected list order was lost")

    ref = np.load(reference_dir / "disk_sample.npy")
    if ref.shape[1] != SELECTED_DIM:
        raise ModelError(f"disk_sample.npy has {ref.shape[1]} columns, expected {SELECTED_DIM}")
    if not np.isfinite(ref).all():
        raise ModelError("disk_sample.npy contains NaN or Inf")

    _check_reference(ref)
    return len(_selected)


def _check_reference(ref):
    p = predict_batch(ref)
    above = float((p >= _threshold).mean())
    mid = float(((p > 0.05) & (p < 0.95)).mean())
    if not 0.45 <= above <= 0.55 or mid > 0.25:
        raise ModelError(
            f"disk reference distribution looks wrong: {above:.3f} above threshold "
            f"(expect ~0.49), {mid:.3f} in the 0.05-0.95 band (expect ~0.13). "
            "A permuted feature order is the usual cause.")


def subset(vec_2381):
    """2381 EMBER features down to the 150 the model was fitted on."""
    vec = np.asarray(vec_2381)
    if vec.shape[-1] != FULL_DIM:
        raise ModelError(f"expected {FULL_DIM} features from EMBER, got {vec.shape[-1]}")
    return vec[..., _idx]


def predict_batch(mat):
    mat = np.ascontiguousarray(mat, dtype=np.float64)
    return _booster.predict(mat)


def predict(vec_150):
    if len(vec_150) != SELECTED_DIM:
        raise ModelError(f"expected a {SELECTED_DIM}-length vector, got {len(vec_150)}")
    p = float(predict_batch(np.asarray(vec_150).reshape(1, -1))[0])
    return p, p >= _threshold


def names():
    return list(_selected)


def indices():
    return list(_idx)


def threshold():
    return _threshold