import logging

import numpy as np

log = logging.getLogger(__name__)

CLASSES = ["Benign", "Malware"]

_memory = None
_disk = None


def _explainer(sample, names, discretize=True):
    from lime.lime_tabular import LimeTabularExplainer

    return LimeTabularExplainer(
        sample, feature_names=list(names), class_names=CLASSES,
        discretize_continuous=discretize, mode="classification",
        # No scaling anywhere in this project - none was used in training and
        # adding one here would silently invalidate both the predictions and the
        # explanations (hard rule 13). LIME standardises internally for its own
        # local model only, which does not touch what we pass to predict.
        random_state=42)


def init(models_dir, reference_dir):
    """Construct both explainers once. Building them is the expensive part; the
    per-prediction call is comparatively cheap."""
    global _memory, _disk
    from .inference import disk, memory

    mem_sample = np.load(reference_dir / "memory_sample.npy")
    disk_sample = np.load(reference_dir / "disk_sample.npy")

    try:
        _memory = _explainer(mem_sample, memory.names())
        # The memory sample has four zero-variance columns; if the quartile
        # discretiser degenerates on them, fall back rather than dropping the
        # columns, which would change the feature space the model was fitted on.
        _memory.explain_instance(mem_sample[0], _proba(memory), num_features=1,
                                 num_samples=20)
    except (ValueError, IndexError) as e:
        log.warning("LIME quartile discretiser failed on the memory sample (%s); "
                    "falling back to discretize_continuous=False", e)
        _memory = _explainer(mem_sample, memory.names(), discretize=False)

    _disk = _explainer(disk_sample, disk.names())


def _proba(model):
    def predict(matrix):
        p = np.asarray(model.predict_batch(matrix), dtype=np.float64)
        return np.column_stack([1.0 - p, p])
    return predict


def _top(explanation, names, limit):
    """Resolve LIME's output through as_map(), never as_list().

    as_list() returns discretised condition strings like
    "malfind.ninjections > 5.00", so a lookup keyed on feature names misses every
    time and yields an empty findings list that looks exactly like "nothing
    matched" (hard rule 19). as_map() gives indices, which we resolve against our
    own JSON feature list - which also keeps names off the model object.
    """
    from .forensics import meanings

    out = []
    for index, weight in explanation.as_map()[1]:
        # Only contributions toward the malicious class are findings; negative
        # weights are evidence the file is benign.
        if weight <= 0:
            continue
        described = meanings.describe(names[index])
        if described is None:
            continue
        described["weight"] = float(weight)
        described["rank"] = len(out) + 1
        out.append(described)
        if len(out) >= limit:
            break
    return out


def memory_findings(vec, num_features=15, display=8):
    from .inference import memory

    if _memory is None:
        raise RuntimeError("explainers not initialised")
    exp = _memory.explain_instance(np.asarray(vec, dtype=np.float64),
                                   _proba(memory), num_features=num_features,
                                   labels=(1,))
    return _top(exp, memory.names(), display)


def disk_findings(vec_150, num_features=15, display=8):
    from .inference import disk

    if _disk is None:
        raise RuntimeError("explainers not initialised")
    exp = _disk.explain_instance(np.asarray(vec_150, dtype=np.float64),
                                 _proba(disk), num_features=num_features,
                                 labels=(1,))
    return _top(exp, disk.names(), display)


def ready():
    return _memory is not None and _disk is not None