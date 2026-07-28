import numpy as np
import pytest

from app.config import Config
from app.inference import disk, memory
from app.inference.disk import ModelError

MEM_THRESHOLD = 0.2336726188659668
DISK_THRESHOLD = 0.5010602922493019


@pytest.fixture(scope="module", autouse=True)
def models():
    memory.load(Config.MODELS_DIR, Config.REFERENCE_DIR)
    disk.load(Config.MODELS_DIR, Config.REFERENCE_DIR)


@pytest.fixture(scope="module")
def mem_ref():
    return np.load(Config.REFERENCE_DIR / "memory_sample.npy")


@pytest.fixture(scope="module")
def disk_ref():
    return np.load(Config.REFERENCE_DIR / "disk_sample.npy")


def test_feature_counts():
    assert len(memory.names()) == 55
    assert len(disk.names()) == 150


def test_thresholds_come_from_metadata_and_are_not_half():
    assert memory.threshold() == MEM_THRESHOLD
    assert disk.threshold() == DISK_THRESHOLD
    assert memory.threshold() != 0.5 and disk.threshold() != 0.5


def test_subset_indices_are_not_sorted():
    idx = disk.indices()
    assert len(idx) == 150
    assert idx != sorted(idx), "hard rule 18"
    assert min(idx) >= 0 and max(idx) < 2381
    assert len(set(idx)) == 150


def test_subset_picks_the_positions_the_selected_list_asks_for():
    probe = np.arange(2381, dtype=np.float64)
    assert disk.subset(probe).tolist() == [float(i) for i in disk.indices()]


def test_subset_rejects_a_wrong_width_vector():
    with pytest.raises(ModelError):
        disk.subset(np.zeros(2380))


def test_memory_reference_split_is_bimodal(mem_ref):
    p = memory.predict_batch(mem_ref)
    assert 0.45 <= (p >= memory.threshold()).mean() <= 0.55
    assert ((p > 0.05) & (p < 0.95)).mean() < 0.05


def test_disk_reference_split_is_bimodal(disk_ref):
    p = disk.predict_batch(disk_ref)
    assert 0.45 <= (p >= disk.threshold()).mean() <= 0.55
    assert ((p > 0.05) & (p < 0.95)).mean() < 0.25


@pytest.mark.parametrize("seed", range(8))
def test_scrambled_memory_columns_are_rejected_at_load(mem_ref, seed):
    # Permanent control, not a one-off. Measured over 200 permutations the guard
    # catches all of them, but the failure signature varies - some scrambles push
    # everything above the threshold, others squash it into the middle - so the
    # assertion is "the startup check refuses this", never a fixed statistic.
    perm = np.random.default_rng(seed).permutation(55)
    with pytest.raises(memory.ModelError, match="distribution"):
        memory._check_reference(mem_ref[:, perm])


@pytest.mark.parametrize("seed", range(8))
def test_scrambled_disk_columns_are_rejected_at_load(disk_ref, seed):
    perm = np.random.default_rng(seed).permutation(150)
    with pytest.raises(ModelError, match="distribution"):
        disk._check_reference(disk_ref[:, perm])


def test_the_distribution_check_does_not_catch_small_transpositions(disk_ref):
    """Documents a real limit, so nobody trusts this check further than it goes.

    Swapping two adjacent columns leaves the aggregate distribution intact: 0 of
    149 adjacent swaps are caught on disk and only 5 of 54 on memory. Whole-vector
    scrambles are caught every time. The guard against a two-field transposition
    is therefore structural - vectors are emitted in JSON feature-list order
    rather than hand-sequenced - not statistical.
    """
    perm = list(range(150))
    perm[40], perm[41] = perm[41], perm[40]
    disk._check_reference(disk_ref[:, perm])


def test_sorting_the_subset_indices_changes_the_answer(disk_ref):
    # Guards the specific mistake hard rule 18 describes: both orderings produce
    # a valid 150-vector and neither raises.
    probe = np.zeros(2381)
    probe[disk.indices()] = np.linspace(1, 100, 150)
    right = disk.predict(disk.subset(probe))[0]
    wrong = disk.predict(probe[sorted(disk.indices())])[0]
    assert right != wrong


def test_hand_built_memory_vector_predicts(mem_ref):
    vec = np.median(mem_ref, axis=0)
    p, verdict = memory.predict(vec)
    assert 0.0 <= p <= 1.0
    assert verdict == (p >= memory.threshold())


def test_hand_built_disk_vector_predicts(disk_ref):
    vec = np.median(disk_ref, axis=0)
    p, verdict = disk.predict(vec)
    assert 0.0 <= p <= 1.0
    assert verdict == (p >= disk.threshold())


def test_memory_rejects_a_wrong_length_vector():
    with pytest.raises(memory.ModelError):
        memory.predict(np.zeros(54))


def test_tree_count_is_pinned_not_inherited(mem_ref):
    import xgboost as xgb
    bst = xgb.Booster()
    bst.load_model(str(Config.MODELS_DIR / "memory" / "xgboost_model.json"))
    explicit = bst.inplace_predict(np.ascontiguousarray(mem_ref, dtype=np.float32),
                                   iteration_range=(0, 173))
    assert memory.TREES == (0, 173)
    assert np.allclose(memory.predict_batch(mem_ref), explicit)


def test_ood_is_silent_on_training_rows(mem_ref):
    count, fields = memory.ood(mem_ref[0])
    assert count == 0 and fields == []


def test_ood_flags_a_modern_host(mem_ref):
    # Roughly what a real Windows 10/11 x64 dump produces. Every one of these is
    # outside the single VM build CIC-MalMem-2022 was captured from.
    vec = np.median(mem_ref, axis=0)
    for name, real in (("modules.nmodules", 400), ("svcscan.nservices", 600),
                       ("svcscan.kernel_drivers", 350), ("pslist.nprocs64bit", 40),
                       ("handles.nmutant", 900)):
        vec[memory.names().index(name)] = real

    count, fields = memory.ood(vec)
    assert count >= 5
    assert "modules.nmodules" in fields and "pslist.nprocs64bit" in fields


def test_dominant_ood_reports_the_features_the_model_leans_on(mem_ref):
    vec = np.median(mem_ref, axis=0)
    assert memory.dominant_ood(vec) == []

    for name in memory.DOMINANT:
        lo, hi = memory.training_range(name)
        vec[memory.names().index(name)] = hi * 2 + 1
    assert sorted(memory.dominant_ood(vec)) == sorted(memory.DOMINANT)


def test_the_four_dominant_features_are_the_measured_ones():
    assert set(memory.DOMINANT) == {
        "svcscan.nservices", "handles.nmutant",
        "svcscan.shared_process_services", "svcscan.kernel_drivers"}
    assert all(n in memory.names() for n in memory.DOMINANT)