import json

import pytest

from app.config import Config
from app.forensics import meanings, mitre, severity
from app.models import CRITICAL, HIGH, LOW, MEDIUM

MEM_NAMES = json.loads((Config.MODELS_DIR / "memory" / "feature_list.json").read_text())
DISK_NAMES = json.loads(
    (Config.MODELS_DIR / "disk" / "feature_list_selected.json").read_text())


def test_every_selected_disk_feature_resolves():
    unresolved = [n for n in DISK_NAMES if meanings.describe(n) is None]
    assert unresolved == []


def test_byte_histogram_is_covered():
    # 26 of the 150 selected features are byte_histogram; an earlier draft of the
    # lookup table omitted the group entirely.
    hist = [n for n in DISK_NAMES if n.startswith("byte_histogram")]
    assert len(hist) == 26
    assert all(meanings.describe(n)["label"] for n in hist)


def test_named_general_features_are_exact():
    assert meanings.describe("general_feat_7")["label"] == "Authenticode signature present"
    assert meanings.describe("general_feat_4")["label"] == "Imported function count"
    assert meanings.describe("general_feat_0")["exact"] is True


def test_data_directory_indices_split_size_and_address():
    # ember writes features[2i] = size, features[2i+1] = virtual address, over
    # _name_order. Index 8/9 is the certificate table.
    assert meanings.describe("datadirectory_feat_8")["label"] == "Certificate table size"
    assert meanings.describe("datadirectory_feat_9")["label"] == \
        "Certificate table virtual address"
    assert "no authenticode signature" in meanings.describe("datadirectory_feat_8")["why"]
    assert meanings.describe("datadirectory_feat_2")["label"] == "Import table size"


def test_named_section_counts_are_exact_and_hashed_ones_are_not():
    assert meanings.describe("section_feat_3")["label"] == "Readable and executable sections"
    assert meanings.describe("section_feat_4")["label"] == "Writable sections"
    assert meanings.describe("section_feat_3")["exact"] is True
    assert meanings.describe("section_feat_96")["exact"] is False
    assert "entropy" in meanings.describe("section_feat_96")["label"].lower()


def test_header_timestamp_is_exact_and_hash_buckets_are_not():
    assert meanings.describe("header_feat_0")["label"] == "Compile timestamp"
    assert meanings.describe("header_feat_53")["label"] == "Major linker version"
    assert meanings.describe("header_feat_11")["exact"] is False


def test_hash_groups_never_claim_a_specific_api():
    # Hard rule 15: imports_hash buckets cannot name a DLL or function.
    for name in [n for n in DISK_NAMES if n.startswith("imports_hash")]:
        d = meanings.describe(name)
        assert d["exact"] is False
        blob = (d["label"] + d["why"]).lower()
        for forbidden in ("createremotethread", "kernel32", "virtualalloc", "ntdll"):
            assert forbidden not in blob


def test_memory_meanings_cover_the_features_tags_rely_on():
    referenced = {f for e in mitre.TAGS if e["pipeline"] == "memory"
                  for f in e.get("features", [])}
    missing = [f for f in referenced if f not in MEM_NAMES]
    assert missing == [], f"tag references features not in the model: {missing}"


def test_banned_techniques_are_absent():
    ids = {e["id"] for e in mitre.TAGS}
    assert not (ids & {"T1179", "T1547.006", "T1574"}), "hard rule 21"


def test_mitre_urls_expand_sub_techniques():
    assert mitre.url("T1055.012") == "https://attack.mitre.org/techniques/T1055/012/"
    assert mitre.url("T1014") == "https://attack.mitre.org/techniques/T1014/"


def test_all_matching_tags_are_emitted_not_just_one():
    matched = mitre.match(
        ["malfind.ninjections", "ldrmodules.not_in_init", "callbacks.nanonymous"],
        "memory")
    tags = {m["tag"] for m in matched}
    assert {"Process Injection", "Hidden Modules / DLL Concealment",
            "Kernel Callbacks / Driver Persistence"} <= tags


def test_service_counts_no_longer_assert_a_persistence_technique():
    """The T1543.003 services row was removed 2026-08-02: a higher service count
    than the baseline is evidence of installed software, not of persistence."""
    assert mitre.match(["svcscan.nservices", "svcscan.kernel_drivers",
                        "svcscan.nactive"], "memory") == []


def test_process_hollowing_needs_both_signals():
    only_ldr = mitre.match(["ldrmodules.not_in_load"], "memory")
    assert "Process Hollowing" not in {m["tag"] for m in only_ldr}

    both = mitre.match(["ldrmodules.not_in_load", "malfind.ninjections"], "memory")
    assert "Process Hollowing" in {m["tag"] for m in both}


def test_disk_groups_match_by_prefix():
    matched = mitre.match(["byte_entropy_247", "imports_hash_1198"], "disk")
    tags = {m["tag"] for m in matched}
    assert tags == {"Obfuscated / Packed Files", "Suspicious API Imports"}


def test_unsigned_binary_stays_low_confidence():
    matched = mitre.match(["general_feat_7", "datadirectory_feat_8"], "disk",
                          values={"general_feat_7": 0, "datadirectory_feat_8": 0})
    entry = next(m for m in matched if "Unsigned" in m["tag"])
    assert entry["confidence"] == "low"
    assert entry["mitre_id"] == "T1553.002"


def test_a_signed_binary_is_not_reported_as_unsigned():
    # general_feat_7 is has_signature and datadirectory_feat_8 is the certificate
    # table size. Both are exact features, so the value is readable and the tag
    # must respect it rather than firing on the feature name alone.
    signed = mitre.match(["general_feat_7", "datadirectory_feat_8"], "disk",
                         values={"general_feat_7": 1, "datadirectory_feat_8": 4312})
    assert not any("Unsigned" in m["tag"] for m in signed)


def test_a_value_aware_tag_stays_silent_without_values():
    # Better to say nothing than to assert something we did not check.
    assert not any("Unsigned" in m["tag"]
                   for m in mitre.match(["general_feat_7"], "disk"))


def test_pipelines_do_not_borrow_each_others_tags():
    assert mitre.match(["malfind.ninjections"], "disk") == []
    assert mitre.match(["byte_entropy_247"], "memory") == []


def test_disk_severity_is_verdict_led():
    low, note = severity.for_disk(0.10, [], 0.5010602922493019)
    assert low == LOW and "0.10" in note

    high, _ = severity.for_disk(0.97, mitre.match(["imports_hash_1", "byte_entropy_2"],
                                                  "disk"), 0.5010602922493019)
    assert high in (HIGH, CRITICAL)


def test_a_clean_capture_matching_its_own_baseline_is_not_critical():
    """The regression that made this rule explicit.

    Every healthy Windows system produces malfind, ldrmodules and psxview hits.
    Scoring on indicators that are merely present matched four high-risk
    categories on the clean reference capture and reported it as Critical, while
    every individual finding read "consistent with a healthy system".
    """
    observed = {"malfind.ninjections": False, "ldrmodules.not_in_init": False,
                "psxview.not_in_pslist": False, "ldrmodules.not_in_load": False}
    standout = mitre.match([f for f, hot in observed.items() if hot], "memory")
    sev, note = severity.for_memory(observed, standout, probability=0.0084,
                                    model_reliable=False)
    assert sev == LOW
    assert "0 high-risk" in note and "baseline" in note


def test_elevated_indicators_do_raise_severity():
    observed = {"malfind.ninjections": True, "ldrmodules.not_in_init": True,
                "psxview.not_in_pslist": True}
    standout = mitre.match([f for f, hot in observed.items() if hot], "memory")
    sev, _ = severity.for_memory(observed, standout, probability=0.5,
                                 model_reliable=False)
    assert sev in (HIGH, CRITICAL)


def test_without_a_baseline_the_claim_is_capped():
    # Nothing to compare against, so presence is all we have - say so and do not
    # escalate past Medium on it.
    present = mitre.match(["malfind.ninjections", "ldrmodules.not_in_init",
                           "psxview.not_in_pslist"], "memory")
    sev, note = severity.for_memory({}, present, baselined=False)
    assert sev == MEDIUM
    assert "no clean-system baseline" in note


def test_memory_severity_ignores_the_model_when_out_of_distribution():
    matched = mitre.match(["malfind.ninjections", "ldrmodules.not_in_init",
                           "psxview.not_in_pslist"], "memory")
    sev, note = severity.for_memory({}, matched, probability=0.99,
                                    model_reliable=False)
    assert sev in (HIGH, CRITICAL)
    assert "withheld" in note
    assert "0.99" not in note


def test_memory_severity_is_driven_by_observations_not_the_score():
    # No indicators at all: a confident but unreliable score must not manufacture
    # severity on its own.
    sev, _ = severity.for_memory({}, [], probability=0.99, model_reliable=False)
    assert sev == LOW


def test_memory_score_contributes_but_never_drives():
    matched = mitre.match(["malfind.ninjections"], "memory")
    without = severity.for_memory({}, matched, probability=0.99, model_reliable=False)[0]
    with_score = severity.for_memory({}, matched, probability=0.99, model_reliable=True)[0]
    assert without == MEDIUM
    assert with_score == HIGH

    # Even a reliable, confident score cannot reach Critical unaided, and cannot
    # move anything when no indicator matched at all.
    assert severity.for_memory({}, [], probability=1.0, model_reliable=True)[0] == LOW
    everything = mitre.match(["malfind.ninjections", "ldrmodules.not_in_init",
                              "psxview.not_in_pslist", "svcscan.kernel_drivers",
                              "callbacks.nanonymous"], "memory")
    assert severity.for_memory({}, everything, probability=1.0,
                               model_reliable=True)[0] == CRITICAL


def test_severity_note_is_human_readable():
    _, note = severity.for_disk(0.94, mitre.match(["imports_hash_1"], "disk"),
                                0.5010602922493019)
    assert "model confidence 0.94" in note
    assert "high-risk" in note


def test_disclaimer_text_is_present_and_specific():
    assert "investigative leads" in mitre.DISCLAIMER
    assert "not from observed runtime behavior" in mitre.DISCLAIMER