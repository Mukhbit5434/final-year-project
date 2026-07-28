import json

import pytest

from app.config import Config
from app.extractors import memory as ex

NAMES = json.loads((Config.MODELS_DIR / "memory" / "feature_list.json").read_text())


def sample_parts():
    pslist = [{"PID": 4, "PPID": 0, "Threads": 100, "Handles": 2000, "Wow64": False},
              {"PID": 88, "PPID": 4, "Threads": 20, "Handles": 400, "Wow64": True},
              {"PID": 92, "PPID": 4, "Threads": 10, "Handles": 200, "Wow64": False}]
    dlllist = [{"PID": 4}] * 60
    handles = ([{"Type": "File"}] * 5 + [{"Type": "Key"}] * 3 +
               [{"Type": "Mutant"}] * 2 + [{"Type": "Section"}])
    ldrmodules = [{"InLoad": True, "InInit": True, "InMem": True},
                  {"InLoad": False, "InInit": False, "InMem": True},
                  {"InLoad": True, "InInit": False, "InMem": True},
                  {"InLoad": True, "InInit": True, "InMem": False}]
    malfind = [{"PID": 88, "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 3},
               {"PID": 88, "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 5},
               {"PID": 92, "Protection": "PAGE_EXECUTE_READ", "CommitCharge": 1}]
    psxview = [{"pslist": True, "psscan": True, "thrdscan": True, "csrss": True},
               {"pslist": False, "psscan": True, "thrdscan": True, "csrss": False},
               {"pslist": True, "psscan": True, "thrdscan": False, "csrss": True}]
    modules = [{"Name": f"drv{i}.sys"} for i in range(7)]
    svcscan = [{"Type": "SERVICE_KERNEL_DRIVER", "State": "SERVICE_RUNNING"},
               {"Type": "SERVICE_KERNEL_DRIVER", "State": "SERVICE_STOPPED"},
               {"Type": "SERVICE_FILE_SYSTEM_DRIVER", "State": "SERVICE_RUNNING"},
               {"Type": "SERVICE_WIN32_OWN_PROCESS", "State": "SERVICE_RUNNING"},
               {"Type": "SERVICE_WIN32_SHARE_PROCESS", "State": "SERVICE_STOPPED"}]
    callbacks = [{"Type": "PsSetCreateProcessNotifyRoutine", "Module": "ntoskrnl.exe"},
                 {"Type": "GenericKernelCallback", "Module": ""},
                 {"Type": "KeBugCheckCallbackListHead", "Module": "UNKNOWN"}]

    nproc = len(pslist)
    malfind_fields, unknown = ex.from_malfind(malfind, nproc)
    parts = [ex.from_pslist(pslist), ex.from_dlllist(dlllist, nproc),
             ex.from_handles(handles, nproc), ex.from_ldrmodules(ldrmodules),
             malfind_fields, ex.from_psxview(psxview), ex.from_modules(modules),
             ex.from_svcscan(svcscan), ex.from_callbacks(callbacks)]
    return parts, unknown


def values():
    parts, _ = sample_parts()
    merged = {}
    for p in parts:
        merged.update(p)
    return merged


def test_every_one_of_the_55_features_is_produced():
    vec, _ = ex.assemble(*sample_parts()[:1], NAMES)
    assert len(vec) == 55


def test_the_vector_follows_json_order_not_insertion_order():
    # The startup distribution check catches a full scramble but only 5 of 54
    # adjacent swaps, so ordering here has to be structural.
    parts, unknown = sample_parts()
    vec, _ = ex.assemble(parts, NAMES, unknown)
    merged = values()
    assert vec == [float(merged[name]) for name in NAMES]

    shuffled = list(reversed(NAMES))
    other, _ = ex.assemble(parts, shuffled, unknown)
    assert other == list(reversed(vec))


def test_a_missing_field_fails_loudly_rather_than_defaulting():
    parts, _ = sample_parts()
    del parts[0]["pslist.nproc"]
    with pytest.raises(ex.ExtractionError, match="no value for"):
        ex.assemble(parts, NAMES)


def test_an_unknown_field_fails_loudly():
    parts, _ = sample_parts()
    parts[0]["pslist.invented"] = 1.0
    with pytest.raises(ex.ExtractionError, match="unknown features"):
        ex.assemble(parts, NAMES)


def test_process_and_dll_counts():
    v = values()
    assert v["pslist.nproc"] == 3
    assert v["pslist.nppid"] == 2
    assert v["pslist.avg_threads"] == pytest.approx(130 / 3)
    assert v["dlllist.ndlls"] == 60
    assert v["dlllist.avg_dlls_per_proc"] == pytest.approx(20.0)


def test_nprocs64bit_counts_non_wow64_processes():
    # Constant 0 in training because the dataset came off a 32-bit VM. Emitted
    # honestly anyway; the OOD check is what covers the resulting out-of-range
    # value on a modern host.
    assert values()["pslist.nprocs64bit"] == 2


def test_handle_types_are_counted_and_port_is_zero():
    v = values()
    assert v["handles.nhandles"] == 11
    assert v["handles.nfile"] == 5 and v["handles.nkey"] == 3
    assert v["handles.nmutant"] == 2 and v["handles.nsection"] == 1
    assert v["handles.nevent"] == 0
    assert v["handles.nport"] == 0.0


def test_ldrmodules_avg_divides_by_its_own_row_count():
    v = values()
    assert v["ldrmodules.not_in_load"] == 1
    assert v["ldrmodules.not_in_init"] == 2
    assert v["ldrmodules.not_in_mem"] == 1
    assert v["ldrmodules.not_in_init_avg"] == pytest.approx(2 / 4)


def test_malfind_protection_sums_volatility2_indices():
    # PAGE_EXECUTE_READWRITE is index 6, PAGE_EXECUTE_READ is 3 -> 6 + 6 + 3.
    v = values()
    assert v["malfind.protection"] == 15.0
    assert v["malfind.ninjections"] == 3
    assert v["malfind.commitCharge"] == 9
    assert v["malfind.uniqueInjections"] == pytest.approx(1.5)


def test_an_unrecognised_protection_flag_is_disclosed_not_guessed():
    rows = [{"PID": 1, "Protection": "PAGE_SOMETHING_NEW", "CommitCharge": 1}]
    fields, unknown = ex.from_malfind(rows, 1)
    assert fields["malfind.protection"] == 0.0
    assert unknown == {"PAGE_SOMETHING_NEW"}

    parts, _ = sample_parts()
    _, gaps = ex.assemble(parts, NAMES, unknown)
    assert any("PAGE_SOMETHING_NEW" in g["reason"] for g in gaps)


def test_psxview_maps_the_four_available_sources():
    v = values()
    assert v["psxview.not_in_pslist"] == 1
    assert v["psxview.not_in_eprocess_pool"] == 0
    assert v["psxview.not_in_ethread_pool"] == 1
    assert v["psxview.not_in_csrss_handles"] == 1
    assert v["psxview.not_in_csrss_handles_false_avg"] == pytest.approx(1 / 3)


def test_the_three_unavailable_psxview_sources_are_zero_not_invented():
    v = values()
    for field in ("not_in_pspcid_list", "not_in_session", "not_in_deskthrd"):
        assert v[f"psxview.{field}"] == 0.0
        assert v[f"psxview.{field}_false_avg"] == 0.0


def test_svcscan_and_callback_counts():
    v = values()
    assert v["svcscan.nservices"] == 5
    assert v["svcscan.kernel_drivers"] == 2
    assert v["svcscan.fs_drivers"] == 1
    assert v["svcscan.nactive"] == 3
    assert v["svcscan.interactive_process_services"] == 0
    assert v["callbacks.ncallbacks"] == 3
    assert v["callbacks.nanonymous"] == 2
    assert v["callbacks.ngeneric"] == 1


def test_gaps_separate_missing_fields_from_inferred_ones():
    parts, unknown = sample_parts()
    _, gaps = ex.assemble(parts, NAMES, unknown)

    missing = {g["field"] for g in gaps if g["confidence"] == "missing"}
    inferred = {g["field"] for g in gaps if g["confidence"] == "inferred"}

    assert missing == {
        "psxview.not_in_pspcid_list", "psxview.not_in_pspcid_list_false_avg",
        "psxview.not_in_session", "psxview.not_in_session_false_avg",
        "psxview.not_in_deskthrd", "psxview.not_in_deskthrd_false_avg"}
    assert "malfind.protection" in inferred
    assert "malfind.uniqueInjections" in inferred
    assert all(g["reason"] and g["plugin"] for g in gaps)


def test_the_gap_list_is_never_empty():
    # An empty extraction_gaps would be a lie: six features cannot be produced by
    # Volatility 3 at all (hard rule 8).
    _, gaps = ex.assemble(*sample_parts()[:1], NAMES)
    assert len(gaps) >= 14


def test_division_by_zero_yields_zero_not_a_crash():
    assert ex.from_dlllist([], 0)["dlllist.avg_dlls_per_proc"] == 0.0
    assert ex.from_ldrmodules([])["ldrmodules.not_in_load_avg"] == 0.0
    assert ex.from_psxview([])["psxview.not_in_pslist_false_avg"] == 0.0


def test_all_nine_plugins_exist_in_the_installed_volatility():
    from volatility3 import framework
    import volatility3.plugins

    framework.import_files(volatility3.plugins, True)
    catalog = framework.list_plugins()
    for key, plugin in ex.PLUGINS.items():
        assert plugin in catalog, f"{key} -> {plugin} missing"


def test_psxview_still_exposes_only_the_four_columns_we_mapped():
    # If a volatility3 upgrade restores pspcid/session/deskthrd this fails, which
    # is the point - the mapping must be rebuilt from the installed source.
    import inspect

    from volatility3 import framework
    import volatility3.plugins

    framework.import_files(volatility3.plugins, True)
    src = inspect.getsource(framework.list_plugins()["windows.psxview.PsXView"].run)
    for column in ("pslist", "psscan", "thrdscan", "csrss"):
        assert f'("{column}", bool)' in src
    for absent in ("pspcid", "session", "deskthrd"):
        assert f'("{absent}", bool)' not in src