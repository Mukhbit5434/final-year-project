import json

import pytest

from app.config import Config
from app.extractors import memory as ex

NAMES = json.loads((Config.MODELS_DIR / "memory" / "feature_list.json").read_text())


def sample_parts():
    pslist = [{"PID": 4, "PPID": 0, "Threads": 100, "Handles": 2000, "Wow64": False},
              {"PID": 88, "PPID": 4, "Threads": 20, "Handles": 400, "Wow64": True},
              {"PID": 92, "PPID": 4, "Threads": 10, "Handles": 200, "Wow64": False}]
    dlllist = [{"PID": 4}] * 40 + [{"PID": 88}] * 20
    handles = ([{"PID": 4, "Type": "File"}] * 5 + [{"PID": 4, "Type": "Key"}] * 3 +
               [{"PID": 88, "Type": "Mutant"}] * 2 + [{"PID": 88, "Type": "Section"}])
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
    parts = [ex.from_pslist(pslist, len(handles)),
             ex.from_dlllist(dlllist),
             ex.from_handles(handles), ex.from_ldrmodules(ldrmodules),
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


def test_dll_average_divides_by_processes_present_in_dlllist():
    assert values()["dlllist.avg_dlls_per_proc"] == pytest.approx(30.0)


def test_handle_average_divides_by_processes_holding_handles():
    assert values()["handles.avg_handles_per_proc"] == pytest.approx(11 / 2)


def test_nprocs64bit_counts_wow64_processes_despite_its_name():
    assert values()["pslist.nprocs64bit"] == 1


def test_avg_handlers_uses_the_handles_plugin_not_the_pslist_column():
    rows = [{"PID": 4, "PPID": 0, "Threads": 10}, {"PID": 8, "PPID": 4, "Threads": 10}]
    assert ex.from_pslist(rows, 900)["pslist.avg_handlers"] == pytest.approx(450.0)


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
    assert v["callbacks.nanonymous"] == 1
    assert v["callbacks.ngeneric"] == 1


def test_service_types_match_exactly_never_by_substring():
    rows = [{"Type": "SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS",
             "State": "SERVICE_RUNNING"},
            {"Type": "SERVICE_WIN32_OWN_PROCESS", "State": "SERVICE_STOPPED"}]
    out = ex.from_svcscan(rows)
    assert out["svcscan.interactive_process_services"] == 0
    assert out["svcscan.process_services"] == 1


def test_duplicate_service_records_are_collapsed_by_order():
    rows = [{"Order": 1, "Name": "Wlansvc", "Type": "SERVICE_KERNEL_DRIVER"},
            {"Order": 1, "Name": "Wlansvc", "Type": "SERVICE_KERNEL_DRIVER"},
            {"Order": 1, "Name": "Wlansvc", "Type": "SERVICE_KERNEL_DRIVER"},
            {"Order": 2, "Name": "WinRM", "Type": "SERVICE_KERNEL_DRIVER"}]
    out = ex.dedupe_services(rows)
    assert len(out) == 2
    assert ex.from_svcscan(out)["svcscan.nservices"] == 2


def test_feature_count_is_locked_at_55():
    assert ex.FEATURE_COUNT == 55
    assert len(NAMES) == 55
    with pytest.raises(ex.ExtractionError, match="55 feature names"):
        ex.assemble(*sample_parts()[:1], NAMES + ["apihooks.nhooks"])


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
    _, gaps = ex.assemble(*sample_parts()[:1], NAMES)
    assert len(gaps) >= 14


def test_division_by_zero_yields_zero_not_a_crash():
    assert ex.from_dlllist([])["dlllist.avg_dlls_per_proc"] == 0.0
    assert ex.from_handles([])["handles.avg_handles_per_proc"] == 0.0
    assert ex.from_ldrmodules([])["ldrmodules.not_in_load_avg"] == 0.0
    assert ex.from_psxview([])["psxview.not_in_pslist_false_avg"] == 0.0


def test_all_nine_plugins_exist_in_the_installed_volatility():
    from volatility3 import framework
    import volatility3.plugins

    framework.import_files(volatility3.plugins, True)
    catalog = framework.list_plugins()
    for key, plugin in ex.PLUGINS.items():
        assert plugin in catalog, f"{key} -> {plugin} missing"


def test_local_symbols_go_to_the_front_of_the_search_path(monkeypatch, tmp_path):
    """Offline analysis depends on the repo-local ISF cache being consulted first;
    volatility's own cache lives in the user's AppData, outside the project."""
    import volatility3.symbols

    original = list(volatility3.symbols.__path__)
    monkeypatch.setattr(ex, "SYMBOLS", tmp_path)
    try:
        ex._use_local_symbols()
        assert volatility3.symbols.__path__[0] == str(tmp_path)
        ex._use_local_symbols()
        assert volatility3.symbols.__path__.count(str(tmp_path)) == 1, "not idempotent"
    finally:
        volatility3.symbols.__path__ = original


def test_local_symbols_is_a_no_op_when_the_directory_is_absent(monkeypatch, tmp_path):
    import volatility3.symbols

    original = list(volatility3.symbols.__path__)
    monkeypatch.setattr(ex, "SYMBOLS", tmp_path / "nope")
    ex._use_local_symbols()
    assert list(volatility3.symbols.__path__) == original


def test_psxview_still_exposes_only_the_four_columns_we_mapped():
    import inspect

    from volatility3 import framework
    import volatility3.plugins

    framework.import_files(volatility3.plugins, True)
    src = inspect.getsource(framework.list_plugins()[ex.PLUGINS["psxview"]].run)
    for column in ("pslist", "psscan", "thrdscan", "csrss"):
        assert f'("{column}", bool)' in src
    for absent in ("pspcid", "session", "deskthrd"):
        assert f'("{absent}", bool)' not in src