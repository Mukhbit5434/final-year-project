"""Per-process locators: extraction, shaping, and both renderers."""
from app import report
from app.db import db
from app.extractors import memory as ex
from app.models import MEMORY, Job


COLLECTED = {
    # PID/PPID/name chain deliberately covering every PID the other plugins'
    # rows below reference, plus one (PID 4's own PPID, 0) that pslist never
    # enumerates at all - the real shape of "System"'s real parent on Windows.
    "pslist": [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 660, "PPID": 4, "ImageFileName": "explorer.exe"},
        {"PID": 1204, "PPID": 660, "ImageFileName": "svchost.exe"},
        {"PID": 8, "PPID": 4, "ImageFileName": "fine.exe"},
        {"PID": 900, "PPID": 4, "ImageFileName": "normal.exe"},
        {"PID": 4512, "PPID": 900, "ImageFileName": "hidden.exe"},
    ],
    "malfind": [
        {"PID": 1204, "Process": "svchost.exe", "Start VPN": 0x7ff800000000,
         "End VPN": 0x7ff800000fff, "Protection": "PAGE_EXECUTE_READWRITE",
         "CommitCharge": 1, "PrivateMemory": 1},
        {"PID": 660, "Process": "explorer.exe", "Start VPN": 0x1000,
         "End VPN": 0x100fff, "Protection": "PAGE_EXECUTE_READWRITE",
         "CommitCharge": 256, "PrivateMemory": 1},
    ],
    "ldrmodules": [
        {"Pid": 660, "Process": "explorer.exe", "Base": 0x400000, "InLoad": False,
         "InInit": False, "InMem": False, "MappedPath": r"\Device\HD\evil.dll"},
        {"Pid": 4, "Process": "System", "Base": 0x500000, "InLoad": True,
         "InInit": False, "InMem": True, "MappedPath": r"\Device\HD\ok.dll"},
        {"Pid": 8, "Process": "fine.exe", "Base": 0x600000, "InLoad": True,
         "InInit": True, "InMem": True, "MappedPath": r"\Device\HD\fine.dll"},
    ],
    "psxview": [
        {"Name": "hidden.exe", "PID": 4512, "pslist": False, "psscan": True,
         "thrdscan": False, "csrss": True, "Exit Time": ""},
        {"Name": "normal.exe", "PID": 900, "pslist": True, "psscan": True,
         "thrdscan": True, "csrss": True, "Exit Time": ""},
    ],
    "callbacks": [
        {"Type": "GenericKernelCallback", "Callback": 0xfffff80012345678,
         "Module": "UNKNOWN", "Symbol": "-"},
        {"Type": "GenericKernelCallback", "Callback": 0xfffff80087654321,
         "Module": "ntoskrnl.exe", "Symbol": "Ki"},
    ],
}


def test_injected_regions_carry_process_address_and_size():
    ev = ex.evidence(COLLECTED)
    first = ev["injected_regions"][0]
    # Largest first: a 1 MB RWX region outranks a single 4 KB page.
    assert first["process"] == "explorer.exe"
    assert first["size"] == 0x100000
    assert first["start"] == "0x1000"
    assert first["protection"] == "PAGE_EXECUTE_READWRITE"


def test_only_modules_actually_missing_from_a_list_are_reported():
    ev = ex.evidence(COLLECTED)
    mods = ev["hidden_modules"]
    assert len(mods) == 2, "the module present in all three lists must not appear"
    assert mods[0]["absent_from"] == ["load", "init", "mem"]
    assert mods[0]["path"].endswith("evil.dll")


def test_only_processes_missing_from_an_enumeration_are_reported():
    ev = ex.evidence(COLLECTED)
    procs = ev["hidden_processes"]
    assert [p["pid"] for p in procs] == [4512]
    assert procs[0]["missing_from"] == ["pslist", "thrdscan"]
    assert procs[0]["exit_time"] is None


def test_only_unbacked_callbacks_are_reported():
    ev = ex.evidence(COLLECTED)
    assert len(ev["unbacked_callbacks"]) == 1
    assert ev["unbacked_callbacks"][0]["callback"] == "0xfffff80012345678"


def test_parent_process_is_resolved_for_named_processes():
    """ImageFileName has never been read anywhere in this codebase before this
    feature - confirmed against the real installed volatility3.PsList source,
    not assumed. This is the first test that actually exercises it."""
    ev = ex.evidence(COLLECTED)
    by_process = {d["process"]: d["parent"] for d in ev["injected_regions"]}
    assert by_process["explorer.exe"] == {"pid": 4, "name": "System"}
    assert by_process["svchost.exe"] == {"pid": 660, "name": "explorer.exe"}

    hidden = {d["pid"]: d["parent"] for d in ev["hidden_processes"]}
    assert hidden[4512] == {"pid": 900, "name": "normal.exe"}


def test_parent_is_unresolved_but_present_for_a_pid_pslist_never_saw():
    # PID 4's own real PPID is 0 - the System Idle Process, which pslist does
    # not enumerate as a row of its own. The parent PID is still known; only
    # its name cannot be filled in, and that must read as unresolved, not as
    # "no parent at all".
    mods = {d["pid"]: d["parent"] for d in ex.evidence(COLLECTED)["hidden_modules"]}
    assert mods[4] == {"pid": 0, "name": None}


def test_parent_is_none_with_no_pslist_data_at_all():
    # The exact shape every fixture in this file used before parent
    # resolution was added - must degrade to "no parent info", not crash.
    ev = ex.evidence({"malfind": COLLECTED["malfind"]})
    assert all(d["parent"] is None for d in ev["injected_regions"])


def test_parent_lookup_excludes_torn_pslist_rows():
    collected = dict(COLLECTED)
    collected["pslist"] = [
        {"PID": 660, "PPID": 88804946376740, "ImageFileName": "explorer.exe"},
    ]
    explorer = [d for d in ex.evidence(collected)["injected_regions"]
               if d["process"] == "explorer.exe"][0]
    assert explorer["parent"] is None, "an insane PPID must not be resolved as real"


def test_totals_count_everything_found_not_what_survived_the_cap(monkeypatch):
    monkeypatch.setattr(ex, "EVIDENCE_CAP", 1)
    ev = ex.evidence(COLLECTED)
    assert len(ev["injected_regions"]) == 1
    assert ev["totals"]["injected_regions"] == 2, "the cap must not hide the real count"


def test_evidence_survives_empty_and_malformed_rows():
    ev = ex.evidence({"malfind": [{"PID": None, "Start VPN": None, "End VPN": None}]})
    assert ev["injected_regions"][0]["size"] is None
    assert ev["hidden_modules"] == []
    assert ex.evidence({})["totals"]["injected_regions"] == 0


class Unreadable:
    """Stands in for volatility's renderer objects - BitField, UnreadableValue.

    The real ones pickle inside the worker and fail on the way back out, which
    kills the pool with BrokenProcessPool rather than failing the one job. This
    is the bug that broke the first evidence run; the unit tests missed it
    because their fixtures used plain ints.
    """

    def __int__(self):
        raise ValueError("unreadable")

    def __str__(self):
        return "-"


def test_evidence_holds_only_builtins_and_survives_pickling():
    import pickle

    rows = {
        "malfind": [{"PID": Unreadable(), "Process": "x.exe",
                     "Start VPN": Unreadable(), "End VPN": Unreadable(),
                     "Protection": "PAGE_EXECUTE_READWRITE",
                     "CommitCharge": Unreadable(), "PrivateMemory": Unreadable()}],
        "ldrmodules": [{"Pid": Unreadable(), "Process": "y.exe", "Base": Unreadable(),
                        "InLoad": False, "InInit": True, "InMem": True,
                        "MappedPath": "p"}],
        "psxview": [{"Name": "z.exe", "PID": Unreadable(), "pslist": False,
                     "psscan": True, "thrdscan": True, "csrss": True,
                     "Exit Time": ""}],
        "callbacks": [{"Type": "T", "Callback": Unreadable(), "Module": "UNKNOWN",
                       "Symbol": "s"}],
    }
    ev = ex.evidence(rows)

    def check(node):
        if isinstance(node, dict):
            [check(v) for v in node.values()]
        elif isinstance(node, list):
            [check(v) for v in node]
        else:
            assert node is None or type(node) in (int, float, str, bool), repr(node)

    check(ev)
    assert pickle.loads(pickle.dumps(ev)) == ev
    assert ev["injected_regions"][0]["pid"] is None
    assert ev["injected_regions"][0]["size"] is None


def _job(db, analyst, evidence):
    job = Job(user=analyst, filename="m.raw", stored_name=f"ev{id(evidence)}.raw",
              sha256="e" * 64, size_bytes=2 * 1024 ** 3, artifact=MEMORY,
              status="COMPLETED", ood_count=21, evidence=evidence)
    db.session.add(job)
    db.session.commit()
    return job


def test_evidence_rows_skips_empty_categories(db, analyst):
    job = _job(db, analyst, ex.evidence(COLLECTED))
    headings = [h for h, _, _, _, _ in report.evidence_rows(job)]
    assert "Injected executable memory" in headings
    assert len(headings) == 4

    bare = _job(db, analyst, ex.evidence({}))
    assert report.evidence_rows(bare) == []


def test_a_memory_job_without_evidence_still_renders(db, analyst):
    job = _job(db, analyst, None)
    assert report.evidence_rows(job) == []
    assert report.render(job, compress=False).startswith(b"%PDF")


def test_locators_reach_the_rendered_pdf(db, analyst):
    from tests.test_report import text_of

    job = _job(db, analyst, ex.evidence(COLLECTED))
    body = text_of(report.render(job, compress=False))
    assert "svchost.exe" in body
    assert "explorer.exe" in body
    assert "hidden.exe" in body
    assert "evil.dll" in body


def test_locators_reach_the_job_page(client, signed_in, db, analyst):
    job = _job(db, analyst, ex.evidence(COLLECTED))
    body = client.get(f"/jobs/{job.id}").get_data(as_text=True)
    assert "Where these indicators were observed" in body
    assert "svchost.exe" in body and "evil.dll" in body


def test_parent_process_column_reaches_the_rendered_pdf(db, analyst):
    from tests.test_report import text_of

    job = _job(db, analyst, ex.evidence(COLLECTED))
    body = text_of(report.render(job, compress=False))
    assert "Parent process" in body
    assert "explorer.exe, PID 660" in body, "svchost.exe's resolved parent, by name and PID"


def test_parent_process_column_reaches_the_job_page(client, signed_in, db, analyst):
    job = _job(db, analyst, ex.evidence(COLLECTED))
    body = client.get(f"/jobs/{job.id}").get_data(as_text=True)
    assert "Parent process" in body
    assert "explorer.exe, PID 660" in body


def test_memory_report_sections_are_numbered_without_a_duplicate(db, analyst):
    """The evidence section is 5, so Scope and limitations must renumber to 6
    rather than colliding with a second 5. There is no Appendix section any more
    (CLAUDE.md §18, seventh pass) - Scope and limitations is the last section."""
    from tests.test_report import text_of

    job = _job(db, analyst, ex.evidence(COLLECTED))
    body = text_of(report.render(job, compress=False))
    assert "5. Where these indicators were observed" in body
    assert "6. Scope and limitations" in body
    assert "5. Scope and limitations" not in body
    assert "Appendix" not in body


def test_memory_report_without_evidence_keeps_scope_at_five(db, analyst):
    from tests.test_report import text_of

    job = _job(db, analyst, None)
    body = text_of(report.render(job, compress=False))
    assert "5. Scope and limitations" in body
    assert "Appendix" not in body


def test_severity_never_defaults_to_low_when_it_was_not_computed(db, analyst):
    """A missing severity means it could not be scored. Rendering that as Low is
    the wrong failure direction - it reads as 'nothing to worry about'."""
    from tests.test_report import text_of

    job = _job(db, analyst, None)
    body = text_of(report.render(job, compress=False))
    assert "Overall severity: not scored" in body
    assert "Overall severity: Low" not in body
