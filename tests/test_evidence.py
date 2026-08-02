"""Per-process locators: extraction, shaping, and both renderers."""
from app import report
from app.db import db
from app.extractors import memory as ex
from app.models import MEMORY, Job


COLLECTED = {
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


def test_memory_report_sections_are_numbered_without_a_duplicate(db, analyst):
    """The evidence section is 5, so Scope and Appendix must renumber to 6 and 7
    rather than colliding with a second 5."""
    from tests.test_report import text_of

    job = _job(db, analyst, ex.evidence(COLLECTED))
    body = text_of(report.render(job, compress=False))
    assert "5. Where these indicators were observed" in body
    assert "6. Scope and limitations" in body
    assert "7. Appendix" in body
    assert "5. Scope and limitations" not in body


def test_memory_report_without_evidence_keeps_scope_at_five(db, analyst):
    from tests.test_report import text_of

    job = _job(db, analyst, None)
    body = text_of(report.render(job, compress=False))
    assert "5. Scope and limitations" in body
    assert "6. Appendix" in body


def test_severity_never_defaults_to_low_when_it_was_not_computed(db, analyst):
    """A missing severity means it could not be scored. Rendering that as Low is
    the wrong failure direction - it reads as 'nothing to worry about'."""
    from tests.test_report import text_of

    job = _job(db, analyst, None)
    body = text_of(report.render(job, compress=False))
    assert "Overall severity: not scored" in body
    assert "Overall severity: Low" not in body
