import hashlib
import io

import pytest

from app import artifacts
from app.db import db
from app.models import DISK, MEMORY, NEEDS_TYPE, PENDING, AuditLog, Job, User

MBR = b"\x33\xc0" + b"\x00" * 508 + b"\x55\xaa" + b"\x00" * 512
GPT = b"\x00" * 512 + b"EFI PART" + b"\x00" * 504
CRASH = b"PAGEDU64" + b"\x00" * 1016
VMEM = bytes(range(256)) * 8


def send(client, data, name="image.dd", artifact="auto", case_ref=None):
    payload = {"artifact_file": (io.BytesIO(data), name), "artifact": artifact}
    if case_ref is not None:
        payload["case_ref"] = case_ref
    return client.post("/upload", data=payload,
                       content_type="multipart/form-data", follow_redirects=False)


def test_mbr_is_detected_as_disk(client, signed_in):
    send(client, MBR)
    job = db.session.query(Job).one()
    assert job.artifact == DISK and job.status == PENDING
    assert "MBR" in job.detected_as


def test_gpt_is_detected_as_disk(client, signed_in):
    send(client, GPT, name="image.raw")
    assert db.session.query(Job).one().artifact == DISK


def test_crash_dump_header_is_detected_as_memory(client, signed_in):
    send(client, CRASH, name="memory.dmp")
    job = db.session.query(Job).one()
    assert job.artifact == MEMORY and "PAGEDU64" in job.detected_as


def test_headerless_raw_asks_the_analyst(client, signed_in):
    r = send(client, VMEM, name="capture.raw")
    job = db.session.query(Job).one()
    assert job.artifact is None and job.status == NEEDS_TYPE
    assert f"/jobs/{job.id}/type" in r.headers["Location"]


def test_absence_of_a_disk_signature_is_not_treated_as_memory(client, signed_in):
    send(client, VMEM, name="capture.raw")
    assert db.session.query(Job).one().artifact is None


def test_analyst_can_resolve_an_ambiguous_artifact(client, signed_in):
    send(client, VMEM, name="capture.raw")
    job = db.session.query(Job).one()

    client.post(f"/jobs/{job.id}/type", data={"artifact": MEMORY})
    db.session.refresh(job)
    assert job.artifact == MEMORY and job.status == PENDING
    assert db.session.query(AuditLog).filter_by(action="artifact_type_set").count() == 1


def test_explicit_type_skips_detection(client, signed_in):
    send(client, VMEM, name="capture.raw", artifact=MEMORY)
    job = db.session.query(Job).one()
    assert job.artifact == MEMORY and "analyst" in job.detected_as


def test_sha256_matches_the_uploaded_bytes(client, signed_in):
    send(client, MBR)
    assert db.session.query(Job).one().sha256 == hashlib.sha256(MBR).hexdigest()


def test_stored_name_is_ours_not_the_clients(client, signed_in):
    send(client, MBR, name="../../../../windows/system32/evil.dd")
    job = db.session.query(Job).one()
    assert ".." not in job.stored_name and "/" not in job.stored_name
    assert job.stored_name.endswith(".dd")
    # the original is kept for the report, but only ever as a display string
    assert ".." in job.filename


def test_case_reference_is_optional_and_uploads_without_one_work_exactly_as_before(
        client, signed_in):
    send(client, MBR)
    job = db.session.query(Job).one()
    assert job.case_reference is None
    assert job.artifact == DISK and job.status == PENDING


def test_case_reference_is_stored_when_supplied(client, signed_in):
    send(client, MBR, case_ref="CASE-2026-0142")
    assert db.session.query(Job).one().case_reference == "CASE-2026-0142"


def test_case_reference_is_trimmed_and_blank_becomes_none(client, signed_in):
    send(client, MBR, case_ref="   ")
    assert db.session.query(Job).one().case_reference is None


def test_disallowed_extension_is_refused(client, signed_in):
    send(client, MBR, name="payload.exe")
    assert db.session.query(Job).count() == 0
    assert db.session.query(AuditLog).filter_by(action="upload_rejected").count() == 1


def test_upload_is_audited_with_hash_and_size(client, signed_in):
    send(client, MBR)
    row = db.session.query(AuditLog).filter_by(action="upload").one()
    assert hashlib.sha256(MBR).hexdigest() in row.detail
    assert str(len(MBR)) in row.detail


def test_artifacts_are_not_reachable_over_http(client, signed_in, app):
    send(client, MBR)
    job = db.session.query(Job).one()
    for path in (f"/static/{job.stored_name}", f"/uploads/{job.stored_name}",
                 f"/static/../uploads/{job.stored_name}"):
        assert client.get(path).status_code in (404, 308)

    served = [str(r) for r in app.url_map.iter_rules()]
    assert not any("upload" in r and "<path" in r for r in served)


def test_a_job_belonging_to_someone_else_is_404_not_403(client, signed_in):
    send(client, MBR)
    job = db.session.query(Job).one()

    other = User(username="stranger")
    other.set_password("x" * 12)
    db.session.add(other)
    db.session.commit()

    client.post("/logout")
    client.post("/login", data={"username": "stranger", "password": "x" * 12})
    assert client.get(f"/jobs/{job.id}").status_code == 404


def test_upload_rate_limit(client, signed_in):
    codes = [send(client, MBR).status_code for _ in range(12)]
    assert codes.count(429) == 2
    assert db.session.query(Job).count() == 10


def test_the_rate_limit_comes_from_config(client, signed_in):
    """It is read per request, not baked in at registration - otherwise raising it
    for a capture session would mean editing routes.py."""
    client.application.config["UPLOAD_RATE_LIMIT"] = "3 per hour"
    codes = [send(client, MBR).status_code for _ in range(5)]
    assert codes.count(429) == 2, codes
    assert db.session.query(Job).count() == 3


@pytest.mark.parametrize("data,expected", [
    (MBR, DISK), (GPT, DISK), (CRASH, MEMORY), (VMEM, None),
])
def test_sniff_directly(tmp_path, data, expected):
    p = tmp_path / "a.bin"
    p.write_bytes(data)
    assert artifacts.sniff(p)[0] == expected