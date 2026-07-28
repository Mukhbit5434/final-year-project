import struct

import pytest

from app.config import Config
from app.extractors import disk as extractor

IMAGE = Config.MODELS_DIR.parent / "sample" / "disk" / "2020JimmyWilson.E01"
needs_image = pytest.mark.skipif(not IMAGE.exists(),
                                 reason="sample disk image not present")


def dos_header(lfanew=0x80):
    head = bytearray(b"\x00" * 0x40)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, lfanew)
    return bytes(head)


def fake_pe(lfanew=0x80, signature=b"PE\x00\x00"):
    body = bytearray(dos_header(lfanew) + b"\x00" * 0x200)
    body[lfanew:lfanew + 4] = signature
    return bytes(body)


def reader(blob):
    return lambda offset, size: blob[offset:offset + size]


def test_a_real_pe_is_accepted():
    blob = fake_pe()
    assert extractor.looks_like_pe(blob[:0x40], len(blob), reader(blob))


def test_mz_without_the_pe_signature_is_rejected():
    # The bug this guards: checking MZ and the e_lfanew bounds but never reading
    # the signature lets any file that happens to start with 'MZ' through.
    blob = fake_pe(signature=b"\xde\xad\xbe\xef")
    assert not extractor.looks_like_pe(blob[:0x40], len(blob), reader(blob))


def test_a_text_file_named_exe_is_rejected():
    blob = b"This is plainly not a binary.\n" * 40
    assert not extractor.looks_like_pe(blob[:0x40], len(blob), reader(blob))


def test_e_lfanew_past_the_end_of_the_file_is_rejected():
    blob = dos_header(lfanew=0x9999999) + b"\x00" * 16
    assert not extractor.looks_like_pe(blob[:0x40], len(blob), reader(blob))


def test_e_lfanew_pointing_inside_the_dos_header_is_rejected():
    blob = fake_pe(lfanew=0x10)
    assert not extractor.looks_like_pe(blob[:0x40], len(blob), reader(blob))


def test_a_file_shorter_than_the_dos_header_is_rejected():
    blob = b"MZ\x90\x00"
    assert not extractor.looks_like_pe(blob, len(blob), reader(blob))


@pytest.fixture(scope="module")
def scan():
    return extractor.scan(IMAGE, workers=2)


@needs_image
class TestAgainstRealImage:
    def test_acquisition_metadata_is_recoverable(self):
        info = extractor.ewf_metadata(IMAGE)
        assert info["examiner_name"] == "CEDONLEY"
        assert "acquiry_date" in info

    def test_the_ntfs_volume_is_found_and_walked(self, scan):
        assert scan["volumes"] == ["p6:Basic data partition"]
        assert scan["examined"] > 3000

    def test_every_pe_in_the_image_is_accounted_for(self, scan):
        # 19 PE files exist; 6 are byte-identical copies under System32/Wat and
        # SysWOW64/Wat, so 13 unique ones survive dedupe.
        deduped = [s for s in scan["skipped"] if "same SHA-256" in s["reason"]]
        assert len(scan["files"]) == 13
        assert len(deduped) == 6

    def test_files_are_identified_by_content_not_extension(self, scan):
        names = [r["path"] for r in scan["files"]]
        assert any(n.endswith(".db") for n in names)
        assert any(n.endswith(".regtrans-ms") for n in names)
        assert any(n.endswith(".dll") for n in names)

    def test_every_result_carries_what_an_analyst_needs(self, scan):
        for rec in scan["files"]:
            assert rec["path"].startswith("p6:")
            assert len(rec["file_sha256"]) == 64
            assert len(rec["file_md5"]) == 32
            assert rec["file_size"] > 0
            assert rec["inode"]
            assert rec["allocated"] in (True, False)

    def test_macb_timestamps_are_populated(self, scan):
        rec = next(r for r in scan["files"] if r["path"].endswith("BCTextEncoder.exe"))
        for field in ("mtime", "atime", "ctime", "btime"):
            assert rec[field] is not None, field
        assert rec["btime"].year >= 2009

    def test_vectors_are_the_full_ember_width(self, scan):
        for rec in scan["files"]:
            assert rec["vec"].shape == (2381,)

    def test_deleted_entries_are_recorded_rather_than_dropped(self, scan):
        deleted = [s for s in scan["skipped"] if "deleted entry" in s["reason"]]
        assert len(deleted) > 20

    def test_the_file_count_cap_is_enforced_and_reported(self):
        out = extractor.scan(IMAGE, max_files=4, workers=2)
        assert len(out["files"]) == 4
        assert any("file-count cap" in s["reason"] for s in out["skipped"])

    def test_the_size_cap_is_enforced_and_reported(self):
        out = extractor.scan(IMAGE, max_bytes=200_000, workers=2)
        assert any("size cap" in s["reason"] for s in out["skipped"])
        assert all(r["file_size"] <= 200_000 for r in out["files"])

    def test_a_clean_image_produces_no_detections(self, scan):
        from app.inference import disk as model
        model.load(Config.MODELS_DIR, Config.REFERENCE_DIR)

        probs = [model.predict(model.subset(r["vec"]))[0] for r in scan["files"]]
        assert max(probs) < model.threshold(), "false positive on known-good binaries"