import hashlib
import uuid
from pathlib import Path

from .models import DISK, MEMORY

CHUNK = 4 * 1024 * 1024

# Positive identification only. There is no signature that says "this is a raw
# memory dump" - .raw/.mem/.vmem carry nothing at all - so failing to find a disk
# signature is not evidence of memory. Anything unmatched goes to the analyst.
EWF = b"EVF\x09\x0d\x0a\xff\x00"
EWF2 = b"EVF2\x0d\x0a\x81\x00"
CRASHDUMPS = (b"PAGEDUMP", b"PAGEDU64", b"PAGEDUMP64")


def sniff(path):
    """-> (artifact or None, human-readable reason)"""
    with open(path, "rb") as f:
        head = f.read(1024)
        f.seek(510)
        mbr = f.read(2)
        f.seek(512)
        gpt = f.read(8)

    for magic in CRASHDUMPS:
        if head.startswith(magic):
            return MEMORY, f"Windows crash dump header {magic.decode()}"

    if head.startswith(EWF) or head.startswith(EWF2):
        return DISK, "EWF/E01 evidence container"
    if gpt == b"EFI PART":
        return DISK, "GPT protective header at offset 512"
    if mbr == b"\x55\xaa":
        return DISK, "MBR boot signature 0x55AA at offset 510"

    return None, "no disk signature and no crash-dump header; raw memory images carry neither"


def store(stream, dest_dir, suffix):
    """Stream to disk in chunks, hashing as we go. Multi-GB images must never be
    read into memory, and a second pass just to hash would double the I/O."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Our own name, never the client's: this is what keeps a crafted filename
    # from escaping the upload directory.
    name = f"{uuid.uuid4().hex}{suffix}"
    path = dest_dir / name

    sha = hashlib.sha256()
    size = 0
    with open(path, "wb") as out:
        while True:
            buf = stream.read(CHUNK)
            if not buf:
                break
            sha.update(buf)
            size += len(buf)
            out.write(buf)

    return name, sha.hexdigest(), size


def ext_of(filename):
    suffix = Path(filename or "").suffix.lower()
    return suffix if suffix else ""