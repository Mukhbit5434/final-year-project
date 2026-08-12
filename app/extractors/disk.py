import hashlib
import struct
import sys
from concurrent.futures import ProcessPoolExecutor, TimeoutError as PoolTimeout
from datetime import datetime, timezone
from pathlib import Path

import pytsk3

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
SECTOR = 512
READ_CHUNK = 1024 * 1024

HEADER_PEEK = 0x40

EWF_EXT = {".e01", ".ex01", ".s01"}


class ImageError(RuntimeError):
    pass


class _EWFImg(pytsk3.Img_Info):
    def __init__(self, handle):
        self._h = handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._h.close()

    def read(self, offset, size):
        self._h.seek(offset)
        return self._h.read(size)

    def get_size(self):
        return self._h.get_media_size()


def open_image(path):
    path = Path(path)
    if path.suffix.lower() in EWF_EXT:
        import pyewf
        segments = pyewf.glob(str(path))
        if not segments:
            raise ImageError(f"no EWF segments found for {path.name}")
        handle = pyewf.handle()
        handle.open(segments)
        return _EWFImg(handle)
    return pytsk3.Img_Info(str(path))


def ewf_metadata(path):
    """Acquisition details recorded by the imaging tool. Worth surfacing in the
    report's chain-of-custody section - it is provenance we did not have to
    invent."""
    if Path(path).suffix.lower() not in EWF_EXT:
        return {}
    import pyewf
    handle = pyewf.handle()
    handle.open(pyewf.glob(str(path)))
    try:
        return dict(handle.get_header_values())
    except OSError:
        return {}
    finally:
        handle.close()


def filesystems(img):
    """-> [(byte_offset, label)] for every volume that actually mounts."""
    found = []
    try:
        vol = pytsk3.Volume_Info(img)
    except OSError:
        try:
            pytsk3.FS_Info(img, offset=0)
        except OSError as e:
            raise ImageError(f"not a disk image, or an unsupported filesystem: {e}")
        return [(0, "p0")]

    for part in vol:
        if not part.flags & 0x01 or part.len <= 2048:
            continue
        offset = part.start * SECTOR
        try:
            pytsk3.FS_Info(img, offset=offset)
        except OSError:
            continue
        desc = part.desc.decode("utf-8", "replace") if part.desc else ""
        found.append((offset, f"p{part.addr}:{desc}".rstrip(": ")))

    if not found:
        raise ImageError("no mountable filesystem found in any partition")
    return found


def looks_like_pe(head, size, read_at):
    """MZ, then follow e_lfanew and confirm PE\\0\\0 actually sits there.

    Extensions are never consulted - malware is routinely renamed and this image
    alone holds two genuine PEs called .db and .regtrans-ms. The second read is
    the part that matters: plenty of files open with 'MZ' by coincidence, and
    without checking the signature they all get vectorized as executables.
    """
    if len(head) < HEADER_PEEK or head[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", head, 0x3C)[0]
    if offset < HEADER_PEEK or offset + 4 > size or offset > 0x10000000:
        return False
    return read_at(offset, 4) == b"PE\x00\x00"


def _macb(meta):
    def when(ts):
        if not ts:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    return {"mtime": when(meta.mtime), "atime": when(meta.atime),
            "ctime": when(meta.ctime), "btime": when(meta.crtime)}


def _data_offset(entry, part_offset, block_size):
    """Byte offset of the file's first data run inside the image, for carving.
    Resident NTFS files live inside the MFT record and have no run list, so this
    returns None rather than a fabricated number."""
    try:
        for attr in entry:
            if attr.info.type != pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA:
                continue
            for run in attr:
                if run.len and run.addr:
                    return part_offset + run.addr * block_size
    except (OSError, AttributeError):
        pass
    return None


def _read(entry, size):
    out = bytearray()
    got = 0
    while got < size:
        chunk = entry.read_random(got, min(READ_CHUNK, size - got))
        if not chunk:
            break
        out += chunk
        got += len(chunk)
    return bytes(out)


def walk(fs, part_offset, label, max_bytes, include_unallocated=True):
    """Yield every regular file that carries a PE header, with its locators."""
    block_size = fs.info.block_size
    seen_inodes = set()
    stack = [("", fs.open_dir(path="/"))]

    while stack:
        prefix, directory = stack.pop()
        for entry in directory:
            name_obj = entry.info.name
            if not name_obj or not name_obj.name:
                continue
            name = name_obj.name.decode("utf-8", "replace")
            if name in (".", ".."):
                continue

            meta = entry.info.meta
            path = f"{prefix}/{name}"

            if meta is None:
                yield {"skip": {"path": f"{label}{path}",
                                "reason": "deleted entry, metadata no longer recoverable"}}
                continue

            allocated = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
            if not allocated and not include_unallocated:
                continue

            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                if meta.addr in seen_inodes:
                    continue
                seen_inodes.add(meta.addr)
                try:
                    stack.append((path, entry.as_directory()))
                except OSError:
                    yield {"skip": {"path": f"{label}{path}", "reason": "directory unreadable"}}
                continue

            if meta.type != pytsk3.TSK_FS_META_TYPE_REG or not meta.size:
                continue

            yield {"examined": 1}
            try:
                head = entry.read_random(0, min(HEADER_PEEK, meta.size))
                if not looks_like_pe(head, meta.size, entry.read_random):
                    continue
            except OSError:
                yield {"skip": {"path": f"{label}{path}", "reason": "unreadable"}}
                continue

            if meta.size > max_bytes:
                yield {"skip": {"path": f"{label}{path}",
                                "reason": f"exceeds {max_bytes // 1024**2} MB size cap"}}
                continue

            try:
                data = _read(entry, meta.size)
            except OSError:
                yield {"skip": {"path": f"{label}{path}", "reason": "read error"}}
                continue

            if len(data) != meta.size:
                yield {"skip": {"path": f"{label}{path}",
                                "reason": f"truncated: read {len(data)} of {meta.size} bytes"}}
                continue

            rec = {"path": f"{label}{path}", "partition": label,
                   "inode": str(meta.addr), "file_size": meta.size,
                   "allocated": allocated,
                   "file_sha256": hashlib.sha256(data).hexdigest(),
                   "file_md5": hashlib.md5(data).hexdigest(),
                   "data_offset": _data_offset(entry, part_offset, block_size)}
            rec.update(_macb(meta))
            yield {"pe": rec, "data": data}


_ext = None


def _init_worker():
    global _ext
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import patch_ember
    _ext = patch_ember.load_features().PEFeatureExtractor(
        feature_version=2, print_feature_warning=False)


def _vectorize(data):
    return _ext.feature_vector(data)


def scan(image_path, max_files=500, max_bytes=64 * 1024 ** 2, workers=2,
         include_unallocated=True, timeout=120, progress=None):
    """Find every PE in the image and turn it into a 2381-length EMBER vector.

    Vectorization runs in a process pool because lief parses hostile input in
    native code: a malformed PE can segfault the interpreter, and that must cost
    one worker rather than every job on the box (hard rule 20).
    """
    img = open_image(image_path)
    volumes = filesystems(img)

    found, skipped = [], []
    by_hash = {}
    examined = 0

    for offset, label in volumes:
        fs = pytsk3.FS_Info(img, offset=offset)
        for item in walk(fs, offset, label, max_bytes, include_unallocated):
            if "examined" in item:
                examined += 1
                continue
            if "skip" in item:
                skipped.append(item["skip"])
                continue

            rec, data = item["pe"], item["data"]
            if len(found) >= max_files:
                skipped.append({"path": rec["path"],
                                "reason": f"file-count cap of {max_files} reached"})
                continue

            dupe = by_hash.get(rec["file_sha256"])
            if dupe:
                skipped.append({"path": rec["path"],
                                "reason": f"identical to {dupe} (same SHA-256)"})
                continue

            by_hash[rec["file_sha256"]] = rec["path"]
            found.append((rec, data))
            if progress:
                progress(len(found), rec["path"])

    results = []
    if found:
        with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker) as pool:
            futures = {pool.submit(_vectorize, data): rec for rec, data in found}
            for future, rec in futures.items():
                try:
                    rec["vec"] = future.result(timeout=timeout)
                except PoolTimeout:
                    skipped.append({"path": rec["path"],
                                    "reason": f"vectorization timed out after {timeout}s"})
                    continue
                except Exception as e:
                    skipped.append({"path": rec["path"],
                                    "reason": f"EMBER parse failure: {type(e).__name__}"})
                    continue
                results.append(rec)

    return {"files": results, "skipped": skipped,
            "volumes": [label for _, label in volumes],
            "examined": examined, "pe_found": len(found)}