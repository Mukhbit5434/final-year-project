# 09 — Disk Extraction: `app/extractors/disk.py`

This file turns a raw disk image into a list of feature vectors, one per
executable found inside it. Every function in the real source file is
covered below, in the order they actually run during a real scan.

## The big picture before the code

A disk image is a byte-for-byte copy of a hard drive or partition. Reading
it means: figure out what filesystem(s) it contains, walk every directory
in each one, find the files that are actually executables (not by trusting
their name — by reading their real bytes), and for each one, run it through
`ember`'s feature extractor (file 01) to get the 2,381-number vector the
disk model expects (reduced to 150 in `app/inference/disk.py`, file 08).

## Opening the image

```python
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
```

`pytsk3.Img_Info` is the class pytsk3 (file 01) expects to represent "an
open disk image" — but pytsk3 doesn't natively understand the E01/EWF
container format. This class solves that by **subclassing** `Img_Info` (a
class built from another class, inheriting its behaviour and overriding
specific pieces — the same pattern used for `TestConfig` in file 03) and
overriding the handful of methods pytsk3 actually calls on it (`read`,
`get_size`, `close`) to instead delegate to a `pyewf` handle underneath.
`type=pytsk3.TSK_IMG_TYPE_EXTERNAL` tells pytsk3 "don't try to open this
yourself, trust the methods I'm giving you." The effect: everywhere else in
this file, an E01 image and a raw `.dd`/`.img` image look completely
identical to pytsk3 — one small adapter class absorbs the entire format
difference in one place.

```python
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
```

The actual entry point: check the file extension (`EWF_EXT = {".e01",
".ex01", ".s01"}`), and if it's an EWF-family format, use `pyewf.glob(...)`
(file 01) to find every segment belonging to the same logical image — a
large E01 acquisition is commonly split across multiple numbered files —
open them all as one handle, and wrap that handle in the adapter class
above. Otherwise, hand the path straight to pytsk3's own native raw-image
support.

```python
def ewf_metadata(path):
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
```

A separate, small function that reads acquisition metadata (examiner name,
case notes, acquisition date — whatever the imaging tool wrote into the E01
file itself) purely for display, worth surfacing in a report's chain-of-
custody section because it's provenance information the extractor didn't
have to invent — it was already recorded by whoever captured the evidence
in the first place. Returns an empty dictionary for anything that isn't an
E01 image, or if reading the header values fails for any reason
(`OSError`) — never crashes the whole scan just because optional metadata
wasn't readable.

## Finding filesystems inside the image

```python
def filesystems(img):
    found = []
    try:
        vol = pytsk3.Volume_Info(img)
    except OSError:
        try:
            pytsk3.FS_Info(img, offset=0)
        except OSError as e:
            raise ImageError(f"not a disk image, or an unsupported filesystem: {e}")
        return [(0, "p0")]
```

`pytsk3.Volume_Info(img)` tries to read a partition table. If the image has
none at all — it's a bare filesystem image with no partitioning, starting
directly at byte offset 0 — that call raises `OSError`, which is caught
here deliberately (not a bug being swallowed, an expected alternative
shape of input): the code falls back to trying to open a filesystem
directly at offset 0, and if *that* fails too, the image genuinely isn't
readable at all and an `ImageError` (this file's own exception type) is
raised with a clear message.

```python
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
```

If there *is* a partition table, loop over every partition entry it
contains. `part.flags & 0x01` is a **bitwise AND** — checking whether a
specific bit (bit 0, which The Sleuth Kit defines as
`TSK_VS_PART_FLAG_ALLOC`, "this partition entry is an allocated, real
partition") is set in the partition's flags value; entries that represent
the partition table itself or unallocated space are skipped, as are
suspiciously tiny partitions (`part.len <= 2048` sectors) unlikely to hold
a real filesystem. `part.start * SECTOR` converts a partition's start
position (given in 512-byte sectors, the constant `SECTOR = 512`) into a
real byte offset. Each partition that pytsk3 can actually open a filesystem
on gets recorded as a `(byte_offset, label)` pair — the label combines the
partition's index and its description (`decode("utf-8", "replace")` turns
raw bytes into text, substituting a placeholder character for anything that
isn't valid UTF-8 rather than crashing on it). If genuinely nothing
mountable was found across every partition, that's also a hard failure —
there's no useful analysis to run on an image with no readable filesystem
at all.

## The heart of "is this really an executable?" — `looks_like_pe()`

```python
HEADER_PEEK = 0x40

def looks_like_pe(head, size, read_at):
    if len(head) < HEADER_PEEK or head[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", head, 0x3C)[0]
    if offset < HEADER_PEEK or offset + 4 > size or offset > 0x10000000:
        return False
    return read_at(offset, 4) == b"PE\x00\x00"
```

This function is where **silent bug #1** from STATUS.md was found and
fixed, and it's worth understanding exactly why the fix matters. Every
Windows executable (PE — Portable Executable — format) begins with a small
legacy "DOS header" whose first two bytes are always the letters `"MZ"`
(the initials of one of the format's original designers). But — and this
is the important part — **plenty of files that are not executables at all
can coincidentally start with those same two bytes**, and a surprising
number of files, including two genuine, real executables discovered in this
project's own CFReDS test image, are named things like `.db` or
`.regtrans-ms` — names that give no hint at all that they're actually PE
files.

The correct, full check is: does it start with `"MZ"` (`head[:2] != b"MZ"`
returning early if not), **and** — critically, this is the part the
original buggy version skipped — does a specific 4-byte value inside the
DOS header, called `e_lfanew` (a pointer to where the *real* PE header
lives, always found at fixed byte offset `0x3C` from the start of the
file), actually point to a location that, when you go read 4 bytes from
there, contains the literal bytes `"PE\x00\x00"` (the real PE format's own
distinct signature)?

`struct.unpack_from("<I", head, 0x3C)` uses Python's standard `struct`
module to interpret 4 raw bytes, starting at offset `0x3C` within the
already-read `head` buffer, as a single **unsigned 32-bit integer** in
**little-endian** byte order (`"<I"` — `<` for little-endian, `I` for
unsigned int; this matters because raw binary numbers can be stored with
their bytes in different orders depending on the format, and getting this
wrong would produce a nonsense offset). The two sanity bounds
(`offset < HEADER_PEEK` — pointing back into the header we just read, which
would be nonsensical — and `offset + 4 > size` or `offset > 0x10000000`
— pointing past the end of the file, or an absurdly large offset that's
almost certainly evidence of a corrupted or deliberately malformed file)
protect the *next* line, `read_at(offset, 4)`, from being asked to read
from somewhere invalid. Only if all of that lines up does the function
actually go read those 4 bytes and compare them to the real PE signature.

The comment directly above this function in the real source states the
consequence plainly: **extensions are never consulted at all**, anywhere in
this decision. A file can be named `readme.txt` and still get analysed if
its actual bytes are a PE file (this is exactly how malware commonly hides
— an executable renamed to look innocuous), and a file named
`totally-a-virus.exe` that's actually just plain text would correctly be
skipped, because its bytes don't back up the claim its extension makes.

## Reading forensic metadata off a file

```python
def _macb(meta):
    def when(ts):
        if not ts:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    return {"mtime": when(meta.mtime), "atime": when(meta.atime),
            "ctime": when(meta.ctime), "btime": when(meta.crtime)}
```

A small helper that converts the four raw Unix timestamps pytsk3 exposes
(`mtime`=Modified, `atime`=Accessed, `ctime`=Changed, `crtime`=Created/Born)
into proper timezone-aware Python `datetime` objects, explicit about UTC
(a raw timestamp is just a plain number of seconds since a fixed reference
point — it carries no timezone information of its own, so being explicit
about UTC here avoids any later ambiguity). `if not ts: return None` handles
the case where a filesystem simply doesn't track one of the four
timestamps at all for a given entry — a real `None`, distinct from the
timestamp genuinely being "the epoch," `1970-01-01`.

```python
def _data_offset(entry, part_offset, block_size):
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
```

This computes the exact byte offset, *within the whole disk image*, where a
file's actual content begins — enabling direct carving with an external
tool later. It works by finding the file's NTFS "data attribute" and
reading its first "run" (a contiguous stretch of disk blocks a file's data
occupies — NTFS files aren't necessarily stored in one single contiguous
block, but the *first* run's start is enough for a locator). The comment on
this function is explicit and honest about a real limitation: **resident
NTFS files** — very small files whose entire content fits directly inside
their MFT (Master File Table) record, with no separate data run on disk at
all — simply have nothing here to return, so the function returns `None`
rather than fabricating a number. This is a concrete instance of hard rule
8 ("never fabricate a value to fill a gap — emit `None`/0.0 and disclose")
applied at the extraction level, matching the same honesty this project
insists on throughout the memory pipeline too.

```python
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
```

Reads a file's full content in chunks (`READ_CHUNK = 1024 * 1024`, one
megabyte at a time) rather than in one call — the same streaming discipline
seen already in `artifacts.py:store()` (file 07), here applied to reading
rather than writing. `bytearray()` is a mutable, growable byte buffer
(unlike Python's plain `bytes`, which is immutable and would need to be
recreated on every append); `bytes(out)` converts it back to an ordinary,
immutable `bytes` object once reading is complete, which is what gets
handed off for vectorization.

## `walk()` — the actual filesystem traversal

```python
def walk(fs, part_offset, label, max_bytes, include_unallocated=True):
    block_size = fs.info.block_size
    seen_inodes = set()
    stack = [("", fs.open_dir(path="/"))]

    while stack:
        prefix, directory = stack.pop()
        for entry in directory:
            ...
```

This is a **generator function** — note it uses `yield` (below) rather
than `return` at every point it produces a result, which means calling
`walk(...)` doesn't run the whole function immediately; it returns an
iterator that produces one item at a time, on demand, as the caller asks
for the next one. This matters for a disk image that could contain
hundreds of thousands of files: nothing forces the *entire* list of every
file examined to exist in memory at once.

`stack = [("", fs.open_dir(path="/"))]` sets up an explicit **stack** (a
last-in-first-out list) starting with the root directory, and the `while
stack: prefix, directory = stack.pop()` loop is a manual, iterative
implementation of directory recursion — walking into a subdirectory means
pushing it onto the stack rather than the more familiar approach of a
function calling itself recursively. This avoids Python's recursion depth
limit ever becoming a problem on a disk image with an unusually deep
directory structure, which a naive recursive function could hit.

```python
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
```

Every directory entry is checked for a real name (some filesystem entries
carry no usable name at all and are skipped outright), and the two special
self/parent directory entries (`"."`, `".."`) are skipped to avoid an
infinite loop walking back into themselves. If an entry's `meta` (its
actual file metadata — size, timestamps, allocation status) is `None`, the
comment explains exactly what that represents: **a deleted file's name
still survives in its parent directory's index, but its MFT record has
already been reused for something else**, so nothing else about it can be
recovered. Rather than silently skipping this (which would hide from the
analyst that a deleted entry with this name existed at all), it's recorded
as an explicit skip with a specific reason — the same "never silently drop,
always disclose why" discipline seen throughout this whole project.

```python
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
```

`allocated` is computed the same bitwise way as the partition flags earlier
— whether this entry's underlying storage is still considered "in use" by
the filesystem, as opposed to marked deleted/free but not yet overwritten.
For directories: `seen_inodes` is a **set** (an unordered collection with
fast membership checks and no duplicates) tracking which directory inodes
have already been queued, specifically guarding against a filesystem
structure that could otherwise cause the same directory to be walked twice
(or, in a pathological/corrupted image, infinitely) — `meta.addr` is the
inode number, and checking `in seen_inodes` before adding it to the stack
closes that loophole. A directory that can't actually be opened
(`entry.as_directory()` raising `OSError`) is recorded as a skip rather
than silently ignored or crashing the whole scan.

```python
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
```

Non-regular-file entries (directories were handled above; anything that
isn't a directory and isn't a plain regular file — special filesystem
objects — is skipped) and zero-size files are ignored outright — there's
nothing to vectorize in an empty file. For every genuine regular file with
content, `yield {"examined": 1}` reports it as "looked at" (this is what
feeds `Job.files_scanned`, distinct from how many turned out to actually be
executables), then just enough of the file's header is read
(`min(HEADER_PEEK, meta.size)` — never more bytes than the file actually
has) and handed to `looks_like_pe()`. Anything that doesn't pass that check
is silently skipped **without being recorded as a "skip"** — this is a
deliberate distinction from every other skip reason in this function: "not
a PE file" isn't a limitation or a failure worth disclosing to the analyst,
it's simply the overwhelming majority of ordinary, correctly-identified
non-executable files on any real disk image, and recording every single
one would make the skip list enormous and useless.

```python
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
```

For files that *do* look like genuine PE files: the size cap from `Config`
(file 03's `MAX_PE_BYTES`) is checked and disclosed if exceeded; the file's
full content is read (with its own error handling, again disclosed rather
than silently dropped); and — a subtle but real correctness check — if the
number of bytes actually read doesn't match what the filesystem *claimed*
the file's size was, that's recorded as a truncation rather than silently
proceeding to vectorize a partial, misleading copy of the file.

```python
            rec = {"path": f"{label}{path}", "partition": label,
                   "inode": str(meta.addr), "file_size": meta.size,
                   "allocated": allocated,
                   "file_sha256": hashlib.sha256(data).hexdigest(),
                   "file_md5": hashlib.md5(data).hexdigest(),
                   "data_offset": _data_offset(entry, part_offset, block_size)}
            rec.update(_macb(meta))
            yield {"pe": rec, "data": data}
```

Finally, for a file that passed every check: a dictionary carrying every
locator field hard rule 16 requires (path, partition, inode, both hashes,
size, allocation status, data offset, and the four MACB timestamps merged
in via `.update(_macb(meta))`) is yielded alongside the actual raw file
bytes, ready for the next stage — vectorization.

## `_init_worker()` and `_vectorize()` — what runs inside the process-pool workers

```python
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
```

Recall from file 07 that vectorizing PE files runs in a separate process
pool, specifically because `lief` (called deep inside `ember`'s
`PEFeatureExtractor`) is native code parsing potentially hostile,
malformed input — a crash there must cost one worker, never the whole
system. `_init_worker()` is passed to `ProcessPoolExecutor` as an
`initializer` — a function that runs exactly once, when each worker process
first starts up, before it's given any actual work. It builds the
`ember` feature extractor once per worker (via `patch_ember.load_features()`,
file 01 and file 15 — the patched, standalone-loaded version of `ember`'s
`features.py`) and stores it in a **module-level** `_ext` variable that's
private to that specific worker process. `_vectorize(data)` — the actual
task each worker runs, once per file — is then trivially small: hand the
raw bytes to the already-built extractor and return its 2,381-value result.
This split (build the expensive extractor once per *worker*, reuse it for
every file that worker is assigned) avoids rebuilding it from scratch for
every single PE file, which would be wasteful.

## `scan()` — tying it all together

```python
def scan(image_path, max_files=500, max_bytes=64 * 1024 ** 2, workers=2,
         include_unallocated=True, timeout=120, progress=None):
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
```

This is the function `jobs.py:extract_disk()` (file 07) calls. It opens the
image, finds every filesystem inside it, and for each one, consumes the
`walk()` generator from above — the `for item in walk(...)` loop is what
actually pulls items out of that generator one at a time. Each item is one
of three shapes (`"examined"`, `"skip"`, or `"pe"` with `"data"`), and this
loop dispatches on which shape it got.

Two of `Config`'s caps (file 03) are enforced right here, at this level
rather than inside `walk()` itself: the **file-count cap**
(`len(found) >= max_files`) and **deduplication by content hash**
(`by_hash.get(rec["file_sha256"])` — if the exact same bytes, identified by
their SHA-256, have already been found once in this scan, this second copy
is skipped with a reason naming the first occurrence, rather than wasting
time vectorizing and predicting on an identical file twice). Both are
recorded as skips with clear reasons, continuing the same disclosure
discipline as everything above. `progress(len(found), rec["path"])`, when
supplied, is what drives the "Vectorising executable 47" live-progress
messages seen in file 07's `extract_disk()`.

```python
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
```

Only once the *entire* filesystem walk is done — every candidate PE file
found, deduplicated, capped — does vectorization begin, as a genuinely
separate phase. `with ProcessPoolExecutor(max_workers=workers,
initializer=_init_worker) as pool:` creates a fresh, disposable process pool
just for this scan (distinct from, and unrelated to, the single-worker
extraction-supervisor pool in `jobs.py`, file 07 — this is a second,
independent instance, sized by the `workers` parameter, specifically for
parallel *vectorization* of however many PE files were found), and the
`with` block guarantees it's cleanly shut down afterward even if something
inside raises an exception.

`{pool.submit(_vectorize, data): rec for rec, data in found}` is a
dictionary comprehension building a mapping from each submitted "future"
(the pending-result placeholder, same concept introduced in file 07) back
to that file's own record dictionary — this is what lets the loop below
match a completed (or failed, or timed-out) result back to the specific
file it belongs to. For each one: `future.result(timeout=timeout)` waits
(up to `timeout` seconds, default 120) for that specific file's
vectorization to finish. Two distinct failure modes are handled separately
and explicitly: `PoolTimeout` (a single malformed or unusually complex file
taking too long — recorded as a timeout, without affecting any other
file's result) and any other `Exception` (a genuine parse failure inside
`ember`/`lief` — recorded with the exception's type name, again without
affecting anything else). This per-file isolation is exactly the payoff of
running vectorization in a separate process pool at all: one bad file
produces one skip entry with a clear reason, never a crashed scan.

Finally, `scan()` returns one dictionary summarising the whole run:
every successfully vectorized file (`"files"`), every skip with its reason
(`"skipped"`), which filesystem labels were found, and the raw examined/
found counts — exactly the shape `jobs.py`'s `_disk()` (file 07) expects to
receive and turn into `Result` rows.

## Check your understanding

**Q1. Why does `looks_like_pe()` check for the `"PE\x00\x00"` signature at
the offset named inside the file's own DOS header, rather than just
checking for the `"MZ"` bytes at the start and stopping there?**

A: Because `"MZ"` alone is not a reliable signal — plenty of non-executable
files can coincidentally start with those two bytes. The real, distinguishing
proof that a file is genuinely a PE executable is the second signature,
`"PE\x00\x00"`, found by following a pointer (`e_lfanew`) stored inside the
DOS header. Checking only the first two bytes was a real bug in an earlier
version of this project — silent bug #1 — and would have caused any file
merely starting with "MZ" to be treated as an executable and vectorized.

**Q2. Why does `_data_offset()` return `None` for some files rather than
always computing a byte offset?**

A: Because very small NTFS files can be stored entirely "resident" inside
their own MFT record, with no separate data run on the disk to point to at
all. There is genuinely no meaningful byte offset to report for such a
file, and this project's discipline (hard rule 8) is to disclose that
honestly with `None` rather than inventing or guessing a plausible-looking
number.

**Q3. `walk()` records a "skip" with a reason for a directory that fails
to open, a file that fails to read, and a deleted entry — but does *not*
record a skip for a file whose header simply doesn't look like a PE. Why
the difference?**

A: The skip list is meant to answer "what did we fail to properly examine,
and why couldn't we?" — genuine limitations an analyst should know about.
A file correctly identified as *not* being a PE executable isn't a failure
or a limitation at all; it's the extractor working exactly as intended for
the (overwhelming majority) of ordinary non-executable files on any real
disk. Recording every single one as a "skip" would make the skip list
enormous and would blur the meaningful signal (genuine gaps in coverage)
with routine, expected non-matches.

**Q4. Why does vectorization happen in a completely separate phase, after
the entire filesystem walk finishes, rather than vectorizing each PE file
the moment it's found during the walk?**

A: Two enforced limits — the file-count cap and content-hash deduplication
— need to see the *complete* set of candidate files first to decide which
ones to actually process; vectorizing eagerly, one at a time as they're
discovered, could waste real work vectorizing a file that later turns out
to be the 501st found (past the cap) or an exact duplicate of one already
seen. Separating discovery from vectorization also lets vectorization run
in parallel across multiple worker processes, which wouldn't make sense to
interleave with the inherently sequential, single-threaded filesystem walk.

**Q5. If `_vectorize()` crashes (say, on a deliberately malformed,
hostile PE file) while it's running inside one of the process-pool
workers, what actually happens to the rest of the scan?**

A: Nothing else in the scan is affected. `future.result(timeout=...)` for
that specific file's future raises an exception in the *calling* code
(back in `scan()`, running in the main process), which is caught by the
`except Exception as e:` branch and recorded as a skip naming the failure
type — every other file's future is completely unaffected and continues
processing normally. This is the entire point of running vectorization in
a separate process pool in the first place: a crash is contained to one
worker and reported as a clean, specific failure for one file, rather than
being able to take down the whole scan (or, if it happened inside the main
Flask process instead, the whole web server).
