# 10 — Memory Extraction: `app/extractors/memory.py`

This is the largest and most intricate source file in the entire project.
It turns a raw memory dump into exactly 55 numbers, using nine separate
Volatility 3 plugins, while honestly tracking every place the mapping
between "what the training dataset's tool produced" and "what this
project's tool can actually measure" isn't perfectly clean. Take this file
slowly — it rewards it.

## The core problem this whole file navigates

The model this project ships was trained on CIC-MalMem-2022, a dataset
built using **Volatility 2** — an older, now-archived tool. This project
runs **Volatility 3** instead (file 01 covers why: Volatility 2 is Python
2.7-only, has no profile for modern Windows builds, and its repository was
archived in 2025 — it genuinely cannot be used as a live tool on this
project's target machine). The two versions don't always expose exactly the
same plugin output, under exactly the same names, in exactly the same
shape. So almost every function in this file isn't simply "call a plugin,
read a column" — it's "call a plugin, and carefully reconstruct the exact
number VolMemLyzer (the tool that actually produced CIC-MalMem-2022's
features) would have computed from Volatility 2's differently-shaped
output." Where that reconstruction is uncertain, this file says so
explicitly, in a structured way (the `extraction_gaps` list), rather than
quietly guessing.

## The reference tables at the top of the file

```python
PROTECT_INDEX = {
    "PAGE_NOACCESS": 0, "PAGE_READONLY": 1, "PAGE_EXECUTE": 2,
    "PAGE_EXECUTE_READ": 3, "PAGE_READWRITE": 4, "PAGE_WRITECOPY": 5,
    "PAGE_EXECUTE_READWRITE": 6, "PAGE_EXECUTE_WRITECOPY": 7,
}
```

Volatility 2's `malfind` plugin reports a memory region's protection flags
(NOACCESS, READWRITE, EXECUTE_READWRITE, etc.) internally as a small
*index* number into a fixed list, not as the underlying operating system's
own numeric constant. CIC-MalMem-2022's `malfind.protection` feature turns
out — reverse-engineered from the training data itself, since the dataset
authors never documented this — to be the **sum of these small index
numbers** across every flagged region, not a sum of the real Win32
protection constants (which are much larger numbers like `0x40` for
`PAGE_EXECUTE_READWRITE`, and wouldn't fit the training data's observed
scale at all). Volatility 3 reports this same protection information as a
plain *string* (`"PAGE_EXECUTE_READWRITE"`), so this dictionary exists
purely to translate that string back into the small index number the
original Volatility 2-based feature actually summed.

```python
PSXVIEW_SOURCE = {
    "not_in_pslist": "pslist", "not_in_eprocess_pool": "psscan",
    "not_in_ethread_pool": "thrdscan", "not_in_csrss_handles": "csrss",
    "not_in_pspcid_list": None, "not_in_session": None, "not_in_deskthrd": None,
}
```

`psxview` is a plugin that tries to find every running process using
several *independent* methods, on the logic that malware hiding a process
from one enumeration method (say, the normal process list) often fails to
hide it from a different one (say, scanning raw memory pools for process
structures) — a mismatch between methods is a classic rootkit indicator.
Volatility 2's `psxview` checked **seven** different sources; Volatility
3's checks only **four** (confirmed, the comment states, "against the
installed volatility3 2.28 source, not documentation" — an important
methodological point: this project verified the real, installed tool's
actual columns rather than trusting possibly-outdated documentation).
This dictionary maps each of the seven CIC-MalMem-2022 feature names to
either the real Volatility 3 column that corresponds to it, or `None` for
the three sources that simply have no Volatility 3 equivalent at all — a
structural gap, not a bug, and one this file handles honestly (see
`from_psxview()` below) rather than trying to paper over.

```python
HANDLE_TYPES = {
    "handles.nfile": "File", "handles.nevent": "Event", ...
}

PLUGINS = {
    "pslist": "windows.pslist.PsList", "dlllist": "windows.dlllist.DllList",
    "handles": "windows.handles.Handles",
    "ldrmodules": "windows.malware.ldrmodules.LdrModules",
    "malfind": "windows.malware.malfind.Malfind",
    "psxview": "windows.malware.psxview.PsXView",
    "modules": "windows.modules.Modules", "svcscan": "windows.svcscan.SvcScan",
    "callbacks": "windows.callbacks.Callbacks",
}

FEATURE_COUNT = 55
```

`HANDLE_TYPES` maps each handle-count feature to the exact string
Volatility 3 uses for that Windows kernel object type (`"File"`, `"Event"`,
`"Mutant"`, etc.). `PLUGINS` is the definitive list of the **nine**
Volatility 3 plugins this project actually runs, each named by its full
Python class path — notice three of them (`ldrmodules`, `malfind`,
`psxview`) live under `windows.malware.*` rather than plain `windows.*`; the
comment notes the older `windows.*` names still work but emit a deprecation
warning, so the newer canonical location is used. `FEATURE_COUNT = 55` is a
constant checked in `assemble()` (below), and it directly encodes hard rule
23: CIC-MalMem-2022's *original* published paper actually described 58
features, including three "Apihooks" ones the released dataset simply
never included. This model has genuinely never seen those three features,
and this codebase must never try to emit them.

## Symbol resolution and the architecture gate

```python
SYMBOLS = Path(__file__).resolve().parents[2] / "symbols"

def _use_local_symbols():
    import volatility3.symbols
    if not SYMBOLS.is_dir():
        return
    path = str(SYMBOLS)
    if path not in volatility3.symbols.__path__:
        volatility3.symbols.__path__ = [path] + list(volatility3.symbols.__path__)
```

Volatility 3 needs to know the precise internal layout of Windows kernel
data structures for the exact build being analysed — information it
normally fetches on-demand from a public download server the first time it
meets an unfamiliar build, caching the result under the *user's* AppData
folder, outside this project entirely. `_use_local_symbols()` instead
prepends this project's own repo-local `symbols/` folder (populated ahead
of time by `scripts/fetch_symbols.py`, covered in file 15) to the front of
Volatility's own internal search-path list, so a symbol file staged there
is found and used *before* Volatility ever considers reaching out to the
network. `volatility3.symbols.__path__` is a genuine Python mechanism
(`__path__` on a package) that controls where Python looks for that
package's own submodules/data — modifying it directly, as done here, is
exactly how the project makes offline analysis work at all, and the
comment notes precisely why this has to happen inside the extractor itself
rather than during `create_app()`: extraction runs in a completely separate
worker *process* (file 07) that never builds a Flask app at all, so wiring
this into startup would simply never run for the process that actually
needs it.

```python
def build_context(dump, catalog=None):
    ...
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = _url(dump)
    cls = catalog["windows.pslist.PsList"]
    autos = automagic.choose_automagic(automagic.available(ctx), cls)
    plugins.construct_plugin(ctx, autos, cls, "plugins", None, _no_files())

    layer = ctx.config["plugins.PsList.kernel.layer_name"]
    bits = 64 if isinstance(ctx.layers[layer], intel.Intel32e) else 32
    if bits != 64:
        raise ExtractionError(
            "this memory capture is not 64-bit. The memory pipeline is scoped to a "
            "controlled reference environment, Windows 10 x64, and does not analyse "
            "any other architecture")

    return {"ctx": ctx, "layer": layer,
            "symbols": ctx.config["plugins.PsList.kernel.symbol_table_name"],
            "offset": ctx.config["plugins.PsList.kernel.offset"],
            "bits": bits}
```

This function is the **single earliest point** at which anything about the
dump is actually understood, and it doubles as the project's architecture
gate — the concrete enforcement of CLAUDE.md §11.1's "Windows 10 x64 only"
scope decision. It builds a fresh Volatility context, points it at the
dump file (`_url(dump)` — a small helper turning a filesystem path into the
`file://` URL format Volatility's own configuration system expects, using
`urllib.request.pathname2url` specifically because a naive string
concatenation would mishandle the literal spaces in this project's own
folder path, `"Final Year Project"`), and — using Volatility's own
"automagic" system (its built-in automatic profile/layout detection,
introduced briefly in file 01) — constructs just enough of one plugin
(`PsList`, chosen because it's lightweight and forces the automagic system
to fully resolve the memory layer) to determine what kind of memory layer
this dump actually uses.

`isinstance(ctx.layers[layer], intel.Intel32e)` is the actual architecture
check: `Intel32e` is Volatility 3's specific class name for the 64-bit x86
("Intel 32-bit extended," a slightly confusing but standard technical name
for what's colloquially called x64) memory layout. If the constructed layer
*isn't* an instance of that class, the dump is refused outright, before any
of the nine real plugins ever run — the comment explains precisely why this
is the earliest reliable point it *can* be checked: a raw memory dump
carries no header of its own that identifies its architecture at all (this
is why upload-time detection, back in `artifacts.sniff()` from file 07,
can never make this determination for a `.raw`/`.mem`/`.vmem` file — only a
`.dmp` crash dump carries a distinguishing header, `PAGEDUMP` vs.
`PAGEDU64`). The memory layer class is the first thing in the entire
analysis pipeline that settles the question for every format, and it
settles it before any of the nine (comparatively expensive) plugins get a
chance to run — so a rejected, wrong-architecture capture costs exactly one
cheap layer build, not a wasted multi-minute extraction attempt.

```python
def run_plugin(dump, plugin, catalog=None, prepared=None):
    ...
    if prepared is None:
        ctx = contexts.Context()
        ctx.config["automagic.LayerStacker.single_location"] = _url(dump)
    else:
        ctx = prepared["ctx"].clone()
        base = f"plugins.{name}.kernel"
        ctx.config[f"{base}.layer_name"] = prepared["layer"]
        ctx.config[f"{base}.symbol_table_name"] = prepared["symbols"]
        ctx.config[f"{base}.offset"] = prepared["offset"]
        ctx.config[f"{base}.layer_name.kernel_virtual_offset"] = prepared["offset"]
    autos = automagic.choose_automagic(automagic.available(ctx), cls)

    built = plugins.construct_plugin(ctx, autos, cls, "plugins", None, _no_files())

    grid = built.run()
    cols = [c.name for c in grid.columns]
    rows = []

    def visit(node, _accumulator):
        rows.append(dict(zip(cols, node.values)))
        return None

    grid.populate(visit, None)
    return cols, rows
```

This is the function that actually runs **any one** of the nine plugins and
turns its output into plain Python dictionaries. The `if prepared is None`
branch (building a completely fresh context, re-resolving the layer from
scratch) exists for callers that just want to run one plugin in isolation
(some of this project's diagnostic scripts, file 15). The far more common
path in real extraction is the `else` branch: reuse the *already resolved*
layer, symbol table, and kernel offset from `build_context()`'s one-time
work (`prepared["ctx"].clone()` — cloning rather than reusing the exact
same context object directly, since each plugin needs its own independent
configuration namespace) — this is what avoids re-running the expensive
automagic resolution process nine separate times, once per plugin, when it
only genuinely needs to happen once. The comment flags one subtle detail
worth knowing: `KernelModule` (used by several of these plugins internally)
reads the kernel's base virtual address from underneath the *layer
requirement's own* configuration path rather than from the layer's own
settings, so that value has to be set at that specific extra path too, or
some plugins would silently fail to find it.

Once the plugin actually runs (`built.run()`), Volatility 3 returns its
results as a "tree grid" — a general-purpose structure that can represent
either a flat table or a genuinely hierarchical tree of results, depending
on the plugin. `grid.columns` gives the column names in order; `cols =
[c.name for c in grid.columns]` extracts just the names as a plain list.
`grid.populate(visit, None)` is how you actually walk every row Volatility
produced — you hand it a callback function (`visit`), and it calls that
function once per row, passing a `node` object whose `.values` are the raw
column values for that row. `dict(zip(cols, node.values))` — a very common
Python idiom — pairs up the column names and that row's values
positionally and builds a plain dictionary out of them (e.g. `{"PID": 4400,
"Name": "python.exe", ...}`), which is appended to the growing `rows` list.
By the time `run_plugin()` returns, Volatility's own internal object model
is completely gone — everything downstream in this file works with nothing
more exotic than lists of plain Python dictionaries.

## Handling a real, messy hazard: torn rows from live acquisition

```python
MAX_PID = 0xFFFFFFFF
MAX_THREADS = 100000

def _sane(value, ceiling):
    return isinstance(value, int) and 0 <= value <= ceiling

def torn_rows(rows):
    return [r for r in rows
            if not _sane(r.get("PID"), MAX_PID)
            or not _sane(r.get("Threads"), MAX_THREADS)]
```

The comment above this section tells a real, specific story recorded in
STATUS.md: a **live** memory acquisition tool (as opposed to a VM
snapshot, which freezes everything atomically) reads memory while Windows
is still actively modifying it — meaning the process list can genuinely be
caught mid-update, producing a structurally impossible row: on this
project's first x64 capture, one single row had an unprintable image name,
a PID of `88804946376740` (nowhere near a real Windows PID, which is always
a modest, bounded number), a thread count of `333,494,799`, and an exit
time centuries in the future. That one row alone moved
`pslist.avg_threads` from a reasonable `13.1` all the way to `4,977,547` —
a single garbage row completely dominating an average across dozens of
otherwise-normal processes.

`_sane(value, ceiling)` is a small, general bounds check: is this actually
a plain Python integer, and does it fall between 0 and some sensible upper
bound? `torn_rows(rows)` uses it to identify every row whose PID or thread
count fails that basic sanity test — those are the "torn" rows. Notice this
function's job is purely to **identify** torn rows, not to decide what to
do about them — that decision is made separately, feature by feature, in
`from_pslist()` below, and it's a genuinely nuanced one: the process itself
is *real* (it does exist, and dropping it from the count entirely would
make `pslist.nproc` read one lower than the true, ground-truth process
count) — it's only this specific row's *fields* that are unreadable
garbage.

## The `from_*()` functions — one per plugin, turning rows into features

Each of these takes the plain-dictionary rows from one plugin and returns
a small dictionary of `{feature_name: value}` pairs. Together, all nine
outputs get merged into the final 55-value vector by `assemble()`. Every
one of them is covered here, including the specific, sometimes
counter-intuitive reasoning behind each derivation — all of it verified,
per CLAUDE.md, against `ahlashkari/VolMemLyzer` (the actual reference
implementation that produced the training dataset's features), not
invented from scratch.

```python
def from_pslist(rows, nhandles):
    n = len(rows)
    threads = [r.get("Threads") for r in rows if _sane(r.get("Threads"), MAX_THREADS)]
    ppids = {r.get("PPID") for r in rows if _sane(r.get("PPID"), MAX_PID)}
    return {
        "pslist.nproc": float(n),
        "pslist.nppid": float(len(ppids)),
        "pslist.avg_threads": _ratio(sum(threads), len(threads)),
        "pslist.nprocs64bit": _count(rows, lambda r: r.get("Wow64") is True),
        "pslist.avg_handlers": _ratio(nhandles, n),
    }
```

`pslist.nproc` is simply the full row count — deliberately including torn
rows, so the process count itself stays accurate even when a row's other
fields are garbage. `pslist.avg_threads`, by contrast, is computed only
from the `threads` list, which was already filtered through `_sane()` — so
a torn row's absurd thread count never enters the average at all; this is
exactly how the earlier "one garbage row, 380,000× the real average" bug
was fixed. `pslist.nppid` counts **distinct** parent process IDs (a Python
`set` comprehension, `{...}`, automatically discards duplicates), also
filtered for sanity.

`pslist.nprocs64bit` is a genuine naming trap, and the comment states it
directly: despite the feature's name suggesting "count of 64-bit
processes," what the reference implementation (VolMemLyzer) actually
computes is a count of **WOW64** processes — 32-bit processes running
*under emulation* on a 64-bit kernel — which is close to the *opposite* of
what the name implies. This project deliberately matches that behaviour
exactly (`r.get("Wow64") is True`), bugs and all, because hard rule 24 is
explicit: match the training-data-producing reference implementation's
actual behaviour, never "fix" it toward what seems more correct in the
abstract, because the model was trained on the reference implementation's
real (if oddly-named) output, not on a hypothetically corrected version of
it.

`pslist.avg_handlers` divides the *handles* plugin's total handle count by
the *pslist* plugin's process count — not, as you might first guess, some
handle-count column native to `pslist` itself. The comment explains why:
Volatility 3 simply leaves `pslist`'s own `Handles` column empty/unpopulated,
so using it directly would silently yield `0.0` against a training range
whose floor sits around `50.4` — visibly, obviously wrong. Sourcing the
numerator from the separate `handles` plugin instead (passed in here as the
`nhandles` parameter) is what makes this feature meaningful at all.

```python
def from_dlllist(rows):
    n = len(rows)
    return {
        "dlllist.ndlls": float(n),
        "dlllist.avg_dlls_per_proc": _ratio(n, len({r.get("PID") for r in rows})),
    }
```

`dlllist.ndlls` is simply every loaded-module row found, across every
process. `avg_dlls_per_proc` divides that by the number of **distinct
processes appearing in the dlllist output itself** — not by
`pslist.nproc`. This distinction matters: a process whose module list
couldn't be read at all for some reason simply never appears in `dlllist`'s
rows, and dividing by the *pslist* process count instead would produce a
systematically different (and, per the comment, measurably wrong by about
1.8%) answer than what the reference implementation actually computes.

```python
def from_handles(rows):
    out = {"handles.nhandles": float(len(rows)),
           "handles.avg_handles_per_proc": _ratio(
               len(rows), len({r.get("PID") for r in rows})),
           "handles.nport": 0.0}
    for field, type_name in HANDLE_TYPES.items():
        out[field] = _count(rows, lambda r, t=type_name: r.get("Type") == t)
    return out
```

Same "denominator is the processes actually present in *this* plugin's own
output, not `pslist.nproc`" pattern as `dlllist` above, applied to handle
counts. `handles.nport` is hardcoded to `0.0` directly, with a real reason
given: the `Port` object type is an XP/2003-era Windows concept that simply
doesn't exist on any modern Windows version — the training data itself
shows `0` everywhere for this feature too, so emitting a hardcoded `0.0`
here costs nothing in accuracy and is honestly, correctly, always the right
answer. The final loop counts, for each of the ten named handle types in
`HANDLE_TYPES`, exactly how many handle rows carry that exact type string
— note the `t=type_name` default-argument trick inside the `lambda`, a
standard Python pattern needed because a `lambda` defined inside a loop
would otherwise capture the *variable* `type_name` by reference (and by
the time any of these lambdas actually ran, `type_name` would have already
moved on to its final loop value for every one of them) rather than the
specific value it had at the moment that particular lambda was created —
binding it as a default argument value freezes it correctly, once, per
iteration.

```python
def from_ldrmodules(rows):
    n = len(rows)
    out = {}
    for field, column in (("not_in_load", "InLoad"), ("not_in_init", "InInit"),
                          ("not_in_mem", "InMem")):
        missing = _count(rows, lambda r, c=column: r.get(c) is False)
        out[f"ldrmodules.{field}"] = missing
        out[f"ldrmodules.{field}_avg"] = _ratio(missing, n)
    return out
```

`ldrmodules` checks, for every loaded module of every process, whether that
module appears in each of the three separate linked lists the Windows
loader (PEB) is supposed to keep consistent — a module present in memory
but genuinely missing from one or more of these lists is a classic sign of
DLL hiding or process hollowing (file 11 covers the forensic *meaning* of
this in more depth). `r.get(c) is False` — deliberately `is False`, not
just a falsy check — matters because Volatility can, in principle, return
`None` for a value it couldn't determine at all, which is a genuinely
different situation from a confirmed `False` ("checked, and it's
definitely missing"); using `is False` avoids silently treating an
"unknown" result as a "missing" one. Each `_avg` variant divides by `n`,
`ldrmodules`'s own row count — verified, per the comment, to be the correct
denominator (matching a manual check against the reference data), as
opposed to dividing by `dlllist.ndlls`, which would leave a small but
measurable, consistent error.

```python
def from_malfind(rows, nproc):
    protection = 0.0
    unknown = set()
    for r in rows:
        flag = str(r.get("Protection") or "").strip()
        if flag in PROTECT_INDEX:
            protection += PROTECT_INDEX[flag]
        elif flag:
            unknown.add(flag)

    injected_procs = len({r.get("PID") for r in rows})
    return {
        "malfind.ninjections": float(len(rows)),
        "malfind.commitCharge": float(sum(r.get("CommitCharge") or 0 for r in rows)),
        "malfind.protection": protection,
        "malfind.uniqueInjections": _ratio(len(rows), injected_procs),
    }, unknown
```

`malfind` is, per CLAUDE.md, the single most reliable *behavioural*
indicator this whole pipeline has — it flags private memory regions marked
executable, the classic shape process injection takes. `ninjections` is
simply the count of flagged regions across the whole dump. `commitCharge`
sums each region's actual committed page count. `protection` uses the
`PROTECT_INDEX` table from the top of the file to reconstruct the
Volatility-2-style summed index; the `unknown` set collects any protection
flag string this project doesn't recognise (a genuinely defensive measure
— if some Windows build reports a protection flag this table has never
seen, it's tracked and disclosed as a gap rather than silently contributing
nothing, or crashing).

`uniqueInjections` is the feature CLAUDE.md flags as the hardest to pin
down with certainty — it's a *fractional* value in the real training data
(observed as high as `68.25`), which immediately rules out it being a
simple count of anything. The comment states the best surviving hypothesis
plainly: **injections per injected process** — `len(rows) / injected_procs`,
where `injected_procs` counts distinct PIDs that appear at all in
`malfind`'s output. This is disclosed as an *inferred* derivation (see
`INFERRED`, below), not asserted with full confidence, because its true
original derivation was never documented by the dataset's own authors.

```python
def from_psxview(rows):
    n = len(rows)
    out = {}
    for field, column in PSXVIEW_SOURCE.items():
        if column is None:
            out[f"psxview.{field}"] = 0.0
            out[f"psxview.{field}_false_avg"] = 0.0
            continue
        missing = _count(rows, lambda r, c=column: r.get(c) is False)
        out[f"psxview.{field}"] = missing
        out[f"psxview.{field}_false_avg"] = _ratio(missing, n)
    return out
```

This is where the `PSXVIEW_SOURCE` table from the top of the file gets
used directly. For the four sources Volatility 3 genuinely provides
(`pslist`, `psscan`, `thrdscan`, `csrss`), the same "count where the column
is explicitly `False`" pattern from `ldrmodules` applies, with the ratio
divided by `psxview`'s own row count (again the plugin's own count, not
`pslist.nproc` — the comment notes testing against `pslist.nproc` instead
leaves a consistent ~2.27% error, because `psscan` legitimately finds some
terminated processes `pslist` doesn't, inflating `psxview`'s own total
slightly above the live process count). For the **three** sources that have
genuinely no Volatility 3 equivalent (`column is None`), both the count and
its average are emitted as a plain, honest `0.0` — never guessed, never
interpolated — and, as covered below, disclosed in the `MISSING` table as a
structural gap rather than a value anyone should mistake for a real
measurement of zero.

```python
def dedupe_services(rows):
    by_order = {}
    for r in rows:
        by_order.setdefault(r.get("Order"), r)
    return list(by_order.values())
```

This function fixes a real, measured bug in the installed Volatility 3
itself, not in this project's own code — and it's one of the more
interesting stories in the whole codebase. Volatility 3's `svcscan` plugin
scans every process's address space looking for a specific tag (`serH`)
marking the Windows service list, and it can find — and fully re-traverse —
that same list from *multiple different processes' memory* if it's mapped
into more than one of them, producing genuine duplicate rows for the exact
same service. Volatility's own internal `seen` guard, meant to prevent
exactly this, compares tuples that can contain special "renderer" objects
(like `UnreadableValue` — Volatility's placeholder for "this field couldn't
be read"), and those objects, per the comment, "never compare equal" to
each other even when they represent the same thing — so the guard silently
does nothing. Measured directly on a real Windows 10 capture: **1,311**
raw rows for only **594** genuinely distinct services, some individual
services repeated as many as 12 times. `dedupe_services()` fixes this by
keying on `"Order"` — each service's position in the service list, which is
genuinely unique per real service, unlike the broken tuple comparison
Volatility itself relies on. `by_order.setdefault(r.get("Order"), r)`
keeps only the *first* row seen for each distinct order value, discarding
the rest.

```python
def from_svcscan(rows):
    def typed(name):
        return _count(rows, lambda r: str(r.get("Type")) == name)

    return {
        "svcscan.nservices": float(len(rows)),
        "svcscan.kernel_drivers": typed("SERVICE_KERNEL_DRIVER"),
        "svcscan.fs_drivers": typed("SERVICE_FILE_SYSTEM_DRIVER"),
        "svcscan.process_services": typed("SERVICE_WIN32_OWN_PROCESS"),
        "svcscan.shared_process_services": typed("SERVICE_WIN32_SHARE_PROCESS"),
        "svcscan.interactive_process_services": typed("SERVICE_INTERACTIVE_PROCESS"),
        "svcscan.nactive": _count(rows, lambda r: str(r.get("State")) == "SERVICE_RUNNING"),
    }
```

Called on the already-deduplicated rows. Every `typed(...)` comparison is
**exact string equality**, never a substring or partial match — and the
comment explains precisely why that specific choice matters for one
feature in particular: `interactive_process_services` is, in the real
training data, *always* zero, and the reason is structural rather than
incidental. Windows only ever exposes an "interactive" service as part of
a **combined** flag string, something like
`"SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS"`, never as the
bare standalone string `"SERVICE_INTERACTIVE_PROCESS"` this exact-equality
check is looking for — so the comparison can genuinely never match,
reproducing the reference implementation's real (if perhaps unintended)
behaviour exactly. A more "helpful" substring match here would silently
un-zero this feature and push real captures further off the distribution
the model was actually trained on — hard rule 24 again, in concrete form.
`nactive` counts services literally in the running state — confirmed,
by direct comparison against `nservices` across 5,000 reference rows, to
always be a smaller number, ruling out the alternative (and initially
plausible) hypothesis that `nservices` itself might already mean "running
services only."

```python
def from_callbacks(rows):
    return {
        "callbacks.ncallbacks": float(len(rows)),
        "callbacks.nanonymous": _count(rows, lambda r: str(r.get("Module")) == "UNKNOWN"),
        "callbacks.ngeneric": _count(
            rows, lambda r: "GenericKernelCallback" in str(r.get("Type") or "")),
    }
```

Kernel callbacks are routines the Windows kernel invokes automatically on
events like process creation or module loading — a legitimate mechanism,
but also one malware can abuse for kernel-level monitoring or persistence
(file 11). `nanonymous` counts callbacks whose owning module Volatility
couldn't resolve at all (reported literally as the string `"UNKNOWN"`) —
again exact-match, not a substring check, matching the reference
implementation's own behaviour and avoiding accidentally also counting
blank or `"N/A"` values as anonymous, which would inflate this feature
beyond what the model was trained to expect. `ngeneric` — mentioned
repeatedly elsewhere in this project's documentation as a genuinely
constant feature (`8.0` in every training row) — is still computed
honestly here rather than hardcoded, on the reasoning that a constant
*input* doesn't excuse incorrect *logic*; it just happens that this
particular value can never actually change what the trained model predicts,
since a feature the model never saw vary during training was never used to
split any of its trees.

## `assemble()` — laying the 55 values out in the exact right order

```python
def assemble(parts, feature_names, unknown_protection=(), torn=0):
    if len(feature_names) != FEATURE_COUNT:
        raise ExtractionError(...)

    values = {}
    for part in parts:
        values.update(part)

    missing = [n for n in feature_names if n not in values]
    if missing:
        raise ExtractionError(f"extractor produced no value for {len(missing)} "
                              f"features, e.g. {missing[:5]}")
    extra = set(values) - set(feature_names)
    if extra:
        raise ExtractionError(f"extractor produced unknown features: {sorted(extra)[:5]}")

    vec = [float(values[name]) for name in feature_names]
```

This is the function that finally connects everything covered above to
file 08's warning about feature order being the single most dangerous
thing in the whole project — and notice exactly *how* it does it. Every
one of the nine `from_*()` functions returns a plain `{name: value}`
dictionary; `values = {}` followed by `for part in parts: values.update(part)`
merges all nine of those dictionaries together into one big one, **keyed
by name, not by position** — there is no implicit ordering being relied on
anywhere up to this point. Only the very last line,
`vec = [float(values[name]) for name in feature_names]`, actually produces
an ordered list — and it does so by iterating over `feature_names` (the
real JSON list, passed in from the model's own `feature_list.json`, file
08), looking each one up by its name. This is the concrete implementation
of the rule stated directly in CLAUDE.md: build the vector as a dictionary
keyed by feature name, and only emit it in the JSON's order at the very
last step — never hand-sequence the fields anywhere along the way.

The two checks right before that — `missing` (a feature the JSON list
expects but nothing computed a value for at all) and `extra` (this
extractor computed a value for something the JSON list never asked for) —
are a structural, exhaustive cross-check that the *set* of names being
produced exactly matches the *set* of names expected, independent of and
in addition to the later positional-ordering guard covered in file 08.

```python
    gaps = [{"field": f, "plugin": f.split(".")[0], "confidence": "missing", "reason": r}
            for f, r in sorted(MISSING.items())]
    gaps += [{"field": f, "plugin": f.split(".")[0], "confidence": "inferred", "reason": r}
             for f, r in sorted(INFERRED.items())]
    for flag in sorted(unknown_protection):
        gaps.append({"field": "malfind.protection", "plugin": "malfind",
                     "confidence": "inferred",
                     "reason": f"protection flag {flag!r} has no Volatility 2 index; "
                               "contributed 0 to the sum"})
    if torn:
        gaps.append({"field": "pslist.avg_threads", "plugin": "pslist",
                     "confidence": "inferred",
                     "reason": f"{torn} process row(s) were structurally torn, ..."})
    return vec, gaps
```

The second half of `assemble()`'s job is building the `extraction_gaps`
list — the honest, structured record of every place this extraction wasn't
100% certain, that eventually reaches the report's limitations section
(file 12). `MISSING` (built from `PSXVIEW_SOURCE`'s three `None` entries)
and `INFERRED` (a hand-maintained dictionary at module level, covering
`malfind.protection`, `malfind.uniqueInjections`, `pslist.nppid`,
`pslist.avg_handlers`, `handles.avg_handles_per_proc`, and the three
`ldrmodules.*_avg` fields — every derivation this file's own comments,
covered above, flagged as inferred rather than certain) both get folded in
as **data-driven** gap entries, generated automatically from these tables
rather than something that could be forgotten by whoever last edited a
`from_*()` function — this is a deliberate structural choice, ensuring it's
impossible to add a new inferred field without it automatically showing up
in the disclosed gap list. Any unrecognised protection flags encountered
during this specific extraction, and a note about any torn rows found,
round out the list with genuinely per-capture, dynamic entries.

## `evidence()` — building the human-investigable locators

```python
EVIDENCE_CAP = 25

def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def _hex(value):
    n = _int(value)
    return f"{n:#x}" if n is not None else None

def _text(value):
    if value is None:
        return None
    out = str(value).strip()
    return out or None
```

Before covering `evidence()` itself, these three tiny coercion helpers need
explaining, because the comment right above them describes a real, second
silent bug found in this project (STATUS.md's silent bug #7) — arguably the
most instructive one in the whole codebase. Volatility 3 doesn't always
hand back plain Python values (`int`, `str`) for a row's fields — it can
return special internal "renderer" objects like `BitField` or
`UnreadableValue` in their place, which display sensibly when printed but
are not, underneath, ordinary built-in Python types. The evidence data
computed here has to travel back across the process boundary (via pickling,
the same concept introduced in file 07 for `extract_disk`'s return value)
from the worker process to the supervisor — and those renderer objects, it
turns out, can pickle just fine going *into* the worker's serialized
output, but then **fail while being reconstructed on the way back out** in
the parent process, taking down the *entire* process pool
(`BrokenProcessPool`) rather than just failing this one job — with a
traceback pointing generically at `concurrent.futures` internals, nowhere
near the actual cause. `_int()`, `_hex()`, and `_text()` exist purely to
force every single value that goes into the evidence structure through a
genuine Python builtin (`int`, a formatted hex string, or a plain stripped
`str`) — coercing anything that fails cleanly to `None` rather than letting
an un-picklable renderer object anywhere near the return value.

```python
def evidence(collected):
    out = {}

    injected = []
    for r in collected.get("malfind", []):
        start, end = _int(r.get("Start VPN")), _int(r.get("End VPN"))
        size = end - start + 1 if start is not None and end is not None and end >= start \
            else None
        injected.append({
            "pid": _int(r.get("PID")), "process": _text(r.get("Process")),
            "start": _hex(start), "end": _hex(end), "size": size,
            "protection": _text(r.get("Protection")),
            "commit": _int(r.get("CommitCharge")),
            "private": _int(r.get("PrivateMemory")) == 1,
        })
    injected.sort(key=lambda d: -(d["size"] or 0))
    out["injected_regions"] = injected[:EVIDENCE_CAP]
```

This function's whole purpose, stated plainly in its own comment, is:
"counts are a statistic; 'svchost.exe PID 1204 holds an RWX region at
0x7ff8…' is something an analyst can act on." Every field it uses here
comes from a plugin that has *already run* as part of building the 55-value
vector — so this evidence collection costs essentially no extra runtime; it
only uses the rows that would otherwise have been discarded once their
aggregate counts were computed. For every `malfind` hit: compute the
region's size from its start/end virtual page numbers (guarding against
either being unreadable), and build a small dictionary with every field an
analyst would need to go look at this exact region directly in the capture.
Sorted **largest region first** — the comment explains why: "a 4 KB RWX
page is ordinary, a multi-megabyte one is not," so the most interesting
entries surface first even after the cap.

```python
    hidden_modules = []
    for r in collected.get("ldrmodules", []):
        absent = [name for name, col in (("load", "InLoad"), ("init", "InInit"),
                                         ("mem", "InMem")) if r.get(col) is False]
        if not absent:
            continue
        hidden_modules.append({...})
    hidden_modules.sort(key=lambda d: -len(d["absent_from"]))
    out["hidden_modules"] = hidden_modules[:EVIDENCE_CAP]
```

Same pattern for loader-list mismatches — only modules missing from *at
least one* of the three lists are included at all (`if not absent:
continue` skips modules that are fine), sorted by how many lists they're
missing from (missing from all three is the strongest signal — the comment
notes this directly: "missing from all three lists is the strong signal;
one omission is routine").

```python
    hidden_procs = []
    for r in collected.get("psxview", []):
        absent = [name for name in ("pslist", "psscan", "thrdscan", "csrss")
                  if r.get(name) is False]
        if not absent:
            continue
        hidden_procs.append({
            "pid": _int(r.get("PID")), "name": _text(r.get("Name")),
            "missing_from": absent,
            "exit_time": _text(r.get("Exit Time")),
        })
    hidden_procs.sort(key=lambda d: -len(d["missing_from"]))
    out["hidden_processes"] = hidden_procs[:EVIDENCE_CAP]
```

Same idea for psxview discrepancies, with one important addition: the
`exit_time` field, whose comment states directly why it's included — "a
terminated process legitimately survives in pool scans, so an exit time is
usually the innocent explanation for the discrepancy." Recording it here is
what lets a report show a genuinely terminated process's exit timestamp
right alongside the "hidden" flag, so an analyst can immediately see the
mundane explanation rather than reading a bare mismatch as automatically
suspicious.

```python
    unbacked = [{
        "type": _text(r.get("Type")), "callback": _hex(r.get("Callback")),
        "module": _text(r.get("Module")), "symbol": _text(r.get("Symbol")),
    } for r in collected.get("callbacks", []) if str(r.get("Module")) == "UNKNOWN"]
    out["unbacked_callbacks"] = unbacked[:EVIDENCE_CAP]

    out["totals"] = {"injected_regions": len(injected),
                     "hidden_modules": len(hidden_modules),
                     "hidden_processes": len(hidden_procs),
                     "unbacked_callbacks": len(unbacked)}
    out["capped_at"] = EVIDENCE_CAP
    return out
```

Kernel callbacks with no resolvable owning module get their own list, same
shape. And crucially, `out["totals"]` records the **true, full count** of
every category, computed *before* the `[:EVIDENCE_CAP]` slicing that
limits what actually gets stored (25 entries per category, per the comment,
because "an analyst reads the top of the list and pivots" — keeping every
single row of what can be hundreds of loader-list mismatches would bloat
the job row for no real gain). This distinction between "true total" and
"shown, capped subset" matters directly for report honesty (file 12) — the
report always states both, so it never silently understates how much was
actually found just because only a subset is displayed.

## `extract()` — the top-level function that runs the whole pipeline

```python
def extract(dump, feature_names, progress=None):
    from volatility3 import framework
    import volatility3.plugins

    framework.import_files(volatility3.plugins, True)
    catalog = framework.list_plugins()

    timings = {}
    t0 = time.perf_counter()
    prepared = build_context(dump, catalog)
    timings["build_context"] = round(time.perf_counter() - t0, 1)

    collected = {}
    for key, plugin in PLUGINS.items():
        if progress:
            progress(key, plugin)
        started = time.perf_counter()
        _, rows = run_plugin(dump, plugin, catalog, prepared)
        collected[key] = rows
        timings[key] = round(time.perf_counter() - started, 1)
        log.info("%s: %d rows in %.1fs", plugin, len(rows), timings[key])
```

This is the function `jobs.py:extract_memory()` (file 07) actually calls
inside the worker process. `framework.import_files(...)` and
`framework.list_plugins()` (file 01) build the full catalog of everything
Volatility 3 knows about, once. `build_context(dump, catalog)` runs the
architecture-gating step covered above — if the dump isn't 64-bit, this is
where extraction stops entirely, before any of the nine real plugins run.

The `for key, plugin in PLUGINS.items():` loop is where all nine plugins
actually run, one after another (recall from file 07 this is also exactly
what drives the "Running windows.malfind (5 of 9)" live progress text, via
the `progress` callback). Every plugin's wall-clock time is individually
recorded into `timings` — this is the `plugin_seconds` data that ends up
on the `Job` row (file 04, file 07), kept specifically because STATUS.md
records that total runtime has been observed to vary roughly 2× between
runs on identical input, with the cause genuinely not yet identified —
having per-plugin timing is what would eventually let someone localise
where that variance actually comes from, rather than only having one
opaque total.

```python
    raw_services = len(collected["svcscan"])
    collected["svcscan"] = dedupe_services(collected["svcscan"])

    nproc = len(collected["pslist"])
    nhandles = len(collected["handles"])
    malfind_fields, unknown = from_malfind(collected["malfind"], nproc)

    parts = [
        from_pslist(collected["pslist"], nhandles),
        from_dlllist(collected["dlllist"]),
        from_handles(collected["handles"]),
        from_ldrmodules(collected["ldrmodules"]),
        malfind_fields,
        from_psxview(collected["psxview"]),
        from_modules(collected["modules"]),
        from_svcscan(collected["svcscan"]),
        from_callbacks(collected["callbacks"]),
    ]
    torn = len(torn_rows(collected["pslist"]))
    vec, gaps = assemble(parts, feature_names, unknown, torn)
    counts = {k: len(v) for k, v in collected.items()}
    return {"vec": vec, "gaps": gaps, "plugin_rows": counts, "bits": prepared["bits"],
            "plugin_seconds": timings, "evidence": evidence(collected),
            "torn_process_rows": torn, "svcscan_raw_rows": raw_services,
            "svcscan_duplicate_ratio": raw_services / max(len(collected["svcscan"]), 1)}
```

The raw `svcscan` row count is saved (`raw_services`) *before*
deduplication, specifically so the duplicate ratio at the very bottom of
the return value (`svcscan_duplicate_ratio`) can honestly quantify how much
deduplication actually mattered for this specific capture — this is a
diagnostic figure, not something the model ever sees, but exactly the kind
of number that made the duplication bug discoverable and verifiable in the
first place. Every one of the nine `from_*()` functions runs exactly once,
with `malfind`'s slightly different two-value return (`malfind_fields,
unknown = from_malfind(...)`) unpacked separately since it also needs to
report the set of unrecognised protection flags. `assemble()` (covered
above) then produces the final ordered vector and the gap list.

The final returned dictionary is everything `jobs.py`'s `_memory()` (file
07) needs: the 55-value `vec` itself, the honest `gaps` list, raw
per-plugin row counts (useful for diagnostics), the confirmed bit-width,
per-plugin timings, the full evidence structure, the torn-row count, and
the raw-versus-deduplicated service counts — a single, self-contained
package representing everything this one extraction run discovered and had
to be honest about.

## Check your understanding

**Q1. Why does `build_context()` check the memory *layer's class*
(`Intel32e`) to determine whether a dump is 64-bit, rather than reading
some kind of architecture field directly out of the dump file?**

A: Because a raw memory dump (`.raw`, `.mem`, `.vmem`) carries no header of
its own that identifies its architecture at all — there's nothing to
directly "read." The memory layer Volatility 3's own automagic system
constructs, after examining the dump's actual structure, is the earliest
point in the entire pipeline where the architecture is genuinely,
reliably known, which is exactly why the check happens there, before any
of the nine real analysis plugins run.

**Q2. `pslist.nprocs64bit` actually counts WOW64 (32-bit-on-64-bit)
processes, despite its name suggesting the opposite. Why does this project
keep that seemingly backwards behaviour rather than fixing it?**

A: Because the trained model was fitted on features produced by
VolMemLyzer, the reference implementation that actually generated
CIC-MalMem-2022 — and that implementation genuinely computes it this way,
regardless of what the feature's name suggests. "Fixing" it to match the
name's apparent meaning would produce a value the model was never trained
on, making predictions on real data less accurate, not more — hard rule 24
requires reproducing the reference implementation's real behaviour exactly,
including any of its own naming inconsistencies.

**Q3. What specific problem does `dedupe_services()` fix, and why couldn't
Volatility 3's own built-in duplicate-prevention logic catch it?**

A: Volatility 3's `svcscan` plugin can find and fully re-traverse the same
Windows service list from multiple different processes' memory, producing
genuine duplicate rows for the same real service — measured as high as
1,311 raw rows for only 594 actually distinct services. Volatility's own
internal guard against this compares tuples that can contain special
"renderer" objects like `UnreadableValue`, and those objects never compare
equal to each other even when they represent the same underlying value, so
the guard silently does nothing. This project's fix instead keys on
`"Order"` — each service's position in the list, which genuinely is unique
per real service — to correctly identify and discard the duplicates.

**Q4. What specific, real failure mode do the `_int()`, `_hex()`, and
`_text()` helper functions in the evidence-building code exist to prevent,
and why was it so hard to diagnose the first time it happened?**

A: They force every value going into the per-process evidence structure
through a genuine Python builtin type, because Volatility 3 can hand back
special internal "renderer" objects (like `BitField` or `UnreadableValue`)
in place of plain values. Those objects can pickle successfully going into
a worker process's returned result, but fail while being reconstructed back
in the parent process — and when that happens, the *entire* process pool is
reported as broken (`BrokenProcessPool`), with a traceback pointing at
generic `concurrent.futures` internals, nowhere near the actual cause
(a specific field, in a specific plugin's output, holding a non-builtin
object) — which is exactly why it was hard to diagnose without deliberately
testing a real capture's real evidence data end to end.

**Q5. `assemble()` merges nine separate dictionaries and only converts the
result into an ordered list on its very last line. Why does building it
this way — as a dictionary first, ordered list last — matter so much for
this project's correctness?**

A: Because it structurally rules out an entire class of possible bugs: at
no point before the final line is any code relying on the nine `from_*()`
functions being called in a particular order, or on Python dictionaries
preserving any particular internal order. The single, final line —
`[float(values[name]) for name in feature_names]` — is the *only* place
ordering is ever imposed, and it's imposed by explicitly looking each
required name up by that name, against the real JSON feature list the
model expects. This directly matches the rule stated in CLAUDE.md: build
the vector as a dictionary keyed by name, and only emit it in the JSON's
order at the very last step — never hand-sequence the fields anywhere
along the way.
