import sys
import urllib.parse
import urllib.request
from pathlib import Path

# Volatility 2's vadinfo.PROTECT_FLAGS, index-for-index. malfind.protection in
# CIC-MalMem-2022 sums these *indices*, not the Win32 constants: mean protection
# over mean ninjections comes to ~6.0, and index 6 is PAGE_EXECUTE_READWRITE,
# which is exactly what malfind hits on. The Win32 value would be 0x40 = 64 and
# does not fit. Vol3 emits the flag as a string, hence this table.
PROTECT_INDEX = {
    "PAGE_NOACCESS": 0,
    "PAGE_READONLY": 1,
    "PAGE_EXECUTE": 2,
    "PAGE_EXECUTE_READ": 3,
    "PAGE_READWRITE": 4,
    "PAGE_WRITECOPY": 5,
    "PAGE_EXECUTE_READWRITE": 6,
    "PAGE_EXECUTE_WRITECOPY": 7,
}

# Vol2's psxview enumerated processes seven ways; vol3's exposes four. Confirmed
# against the installed volatility3 2.28 source, not documentation.
PSXVIEW_SOURCE = {
    "not_in_pslist": "pslist",
    "not_in_eprocess_pool": "psscan",
    "not_in_ethread_pool": "thrdscan",
    "not_in_csrss_handles": "csrss",
    "not_in_pspcid_list": None,
    "not_in_session": None,
    "not_in_deskthrd": None,
}

HANDLE_TYPES = {
    "handles.nfile": "File", "handles.nevent": "Event",
    "handles.ndesktop": "Desktop", "handles.nkey": "Key",
    "handles.nthread": "Thread", "handles.ndirectory": "Directory",
    "handles.nsemaphore": "Semaphore", "handles.ntimer": "Timer",
    "handles.nsection": "Section", "handles.nmutant": "Mutant",
}

# ldrmodules, malfind and psxview live under windows.malware.* now; the old
# windows.* names still resolve but emit a removal warning dated 2026-06-07.
PLUGINS = {
    "pslist": "windows.pslist.PsList",
    "dlllist": "windows.dlllist.DllList",
    "handles": "windows.handles.Handles",
    "ldrmodules": "windows.malware.ldrmodules.LdrModules",
    "malfind": "windows.malware.malfind.Malfind",
    "psxview": "windows.malware.psxview.PsXView",
    "modules": "windows.modules.Modules",
    "svcscan": "windows.svcscan.SvcScan",
    "callbacks": "windows.callbacks.Callbacks",
}


class ExtractionError(RuntimeError):
    pass


def _url(path):
    # pathname2url handles the spaces in this project's own path, which a naive
    # "file://" + str(path) does not.
    return urllib.parse.urljoin("file:", urllib.request.pathname2url(str(Path(path).resolve())))


def _no_files():
    from volatility3.framework import interfaces

    class _NoFiles(interfaces.plugins.FileHandlerInterface):
        def preferred_filename(self):
            return "unused"

        def close(self):
            pass

    return _NoFiles


def find_pae_dtb(ctx, layer_name):
    """Locate a PAE page-directory-pointer table by hand.

    volatility3 2.28 cannot do this itself. WindowsIntelStacker rejects any
    candidate whose 4 KB page holds fewer than 10 valid pointers, as a guard
    against Windows' small dummy page tables - but a PAE PDPT has exactly four
    entries by architecture, so every genuine 32-bit PAE DTB is discarded and no
    layer is ever built. Verified against volatility3 2.28.0 on a Windows 10 x86
    capture: the real DTB sits at 0x1a8000 with 4 valid pointers and is thrown
    away, and both this library and the stock `vol` CLI then report
    "No suitable kernels found during pdbscan".
    """
    from volatility3.framework.automagic import windows as winmagic

    scanner = winmagic.PageMapScanner([winmagic.DtbSelfRefPae()])
    hits = [offset for _, offset in ctx.layers[layer_name].scan(ctx, scanner)]
    if not hits:
        return None
    # Modern Windows randomises the self-referential index but keeps the DTB in
    # a narrow band; prefer a hit there when several turn up.
    preferred = [h for h in hits if 0x1A0000 <= h < 0x1B0000]
    return (preferred or hits)[0]


def build_context(dump):
    """-> (context, layer_name, symbol_table, kernel_offset)

    Tries stock automagic first so 64-bit images and crash dumps keep the
    supported path, then falls back to constructing the PAE layer directly.
    """
    from volatility3 import framework
    from volatility3.framework import automagic, contexts, exceptions
    from volatility3.framework.layers import intel, physical
    from volatility3.framework.symbols.windows import pdbutil
    import volatility3.plugins

    framework.import_files(sys.modules["volatility3.framework.layers"])

    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = _url(dump)
    ctx.config["base.location"] = _url(dump)
    ctx.add_layer(physical.FileLayer(ctx, "base", "base"))

    dtb = find_pae_dtb(ctx, "base")
    if dtb is None:
        return ctx, None, None, None

    ctx.config["primary_cfg.memory_layer"] = "base"
    ctx.config["primary_cfg.page_map_offset"] = dtb
    ctx.add_layer(intel.WindowsIntelPAE(ctx, "primary_cfg", "primary",
                                        metadata={"os": "Windows"}))

    kernels = list(pdbutil.PDBUtility.pdbname_scan(
        ctx=ctx, layer_name="primary", start=0, page_size=0x1000,
        pdb_names=[bytes(n + ".pdb", "utf-8") for n in
                   ("ntkrpamp", "ntkrnlmp", "ntkrnlpa", "ntoskrnl")]))
    if not kernels:
        raise ExtractionError(
            f"a PAE page directory was found at {dtb:#x} but no Windows kernel is "
            "mapped through it; the capture may be torn or from a paused-but-not-"
            "suspended VM")

    kernel = kernels[0]
    table = pdbutil.PDBUtility.load_windows_symbol_table(
        context=ctx, guid=kernel["GUID"], age=kernel["age"],
        pdb_name=kernel["pdb_name"], config_path="pdbutility",
        symbol_table_class="volatility3.framework.symbols.windows.WindowsKernelIntermedSymbols")

    kvo = kernel["mz_offset"]
    ctx.config["primary_cfg.kernel_virtual_offset"] = kvo
    return ctx, "primary", table, kvo


def run_plugin(dump, plugin, catalog=None, prepared=None):
    """Run one Volatility 3 plugin and collect its rows as dicts."""
    from volatility3 import framework
    from volatility3.framework import automagic, contexts, plugins
    import volatility3.plugins

    if catalog is None:
        framework.import_files(volatility3.plugins, True)
        catalog = framework.list_plugins()
    if plugin not in catalog:
        raise ExtractionError(f"{plugin} is not available in this volatility3 build")

    cls = catalog[plugin]
    name = cls.__name__

    if prepared is None:
        ctx = contexts.Context()
        ctx.config["automagic.LayerStacker.single_location"] = _url(dump)
        autos = automagic.choose_automagic(automagic.available(ctx), cls)
    else:
        ctx, layer, table, kvo = prepared
        ctx = ctx.clone()
        ctx.config[f"plugins.{name}.kernel.layer_name"] = layer
        ctx.config[f"plugins.{name}.kernel.symbol_table_name"] = table
        ctx.config[f"plugins.{name}.kernel.offset"] = kvo
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


def _count(rows, predicate):
    return float(sum(1 for r in rows if predicate(r)))


def _ratio(numerator, denominator):
    return float(numerator) / denominator if denominator else 0.0


def from_pslist(rows):
    n = len(rows)
    threads = [r.get("Threads") or 0 for r in rows]
    handles = [r.get("Handles") for r in rows]
    live = [h for h in handles if isinstance(h, int)]
    return {
        "pslist.nproc": float(n),
        # Distinct parent PIDs. Mean 14.7 against nproc 41.5 in training fits this
        # reading; "processes with a live parent" also fits and is not separable
        # from the reference data.
        "pslist.nppid": float(len({r.get("PPID") for r in rows})),
        "pslist.avg_threads": _ratio(sum(threads), n),
        "pslist.nprocs64bit": _count(rows, lambda r: r.get("Wow64") is False),
        "pslist.avg_handlers": _ratio(sum(live), len(live)),
    }


def from_dlllist(rows, nproc):
    n = len(rows)
    return {
        "dlllist.ndlls": float(n),
        # Confirmed exact against the reference data - median relative error
        # 2.8e-8, i.e. float32 rounding and nothing else.
        "dlllist.avg_dlls_per_proc": _ratio(n, nproc),
    }


def from_handles(rows, nproc):
    out = {"handles.nhandles": float(len(rows)),
           "handles.avg_handles_per_proc": _ratio(len(rows), nproc),
           # The Port object type is XP/2003 era and absent from modern Windows.
           # Training saw 0 everywhere too, so this costs nothing.
           "handles.nport": 0.0}
    for field, type_name in HANDLE_TYPES.items():
        out[field] = _count(rows, lambda r, t=type_name: r.get("Type") == t)
    return out


def from_ldrmodules(rows):
    n = len(rows)
    out = {}
    for field, column in (("not_in_load", "InLoad"), ("not_in_init", "InInit"),
                          ("not_in_mem", "InMem")):
        missing = _count(rows, lambda r, c=column: r.get(c) is False)
        out[f"ldrmodules.{field}"] = missing
        # Denominator is this plugin's own row count. Testing the reference data
        # against dlllist.ndlls leaves a consistent 1.8% error; against its own
        # count it closes.
        out[f"ldrmodules.{field}_avg"] = _ratio(missing, n)
    return out


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
        # Fractional in training (max 68.25) so not a count, and 12x off from
        # ninjections/nproc. Injections per *injected* process is the closest
        # reading that survives the reference data; still inferred.
        "malfind.uniqueInjections": _ratio(len(rows), injected_procs),
    }, unknown


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
        # psxview's own union-of-sources count, not pslist.nproc: measured against
        # the reference data the latter leaves a uniform 2.27% error because
        # psscan also turns up terminated processes.
        out[f"psxview.{field}_false_avg"] = _ratio(missing, n)
    return out


def from_modules(rows):
    return {"modules.nmodules": float(len(rows))}


def from_svcscan(rows):
    def typed(fragment):
        return _count(rows, lambda r: fragment in str(r.get("Type") or ""))

    return {
        "svcscan.nservices": float(len(rows)),
        "svcscan.kernel_drivers": typed("SERVICE_KERNEL_DRIVER"),
        "svcscan.fs_drivers": typed("SERVICE_FILE_SYSTEM_DRIVER"),
        "svcscan.process_services": typed("SERVICE_WIN32_OWN_PROCESS"),
        "svcscan.shared_process_services": typed("SERVICE_WIN32_SHARE_PROCESS"),
        "svcscan.interactive_process_services": typed("SERVICE_INTERACTIVE_PROCESS"),
        "svcscan.nactive": _count(rows, lambda r: "RUNNING" in str(r.get("State") or "")),
    }


def from_callbacks(rows):
    return {
        "callbacks.ncallbacks": float(len(rows)),
        "callbacks.nanonymous": _count(
            rows, lambda r: not str(r.get("Module") or "").strip()
            or str(r.get("Module")).upper() in ("UNKNOWN", "N/A")),
        # Constant at 8.0 across every training row, so the model never split on
        # it. Emitted honestly regardless; the value cannot change a prediction.
        "callbacks.ngeneric": _count(
            rows, lambda r: "GenericKernelCallback" in str(r.get("Type") or "")),
    }


# Fields whose value is emitted but whose derivation is inferred rather than
# documented. They belong in extraction_gaps flagged as inferred, not missing -
# hiding them would misrepresent how solid the vector is.
INFERRED = {
    "malfind.protection": "summed Volatility 2 protection index, inferred from training statistics",
    "malfind.uniqueInjections": "injections per injected process; original derivation unknown",
    "pslist.nppid": "count of distinct parent PIDs; two readings fit the training data equally",
    "pslist.avg_handlers": "handles per process; not independently derivable from handles.avg_handles_per_proc",
    "handles.avg_handles_per_proc": "handles per process; shares a numerator with pslist.avg_handlers",
    "ldrmodules.not_in_load_avg": "divided by the ldrmodules row count",
    "ldrmodules.not_in_init_avg": "divided by the ldrmodules row count",
    "ldrmodules.not_in_mem_avg": "divided by the ldrmodules row count",
}

MISSING = {
    f"psxview.{field}{suffix}": "Volatility 3's psxview enumerates processes four "
                                "ways; this source has no equivalent column"
    for field, column in PSXVIEW_SOURCE.items() if column is None
    for suffix in ("", "_false_avg")
}


def assemble(parts, feature_names, unknown_protection=()):
    """Lay the collected values out in feature_list.json order.

    Ordering is derived from the JSON list, never hand-sequenced. The startup
    distribution check catches a wholesale scramble but only 5 of 54 adjacent
    swaps, so a two-field transposition here would otherwise be invisible.
    """
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

    gaps = [{"field": f, "plugin": f.split(".")[0], "confidence": "missing", "reason": r}
            for f, r in sorted(MISSING.items())]
    gaps += [{"field": f, "plugin": f.split(".")[0], "confidence": "inferred", "reason": r}
             for f, r in sorted(INFERRED.items())]
    for flag in sorted(unknown_protection):
        gaps.append({"field": "malfind.protection", "plugin": "malfind",
                     "confidence": "inferred",
                     "reason": f"protection flag {flag!r} has no Volatility 2 index; "
                               "contributed 0 to the sum"})
    return vec, gaps


def extract(dump, feature_names, progress=None):
    from volatility3 import framework
    import volatility3.plugins

    framework.import_files(volatility3.plugins, True)
    catalog = framework.list_plugins()

    prepared = build_context(dump)
    if prepared[1] is None:
        prepared = None

    collected = {}
    for key, plugin in PLUGINS.items():
        if progress:
            progress(key, plugin)
        _, rows = run_plugin(dump, plugin, catalog, prepared)
        collected[key] = rows

    nproc = len(collected["pslist"])
    malfind_fields, unknown = from_malfind(collected["malfind"], nproc)

    parts = [
        from_pslist(collected["pslist"]),
        from_dlllist(collected["dlllist"], nproc),
        from_handles(collected["handles"], nproc),
        from_ldrmodules(collected["ldrmodules"]),
        malfind_fields,
        from_psxview(collected["psxview"]),
        from_modules(collected["modules"]),
        from_svcscan(collected["svcscan"]),
        from_callbacks(collected["callbacks"]),
    ]
    vec, gaps = assemble(parts, feature_names, unknown)
    counts = {k: len(v) for k, v in collected.items()}
    return {"vec": vec, "gaps": gaps, "plugin_rows": counts}