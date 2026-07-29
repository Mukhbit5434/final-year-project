"""Feature -> plain-English forensic significance.

Static tables and a resolver. No model, no inference. Verified against the
installed ember/features.py, not against documentation - the index layouts below
come from reading process_raw_features directly.
"""

MEMORY = {
    "malfind.ninjections": (
        "Injected executable memory regions",
        "Private memory marked executable with no backing file on disk. This is how "
        "injected code is normally staged, though JIT compilers and browsers allocate "
        "it legitimately too."),
    "malfind.commitCharge": (
        "Committed pages in injected regions",
        "Total memory committed across the regions malfind flagged. Large values mean "
        "substantial injected content rather than a few stray pages."),
    "malfind.protection": (
        "Protection flags on injected regions",
        "Summed page-protection of the flagged regions; execute+write is the "
        "combination shellcode needs."),
    "malfind.uniqueInjections": (
        "Injected regions per affected process",
        "Concentration of injected regions. Many regions in one process reads "
        "differently from one region across many."),
    "ldrmodules.not_in_load": (
        "Modules absent from the load-order list",
        "A module mapped in memory but missing from the PEB load-order list. Consistent "
        "with DLL hiding or process hollowing; also occurs during ordinary loading."),
    "ldrmodules.not_in_init": (
        "Modules absent from the initialisation list",
        "Missing from the PEB initialisation-order list, which unlinking rootkits "
        "commonly leave inconsistent."),
    "ldrmodules.not_in_mem": (
        "Modules absent from the memory-order list",
        "Missing from the PEB memory-order list - the third of the three linked lists "
        "an unlinking technique has to patch consistently."),
    "psxview.not_in_pslist": (
        "Processes hidden from the active process list",
        "Found by another enumeration method but absent from the standard process list. "
        "Classic direct kernel object manipulation - but terminated processes still in "
        "freed pool look identical."),
    "psxview.not_in_eprocess_pool": (
        "Processes absent from pool scanning",
        "Visible to list-walking but not to pool scanning."),
    "psxview.not_in_ethread_pool": (
        "Processes with no thread pool records",
        "No matching thread objects were recovered by scanning."),
    "psxview.not_in_csrss_handles": (
        "Processes absent from the CSRSS handle table",
        "The Windows subsystem process normally holds a handle to every session "
        "process; absence is one of the older hiding indicators."),
    "handles.nmutant": (
        "Mutex handles",
        "Named mutexes are the usual way malware enforces a single running instance, "
        "though most software uses them for ordinary synchronisation."),
    "handles.nsection": (
        "Section object handles",
        "Shared memory sections, one of the mechanisms used to move code between "
        "processes."),
    "handles.nkey": (
        "Registry key handles",
        "Open registry keys; persistence is usually written through one."),
    "svcscan.nservices": (
        "Registered services",
        "Total services and drivers registered on the system. A service is the most "
        "common persistence mechanism on Windows."),
    "svcscan.kernel_drivers": (
        "Registered kernel drivers",
        "Kernel-mode drivers, which run with full system privilege."),
    "svcscan.nactive": (
        "Running services",
        "Services actually in the running state at capture time."),
    "svcscan.shared_process_services": (
        "Shared-process services",
        "Services hosted inside a shared svchost process, a routine place to hide a "
        "malicious service among legitimate ones."),
    "callbacks.ncallbacks": (
        "Kernel notification callbacks",
        "Routines the kernel invokes on process, thread and image-load events. "
        "Registering one is a kernel-level persistence and monitoring technique."),
    "callbacks.nanonymous": (
        "Callbacks with no owning module",
        "A callback whose target does not resolve to a loaded driver - the module was "
        "unloaded or hidden after registering it."),
}

# ember GeneralFileInfo.process_raw_features, in order.
GENERAL = ["file size", "virtual size", "debug directory present",
           "exported function count", "imported function count",
           "relocations present", "resources present",
           "authenticode signature present", "TLS callbacks present",
           "symbol count"]

# ember DataDirectories._name_order; index i holds directory i//2, size when
# even and virtual address when odd.
DATA_DIRS = ["export table", "import table", "resource table", "exception table",
             "certificate table", "base relocation table", "debug directory",
             "architecture directory", "global pointer", "TLS directory",
             "load config table", "bound import table", "import address table",
             "delay import descriptor", "CLR runtime header"]

# ember SectionInfo.process_raw_features: five named counts, then five hashed
# blocks of 50.
SECTION_NAMED = ["section count", "zero-length sections", "unnamed sections",
                 "readable and executable sections", "writable sections"]
SECTION_BLOCKS = [(5, 55, "section size"), (55, 105, "section entropy"),
                  (105, 155, "section virtual size"),
                  (155, 205, "entry-point section name"),
                  (205, 255, "entry-point section characteristics")]

# ember HeaderFileInfo.process_raw_features: timestamp, five hashed blocks of
# 10, then eleven named scalars.
HEADER_NAMED = {0: "compile timestamp", 51: "major image version",
                52: "minor image version", 53: "major linker version",
                54: "minor linker version", 55: "major OS version",
                56: "minor OS version", 57: "major subsystem version",
                58: "minor subsystem version", 59: "size of code",
                60: "size of headers", 61: "size of heap commit"}
HEADER_BLOCKS = [(1, 11, "COFF machine type"), (11, 21, "COFF characteristics"),
                 (21, 31, "subsystem"), (31, 41, "DLL characteristics"),
                 (41, 51, "PE magic")]

GROUPS = {
    "byte_histogram": (
        "Byte-value frequency distribution",
        "How often each byte value occurs across the file. Skew toward high-entropy or "
        "non-ASCII ranges is consistent with packing, encryption or embedded compressed "
        "data."),
    "byte_entropy": (
        "Byte-entropy distribution",
        "Entropy measured over a sliding window. Sustained high entropy indicates "
        "packing, encryption or obfuscation."),
    "string_feat": (
        "Embedded string characteristics",
        "Statistics over printable strings, including counts of URLs, registry paths "
        "and filesystem paths."),
    "imports_hash": (
        "Import table characteristics",
        "Hashed representation of the imported library and function names, consistent "
        "with the API capability profile of the binary."),
    "exports_hash": (
        "Export table characteristics",
        "Hashed representation of exported function names."),
}


def _index(name):
    return int(name.rsplit("_", 1)[1])


def _block(index, blocks):
    for lo, hi, label in blocks:
        if lo <= index < hi:
            return label
    return None


def describe(feature):
    """-> {feature, group, exact, label, why}

    `exact` is False for anything resolved from a feature hash. Hard rule 15:
    those are buckets, the original value is unrecoverable, and the wording must
    stay at group level.
    """
    if feature in MEMORY:
        label, why = MEMORY[feature]
        return {"feature": feature, "group": feature.split(".")[0], "exact": True,
                "label": label, "why": why}

    group = feature.rsplit("_", 1)[0]

    if group == "general_feat":
        i = _index(feature)
        return {"feature": feature, "group": group, "exact": True,
                "label": GENERAL[i].capitalize(),
                "why": f"PE metadata: {GENERAL[i]}."}

    if group == "datadirectory_feat":
        i = _index(feature)
        which = DATA_DIRS[i // 2]
        part = "size" if i % 2 == 0 else "virtual address"
        return {"feature": feature, "group": group, "exact": True,
                "label": f"{which.capitalize()} {part}",
                "why": f"The {part} of the PE {which}. A zero certificate table means "
                       "the binary carries no authenticode signature."
                       if which == "certificate table" else
                       f"The {part} of the PE {which}."}

    if group == "section_feat":
        i = _index(feature)
        if i < len(SECTION_NAMED):
            return {"feature": feature, "group": group, "exact": True,
                    "label": SECTION_NAMED[i].capitalize(),
                    "why": f"Section table: {SECTION_NAMED[i]}. Writable and executable "
                           "sections together are unusual in compiler output."}
        label = _block(i, SECTION_BLOCKS)
        return {"feature": feature, "group": group, "exact": False,
                "label": f"{label.capitalize()} distribution" if label else "Section characteristics",
                "why": f"Hashed {label} across the section table; individual sections "
                       "cannot be recovered from it." if label else
                       "Hashed section characteristics."}

    if group == "header_feat":
        i = _index(feature)
        if i in HEADER_NAMED:
            return {"feature": feature, "group": group, "exact": True,
                    "label": HEADER_NAMED[i].capitalize(),
                    "why": f"PE header field: {HEADER_NAMED[i]}."}
        label = _block(i, HEADER_BLOCKS)
        return {"feature": feature, "group": group, "exact": False,
                "label": f"{label.capitalize()} encoding" if label else "PE header characteristics",
                "why": f"Hashed {label} from the PE header." if label else
                       "Hashed PE header characteristics."}

    if group in GROUPS:
        label, why = GROUPS[group]
        return {"feature": feature, "group": group, "exact": False,
                "label": label, "why": why}

    return None