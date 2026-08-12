"""Indicator tags and ATT&CK mapping.

Human-authored interpretation, not inference. Deliberately small: 55 named memory
features and 150 mostly-hashed disk features cannot ground 600+ sub-techniques,
and reaching further would make the report less credible rather than more.

T1179, T1547.006 and T1574 are banned here (hard rule 21). T1179 is revoked;
T1547.006 is Linux/macOS kernel modules and does not cover Windows driver
persistence; T1574 is execution-flow hijacking, which is a different behaviour
from the DLL concealment ldrmodules actually measures.
"""

HIGH, MODERATE, LOW = "high", "moderate", "low"

TAGS = [
    {"tag": "Process Injection", "id": "T1055", "name": "Process Injection",
     "confidence": HIGH, "pipeline": "memory",
     "features": ["malfind.ninjections", "malfind.commitCharge",
                  "malfind.uniqueInjections", "malfind.protection"]},
    {"tag": "Process Hollowing", "id": "T1055.012",
     "name": "Process Injection: Process Hollowing", "confidence": HIGH,
     "pipeline": "memory",
     "features": ["ldrmodules.not_in_load"], "requires": ["malfind.ninjections"]},
    {"tag": "Hidden Modules / DLL Concealment", "id": "T1055.001",
     "name": "Process Injection: Dynamic-link Library Injection",
     "confidence": HIGH, "pipeline": "memory",
     "features": ["ldrmodules.not_in_init", "ldrmodules.not_in_mem",
                  "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg"]},
    {"tag": "Rootkit / Hidden Artifacts", "id": "T1014", "name": "Rootkit",
     "confidence": HIGH, "pipeline": "memory",
     "features": ["psxview.not_in_pslist", "psxview.not_in_eprocess_pool",
                  "psxview.not_in_ethread_pool", "psxview.not_in_csrss_handles",
                  "ldrmodules.not_in_mem"]},
    {"tag": "Kernel Callbacks / Driver Persistence", "id": "T1543.003",
     "name": "Create or Modify System Process: Windows Service",
     "confidence": MODERATE, "pipeline": "memory",
     "features": ["callbacks.ncallbacks", "callbacks.nanonymous", "callbacks.ngeneric"]},
    {"tag": "Credential API Hooking", "id": "T1056.004",
     "name": "Input Capture: Credential API Hooking", "confidence": LOW,
     "pipeline": "memory", "features": ["handles.nkey", "handles.nsection"]},

    {"tag": "Obfuscated / Packed Files", "id": "T1027",
     "name": "Obfuscated Files or Information", "confidence": MODERATE,
     "pipeline": "disk", "groups": ["byte_entropy", "byte_histogram"]},
    {"tag": "Suspicious API Imports", "id": "T1106", "name": "Native API",
     "confidence": MODERATE, "pipeline": "disk", "groups": ["imports_hash"]},
    {"tag": "Defense Evasion - Unsigned Binary", "id": "T1553.002",
     "name": "Subvert Trust Controls: Code Signing", "confidence": LOW,
     "pipeline": "disk",
     "features": ["general_feat_7", "datadirectory_feat_8", "datadirectory_feat_9"],
     "when": lambda v: (v.get("general_feat_7", 0) == 0
                        and v.get("datadirectory_feat_8", 0) == 0)},
]

DISCLAIMER = (
    "MITRE ATT&CK mappings are inferred from statistical feature indicators, not from "
    "observed runtime behavior. They indicate which technique categories the detection "
    "is consistent with, and should be treated as investigative leads rather than "
    "confirmed technique attribution.")


def url(technique_id):
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


def match(features, pipeline, values=None):
    """-> list of matched tags, every one of them.

    A single artifact commonly shows several behaviours at once - injection plus
    hidden modules plus service persistence is ordinary, not an edge case - and
    the severity function counts high-risk categories, so collapsing to a single
    best tag would break it.

    `values` is optional and only consulted by tags carrying a `when` predicate,
    which is how the exact (non-hashed) features get value-aware matching.
    """
    present = set(features)
    values = values or {}
    out = []
    for entry in TAGS:
        if entry["pipeline"] != pipeline:
            continue

        hits = [f for f in entry.get("features", []) if f in present]
        for group in entry.get("groups", []):
            hits += [f for f in present if f.rsplit("_", 1)[0] == group]
        if not hits:
            continue
        if any(r not in present for r in entry.get("requires", [])):
            continue
        predicate = entry.get("when")
        if predicate is not None and not (values and predicate(values)):
            continue

        out.append({"tag": entry["tag"], "mitre_id": entry["id"],
                    "mitre_name": entry["name"], "confidence": entry["confidence"],
                    "features": sorted(set(hits)), "url": url(entry["id"])})

    return out


def techniques(matched):
    return sorted({m["mitre_id"] for m in matched})