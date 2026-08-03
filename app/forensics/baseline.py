import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# An indicator is "elevated" only when it exceeds the highest value observed
# across the clean-capture set for this machine, plus a small margin. Measured,
# not chosen: the seven clean captures put psxview.not_in_pslist at 0-33 (33 from
# a fresh boot, where psscan still sees terminated boot processes), so a
# median-times-constant rule flagged the fresh-boot capture against its own
# baseline - a clean false positive. The observed max is the real ceiling; the
# margin covers capture-to-capture noise without inventing a percentile seven
# samples cannot support.
MARGIN = 1.2

_data = None


def _n_captures():
    caps = (_data or {}).get("captures")
    return len(caps) if caps else 1


def ceiling(feature):
    """-> the value a capture must exceed to count as elevated, or None.

    The highest value seen across the clean captures times MARGIN. Falls back to
    a single-capture baseline's own value when no max block is present, so an
    older baseline still loads.
    """
    if not _data:
        return None
    mx = _data.get("max")
    if mx and feature in mx:
        base = float(mx[feature])
    else:
        ref = _data.get("features") or {}
        af = _data.get("all_features") or {}
        base = ref.get(feature, af.get(feature))
        if base is None:
            return None
        base = float(base)
    return max(base, 1.0) * MARGIN


def load(path):
    global _data
    path = Path(path)
    if not path.exists():
        log.info("no clean-system baseline at %s; findings will be reported "
                 "without baseline context", path)
        return False
    _data = json.loads(path.read_text())
    log.info("baseline loaded: %s, %s", _data.get("label"), _data.get("captured"))
    return True


def loaded():
    return _data is not None


def info():
    if not _data:
        return None
    return {k: _data[k] for k in ("label", "captured", "os", "hypervisor",
                                  "capture_tool", "ground_truth") if k in _data}


def compare(observed):
    """-> {feature: True if it exceeds the clean-capture ceiling for this machine}."""
    if not _data:
        return {}
    out = {}
    for feature, value in observed.items():
        cap = ceiling(feature)
        if cap is None:
            continue
        out[feature] = value > cap
    return out


def _observed_max(feature):
    mx = (_data or {}).get("max") or {}
    if feature in mx:
        return float(mx[feature])
    ref = (_data or {}).get("features") or {}
    af = (_data or {}).get("all_features") or {}
    base = ref.get(feature, af.get(feature))
    return float(base) if base is not None else None


def phrase(feature, value):
    """Wording for a single indicator, relative to the clean-capture range.

    These artifacts occur on healthy Windows systems - malfind flags the RWX
    memory JIT compilers and browsers allocate, ldrmodules mismatches happen
    during ordinary DLL loading, psxview discrepancies are usually terminated
    processes still in freed pool. Reported as a bare count an analyst reads them
    as compromise, so they never ship without this context.
    """
    if not _data:
        return f"{value:g} observed; no clean-system baseline is loaded for comparison"
    hi = _observed_max(feature)
    if hi is None:
        return f"{value:g} observed; this indicator is not in the baseline"
    n = _n_captures()
    span = (f"the highest value ({hi:g}) observed across {n} clean captures of this "
            f"machine")
    if value > ceiling(feature):
        return f"{value:g} observed - exceeds {span} - substantially elevated"
    return f"{value:g} observed - within {span} - consistent with this machine"


# How a machine is *configured*, not what it did. These are reported as context
# and are structurally incapable of reaching severity: severity counts high-risk
# MITRE techniques matched from meanings.BEHAVIOURAL, and no tag maps to any of
# these features (see the removal note in mitre.py). An elevated service count
# means software was installed, which is not a technique.
VOLUMETRIC = [
    "svcscan.nservices", "svcscan.kernel_drivers", "svcscan.fs_drivers",
    "svcscan.shared_process_services", "svcscan.nactive",
    "pslist.nproc", "dlllist.ndlls", "handles.nhandles", "handles.nmutant",
    "modules.nmodules",
]

VOLUMETRIC_LABEL = {
    "svcscan.nservices": "service and driver count",
    "svcscan.kernel_drivers": "kernel driver count",
    "svcscan.fs_drivers": "filesystem driver count",
    "svcscan.shared_process_services": "shared-process service count",
    "svcscan.nactive": "running service count",
    "pslist.nproc": "process count",
    "dlllist.ndlls": "loaded module count",
    "handles.nhandles": "open handle count",
    "handles.nmutant": "mutex count",
    "modules.nmodules": "kernel module count",
}


def volumetric_context(vec, names, behavioural_elevated):
    """-> (list of {feature, label, value, baseline, factor}, note or None).

    Configuration counts compared against the baseline. Reported so an analyst can
    see the machine is busier than when the baseline was taken, and worded to say
    what that actually means. It never contributes to severity - the caller has no
    way to make it, since severity takes only the behavioural dict.
    """
    if not _data:
        return [], None
    index = {n: i for i, n in enumerate(names)}

    raised = []
    for feature in VOLUMETRIC:
        cap = ceiling(feature)
        hi = _observed_max(feature)
        if feature not in index or cap is None or hi is None:
            continue
        value = float(vec[index[feature]])
        if value <= cap:
            continue
        raised.append({"feature": feature,
                       "label": VOLUMETRIC_LABEL.get(feature, feature),
                       "value": value, "baseline": hi,
                       "factor": round(value / hi, 1) if hi else None})

    if not raised:
        return [], None

    named = ", ".join(f"{r['label']} {r['value']:g} against a clean maximum of "
                      f"{r['baseline']:g}" for r in raised)
    if any(behavioural_elevated.values()):
        note = (f"Configuration counts are also elevated ({named}). Read alongside the "
                "behavioural indicators above rather than as an indicator in itself.")
    else:
        note = (f"Configuration counts are elevated ({named}) with no behavioural "
                "indicators present; consistent with additional software rather than "
                "compromise. This does not contribute to severity.")
    return raised, note


NOTE = (
    "Injected memory regions, loader-list mismatches and process-enumeration "
    "discrepancies all occur on uninfected Windows systems: JIT compilers, browsers "
    "and anti-virus allocate executable memory legitimately, DLL loading routinely "
    "leaves the PEB lists briefly inconsistent, and terminated processes remain "
    "visible to pool scanning after they exit. These indicators are meaningful only "
    "when substantially elevated against a known-clean baseline, or when several "
    "appear together.")