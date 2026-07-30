import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# A capture has to exceed the baseline by this much before the report calls it
# elevated. Deliberately loose: measured across 5,000 captures of one machine,
# malfind.commitCharge spans 200x and two random captures of the same clean
# system differ by more than 2x a quarter of the time. A tighter factor would
# manufacture findings out of ordinary variance.
ELEVATED = 3.0

_data = None


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
    """-> {feature: True if substantially elevated against the clean baseline}."""
    if not _data:
        return {}
    ref = _data.get("features", {})
    out = {}
    for feature, value in observed.items():
        base = ref.get(feature)
        if base is None:
            continue
        out[feature] = value > max(base, 1.0) * ELEVATED
    return out


def phrase(feature, value):
    """Wording for a single indicator, relative to baseline.

    These artifacts occur on healthy Windows systems - malfind flags the RWX
    memory JIT compilers and browsers allocate, ldrmodules mismatches happen
    during ordinary DLL loading, psxview discrepancies are usually terminated
    processes still in freed pool. Reported as a bare count an analyst reads them
    as compromise, so they never ship without this context.
    """
    if not _data:
        return f"{value:g} observed; no clean-system baseline is loaded for comparison"
    base = _data.get("features", {}).get(feature)
    if base is None:
        return f"{value:g} observed; this indicator is not in the baseline"
    if value > max(base, 1.0) * ELEVATED:
        return (f"{value:g} observed against a clean-system baseline of {base:g} - "
                f"substantially elevated")
    return (f"{value:g} observed against a clean-system baseline of {base:g} - "
            f"consistent with a healthy system")


NOTE = (
    "Injected memory regions, loader-list mismatches and process-enumeration "
    "discrepancies all occur on uninfected Windows systems: JIT compilers, browsers "
    "and anti-virus allocate executable memory legitimately, DLL loading routinely "
    "leaves the PEB lists briefly inconsistent, and terminated processes remain "
    "visible to pool scanning after they exit. These indicators are meaningful only "
    "when substantially elevated against a known-clean baseline, or when several "
    "appear together.")