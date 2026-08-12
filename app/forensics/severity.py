from ..models import CRITICAL, HIGH, LOW, MEDIUM

# Categories that describe an actively hostile capability rather than an
# observation about how a machine is set up.
HIGH_RISK = {"Process Injection", "Process Hollowing", "Rootkit / Hidden Artifacts",
             "Hidden Modules / DLL Concealment", "Persistence - Services",
             "Kernel Callbacks / Driver Persistence"}


def _bucket(score):
    if score >= 6:
        return CRITICAL
    if score >= 4:
        return HIGH
    if score >= 2:
        return MEDIUM
    return LOW


def for_disk(probability, matched, threshold):
    """Verdict-led. The disk model is validated against the official EMBER
    baseline and its probability is trustworthy, so it carries the score."""
    risky = len({m["mitre_id"] for m in matched if m["tag"] in HIGH_RISK})

    score = 0
    if probability >= threshold:
        score += 2
    if probability >= 0.9:
        score += 2
    elif probability >= 0.75:
        score += 1
    score += min(risky, 3)

    sev = _bucket(score)
    note = (f"model confidence {probability:.2f} against threshold {threshold:.2f}, "
            f"{risky} high-risk indicator categor{'y' if risky == 1 else 'ies'} matched")
    return sev, note


LEVELS = [LOW, MEDIUM, HIGH, CRITICAL]


def for_memory(observed, matched, probability=None, model_reliable=False,
               baselined=True):
    """Evidence-led, and deliberately on a different scale from the disk function.

    The memory model's probability is weak on any capture that is not from the
    CIC-MalMem VM (CLAUDE.md 2 and 9.6), so severity comes from what Volatility
    measured. Categories drive the bucket directly - three hidden modules plus
    injected memory is High because of what was found, not because a number
    crossed a threshold.

    **`matched` must be built from indicators that are elevated against the clean
    baseline, not merely present.** Every healthy Windows system has malfind,
    ldrmodules and psxview hits, so matching on presence scored the clean
    reference capture itself as Critical. `observed` maps indicator name ->
    elevated, and `baselined` says whether that comparison was possible at all.
    """
    risky = len({m["mitre_id"] for m in matched if m["tag"] in HIGH_RISK})
    elevated = sum(1 for v in observed.values() if v)

    level = 0 if risky == 0 else 1 if risky == 1 else 2 if risky <= 3 else 3
    basis = ("elevated against the clean-system baseline" if baselined else
             "present, with no clean-system baseline available for comparison")
    reason = [f"{risky} high-risk indicator categor{'y' if risky == 1 else 'ies'} "
              f"{basis}"]

    if not baselined:
        # Without a baseline every category is "present", which on a healthy
        # machine is most of them. Cap the claim rather than overstate it.
        level = min(level, 1)

    if elevated >= 2:
        level = min(level + 1, 3)
        reason.append(f"{elevated} indicators elevated against baseline")
    elif elevated:
        reason.append("1 indicator elevated against baseline")

    if probability is None or not model_reliable:
        # Unreliable or absent: excluded from both the level (already true above -
        # this branch never touches `level`) and, as of CLAUDE.md §18's seventh pass,
        # from the reason text too. The exclusion itself is still real and still
        # happens; only the sentence explaining it to a reader was removed.
        pass
    elif probability >= 0.9 and level >= 1:
        # Contributes, never drives: it cannot raise severity when no indicator
        # matched, and it cannot lift anything past High on its own. max() keeps
        # the cap from demoting a result the evidence already put at Critical.
        level = max(level, min(level + 1, 2))
        reason.append(f"model confidence {probability:.2f}, in distribution")

    return LEVELS[level], "; ".join(reason)