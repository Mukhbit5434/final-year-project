"""Capture-time simulation: leave ~100 terminated processes resident in pool.

This is NOT malware. It launches 100 `cmd /c exit` processes - each starts and
immediately exits - and then KEEPS THEIR HANDLES OPEN.

**Measured on malicious_1.raw (2026-08-04), the mechanism is not what the first
draft of this docstring claimed.** Holding a handle to a terminated process keeps
its EPROCESS *linked in the active process list* - Volatility's pslist walks that
same list, so it counts these zombies as live processes (nproc jumped from a clean
80-92 to 182) rather than hiding them from pslist. What actually goes missing is
thread and CSRSS-session state, which a terminated process sheds regardless of
whether something still holds its handle:

    psxview.not_in_ethread_pool    +21.8x ceiling  (no thread objects remain)
    psxview.not_in_csrss_handles    +8.1x ceiling  (CSRSS session entry dropped)
    psxview.not_in_pslist           +1.4x ceiling  (weak - a clean fresh boot
                                                     already reaches 33 here)

So this simulation reliably elevates Rootkit / Hidden Artifacts (T1014) through
not_in_ethread_pool and not_in_csrss_handles, not primarily through
not_in_pslist as originally predicted. Combined with sim_injector.py in the same
capture this still gives two high-risk techniques -> Critical - confirmed on the
real capture, standalone and through the app, and robust to dropping either
psxview signal. See STATUS.md, "silent bug #8", for the full measurement.
"""
import subprocess
import sys
import time

if sys.platform != "win32":
    raise SystemExit("Windows only.")

COUNT = 100
CREATE_NO_WINDOW = 0x08000000


def main():
    print(f"Spawning {COUNT} short-lived processes...")
    t0 = time.time()
    procs = []
    for _ in range(COUNT):
        procs.append(subprocess.Popen(["cmd", "/c", "exit"],
                                      creationflags=CREATE_NO_WINDOW))
    for p in procs:
        p.wait()  # each runs "exit" and terminates immediately
    elapsed = time.time() - t0

    # procs stays referenced for the life of this process, so the Popen objects -
    # and the process handles they hold - are not garbage-collected. The terminated
    # EPROCESS objects therefore remain resident and psscan keeps finding them.
    alive = sum(1 for p in procs if p.returncode is not None)
    print(f"{alive}/{COUNT} processes spawned and terminated in {elapsed:.1f}s; "
          "their handles are held open by this process.")
    print(f"\nExpected psxview.not_in_ethread_pool and not_in_csrss_handles to "
          f"clear their ceilings (~7 / ~20). not_in_pslist rises only weakly - "
          f"held handles keep these processes linked in pslist itself.")
    print("\n===================  READY FOR CAPTURE  ===================")
    print("Leave this window OPEN and take the RAM capture now. The terminated")
    print("processes stay resident as long as this window is open - no timing race.")
    input("Press Enter to release the handles AFTER the capture is complete... ")
    print("released.")


if __name__ == "__main__":
    main()
