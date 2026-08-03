"""Capture-time simulation: leave ~100 terminated processes resident in pool.

This is NOT malware. It launches 100 `cmd /c exit` processes - each starts and
immediately exits - and then KEEPS THEIR HANDLES OPEN so the terminated EPROCESS
objects stay resident in kernel pool. A terminated process is unlinked from the
active process list (pslist) but is still found by pool scanning (psscan), which is
exactly the psxview discrepancy the pipeline reports as hidden processes.

Holding the handles is the important part: it pins the terminated processes in
memory for as long as this window stays open, so there is NO timing race - you do
not have to capture within seconds. Just leave it running during the capture.

Expected on the capture:

    psxview.not_in_pslist  ~100   (clean ceiling 39.6)

-> Rootkit / Hidden Artifacts (T1014) elevated. Combined with sim_injector.py in
the same capture this gives two high-risk techniques -> Critical. See STATUS.md.
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
    print(f"\nExpected psxview.not_in_pslist: ~{COUNT} (clean ceiling 39.6).")
    print("\n===================  READY FOR CAPTURE  ===================")
    print("Leave this window OPEN and take the RAM capture now. The terminated")
    print("processes stay resident as long as this window is open - no timing race.")
    input("Press Enter to release the handles AFTER the capture is complete... ")
    print("released.")


if __name__ == "__main__":
    main()
