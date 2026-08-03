"""Capture-time simulation: allocate benign RWX regions so malfind flags this process.

This is NOT malware. It allocates 30 private PAGE_EXECUTE_READWRITE regions in its
own process and writes a plain marker string into each - no shellcode, and nothing
in the regions is ever executed (no thread is created on them). The point is to
produce the exact forensic artifact malfind detects - private RWX VADs tagged VadS,
non-empty - so the memory pipeline's Process Injection path can be demonstrated on
a real capture without any real malicious code.

Run it, leave the window open, take the RAM capture while it is running, then press
Enter to release. Expected on the capture:

    malfind.ninjections      30   (clean ceiling 10.8)
    malfind.uniqueInjections 30   (clean ceiling 5.4)
    malfind.commitCharge   3840   (clean ceiling 2215)

-> Process Injection (T1055) elevated. See STATUS.md for the full capture recipe.
"""
import ctypes
import os
import sys
from ctypes import wintypes

if sys.platform != "win32":
    raise SystemExit("Windows only.")

COUNT = 30
SIZE = 512 * 1024
MEM_COMMIT_RESERVE = 0x3000
PAGE_EXECUTE_READWRITE = 0x40

# malfind's is_vad_empty skips any region whose first 4 KB is all zero, so each
# allocation must be written. A readable marker makes it obvious to an analyst that
# the region is this simulation, not real shellcode. Nothing here is executed.
MARKER = (b"FYP-SIMULATED-INJECTION: benign RWX region for a memory-forensics "
          b"capture. No code is executed in this region.\x00")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                             wintypes.DWORD, wintypes.DWORD]


def main():
    regions = []
    for _ in range(COUNT):
        addr = k32.VirtualAlloc(None, SIZE, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE)
        if not addr:
            raise ctypes.WinError(ctypes.get_last_error())
        ctypes.memmove(addr, MARKER, len(MARKER))
        regions.append(addr)

    print(f"PID {os.getpid()}: allocated {COUNT} private RWX regions of "
          f"{SIZE // 1024} KB and wrote a marker into each.")
    for i, a in enumerate(regions, 1):
        print(f"  {i:2}/{COUNT}   0x{a:016x}")
    print(f"\nExpected malfind: ninjections={COUNT}, uniqueInjections={COUNT}, "
          f"commitCharge~{COUNT * (SIZE // 4096)}.")
    print("\n===================  READY FOR CAPTURE  ===================")
    print("Leave this window OPEN and take the RAM capture now.")
    input("Press Enter to free the regions AFTER the capture is complete... ")
    print("released.")


if __name__ == "__main__":
    main()
