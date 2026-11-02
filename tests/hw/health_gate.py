#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Pre-PoC health gate for the hw sweep.

Bounded (no revive waits, no re-flashes): open the bridge + console, do
one LAB_STATUS round-trip (probe_alive). Exit 0 = the board can take the
next PoC (its own bootstrap will brownout-reset + normalize it); exit
non-zero = wedged/dead, the sweep must stop and the operator replugs.
"""
import sys
import time

sys.path.insert(0, "poc/lib")
import fslab


def main(port):
    t0 = time.time()
    dev = fslab.UsbDevice(fslab.Evidence("healthgate", verbose=False), port)
    ok = dev.probe_alive()
    print(("HEALTHY" if ok else "DEAD") + f" in {time.time() - t0:.0f}s")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
