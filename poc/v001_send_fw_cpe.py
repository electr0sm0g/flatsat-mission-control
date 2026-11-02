#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs

PAY = {0x04: b"\x00\x00", 0x05: b"\x02", 0x06: b"\x03\x92test", 0x0B: b"\x00\x00\x00\x00\x00\x00",
       0x0D: b"\x01", 0x10: b"\x00", 0x11: b"\x00", 0x12: b"\x00", 0x13: b""}

def main(dev, ev):
    # V0-01: unauthenticated APID enumeration -- the TC surface answers a
    # raw radio probe with no challenge, before any authentication state.
    responding = []
    for apid in range(0x01, 0x14):
        payload = PAY.get(apid, b"")
        tms = dev.tc(apid, payload, via="radio")
        kinds = [f"0x{t.apid:02X}" for t in tms]
        ev.log(f"probe 0x{apid:02X} -> TMs {kinds} errors={dev.errors(tms)}")
        if tms:
            responding.append(apid)
    ev.log(f"responding APIDs ({len(responding)}): {[hex(a) for a in responding]}")
    # every responder did it with zero authentication state
    check(len(responding) >= 12, "expected a broad unauthenticated APID surface")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-01 unauthenticated APID enumeration", main))
