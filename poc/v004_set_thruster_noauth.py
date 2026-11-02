#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


def main(dev, ev):
    # V0-04: SET_THRUSTER (0x04) executes with no authentication, from the
    # raw radio, even while GS mode gating exists for other families.
    tms = dev.tc(0x04, bytes([1, 200]), via="radio")   # thruster 1 @ 200
    st = dev.tc(0x0C, b"", via="usb")
    s = dev.find(st, 0x0C)[0]
    ev.log(f"GET_STATUS: thruster powers t0={s.u8(5)} t1={s.u8(6)}")
    check(s.u8(6) == 200, "thruster power must be 200 after unauthenticated TC")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-04 SET_THRUSTER without authentication", main))
