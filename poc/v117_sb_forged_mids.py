#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-17  Internal software bus (cFS SB analogue) with forgeable MIDs:
# the radio is a bus bridge -> raw TCs publish MID 0x102..0x106 and the
# mission model consumes them as truth (attitude, sensors, heaters,
# battery, thrusters).
# SPARTA: LM-0002.01 / PR-0002.01 (lateral movement via internal bus)
def main(dev, ev):
    def pub(mid, data):
        return dev.tc(0x1B, struct.pack(">H", mid) + data, via="radio")

    dev.tc(0x1D, bytes([10, 0, 1]), via="radio")     # time base 0.1x
    # 0x102 attitude rate
    r = dev.find(pub(0x102, struct.pack("<hhh", 321, 0, 0)), 0x1B)[0]
    ev.log(f"MID 0x102 published, ok={r.u8(4)}")
    dev.advance(200)
    f = dev.find(dev.tc(0x1D, b"\x00", via="radio"), 0x1D)[0]
    check(3.0 < f.le16(8) / 100.0 < 3.6, "forged attitude rate consumed")
    # 0x103 sensor mask
    dev.tc(0x1B, struct.pack(">H", 0x103) + bytes([0x00]), via="radio")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(not (st.u8(2) & 0x03), "sensor-present flags rewritten by MID")
    dev.tc(0x1B, struct.pack(">H", 0x103) + bytes([0x03]), via="radio")
    # 0x104 heaters
    base_w = dev.find(dev.tc(0x1D, b"\x00", via="radio"), 0x1D)[0].le16(12)
    dev.tc(0x1B, struct.pack(">H", 0x104) + bytes([1, 1]), via="radio")
    dev.advance(200)
    f = dev.find(dev.tc(0x1D, b"\x00", via="radio"), 0x1D)[0]
    ev.log(f"heater via MID 0x104: power {base_w/100:.1f} -> {f.le16(12)/100:.1f} W")
    check(f.le16(12) - base_w >= 220, "heater switched on via bus (+2.4 W)")
    # 0x105 battery override
    dev.tc(0x1B, struct.pack(">H", 0x105) + bytes([40]), via="radio")
    f = dev.find(dev.tc(0x1D, b"\x00", via="radio"), 0x1D)[0]
    check(2215 <= f.le16(10) <= 2225, "bus voltage now from forged battery (22.2 V)")
    # 0x106 thruster pair
    dev.tc(0x1B, struct.pack(">H", 0x106) + bytes([5, 7]), via="usb")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check((st.u8(5), st.u8(6)) == (5, 7), "thruster powers set via bus")

    # defense: signed bus (MID tag) -- off by default
    r = dev.find(dev.tc(0x25, bytes([4, 1]), via="usb"), 0x25)[0]
    ev.log(f"SB auth enforced: {r.u8(2)}")
    r = dev.find(pub(0x102, struct.pack("<hhh", 0, 0, 0)), 0x1B)[0]
    check(r.u8(4) == 0, "unauthenticated publish rejected once signed")
    r = dev.find(dev.tc(0x1B, struct.pack(">H", 0x102) + b"\xc0\xfe\xee\x11"
                        + struct.pack("<hhh", 1, 0, 0), via="radio"), 0x1B)[0]
    check(r.u8(4) == 1, "tagged publish accepted")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-17 forged software-bus MIDs", main))
