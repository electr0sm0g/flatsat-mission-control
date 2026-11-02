#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


def main(dev, ev):
    # V0-14: SET_BEACON_RATE accepts 0 -> beacon every loop -> downlink is
    # permanently occupied by beacons (jamming of the operator's TM).
    dev.tc(0x05, b"\x01", via="usb")            # first: 1 s so 'changed' latches
    dev.tc(0x05, b"\x00", via="usb")            # then: 0 s == flood
    frames = dev.advance(5000)
    beacon = dev.find(frames, 0x01)
    ev.log(f"beacons emitted in 5 s: {len(beacon)}")
    check(len(beacon) > 20, "beacon flood must saturate the downlink")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-14 SET_BEACON_RATE 0 -> beacon flood", main))
