#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


def main(dev, ev):
    # V0-07: received SPP sequence numbers are logged, never compared.
    # The exact same captured frame executes twice.
    raw = fs.spp_pack(0x0D, fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, b"\x02"), 42)
    tms1 = dev._decode_all(dev._xfer(raw, "radio"))
    tms2 = dev._decode_all(dev._xfer(raw, "radio"))   # replay, same seq 42
    ev.log(f"first  use -> {tms1}")
    ev.log(f"replay use -> {tms2}")
    check(dev.find(tms1, 0x0D) and dev.find(tms2, 0x0D),
          "both the original and the replay must execute")
    check(dev.sim.mode == 0x02, "mission mode must be PAYLOAD (executed twice)")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-07 full replay: sequence never verified", main))
