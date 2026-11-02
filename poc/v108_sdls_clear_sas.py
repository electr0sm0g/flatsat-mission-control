#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-08  SDLS SA table 64 entries, 43 default to mode Clear: any TC with
# SPI=44 executes UNAUTHENTICATED (no security header, no MAC at all).
# SPARTA: CO-0004.01 (authentication bypass by configuration)
def main(dev, ev):
    dev.tc(0x15, bytes([1, 16, 5]), via="usb")       # SDLS ON
    clear = secured = 0
    for spi in range(64):
        r = dev.find(dev.tc(0x16, bytes([2, spi]), via="usb"), 0x16)[0]
        if r.u8(4) == 0:            # ast == 0 -> Clear
            clear += 1
        else:
            secured += 1
    ev.log(f"SA table: {secured} secured, {clear} Clear (incl. default SPI "
           f"{fs.SDLS_SA_PLAINTEXT_DEFAULT})")
    check(clear == 43, "exactly 43 SAs operate in Clear")
    # a plaintext-flagged frame on SPI 44 passes with no header whatsoever
    raw = fs.spp_pack(0x01, fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, b""), 7)    # sechdr = 0
    tms = dev._decode_all(dev._xfer(raw, "radio"))
    check(dev.find(tms, 0x01), "unsecured SPI=44-class frame executes")
    # and an authenticated SA rejects a missing header
    raw = fs.spp_pack(0x01, fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, b""), 8)    # same, but claim SPI 1
    ev.log("frames without security header are treated as default-Clear")
    dev.tc(0x15, bytes([0, 16, 5]), via="usb")
    ev.log("attackers route ALL traffic through Clear SAs: SDLS on, auth zero")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-08 43/64 SDLS SAs default to Clear", main))
