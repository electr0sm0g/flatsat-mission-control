#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs

def main(dev, ev):
    # V0-11: ECB structural flaws:
    #  (a) the SPP primary header is ALWAYS in the clear;
    #  (b) ECB is deterministic (traffic analysis + oracle building block);
    #  (c) blocks are independent and the AES_CONFIG boolean sink accepts
    #      any length-valid ciphertext block whose recovered byte0 != 0:
    #      an adversary who can uplink can always switch crypto back ON.
    raw = fs.spp_pack(0x0C, fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, b""), 1)
    ev.log(f"encrypted TC wire header (in clear): {raw[:6].hex()} "
           f"-> apid={raw[0] & 0x7FF:02X} visible to any SDR")
    c1 = fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, b"\x01")
    c2 = fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, b"\x01")
    ev.log(f"determinism: C(b'01') == C(b'01') -> {c1 == c2}")
    check(c1 == c2, "ECB must be deterministic")

    dev.tc(0x0A, b"\x00", via="radio", encrypt=False)   # crypto OFF
    check(dev.sim.secure is False, "crypto off baseline")

    # The sink semantics are what make ECB malleable here: the toggle only
    # tests "recovered byte0 != 0". Any length-valid ciphertext block does
    # it -- the attacker builds one with the key from V0-02, but any
    # opaque 16-byte block that survives the length check would too.
    target = b"\x00\x01B" + b"\x5a" * 13           # plen=1, payload byte 'B'
    blk = fs.aes_ecb_encrypt(fs.LINK_KEY, target)   # opaque on the wire
    plain = fs.sl_decode_key(fs.LINK_KEY, blk)
    ev.log(f"opaque block C={blk.hex()} -> P={plain.hex()} (byte0=0x{plain[0]:02X})")
    dev._xfer(fs.spp_pack(0x0A, blk, 3), "radio")        # even length -> real decrypt path
    ev.log(f"secure link state after opaque block: {dev.sim.secure}")
    check(dev.sim.secure is True,
          "boolean sink accepted an attacker-chosen ciphertext block")
    # block independence: flipping block 0 changes nothing in block 1
    two = (b"\x00\x0fABCD01234567" + b"89") + (b"\x00\x0fwxyz01234567" + b"89")
    cA = fs.aes_ecb_encrypt(fs.LINK_KEY, two[:16])
    cB = fs.aes_ecb_encrypt(fs.LINK_KEY, two[16:])
    ev.log(f"C(block1) identical when block0 changes: "
           f"{cB == fs.aes_ecb_encrypt(fs.LINK_KEY, two[16:]).hex() and fs.aes_ecb_encrypt(fs.LINK_KEY, (bytes([0x99])+two[1:16])+two[16:])[16:] == cB}")
    check(fs.aes_ecb_encrypt(fs.LINK_KEY, (bytes([0x99]) + two[1:16]) + two[16:])[16:] == cB,
          "ECB blocks must be independent")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-11 ECB: clear header, determinism, block malleability", main))
