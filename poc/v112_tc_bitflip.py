#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-12  No radio-layer CRC and no payload integrity: (a) a flip of the
# CLEAR SPP header re-routes a valid encrypted command to another APID;
# (b) ECB ciphertext blocks are interchangeable -> attacker swaps one
# 16-byte block and the spacecraft executes a silently mutated command.
# SPARTA: CO-0003 (integrity) / IN-0006
def sb_pub(rate, padlen=12):
    # MID + 6-byte rate + filler: the effect bytes sit in ciphertext block 0
    plain = struct.pack(">H", 0x102) + struct.pack("<hhh", *rate) + bytes(padlen)
    return fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, plain)

def tilt_of(dev):
    dev.advance(200)            # mission tick recomputes tilt from rate
    r = dev.find(dev.tc(0x1D, b"\x00", via="radio"), 0x1D)[0]
    return r.le16(8) / 100.0

def main(dev, ev):
    dev.tc(0x1D, bytes([10, 0, 1]), via="radio")     # lab time base 0.1x
    # (a) APID re-routing on the CLEAR header: SB_PUBLISH -> SET_LOG_NAME
    frame = bytearray(fs.spp_pack(0x1B, sb_pub((123, 0, 0)), 4))
    frame[1] ^= 0x01                                  # 0x101B -> 0x101A
    tms = dev._decode_all(dev._xfer(bytes(frame), "radio"))
    check(dev.find(tms, 0x1A) and not dev.find(tms, 0x1B),
          "one clear-header bit re-routed the encrypted command")
    ev.log("flipped primary-header bit 0: SB_PUBLISH(0x1B) executed as "
           "SET_LOG_NAME(0x1A) with the SAME ciphertext -> privilege mixup")

    # (b) ECB block substitution between two captured publishes: blocks
    #     carry no position/sequence binding -> splice block 0 of an old
    #     capture onto a fresh frame and the value changes silently.
    cA = sb_pub((123, 0, 0))                          # rate x = 1.23 deg/s
    cB = sb_pub((0, 450, 0))                          # rate y = 4.50 deg/s
    cB2 = sb_pub((0, 450, 0))
    ev.log(f"ECB determinism: identical publishes give identical ciphertext "
           f"blocks -> {cB == cB2}")
    assert cB == cB2, "ECB deterministic"
    splice = cB[:16] + cA[16:]                        # B's value block in A's tail
    dev._xfer(fs.spp_pack(0x1B, splice, 5), "radio")
    t = tilt_of(dev)
    ev.log(f"spliced publish: frame built from A's capture -> tilt {t:.2f} "
           f"(B's value replayed, no error, no replay detection)")
    check(4.0 < t < 4.8, "block splice silently changed the published value")
    # single ciphertext bit flip -> avalanched block: the device has no
    # cryptographic integrity, the outcome is either silent garbage or a
    # random reject from the length prefix (an accidental oracle).
    flip = bytearray(cA)
    flip[15] ^= 0x01
    tfr = dev._decode_all(dev._xfer(fs.spp_pack(0x1B, bytes(flip), 7), "radio"))
    errors = dev.errors(tfr)
    ev.log(f"one flipped bit -> "
           f"{'executed silently with corrupted fields' if dev.find(tfr, 0x1B) else 'random reject ' + str(errors)}"
           f" -- never an AUTHENTICATED integrity verdict")
    check(not dev.find(tfr, 0x09) or dev.err_text(tfr) == "AES DECRYPT FAIL",
          "reject path only ever the unauthenticated length gate")
    st = dev.find(dev.tc(0x20, b"", via="radio"), 0x20)[0]
    check(st.u8(13) == 0, "radio CRC flag reports OFF -> flips are invisible")
    ev.log("radio CRC disabled by default: mutated TCs execute silently")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-12 silent TC bit-flip / block swap", main))
