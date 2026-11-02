#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-07  SDLS anti-replay window: full replay rejected; window boundary is
# exactly W=5, so brute-force accept probability = 5/2^16 = 7.63e-5.
# SPARTA: CO-0004 anti-replay strength analysis
def sec_frame(apid, payload_wrapped, spi, arc, key, seq=1):
    sec = struct.pack(">HI", spi, arc)
    data = sec + b"\x00" * 16 + payload_wrapped
    hdr = fs.spp_pack(apid, data, seq, sechdr=1)[:6]
    mac = fs.cmac(key, hdr + payload_wrapped)
    return fs.spp_pack(apid, sec + mac + payload_wrapped, seq, sechdr=1)

def main(dev, ev):
    # The SDLS setup MUST land (ack-verified on hardware: the beacon-flood
    # windows drop USB frames and an unconfigured SDLS would silently pass
    # every frame, faking the "all deltas accepted" failure mode).
    dev._tc_ack(0x15, bytes([1, 16, 5]), 0x15)   # SDLS on, 16-bit ARC, W=5
    # Fail fast if the setup did not actually take effect (flood losses):
    # with SDLS off, every frame below would pass unchecked and the window
    # check would report a bogus "all deltas accepted".
    check(dev.sim.sdls_enabled,
          "SDLS configuration not effective on the craft (setup TC lost?)")
    dev._tc_ack(0x16, bytes([3]), 0x16)          # reset ARC counter to 0
    key = fs.LINK_KEY                            # SA1 is configured
    body = fs.aes_ecb_encrypt_wrap(key, b"")     # encrypted GET_STATUS
    accepted = []
    for d in range(10):
        dev._tc_ack(0x16, bytes([3]), 0x16)      # arc_last = 0 each trial
        frame = sec_frame(0x0C, body, 1, d, key)
        r = dev._decode_all(dev._xfer(frame, "radio", want=(0x0C, 0x09)))
        why = dev.err_text(r)
        ok = bool(dev.find(r, 0x0C))
        if ok:
            accepted.append(d)
        ev.log(f"ARC delta {d:2d}: {'ACCEPT' if ok else 'reject (' + str(why) + ')'}")
    check(accepted == [1, 2, 3, 4, 5],
          f"window must be exactly deltas 1..5, got {accepted}")
    dev._tc_ack(0x16, bytes([3]), 0x16)              # arc_last = 0
    arc5 = dev._decode_all(dev._xfer(sec_frame(0x0C, body, 1, 5, key), "radio",
                                     want=(0x0C, 0x09)))
    check(dev.find(arc5, 0x0C), "delta 5 accepted (boundary)")
    rep = dev._decode_all(dev._xfer(sec_frame(0x0C, body, 1, 5, key), "radio",
                                    want=(0x0C, 0x09)))
    check(dev.err_text(rep) == "SDLS ARC FAIL", "full replay (delta 0) rejected")
    ev.log("accept probability for a random ARC = W/2^16 = "
           f"{5 / 65536:.3e}; 16-bit counter wraps every 65536 commands "
           "(~32768 s at 2 cmd/s) and is VOLATILE: RESETC rewinds it -> "
           "a captured valid frame becomes replayable again after a reboot")
    dev.powercycle()      # reboot clears arc_last
    dev._tc_ack(0x15, bytes([1, 16, 5]), 0x15)  # SDLS re-enabled by ops
    check(dev.sim.sdls_enabled,
          "post-reboot SDLS setup lost (secure state drifted?)")
    r2 = dev._decode_all(dev._xfer(sec_frame(0x0C, body, 1, 1, key), "radio"))
    check(dev.find(r2, 0x0C),
          "frame accepted pre-reboot is replayable post-reboot (volatile ARC)")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-07 replay window analysis", main))
