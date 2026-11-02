#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-32  BROADCAST_MSG carries an operator-frequency field with no input
# check: any raw-radio frame can re-point the downlink frequency
# (squatter steals the contact); the FREQ-LOCK defense restricts it.
# SPARTA: IM-0002 / CT-0005 (downlink hijack of the contact frequency)
def main(dev, ev):
    def bcast(freq, msg):
        return dev.tc(0x06, struct.pack(">H", freq) + msg, via="radio")

    st0 = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    f0, v0 = st0.le16(10), st0.le16(8)
    ev.log(f"nominal downlink freq={f0} MHz, forward count={v0}")
    check(f0 == 916, "starts on 916 MHz")
    r = bcast(1234, b"SQUATTER-WAS-HERE")
    check(dev.find(r, 0x06), "broadcast accepted with arbitrary frequency")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"after squat: last_freq={st.le16(10)} MHz -> operator must "
           f"re-tune or lose the pass (no auth on the frequency field)")
    check(st.le16(10) == 1234, "frequency squat took effect")
    check(st.le16(8) == v0 + 1, "forward counter moved (only audit trace)")

    dev.tc(0x25, bytes([0, 0x84]), via="usb")        # FREQ_LOCK | ANOMALY
    bad = bcast(435, b"TRY-AGAIN")
    check(dev.err_text(bad) == "FREQ LOCK", "defense rejects foreign frequency")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.le16(10) == 1234, "locked: squat attempt did NOT move the field")
    ok = bcast(916, b"HOME")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"allowed frequency (916) accepted: last_freq={st.le16(10)}")
    check(st.le16(10) == 916, "whitelisted frequency works")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-32 downlink frequency squat", main))
