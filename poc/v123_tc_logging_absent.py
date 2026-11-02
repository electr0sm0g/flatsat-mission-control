#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-23  No TC journal by default: after an incident the operator cannot
# answer 'who commanded what' -- the log (when enabled) is capped and
# rolls over at 128 entries.
# SPARTA: DV-0004 (audit / attribution gap)
def main(dev, ev):
    r = dev.find(dev.tc(0x25, bytes([1]), via="usb"), 0x25)[0]
    ev.log(f"defenses=0x{r.u8(2):02X} log_entries={r.u8(3)} -> journal OFF")
    check(r.u8(3) == 0, "no journal by default")
    for i in range(5):
        dev.tc(0x0D, bytes([2]), via="radio")        # 5 'suspicious' TCs
    r = dev.find(dev.tc(0x25, bytes([1]), via="usb"), 0x25)[0]
    check(r.u8(3) == 0, "still zero -- zero attribution after the fact")
    ev.log("5 mode-change TCs executed, nothing recorded (no attribution)")

    dev.tc(0x25, bytes([0, 0xC0]), via="usb")        # enable LOG (+ANOMALY)
    for i in range(130):
        dev.tc(0x01, b"\x01", via="radio")
    r = dev.find(dev.tc(0x25, bytes([1]), via="usb"), 0x25)[0]
    n, evicted = r.u8(3), (r.u8(4) << 8) | r.u8(5)
    ev.log(f"after 130 TCs: entries={n} evicted={evicted}")
    check(n == 128 and evicted >= 1, "journal caps at 128, oldest lost")

    dump = dev.find(dev.tc(0x25, bytes([2]) + struct.pack(">H", 0) + bytes([3]),
                          via="usb"), 0x25)[0]
    off = 4
    for i in range(3):
        ms = dump.le32(off)
        apid = (dump.u8(off + 4) << 8) | dump.u8(off + 5)
        seq = (dump.u8(off + 6) << 8) | dump.u8(off + 7)
        ln = dump.u8(off + 8)
        pay = dump.payload[off + 9:off + 9 + ln]
        ev.log(f"entry {i}: t={ms} ms apid=0x{apid:04X} seq={seq} payload={pay.hex()}")
        off += 9 + ln
    ev.log("=> forensics possible ONLY when the optional journal is on, and "
           "even then a flood evicts the evidence within minutes")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-23 TC journal absent / 128-entry cap", main))
