#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-19  Scheduled task queue lives in FLASH and replays after ANY reboot
# (OPS-SAT scheduled-execution analogue): a planted command re-executes
# on every boot -- persistence without touching the image.
# SPARTA: PE-0002 (boot persistence via config)
def main(dev, ev):
    # plant: every 2 s set thruster 1 to full, via internal dispatch
    pay = bytes([0]) + struct.pack(">I", 2) + struct.pack(">H", 0x0004) \
        + bytes([2, 1, 255])
    r = dev.find(dev.tc(0x1E, pay, via="radio"), 0x1E)[0]
    ev.log(f"schedule add ok={r.u8(2)} count={r.u8(3)} persists={r.u8(4)}")
    check(r.u8(2) == 1 and r.u8(4) == 1, "queue entry created, marked persistent")
    dev.advance(2500)
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.u8(6) == 255, "task fired: thruster1 at 255")
    ev.log("task executing on schedule (t1=255)")
    # the kill: soft reset -- queue survives, thruster power is volatile
    dev.tc(0x02, b"", via="usb")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"after RESETC: t1={st.u8(6)} (volatile state rewound)")
    dev.advance(2500)
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.u8(6) == 255, "queue replayed right after reboot")
    ev.log("planted task ALIVE after reboot (no image change, no flash "
           "write beyond the queue sector)")
    # survives even a power cycle:
    dev.powercycle()
    dev.advance(2500)
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.u8(6) == 255, "queue replayed after power cycle too")
    lst = dev.find(dev.tc(0x1E, bytes([2]), via="usb"), 0x1E)[0]
    ev.log(f"queue dump: entries={lst.u8(2)} first_apid="
           f"0x{(lst.u8(4+1) << 8 | lst.u8(4+2)):04X}" if len(lst.payload) > 6 else "")
    dev.tc(0x1E, bytes([1]), via="usb")              # cleanup
    dev.advance(2500)
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.u8(6) != 255, "queue cleared -> persistence gone")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-19 flash-resident schedule persistence", main))
