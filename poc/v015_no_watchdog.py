#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


def main(dev, ev):
    # V0-15: no application watchdog is armed anywhere in the baseline:
    # the V0-03 crash is permanent until an operator is physically at the
    # board. (ledBlink up to 3.2 s per error also amplifies any DoS.)
    dev.tc(0x06, b"\x07", via="radio")           # poison broadcast
    check(dev.silent if dev.hw else dev.sim.state == "CRASHED",
          "device crashed (sim) / silent (usb)")
    for minute in range(5):
        dev.advance(60000)
        alive = dev.tc(0x01, b"", via="radio")
        if alive:
            check(False, "device recovered without intervention?!")
        ev.log(f"t+{minute+1} min: still silent "
               f"({dev.sim.state if not dev.hw else 'NO RESPONSE'})")
    ev.log("no watchdog: mission loss confirmed after 5 simulated minutes")
    dev.powercycle()
    check(dev.tc(0x01, b"", via="radio"), "power cycle is the only recovery")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-15 no watchdog -> permanent loss on crash", main))
