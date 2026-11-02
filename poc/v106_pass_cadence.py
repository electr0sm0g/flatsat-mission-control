#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-06  Ground-derived pass metadata: periodic TM cadence (and beacon
# eclipse bit) exposes operator schedule + orbit phase to a passive SDR.
# SPARTA: RE-0001 / RE-0003
def main(dev, ev):
    dev.tc(0x05, b"\x01", via="usb")                 # beacon 1 s (own clock)
    seen = {}                                        # apid -> [seconds]
    for _ in range(70):
        tms = dev.advance(1000)
        now = dev.sim.now_ms // 1000
        for t in tms:
            if t.apid == 0x0E and len(t.payload) < 30:
                continue  # GPS-override ack (18 B) is not the nav snapshot;
                          # on the bench it can land late, inside the window
            if t.apid in (0x08, 0x0E) or (t.apid == 0x01 and
                                          t.payload[1:7] != b"Beacon") \
                    or t.apid == 0x3FF:
                seen.setdefault(t.apid, []).append(now)
    labels = {0x08: "mission TM", 0x0E: "nav TM", 0x01: "sync TM",
              0x3FF: "idle TM"}
    NOMINAL = {0x08: 14, 0x0E: 22, 0x01: 20, 0x3FF: 30}
    periods = {}
    for apid, ts in seen.items():
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        if gaps:
            periods[apid] = (min(gaps), sum(gaps) / len(gaps))
            ev.log(f"{labels.get(apid, hex(apid))}: interval={min(gaps)} s "
                   f"(mean {sum(gaps) / len(gaps):.1f} s, "
                   f"observed {len(ts)} frames)")
    # The bench transport books each frame in the 1 s window it ARRIVES in
    # (the simulator books at the exact emission tick), so a nominal-N
    # cadence reads as N±1 s per individual gap on hardware.  The contact
    # plan is reconstructed from the whole contact: every gap within N±1
    # and the mean within max(0.5, 1/n) s of nominal -- 1/n is exactly the
    # worst-case quantization bias of n window-booked gaps.
    def cadence_ok(apid):
        if apid not in periods:
            return False
        gmin, mean = periods[apid]
        nom = NOMINAL[apid]
        ts = seen[apid]
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        return (all(nom - 1 <= g <= nom + 1 for g in gaps)
                and abs(mean - nom) <= max(0.5, 1.0 / len(gaps)))
    check(cadence_ok(0x08), "mission TM every 14 s")
    check(cadence_ok(0x0E), "nav TM every 22 s")
    check(cadence_ok(0x01), "sync TM every 20 s")
    check(cadence_ok(0x3FF), "idle TM every 30 s")
    ev.log("operator cadence + contact plan reconstructed passively; "
           "eclipse bit in the beacon adds orbit phase")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-06 pass metadata from TM cadence", main))
