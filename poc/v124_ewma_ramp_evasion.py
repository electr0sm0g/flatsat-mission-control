#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-24  On-board anomaly detector is a hand-tuned EWMA (the course's
# 'impoverished LSTM'): a slow ramp keeps residuals under z*sigma and is
# never flagged; an equal-sized STEP at the end trips it immediately.
# SPARTA: DV-0003 / evasion of statistical defense
def counts(dev, seconds, n):
    # n TCs spread over `seconds` of (virtual or real) time: the 1 Hz
    # EWMA feed on both transports then sees ~n radio TCs per second.
    # A host that blocks on every ack paces at ~2 TC/s regardless of n
    # and would flatten the board's TC-rate channel (see Device.rate_phase).
    dev.rate_phase(n, ms=1000 * seconds)

def alarm(dev):
    f = dev.find(dev.tc(0x1D, b"\x00", via="usb"), 0x1D)[0]
    return f.u8(15), f.u8(16)          # (alarm, channel)

def main(dev, ev):
    dev.tc(0x25, bytes([0, 0x80]), via="usb")        # anomaly detection ON
    dev.tc(0x1D, bytes([8, 25]), via="usb")          # z-score = 2.5 (floor)
    # 40 s training window: noisy but stationary TC rate
    for i in range(40):
        counts(dev, 1, 15 + (2 if i % 2 else -2))
    dev.tc(0x1D, bytes([4]), via="usb")              # clear training alarms
    a, ch = alarm(dev)
    ev.log(f"after training: alarm={a}")
    # slow ramp: +1 TC/s every 10 s for 200 s (total x3 by the end)
    v = 15
    for i in range(200):
        if i % 10 == 9:
            v += 1
        counts(dev, 1, v + (2 if i % 2 else -2))
        if i in (59, 119, 199):
            a, ch = alarm(dev)
            ev.log(f"ramp t+{i+1} s (rate {v} TC/s): alarm={a}")
            check(a == 0, "ramp must evade the detector")
    # one step of the SAME order as the whole ramp's last minute: +10
    for i in range(12):
        counts(dev, 1, 45 + (2 if i % 2 else -2))
    a, ch = alarm(dev)
    ev.log(f"step to 45 TC/s: alarm={a} channel={ch}")
    check(a == 1 and ch == 1, "step trips EWMA on the TC-rate channel")
    ev.log("=> command-rate attacks (credential stuffing, scripted floods) "
           "must creep in under ~0.05 sigma/s to stay invisible")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-24 EWMA ramp evasion", main))
