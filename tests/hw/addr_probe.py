#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Address-map probe (bench parity for MEM_READ), full-capture edition.

Reads a ladder of addresses with MEM_READ (0x19) over the radio-injection
path (v105's exact path). Per step: liveness ping, one TC with a 15 s
want-window, then the NEW console lines since the previous step. The
probe stops at the first dead board; everything is appended to the
stdout log (run: python3 tests/hw/addr_probe.py > log 2>&1).
"""
import struct
import sys
import time

sys.path.insert(0, "poc/lib")
import fslab
import flatsat_sim as fs

PORT = "/dev/serial/by-id/usb-Pwnsat_Pwnsat_-_Flatsat_fsat-if02"

LADDER = [
    (0x20002100, 4),    # SYM_GS_CHALLENGE (known-good in run 1)
    (0x20002104, 4),
    (0x20002180, 4),
    (0x20002200, 4),    # SYM_SA0_KEY, small read
    (0x20002208, 8),
    (0x20002200, 16),   # v105's exact kill
    (0x20002210, 16),
    (0x20002240, 4),
    (0x20002280, 4),
    (0x20002300, 4),    # SYM_ARC_LAST
    (0x20002800, 4),    # SYM_LEAK_POOL
    (0x20003000, 4),    # SYM_MASTER_KEYS
    (0x20002000, 4),    # SYM_LOG_NAME
    (0x10000000, 4),    # XIP baseline
]


def alive(dev):
    try:
        st = dev.sim._need()
        return bool(st[2] & 1)
    except Exception:
        return False


def new_console(dev, seen):
    con = dev.console_tail(16000).decode("latin-1", "replace")
    out = []
    for line in con.splitlines():
        key = line[:60]
        if key not in seen:
            seen.add(key)
            out.append(line)
    return out


def main():
    dev = fslab.UsbDevice(fslab.Evidence("addrprobe2", verbose=False), PORT)
    dev.hard_reset()
    seen = set()
    for line in new_console(dev, seen):
        print("CON-INIT:", line[:110], flush=True)
    for i, (addr, ln) in enumerate(LADDER, 1):
        if not alive(dev):
            print(f"step {i}: BOARD DEAD before step (last good: step {i-1})",
                  flush=True)
            break
        body = struct.pack("<IH", addr, ln)
        enc = dev.secure
        data = fs.aes_ecb_encrypt_wrap(fs.LINK_KEY, body) if enc else body
        frame = fs.spp_pack(0x19, data, 1)
        t0 = time.time()
        raw = dev._xfer(frame, "radio", want=(0x19, 0x09))
        tms = dev._decode_all(raw)
        hit = [t for t in tms if t.apid in (0x19, 0x09)]
        dt = time.time() - t0
        if not hit:
            print(f"step {i:2d}: 0x{addr:08X} len={ln:3d} -- NO RESPONSE "
                  f"({dt:.0f}s window)", flush=True)
        elif hit[0].apid == 0x19:
            t = hit[0]
            print(f"step {i:2d}: 0x{addr:08X} len={ln:3d} OK ({dt:.0f}s) "
                  f"data={t.payload[7:7 + min(ln, 12)].hex()}", flush=True)
        else:
            txt = hit[0].payload[1:].rstrip(b"\x00").decode("latin-1", "replace")
            print(f"step {i:2d}: 0x{addr:08X} len={ln:3d} ERR {txt!r} "
                  f"({dt:.0f}s)", flush=True)
        for line in new_console(dev, seen):
            print(f"        CON: {line[:110]}", flush=True)
    else:
        print("ladder complete", flush=True)
    time.sleep(5)
    print("final alive:", alive(dev), flush=True)
    for line in new_console(dev, seen):
        print("CON-END: ", line[:110], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
