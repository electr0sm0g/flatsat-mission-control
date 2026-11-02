#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
flatsat_sim.py -- byte-for-byte behavioural simulator of the flatsat-lab
"FlatSat v2 vulnerable-by-design" firmware (flatsat-lab/firmware/).

Purpose
-------
Every PoC in flatsat-lab/poc runs against THIS simulator by default
(`--sim`) so the exploit evidence is reproducible offline, and against a
physical FlatSat board with `--usb --port /dev/ttyACM0`. The firmware C++
and this Python are written side-by-side (same payload formats, same
error strings, same counters, same quirks -- including the baseline ones
like "the beacon only ticks after SET_BEACON_RATE changed it").

Self-tests: `python3 flatsat_sim.py --selftest` validates the AES core
against FIPS-197 / SP 800-38A / SP 800-38B vectors and the SDLS state
machine against the course numbers (SPI sweep outcomes, ARC window).

Hardware honesty: FlatSat is RP2040 + 2x SX1262 + BME280 + LIS2DH12 + GPS
UART + 4 MB QSPI NOR. ADCS/EPS/eclipse/battery/brownout/tumble are
*virtual models* driven by the same telecommands a real operator uses;
SpaceCAN is a software bus (no CAN controller on RP2040, no PHY populated)
-- exactly as in the upstream firmware. See docs/DESIGN-RATIONALE.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys

# --------------------------------------------------------------------------
# AES-128 core (encrypt + decrypt), pure python, vector-tested below
# --------------------------------------------------------------------------
def _build_sbox():
    """Canonical AES S-box: multiplicative inverse in GF(2^8) (log/antilog
    tables generated with 3) + affine transform. Same result as the
    firmware's secure_link.cpp table (which itself matches FIPS-197)."""
    # log tables with generator 3
    exp_t = [0] * 512
    log_t = [0] * 256
    x = 1
    for i in range(255):
        exp_t[i] = x
        log_t[x] = i
        x ^= ((x << 1) & 0xFF) ^ (0x1B if x & 0x80 else 0)  # x *= 3
    for i in range(255, 512):
        exp_t[i] = exp_t[i - 255]

    def gmul(a, b):
        if a == 0 or b == 0:
            return 0
        return exp_t[log_t[a] + log_t[b]]

    sbox = [0] * 256
    for c in range(256):
        if c == 0:
            inv = 0
        else:
            inv = exp_t[255 - log_t[c]]
        x = inv
        s = inv
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sbox[c] = s ^ 0x63
    return sbox


SBOX = _build_sbox()


INV_SBOX = [0] * 256
for _i, _s in enumerate(SBOX):
    INV_SBOX[_s] = _i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def key_expansion(key: bytes) -> bytes:
    """AES-128 key schedule -> 176 bytes (mirrors secureLinkKeyExpansionKey)."""
    rk = bytearray(key)
    gen = 16
    rcon_i = 1
    while gen < 176:
        t = list(rk[gen - 4:gen])
        if gen % 16 == 0:
            t = [SBOX[t[1]] ^ RCON[rcon_i], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
            rcon_i += 1
        for i in range(4):
            rk.append(rk[gen - 16] ^ t[i])
            gen += 1
    return bytes(rk)


def _add_rk(s, rk):
    for i in range(16):
        s[i] ^= rk[i]


def _sub(s):
    for i in range(16):
        s[i] = SBOX[s[i]]


def _inv_sub(s):
    for i in range(16):
        s[i] = INV_SBOX[s[i]]


def _shift_rows(s):
    # column-major state: index = row + 4*col
    t = s[1]
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], t
    t = s[2]
    t2 = s[6]
    s[2], s[6], s[10], s[14] = s[10], s[14], t, t2
    t = s[15]
    s[15], s[11], s[7], s[3] = s[11], s[7], s[3], t


def _inv_shift_rows(s):
    t = s[13]
    s[13], s[9], s[5], s[1] = s[9], s[5], s[1], t
    t = s[2]
    t2 = s[6]
    s[2], s[6], s[10], s[14] = s[10], s[14], t, t2
    t = s[3]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], t


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _mix(s):
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = s[i:i + 4]
        t = a0 ^ a1 ^ a2 ^ a3
        s[i] = a0 ^ t ^ _xtime(a0 ^ a1)
        s[i + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
        s[i + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
        s[i + 3] = a3 ^ t ^ _xtime(a3 ^ a0)


def _inv_mix(s):
    def gmul(a, b):
        r = 0
        for _ in range(8):
            if b & 1:
                r ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
            b >>= 1
        return r

    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = s[i:i + 4]
        s[i] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        s[i + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        s[i + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        s[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)


def aes_encrypt_block(rk: bytes, blk: bytes) -> bytes:
    s = list(blk)
    _add_rk(s, rk[0:16])
    for rnd in range(1, 10):
        _sub(s)
        _shift_rows(s)
        _mix(s)
        _add_rk(s, rk[16 * rnd:16 * rnd + 16])
    _sub(s)
    _shift_rows(s)
    _add_rk(s, rk[160:176])
    return bytes(s)


def aes_decrypt_block(rk: bytes, blk: bytes) -> bytes:
    s = list(blk)
    _add_rk(s, rk[160:176])
    for rnd in range(9, 0, -1):
        _inv_shift_rows(s)
        _inv_sub(s)
        _add_rk(s, rk[16 * rnd:16 * rnd + 16])
        _inv_mix(s)
    _inv_shift_rows(s)
    _inv_sub(s)
    _add_rk(s, rk[0:16])
    return bytes(s)


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    rk = key_expansion(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += aes_encrypt_block(rk, data[i:i + 16])
    return bytes(out)


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    rk = key_expansion(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += aes_decrypt_block(rk, data[i:i + 16])
    return bytes(out)


def _gmul1(a):
    return ((a << 1) & 0xFF) ^ (0x87 if a & 0x80 else 0)


def cmac(key: bytes, data: bytes) -> bytes:
    """AES-CMAC (SP 800-38B)."""
    rk = key_expansion(key)
    L = aes_encrypt_block(rk, bytes(16))

    def dbl(v):
        # left shift across the big-endian 128-bit value: the MSB of byte
        # i+1 feeds the LSB of byte i
        out = bytearray(len(v))
        for i in range(len(v)):
            nxt = (v[i + 1] >> 7) & 1 if i + 1 < len(v) else 0
            out[i] = ((v[i] << 1) | nxt) & 0xFF
        return out

    K1 = bytearray(dbl(L))
    if L[0] & 0x80:
        K1[15] ^= 0x87
    K2 = bytearray(dbl(K1))
    if K1[0] & 0x80:
        K2[15] ^= 0x87

    if len(data) == 0:
        n_full = 0
        tail = b"\x80" + bytes(15)
        last_key = K2
    elif len(data) % 16 != 0:
        n_full = len(data) // 16
        rem = data[n_full * 16:]
        tail = rem + b"\x80" + bytes(15 - len(rem))
        last_key = K2
    else:
        n_full = len(data) // 16 - 1
        tail = data[-16:]
        last_key = K1

    x = bytes(16)
    off = 0
    for _ in range(n_full):
        x = aes_encrypt_block(
            rk, bytes(a ^ b for a, b in zip(x, data[off:off + 16])))
        off += 16
    y = bytes(a ^ b ^ c for a, b, c in zip(tail, last_key, x))
    return aes_encrypt_block(rk, y)


def ctr_xor(key: bytes, ctr_block: bytes, data: bytes) -> bytes:
    rk = key_expansion(key)
    ctr = bytearray(ctr_block)
    out = bytearray()
    for off in range(0, len(data), 16):
        ks = aes_encrypt_block(rk, bytes(ctr))
        chunk = data[off:off + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        for i in range(15, -1, -1):
            ctr[i] = (ctr[i] + 1) & 0xFF
            if ctr[i]:
                break
    return bytes(out)


def aes_ecb_encrypt_wrap(key: bytes, plain: bytes) -> bytes:
    """secure-link encode: [len BE16][plain] zero-padded to 16, ECB."""
    blen = ((len(plain) + 2 + 15) // 16) * 16
    body = struct.pack(">H", len(plain)) + plain
    body = body + bytes(blen - len(body))
    return aes_ecb_encrypt(key, body)


def sl_decode_key(key: bytes, cipher: bytes):
    """secure-link decode; None when the plaintext length field is bogus."""
    if len(cipher) == 0 or len(cipher) % 16 != 0:
        return None
    plain = aes_ecb_decrypt(key, cipher)
    plen = struct.unpack(">H", plain[:2])[0]
    if plen > len(cipher) - 2 or plen > 200:
        return None
    return plain[2:2 + plen]


def fnv_digest(data: bytes) -> bytes:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h.to_bytes(8, "big")


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def crc8(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


# --------------------------------------------------------------------------
# constants mirrored from the firmware headers
# --------------------------------------------------------------------------
LINK_KEY = b"PWNsatLabKey1234"
GS_XOR_KEY = 0xC0DEFACE
GS_STATION = (361699000, -1151398000)
GS_RADIUS_M = 35000
GS_SESSION_MS = 300000
GS_CHALLENGE_MS = 60000
BEACON_DEFAULT_MS = 18000
SPACECRAFT_ID = 0x01
DOWNLINK_FREQ = 916

SDLS_NUM_SA = 64
SDLS_SA_PLAINTEXT_DEFAULT = 44
SDLS_MASTER_KEYS = 128
SDLS_SPI_FAULT = 9000
SDLS_SEC_HDR_LEN = 22

FDIR_TILT = 5.0
FDIR_BUS_SAFE_V = 22.0
FDIR_RELEASE_MS = 120000

FLAG_SECURE_LINK = 0x10
FLAG_PAYLOAD_ARMED = 0x20
FLAG_USB_DEBUG = 0x40
FLAG_GPS_FIX = 0x08
FLAG_GPS_UART = 0x04
FLAG_BME = 0x01
FLAG_ACC = 0x02

F2_ANOMALY, F2_SAFE, F2_OTA_B, F2_SDLS, F2_BROWNOUT, F2_PERSIST = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20)

DEF_RADIO_CRC, DEF_CLOAK, DEF_FREQ_LOCK, DEF_I2C_WHOAMI, DEF_GPS_PLAUS, \
    DEF_TM_CTR, DEF_LOG_ENABLE, DEF_ANOMALY_EN = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)

SYMBOLS = {  # fake-but-fixed addresses; firmware build has the real ones
    "labFnDetumble": 0x10012340,
    "labFnLedRainbow": 0x10012440,
    "labFnGsModeOff": 0x10012540,
    "labFnBeaconFlood": 0x10012640,
    "labFnSecureLinkOff": 0x10012740,
    "labFnNoop": 0x10012000,
}
SYM_GS_CHALLENGE = 0x20002100
SYM_SA0_KEY = 0x20002200
SYM_SA_TABLE = 0x20002200
SYM_ARC_LAST = 0x20002300
SYM_MASTER_KEYS = 0x20003000
SYM_LOG_NAME = 0x20002000
SYM_LEAK_POOL = 0x20002800
ADDR_VTOR = 0xE000ED08
ADDR_WDT_SCRATCH = 0x4005802C
ADDR_GPIO = 0x40014000
MRAM_BASE, MRAM_END = 0x20000000, 0x20041000
XIP_BASE, XIP_END = 0x10000000, 0x14000000

IMAGE_DATA = bytes.fromhex(
    "001f0420eb00000035000000310000004d7501037a00c4001d000000002302889a4203d0438804309142f7d1181c704730bffde7f44600f005f8a748002101604160e746a5480021c943016041607047ca9b0d5bf91d0000284329203230323020466f6c6c6f20546865205768746520526162697400000000000000000000002d034c33570354338f034d53b9265334ad264d431d2643340526554291254454a9014445af0157564501494691244558e52352456d235250b5234643512343582123000047525000435258005346cc0153444c02465aca01465334274645282e4453302e4445a43d00007d480168002928d1fff79fff7b490a68530e01d30a"
)

FLASH_WINDOW_BLOB = b'OPS:STORE_FORWARD=ENABLED\r\nOPS:PAYLOAD_WINDOW=0420Z\r\nMAINT:FLASH_WINDOW=A5:C35A\r\nFLAG=PWNSAT{flash_window_store_and_forward}\r\n'

TC_STATS_DEFAULTS = dict(rssi=-95, snr=8.0, ferr=0.0)


def spp_pack(apid: int, payload: bytes, seq: int, ptype: int = 1,
             flags: int = 1, sechdr: int = 0) -> bytes:
    """CCSDS-style SPP primary header + data (v0 firmware layout)."""
    ident = ((ptype & 1) << 12) | ((sechdr & 1) << 11) | (apid & 0x7FF)
    seqc = ((flags & 3) << 14) | (seq & 0x3FFF)
    ln = (len(payload) - 1) & 0xFFFF if payload else 0
    return struct.pack(">HHH", ident, seqc, ln) + payload


def spp_unpack(raw: bytes):
    """Mirror of spp_unpack_packet() INCLUDING the length==200 off-by-one
    (the data field copy takes one extra byte from beyond the frame)."""
    if len(raw) < 6:
        return None
    ident, seqc, ln = struct.unpack(">HHH", raw[:6])
    # firmware copies header.length + 1 bytes unconditionally, with NO
    # check that the received buffer actually holds them: for a declared
    # 200 the memcpy takes 201 bytes (one read past the frame end).
    data_len = ln + 1
    data = raw[6:6 + data_len]
    if len(data) < data_len:
        data = data + bytes([0xFF]) * (data_len - len(data))
    return {
        "type": (ident >> 12) & 1,
        "sechdr": (ident >> 11) & 1,
        "apid": ident & 0x7FF,
        "flags": (seqc >> 14) & 3,
        "seq": seqc & 0x3FFF,
        "data": data,
        "len": data_len,
    }


class Crash(Exception):
    pass


class Hang(Exception):
    pass


class FlatSatSim:
    """One FlatSat v2 device. `send()` consumes one host->device SPP frame
    and returns the list of device->host frames (0xAA-prefixed, as the
    USB stack transmits them)."""

    def __init__(self, seed: int = 42):
        # ---------------- FLASH (survives reboots and power cycles) -------
        self.flash = {
            "ota": {
                "active_slot": 0, "pending_boot": 0, "boot_try": 0,
                "arwc": 7, "arwc_enforce": 0, "sig_required": 0,
                "sig": bytes(8), "hash": bytes(8), "size": 0,
                "booted_slot": 0,
            },
            "sched": [],          # list of dicts every,apid,payload
            "fdict": None,        # set on first boot
            "fdict_hash": bytes(8),
            "fdict_locked": False,
            "tclog": [],
            "tclog_enabled": False,
            "tclog_evicted": 0,
            "persist_cookie": False,   # NOTE: real cookie lives in scratch
        }
        # watchdog scratch: survives soft reboot, cleared by power cycle
        self.scratch = [0] * 8
        self._cold_boot(seed)

    # ---------------------------------------------------------------- boot
    def _cold_boot(self, seed: int):
        self.rng_state = seed
        self.now_ms = 5000
        self.state = "RUN"          # RUN | CRASHED | HANGED
        self.boot_count = self.scratch[5]
        self.tm_counter = 0
        self.tc_counter = 0

        # secure link / mission
        self.secure = True
        self.usb_debug = False
        self.mode = 0x01            # NOMINAL
        self.payload_armed = False
        self.last_freq = DOWNLINK_FREQ
        self.vcc = 0                # payloadForwardCount
        self.last_pl_len = 0

        # GS auth
        self.gs_mode = False
        self.gs_session = False
        self.gs_session_exp = 0
        self.gs_pending = False
        self.gs_challenge = 0
        self.gs_challenge_exp = 0

        # GPS (attached u-blox by default: fix near the station)
        self.gps = {
            "uart": True, "conn": True, "nmea": True, "fix": True,
            "lat": 36.1000000, "lon": -115.2000000, "alt_cm": 40000000 // 100,
            "sats": 8, "ovr": False, "ovr_exp": 0, "kill": False,
            "reject": 0,
        }

        # beacon/timers
        self.beacon_interval = BEACON_DEFAULT_MS
        self.beacon_changed = False      # firmware quirk (V0-14)
        self.t_prev = {"tm": 0, "nav": 0, "beacon": 0, "sync": 0, "idle": 0}

        # SDLS
        self.sdls_enabled = False
        self.arc_bits = 16
        self.arc_win = 5
        self.arc_relaxed = False
        self.arc_last = 0
        self.sa = [dict(est=0, ast=0, key=bytes(16))
                   for _ in range(SDLS_NUM_SA)]
        for i in range(21):
            self.sa[i] = dict(est=1, ast=1, key=LINK_KEY)
        self.master_keys = [bytes(16) for _ in range(SDLS_MASTER_KEYS)]

        # memory service
        self.vtor = 0x10000100
        self.ram = {}

        # V-13 overflow layout (log_name[32] + flags)
        self.log_name = bytearray(b"boot-log\x00" + bytes(23))

        # covert / leak
        self.pad_mode = 0
        self.covert_q = bytearray()
        self.vcc_frozen = False
        self.leak = bytearray(256)
        self.leak_pos = 0

        # defenses
        self.def_flags = DEF_ANOMALY_EN

        # mission model
        self.mm = {"rate": [0.0, 0.0, 0.0], "euler": [0.0, 0.0, 0.0],
                   "tilt": 0.0, "detumble": False, "bus_v": 24.0,
                   "pct": 100.0, "heaters": [False] * 4, "eclipse": False,
                   "power_w": 0.8, "brownout": False}
        self.orbit_s = 0.0
        self.time_scale = 60.0
        self.t_thr = [10, 10]        # thruster powers

        # FDIR
        self.fdir_armed = True
        self.fdir_safe = False
        self.fdir_entry = 0
        self.fdir_triggers = 0
        self.fdir_cause = ""
        self.tilt_over_since = 0
        if self.flash["fdict"] is None:
            self.flash["fdict"] = [
                {"apid": 0x04, "payload": bytes([0, 0, 0])},
                {"apid": 0x05, "payload": bytes([10, 0])},
            ] + [{"apid": None, "payload": b""} for _ in range(6)]

        # SB
        self.sb_auth = False
        self.sensor_mask = 0x03
        self.sb_stats = {}

        # anomaly
        self.anom = [None] * 4
        self.anom_z = 5.0
        self.anom_alarm = False
        self.anom_last_ch = 0
        self.anom_last_feed = 0
        self.tc_seen = 0

        # tc stats
        self._stats_ovr = None  # LAB_CTRL radio injection override
        self.tcs = {"n": 0, "rssi": [], "snr": [], "ferr": [],
                    "last_apid": 0}

        # spacecan sim
        self.sc = {"nodes": {0x04: dict(err=0, off=False, name="MOTOR"),
                             0x07: dict(err=0, off=False, name="BATTERY"),
                             0x01: dict(err=0, off=False, name="SENSOR")},
                   "congested": False, "frames_ts": [],
                   "charge": 80, "last_err": 0}

        # boot flow
        ota = self.flash["ota"]
        if ota["pending_boot"]:
            ota["boot_try"] += 1
            if ota["boot_try"] > 3:
                ota.update(active_slot=0, pending_boot=0, booted_slot=0)
            else:
                ota["booted_slot"] = 1
        self.persist_cookie = (self.scratch[7] == 0x53524550)
        if self.persist_cookie:
            self.secure = False
            self.gs_mode = False
        # scheduled queue replay (V-19): due immediately after boot
        self._out = []
        for e in self.flash["sched"]:
            e["due"] = self.now_ms // 1000
        self._emit_boot_banner()

    def powercycle(self):
        """Unplug/replug: everything volatile dies, flash stays."""
        self.scratch = [0] * 8
        self._cold_boot(99)

    # ------------------------------------------------------------ helpers
    def _leak_write(self, b: bytes):
        for x in b:
            self.leak[self.leak_pos % 256] = x
            self.leak_pos += 1

    def _leak_take(self, n: int) -> bytes:
        out = bytearray()
        pos = self.leak_pos
        for _ in range(n):
            pos = (pos - 1) % 256
            out.append(self.leak[pos])
        return bytes(out)

    def _frame(self, apid: int, payload: bytes, flags=1, ptype=0,
               clear=False, sechdr=0):
        """Build+queue a TM, applying secure-link / CTR policy like
        telemetrySPPBuildPacketEx + dispatchTelemetryPacket."""
        data = payload
        if self.secure and not clear and not self.usb_debug:
            if self.def_flags & DEF_TM_CTR:
                blen = ((len(payload) + 2 + 15) // 16) * 16
                body = struct.pack(">H", len(payload)) + payload
                body = body + bytes(blen - len(body))
                ctrv = self.tm_counter + 1
                ctr = bytes(12) + struct.pack(">I", ctrv & 0xFFFFFFFF)
                data = ctr_xor(self.sa[0]["key"], ctr, body)
            else:
                blen = ((len(payload) + 2 + 15) // 16) * 16
                body = struct.pack(">H", len(payload)) + payload
                body = body + bytes(blen - len(body))
                data = aes_ecb_encrypt(LINK_KEY, body)
        self.tm_counter = (self.tm_counter + 1) % 16384
        if self.tm_counter == 0:
            pass
        self._out.append(b"\xAA" + spp_pack(apid, data, self.tm_counter,
                                            ptype=ptype, flags=flags,
                                            sechdr=sechdr))

    def _err(self, msg: str):
        self._frame(0x09, msg.encode() + b"\x00")

    def _rand(self, *args) -> float:
        h = hashlib.sha256(b"".join(args)).digest()
        return int.from_bytes(h[:4], "big") / 0xFFFFFFFF

    # ------------------------------------------------------------ crypto
    def sl_encode(self, plain: bytes) -> bytes:
        blen = ((len(plain) + 2 + 15) // 16) * 16
        body = struct.pack(">H", len(plain)) + plain
        body = body + bytes(blen - len(body))
        return aes_ecb_encrypt(LINK_KEY, body)

    def sl_decode(self, cipher: bytes):
        if len(cipher) == 0 or len(cipher) % 16 != 0:
            return None
        plain = aes_ecb_decrypt(LINK_KEY, cipher)
        plen = struct.unpack(">H", plain[:2])[0]
        if plen > len(cipher) - 2 or plen > 200:
            return None
        return plain[2:2 + plen]

    # --------------------------------------------------------- GS auth
    def _gps_nav(self):
        g = self.gps
        if g["kill"]:
            return dict(uart=False, conn=False, nmea=False, fix=False,
                        lat=0, lon=0, alt=0, alt_cm=0, sats=0, utc=0)
        if g["ovr"] and self.now_ms < g["ovr_exp"]:
            return g["ovr_nav"]
        return dict(uart=g["uart"], conn=g["conn"], nmea=g["nmea"],
                    fix=g["fix"], lat=g["lat"], lon=g["lon"],
                    alt=g["alt_cm"], alt_cm=g["alt_cm"], sats=g["sats"],
                    utc=int(self.now_ms / 1000) % 60)

    def _gps_usable(self, nav):
        return nav["uart"] and nav["conn"] and nav["nmea"] and nav["fix"] \
            and nav["lat"] != 0 and nav["lon"] != 0

    def _gs_dist_m(self, nav):
        if not self._gps_usable(nav):
            return -1.0
        import math
        lat = math.radians(nav["lat"])
        lon = math.radians(nav["lon"])
        glat = math.radians(GS_STATION[0] / 1e7)
        glon = math.radians(GS_STATION[1] / 1e7)
        x = (glon - lon) * math.cos((lat + glat) / 2)
        y = glat - lat
        return math.sqrt(x * x + y * y) * 6371000.0

    def _gs_within(self, nav):
        d = self._gs_dist_m(nav)
        return 0 <= d <= GS_RADIUS_M

    def _gs_session_active(self):
        if self.gs_session and self.now_ms >= self.gs_session_exp:
            self.gs_session = False
        return self.gs_session

    def _gs_pending_active(self):
        if self.gs_pending and self.now_ms >= self.gs_challenge_exp:
            self.gs_pending = False
            self.gs_challenge = 0
        return self.gs_pending

    def _gs_gate_open(self, nav):
        if not self.gs_mode:
            return True
        return (self._gps_usable(nav) and self._gs_within(nav)
                and self._gs_session_active())

    def _gs_status_byte(self, nav):
        b = 0
        if self.gs_mode:
            b |= 0x01
        if self._gps_usable(nav):
            b |= 0x02
        if self._gs_within(nav):
            b |= 0x04
        if self._gs_session_active():
            b |= 0x08
        if self._gs_pending_active():
            b |= 0x10
        if self._gs_gate_open(nav):
            b |= 0x20
        return b

    def _gps_status_byte(self, nav):
        b = 0
        if nav["uart"]:
            b |= 0x01
        if nav["conn"]:
            b |= 0x02
        if nav["nmea"]:
            b |= 0x04
        if nav["fix"]:
            b |= 0x08
        b |= 0x10
        return b

    def _gs_gen_challenge(self, nav):
        seed = ((self.now_ms << 1) & 0xFFFFFFFF) ^ 0xA55A33CC
        seed ^= int(nav["lat"] * 1e7) & 0xFFFFFFFF
        seed ^= (int(nav["lon"] * 1e7) << 7) & 0xFFFFFFFF
        seed ^= (nav["utc"] << 24) & 0xFFFFFFFF
        seed ^= (nav["sats"] << 16) & 0xFFFFFFFF
        if seed == 0:
            seed = 0x13579BDF
        return seed

    def _gs_allowed(self, apid, via, payload):
        """groundStationCommandAllowed() mirror."""
        if not self.gs_mode:
            return True, ""
        if apid in (0x10, 0x12):
            return True, ""
        if via == "usb" and apid in (0x26, 0x27):
            # bench harness backdoor (LAB_STATUS / LAB_CTRL), PER-0002
            return True, ""
        if apid == 0x11 and len(payload) >= 1 and payload[0] == 0 \
                and via == "usb" and self.usb_debug:
            return True, ""
        nav = self._gps_nav()
        if not self._gps_usable(nav):
            return False, "GS GPS INVALID"
        if not self._gs_within(nav):
            return False, "GS RANGE LOCK"
        if not self._gs_session_active():
            return False, "GS AUTH REQUIRED"
        return True, ""

    def _flags(self):
        f = 0
        if self.sensor_mask & 0x01:
            f |= FLAG_BME
        if self.sensor_mask & 0x02:
            f |= FLAG_ACC
        if self._gps_nav()["uart"]:
            f |= FLAG_GPS_UART
        if self._gps_nav()["fix"]:
            f |= FLAG_GPS_FIX
        if self.secure:
            f |= FLAG_SECURE_LINK
        if self.payload_armed:
            f |= FLAG_PAYLOAD_ARMED
        if self.usb_debug:
            f |= FLAG_USB_DEBUG
        return f

    def _flags2(self):
        f = 0
        if self.anom_alarm:
            f |= F2_ANOMALY
        if self.fdir_safe:
            f |= F2_SAFE
        if self.flash["ota"]["booted_slot"] == 1:
            f |= F2_OTA_B
        if self.sdls_enabled:
            f |= F2_SDLS
        if self.mm["brownout"]:
            f |= F2_BROWNOUT
        if self.persist_cookie:
            f |= F2_PERSIST
        return f

    # ---------------------------------------------------------- main TC
    def send(self, raw: bytes, via: str = "radio"):
        """Process one host->device SPP frame. Returns emitted frames."""
        self._out = []
        if self.state in ("CRASHED", "HANGED"):
            return []
        self._handle(raw, via)
        return list(self._out)

    def _handle(self, raw: bytes, via: str):
        pkt = spp_unpack(raw)
        if pkt is None:
            return
        apid = pkt["apid"]
        payload = pkt["data"]
        self.tc_counter = (self.tc_counter + 1) % 16384

        # radio per-TC stats (V-03/V-29)
        if via == "radio":
            if self._stats_ovr is not None:  # LAB_CTRL bench injection
                rssi, snr, ferr = self._stats_ovr
            else:
                r = self._rand(b"tc", self.tc_counter.to_bytes(4, "big"))
                rssi = -70 + int(r * 20) - 10
                snr = 7.0 + self._rand(b"snr", bytes([self.tc_counter & 0xFF])) * 4
                ferr = -150 + self._rand(b"fe", bytes([(self.tc_counter >> 8) & 0xFF])) * 300
            self.tcs["rssi"].append(rssi)
            self.tcs["snr"].append(snr)
            self.tcs["ferr"].append(ferr)
            self.tcs["n"] = min(64, self.tcs["n"] + 1)
            self.tcs["last_apid"] = apid
            self.tc_seen += 1

        # --- SDLS pre-processing (radio only) ---------------------------
        if via == "radio":
            res = self._sdls_pre(pkt, raw)
            if res == "HANG":
                self.state = "HANGED"
                return
            if res == "MAC":
                self._err("SDLS MAC FAIL")
                return
            if res == "ARC":
                self._err("SDLS ARC FAIL")
                return
            if res == "HDR":
                self._err("SDLS SEC HDR REQ")
                return
            if res in ("OK", "PASS"):
                pass
            payload = pkt["data"]  # possibly stripped

        # --- toggle commands (baseline special path, V0-10) --------------
        if apid in (0x0A, 0x10):
            if len(payload) == 0:
                self._err("AES CONFIG FAIL" if apid == 0x0A else "DEBUG CONFIG FAIL")
                return
            if len(payload) % 16 == 0:
                dec = self.sl_decode(payload)
                new_state = (dec[0] != 0) if dec else (payload[0] != 0)
            else:
                new_state = payload[0] != 0
            if apid == 0x10:
                if via != "usb":
                    self._err("DEBUG USB ONLY")
                    return
                self.usb_debug = new_state
                self._frame(0x10, bytes([SPACECRAFT_ID, self.usb_debug,
                                         self.secure, 0x01]), clear=True)
                return
            ok, why = self._gs_allowed(apid, via, payload)
            if not ok:
                self._err(why)
                self._tm_gs_status()
                return
            self.secure = new_state
            self._frame(0x0A, bytes([SPACECRAFT_ID, self.secure, 0x00]))
            return

        # --- secured PING pilot (baseline, SDLS-off only) -----------------
        if apid == 0x01 and pkt["sechdr"] and not (self.sdls_enabled and via == "radio"):
            ok, why = self._gs_allowed(apid, via, payload)
            if not ok:
                self._err(why)
                self._tm_gs_status()
                return
            counter = struct.unpack(">I", payload[:4] + bytes(4 - min(4, len(payload))))[:1][0] if len(payload) >= 4 else 0
            self._frame(0x01, bytes([SPACECRAFT_ID]) + b"ACK\x00", clear=True)
            return

        # --- secure link decrypt ------------------------------------------
        if self.secure and not (via == "usb" and self.usb_debug):
            dec = self.sl_decode(payload)
            if dec is None:
                self._err("AES DECRYPT FAIL")
                return
            payload = dec

        # --- GS gate ------------------------------------------------------
        ok, why = self._gs_allowed(apid, via, payload)
        if not ok:
            self._err(why)
            self._tm_gs_status()
            return

        self._dispatch(apid, payload, via)

    # ---------------------------------------------------------- baseline
    def _dispatch(self, apid: int, d: bytes, via: str):
        # TC log (V-23)
        if self.flash["tclog_enabled"]:
            self.flash["tclog"].append(
                dict(ms=self.now_ms, apid=apid, seq=self.tc_counter,
                     payload=d[:32]))
            if len(self.flash["tclog"]) > 128:
                self.flash["tclog"].pop(0)
                self.flash["tclog_evicted"] += 1

        if 0xF0 <= apid <= 0xFF:
            if not self.fdir_safe:
                self._err("TESTMODE INACTIVE")
                return
            self._frame(apid, bytes([apid]) + b"TEST")
            return
        if apid == 0x01:  # PING
            self._frame(0x01, bytes([SPACECRAFT_ID]) + b"ACK\x00")
        elif apid == 0x02:  # RESETC
            self._tm_resetc()
        elif apid == 0x03:  # SEND_FW
            self._frame(0x03, bytes([SPACECRAFT_ID, 0, 0, 1, 0]))
        elif apid == 0x04:  # SET_THRUSTER
            if len(d) >= 2:
                tid, pw = d[0], d[1]
                if tid <= 1:
                    self.t_thr[tid] = pw
                    if pw:
                        self.mm["rate"][tid] += 0.3 * pw / 255.0
        elif apid == 0x05:  # SET_BEACON_RATE
            if d[0] <= 30:
                self.beacon_interval = d[0] * 1000
                self.beacon_changed = True
        elif apid == 0x06:  # BROADCAST_MSG (V0-03 underflow, V-32 squat)
            if len(d) < 1:
                return
            freq = struct.unpack(">H", d[:2] + bytes(max(0, 2 - len(d))))[0] if len(d) >= 2 else (d[0] << 8)
            pl = len(d)
            msg_len = pl - 2
            if msg_len < 0:
                self.state = "CRASHED"   # SIZE_MAX memcpy -> HardFault
                return
            msg = d[2:2 + msg_len]
            if self.def_flags & DEF_FREQ_LOCK and freq not in (916, DOWNLINK_FREQ):
                self._err("FREQ LOCK")
                return
            self.last_freq = freq if freq else DOWNLINK_FREQ
            self.vcc += 1
            self.last_pl_len = msg_len
            self._frame(0x06, msg)
        elif apid == 0x07:  # FLASH dump
            total = 255
            n = (total + 15) // 16
            for i in range(n):
                off = i * 16
                size = min(16, total - off)
                body = bytes([SPACECRAFT_ID, i & 0xFF, i >> 8, off & 0xFF,
                              off >> 8, (total - off) & 0xFF,
                              (total - off) >> 8])
                body += IMAGE_DATA[off:off + size] + bytes(max(0, size - len(IMAGE_DATA[off:off + size])))
                body = body[:7 + 16] + bytes([crc8(body[7:7 + 16])])
                flag = 2 if i == 0 else (3 if i == n - 1 else 1)
                self._frame(0x07, body, flags=flag)
        elif apid == 0x0B:  # FLASH_READ
            if len(d) < 6:
                return
            if d[0] != 0xA5 or struct.unpack(">H", d[4:6])[0] != 0xC35A:
                self._err("FLASH WINDOW LOCKED")
                return
            off = struct.unpack("<H", d[1:3])[0]
            ln = d[3]
            if ln == 0:
                self._err("FLASH READ SIZE ZERO")
                return
            if off >= len(FLASH_WINDOW_BLOB):
                self._err("FLASH READ OOB")
                return
            ln = min(ln, 32, len(FLASH_WINDOW_BLOB) - off)
            blob = FLASH_WINDOW_BLOB[off:off + ln]
            self._frame(0x0B, bytes([SPACECRAFT_ID, off & 0xFF, off >> 8, ln])
                        + blob + bytes([crc8(blob)]))
        elif apid == 0x0C:  # GET_STATUS
            self._tm_status()
        elif apid == 0x0D:  # SET_MISSION_MODE
            if d[0] > 4:
                self._err("MISSION MODE INVALID")
                return
            self.mode = d[0]
            self.payload_armed = d[0] in (2, 3)
            if d[0] in (0, 4):
                self.t_thr = [0, 0]
            self._frame(0x0D, bytes([SPACECRAFT_ID, self.mode,
                                     self.payload_armed, self._flags()]))
        elif apid == 0x0E:  # GET_NAV
            self._tm_nav()
        elif apid == 0x0F:
            self._frame(0x0F, bytes([SPACECRAFT_ID, self.mode,
                                     self.payload_armed, self.secure])
                        + struct.pack("<HHB", self.last_freq, self.vcc,
                                      self.last_pl_len) + b"\x00")
        elif apid == 0x11:  # GS_MODE
            nav = self._gps_nav()
            req = 1 if (len(d) >= 1 and d[0]) else 0
            if req == 0:
                if self.gs_mode and not (self._gs_gate_open(nav) or
                                         (via == "usb" and self.usb_debug)):
                    self._err("GS DISABLE AUTH")
                    self._tm_gs_mode(req)
                    return
                self.gs_mode = False
                self.gs_session = False
                self.gs_pending = False
                self._tm_gs_mode(req)
                return
            if not self._gps_usable(nav):
                self._err("GS MODE GPS REQUIRED")
                self._tm_gs_mode(req)
                return
            if not self._gs_within(nav):
                self._err("GS RANGE LOCK")
                self._tm_gs_mode(req)
                return
            self.gs_mode = True
            self._tm_gs_mode(req)
        elif apid == 0x12:  # GS_ACCESS
            nav = self._gps_nav()
            if len(d) == 0:
                self._err("GS ACCESS FORMAT")
                self._tm_gs_access(0xFF, 0x02, nav)
                return
            if not self._gps_usable(nav):
                self._err("GS ACCESS GPS")
                self._tm_gs_access(d[0], 0x02, nav)
                return
            if not self._gs_within(nav):
                self._err("GS RANGE LOCK")
                self._tm_gs_access(d[0], 0x02, nav)
                return
            phase = d[0]
            if phase == 0:
                self.gs_challenge = self._gs_gen_challenge(nav)
                self._leak_write(struct.pack("<I", self.gs_challenge))
                self.gs_pending = True
                self.gs_challenge_exp = self.now_ms + GS_CHALLENGE_MS
                self._tm_gs_access(phase, 0x00, nav)
                return
            if phase != 1 or len(d) < 5:
                self._err("GS ACCESS FORMAT")
                self._tm_gs_access(phase, 0x02, nav)
                return
            if not self._gs_pending_active():
                self._err("GS CHALLENGE NONE")
                self._tm_gs_access(phase, 0x03, nav)
                return
            resp = struct.unpack(">I", d[1:5])[0]
            if resp != (self.gs_challenge ^ GS_XOR_KEY):
                self.gs_pending = False
                self.gs_session = False
                self._err("GS AUTH FAIL")
                self._tm_gs_access(phase, 0x02, nav)
                return
            self.gs_session = True
            self.gs_session_exp = self.now_ms + GS_SESSION_MS
            self.gs_pending = False
            self._tm_gs_access(phase, 0x01, nav)
        elif apid == 0x13:
            self._tm_gs_status()
        elif apid in (0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                      0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                      0x26, 0x27):
            self._ext(apid, d, via)
        else:
            self._err("Error Unknown APID")

    # ------------------------------------------------------------ TMs
    def _tm_status(self, clear=False):
        nav = self._gps_nav()
        p = struct.pack("<BBBBBBBB", SPACECRAFT_ID, self.mode, self._flags(),
                        self._gps_status_byte(nav),
                        min(255, self.beacon_interval // 1000),
                        self.t_thr[0], self.t_thr[1], nav["sats"])
        p += struct.pack("<HH", self.vcc & 0xFFFF, self.last_freq & 0xFFFF)
        p += struct.pack("<I", self.now_ms // 1000)
        utc = nav["utc"]
        p += struct.pack("<BBBBBH", 0, 0, utc, 1, 1, 2026)
        p += bytes([0, 0, 1])
        p += bytes([self._flags2()])   # v2 extension byte at the tail
        self._frame(0x0C, p, clear=clear)

    def _tm_nav(self):
        nav = self._gps_nav()
        p = bytes([SPACECRAFT_ID, self._gps_status_byte(nav), nav["sats"]])
        p += struct.pack("<iiI", int(nav["lat"] * 1e7), int(nav["lon"] * 1e7),
                         int(nav["alt_cm"]))
        p += struct.pack("<BBBBBH", 0, 0, nav["utc"], 1, 1, 2026)
        import math
        shake = 0.3 * math.sin(self.now_ms / 700.0) * (1 + self.mm["tilt"])
        for v in (shake, shake * 0.5, 9.81, 25.0):
            p += struct.pack("<h", int(v * 100))
        self._frame(0x0E, p)

    def _tm_gs_mode(self, req):
        nav = self._gps_nav()
        p = bytes([SPACECRAFT_ID, req, self.gs_mode,
                   self._gs_status_byte(nav), self._gps_status_byte(nav)])
        p += struct.pack("<HH",
                         max(0, (self.gs_session_exp - self.now_ms + 999) // 1000)
                         if self.gs_session else 0,
                         max(0, (self.gs_challenge_exp - self.now_ms + 999) // 1000)
                         if self.gs_pending else 0)
        self._frame(0x11, p)

    def _tm_gs_access(self, phase, auth, nav):
        p = bytes([SPACECRAFT_ID, phase, auth, self._gs_status_byte(nav),
                   self._gps_status_byte(nav)])
        p += struct.pack("<I", self.gs_challenge)
        p += struct.pack("<HH",
                         max(0, (self.gs_session_exp - self.now_ms + 999) // 1000)
                         if self.gs_session else 0,
                         max(0, (self.gs_challenge_exp - self.now_ms + 999) // 1000)
                         if self.gs_pending else 0)
        self._frame(0x12, p)

    def _tm_gs_status(self):
        nav = self._gps_nav()
        d = self._gs_dist_m(nav)
        dist = 0xFFFF if d < 0 or d >= 65535 else int(d)
        p = bytes([SPACECRAFT_ID, self._gs_status_byte(nav),
                   self._gps_status_byte(nav)])
        p += struct.pack("<H", dist)
        p += struct.pack("<H",
                         max(0, (self.gs_session_exp - self.now_ms + 999) // 1000)
                         if self.gs_session else 0)
        p += struct.pack("<I", self.gs_challenge)
        p += struct.pack("<H",
                         max(0, (self.gs_challenge_exp - self.now_ms + 999) // 1000)
                         if self.gs_pending else 0)
        p += struct.pack("<iiH", GS_STATION[0], GS_STATION[1], GS_RADIUS_M)
        self._frame(0x13, p)

    def _tm_resetc(self):
        # ack with boot counter + cookie bit, then reboot
        self._frame(0x02, bytes([SPACECRAFT_ID, (self.boot_count + 1) & 0xFF,
                                 1 if self.persist_cookie else 0, 0x52]),
                    clear=True)
        self._soft_reboot()

    # ------------------------------------------------------------ reboots
    def _soft_reboot(self):
        """watchdog_reboot(): SRAM dies, watchdog scratch survives, flash
        survives. V-21's whole point."""
        cookie = self.scratch[7]
        self.scratch[5] = self.boot_count + 1
        keep_scratch = list(self.scratch)
        sched = self.flash["sched"]
        flash = self.flash
        sdls_keys_saved = None  # keys are volatile (course behaviour)
        self.scratch = keep_scratch
        self._cold_boot(7)
        # _cold_boot reset scratch ref; restore survivors
        self.scratch = keep_scratch
        self.scratch[7] = cookie
        self.flash = flash
        self._cold_boot_flash_reapply()

    def brownout_reset(self):
        """Power event: scratch wiped too (cookie gone), boot count restarts."""
        flash = self.flash
        self.scratch = [0] * 8
        self._cold_boot(3)
        self.flash = flash
        self._cold_boot_flash_reapply()

    def _cold_boot_flash_reapply(self):
        self.flash["tclog_enabled"] = self.flash.get("tclog_enabled", False)
        self.anom_z = self.flash.get("anom_z", 5.0)

    # ---------------------------------------------------- periodic workers
    def advance(self, ms: int):
        """Advance mission time; returns TMs generated along the way."""
        self._out = []
        step = 100
        elapsed = 0
        while elapsed < ms:
            elapsed += step
            self.now_ms += step
            if self.state != "RUN":
                break
            self._workers_tick()
        return list(self._out)

    def _workers_tick(self):
        # mission model (100 ms tick)
        dt_o = (0.1 * self.time_scale)
        self.orbit_s = (self.orbit_s + dt_o) % 95.0
        self.mm["eclipse"] = self.orbit_s < 35.0
        mm = self.mm
        torque = [0.3 * self.t_thr[0] / 255.0, 0.3 * self.t_thr[1] / 255.0, 0.0]
        for ax in range(3):
            if mm["detumble"]:
                damp = min(0.6 * mm["rate"][ax], 0.25)   # B-dot saturation
            else:
                damp = 0.01
            mm["rate"][ax] = max(0.0, mm["rate"][ax] + torque[ax] * dt_o
                                 - damp * dt_o * 10)
            mm["euler"][ax] += mm["rate"][ax] * dt_o
        mm["tilt"] = (mm["rate"][0] ** 2 + mm["rate"][1] ** 2
                      + mm["rate"][2] ** 2) ** 0.5
        load = 0.8 + sum(2.4 for h in mm["heaters"] if h)
        load += (1.2 if self.t_thr[0] > 0 else 0) + (1.2 if self.t_thr[1] > 0 else 0)
        mm["power_w"] = load
        solar = 0.0 if mm["eclipse"] else 3.0
        mm["pct"] = max(0.0, min(100.0, mm["pct"] + ((solar - load) * dt_o / 3600.0) / 40.0 * 100.0))
        mm["bus_v"] = 21.0 + 3.0 * mm["pct"] / 100.0
        if mm["bus_v"] < 21.0 or (mm["pct"] <= 0.0 and solar < load):
            mm["brownout"] = True

        # FDIR
        if self.fdir_armed:
            if mm["tilt"] > FDIR_TILT:
                if self.tilt_over_since == 0:
                    self.tilt_over_since = self.now_ms
                elif self.now_ms - self.tilt_over_since > 2000 and not self.fdir_safe:
                    self._safe_enter("TUMBLE")
            else:
                self.tilt_over_since = 0
            if not self.fdir_safe and mm["bus_v"] < FDIR_BUS_SAFE_V:
                self._safe_enter("BUS_UNDERV")
        if mm["brownout"]:
            # reset FIRST (it rebuilds the TM queue), then emit the boot
            # reason frame so the operator actually sees the 'B' marker
            self.brownout_reset()
            self._frame(0x02, bytes([SPACECRAFT_ID, self.boot_count & 0xFF,
                                     0, 0x42]), clear=True)
            return

        # 1 Hz services
        if self.now_ms % 1000 == 0:
            self._feed_anomaly()
            self._sched_due()

        # periodic TM (baseline intervals, beacon quirk preserved)
        tw = self.t_prev
        if self.now_ms - tw["tm"] > 14000:
            tw["tm"] = self.now_ms
            if self.sensor_mask & 0x01:
                import math
                t = 25.0 + 0.5 * math.sin(self.now_ms / 50000.0)
                vals = [0.02, 0.01, 9.81, 25.0, t, 1013.0, 620.0, 45.0]
                if not (self.sensor_mask & 0x02):
                    vals = [0.0, 0.0, 0.0, 0.0] + vals[4:]
                p = bytes([SPACECRAFT_ID])
                for v in vals:
                    i = int(v * 100) & 0xFFFF      # C int16_t truncation
                    p += struct.pack("<h", i - 0x10000 if i >= 0x8000 else i)
                p += bytes(self.t_thr) + b"\x00"
                self._frame(0x08, p)
        if self.now_ms - tw["nav"] > 22000:
            tw["nav"] = self.now_ms
            self._tm_nav()
        if self.beacon_changed and self.beacon_interval is not None:
            if self.beacon_interval == 0 or (self.now_ms - tw["beacon"]
                                             > self.beacon_interval):
                tw["beacon"] = self.now_ms
                self._beacon()
        if self.now_ms - tw["sync"] > 20000:
            tw["sync"] = self.now_ms
            self._frame(0x01, bytes([SPACECRAFT_ID]) + b"Pwnsat\x00")
        if self.now_ms - tw["idle"] > 30000:
            tw["idle"] = self.now_ms
            self._frame(0x3FF, b"HackTheWorld!\x00")

    def _emit_boot_banner(self):
        self._frame(0x02, bytes([SPACECRAFT_ID, self.boot_count & 0xFF,
                                 1 if self.persist_cookie else 0,
                                 0x42 if False else 0x01]), clear=True)

    def _beacon(self):
        nav = self._gps_nav()
        buf = bytearray(64)
        buf[0:8] = bytes([SPACECRAFT_ID]) + b"Beacon\x00"
        gs_bits = self._gs_status_byte(nav) & 0x0F
        buf[8] = self.mode
        buf[9] = self._flags()
        buf[10] = self._flags2()
        struct.pack_into("<H", buf, 11, int(self.mm["bus_v"] * 100))
        tilt = min(0xFFFF, int(self.mm["tilt"] * 100))
        struct.pack_into("<H", buf, 13, tilt)
        buf[15] = gs_bits | (0x10 if self.mm["eclipse"] else 0)
        struct.pack_into(">I", buf, 16, self.now_ms & 0xFFFFFFFF)
        buf[20] = self.boot_count & 0xFF
        if self.def_flags & DEF_CLOAK:
            buf[8:21] = bytes(13)
        pad_needed = 64 - 21
        if self.pad_mode == 2:
            take = bytes(self.covert_q[:pad_needed])
            del self.covert_q[:len(take)]
            buf[21:21 + len(take)] = take
        elif self.pad_mode == 1:
            buf[21:21 + pad_needed] = self._leak_take(pad_needed)
        self._frame(0x01, bytes(buf))

    # ------------------------------------------------------- SDLS engine
    def _sdls_pre(self, pkt, raw):
        if not self.sdls_enabled:
            return "SKIP"
        if not pkt["sechdr"]:
            spi = SDLS_SA_PLAINTEXT_DEFAULT
            payload_off = 0
            sa = self.sa[spi]
            if sa["ast"] == 0:
                return "PASS"
            return "HDR"
        d = pkt["data"]
        if len(d) < SDLS_SEC_HDR_LEN:
            return "HDR"
        spi = struct.unpack(">H", d[:2])[0]
        arc = struct.unpack(">I", d[2:6])[0]
        mac = d[6:22]
        payload = d[22:]
        if spi >= SDLS_SPI_FAULT:
            return "HANG"
        sa = self.sa[spi] if spi < SDLS_NUM_SA else dict(est=0, ast=0, key=bytes(16))
        if sa["ast"] == 0:
            pkt["data"] = payload
            return "PASS"
        # MAC over raw 6-byte primary header + secured payload
        mac_in = raw[:6] + payload
        if cmac(sa["key"], mac_in) != mac:
            return "MAC"
        p_mod = (1 << self.arc_bits) if self.arc_bits < 32 else 0x100000000
        delta = (arc - self.arc_last) % p_mod
        w = 15 if self.arc_relaxed else self.arc_win
        if 1 <= delta <= w:
            self.arc_last = arc
        else:
            return "ARC"
        pkt["data"] = payload
        return "OK"

    # ------------------------------------------------------- extension cmds
    def _ext(self, apid, d, via):
        src = 1 if via == "usb" else 0
        if apid == 0x14:  # GPS_OVERRIDE
            if len(d) < 13:
                self._err("GPS OVR FORMAT")
                return
            lat, lon, alt = struct.unpack("<iii", d[:12])
            sats = d[12]
            nav = dict(uart=True, conn=True, nmea=True, fix=True,
                       lat=lat / 1e7, lon=lon / 1e7, alt=alt, alt_cm=alt,
                       sats=sats, utc=0)
            if self.def_flags & DEF_GPS_PLAUS and self.gps["ovr"]:
                prev = self.gps["ovr_nav"]
                dt = max(0.01, (self.now_ms - self.gps.get("ovr_set_ms", 0)) / 1000.0)
                dist = ((lat - prev["lat"] * 1e7) ** 2 +
                        ((lon - prev["lon"] * 1e7) * 0.8) ** 2) ** 0.5 / 1e7 * 111.32
                if dist / dt > 500:
                    self.gps["reject"] += 1
                    return
            self.gps["ovr"] = True
            self.gps["ovr_nav"] = nav
            self.gps["ovr_exp"] = self.now_ms + 300000
            self.gps["ovr_set_ms"] = self.now_ms
            tm = bytes([SPACECRAFT_ID]) + d[:13] + bytes(
                [self.pad_mode, self.def_flags, self.mode, 0])
            self._frame(0x0E, tm, clear=True)
        elif apid == 0x15:  # SDLS_CONFIG
            if len(d) < 3:
                self._err("SDLS CFG FORMAT")
                return
            if d[0] <= 1:
                self.sdls_enabled = d[0] == 1
            if d[1] in (16, 20, 32):
                self.arc_bits = d[1]
            if 1 <= d[2] <= 15:
                self.arc_win = d[2]
            self._frame(0x15, bytes([SPACECRAFT_ID, 0x15, self.sdls_enabled,
                                     self.arc_bits, self.sdls_window(),
                                     self.sdls_enabled]), clear=True)
        elif apid == 0x16:  # SDLS_OTA
            if len(d) < 1:
                self._err("SDLS OTA FORMAT")
                return
            sub = d[0]
            if sub == 0:  # OTAR
                if len(d) < 19:
                    self._err("OTAR FORMAT")
                    return
                m, sa_i = d[1], d[2]
                if m >= SDLS_MASTER_KEYS or sa_i >= SDLS_NUM_SA:
                    ok = 0
                else:
                    key = aes_ecb_decrypt(self.master_keys[m], d[3:19])
                    self.sa[sa_i] = dict(est=1, ast=1, key=key)
                    ok = 1
                self._frame(0x16, bytes([SPACECRAFT_ID, 0, ok, m, sa_i]),
                            clear=True)
            elif sub == 1:
                if len(d) < 20:
                    self._err("SA SET FORMAT")
                    return
                sa_i = d[1]
                if sa_i >= SDLS_NUM_SA:
                    ok = 0
                else:
                    self.sa[sa_i] = dict(est=1 if d[2] else 0,
                                         ast=1 if d[3] else 0, key=d[4:20])
                    ok = 1
                self._frame(0x16, bytes([SPACECRAFT_ID, 1, ok, sa_i]),
                            clear=True)
            elif sub == 2:
                sa_i = d[1] if len(d) > 1 else 0
                sa = self.sa[min(sa_i, SDLS_NUM_SA - 1)]
                key = sa["key"] if (via == "usb" or self._gs_session_active()) else bytes(16)
                nulls = sum(1 for k in self.master_keys if k == bytes(16))
                self._frame(0x16, bytes([SPACECRAFT_ID, 2, sa_i, sa["est"],
                                         sa["ast"]]) + key + bytes(
                    [nulls, self.sdls_enabled, 0]), clear=True)
            elif sub == 3:
                self.arc_last = 0
                self._frame(0x16, bytes([SPACECRAFT_ID, 3, 1]), clear=True)
            else:
                self._err("SDLS OTA SUB?")
        elif apid == 0x17:  # KEY_VERIFY (V-11 oracle)
            if len(d) < 21:
                self._err("KV FORMAT")
                return
            kid = d[0]
            sa = self.sa[min(kid, SDLS_NUM_SA - 1)]
            ctr = bytes(12) + d[1:5]
            out = ctr_xor(sa["key"], ctr, d[5:21])
            self._frame(0x17, bytes([SPACECRAFT_ID, kid]) + out + b"\x00",
                        clear=True)
        elif apid == 0x19:  # MEM_READ
            if len(d) < 6:
                self._err("MEM READ FORMAT")
                return
            addr, ln = struct.unpack("<IH", d[:6])
            buf = self._mem_read(addr, ln)
            if buf is None:
                self._err("MEM READ FAULT")
                return
            self._frame(0x19, bytes([SPACECRAFT_ID]) + d[:6] + buf, clear=True)
        elif apid == 0x18:  # MEMCPY
            if len(d) < 10:
                self._err("MEMCPY FORMAT")
                return
            src, dst, ln = struct.unpack("<IIH", d[:10])
            if not self._mem_copy(src, dst, ln):
                self.state = "HANGED"
                return
            self._frame(0x18, bytes([SPACECRAFT_ID, 1]) + d[:10], clear=True)
        elif apid == 0x1A:  # SET_LOG_NAME (V-13)
            self._set_log_name(d)
            self._frame(0x1A, bytes([SPACECRAFT_ID, self.usb_debug,
                                     self.secure, self.gs_mode, self.pad_mode,
                                     0, 0, 0]), clear=True)
        elif apid == 0x1B:  # SB_PUBLISH
            if len(d) < 3:
                self._err("SB FORMAT")
                return
            mid = struct.unpack(">H", d[:2])[0]
            ok = self._sb_publish(mid, d[2:], src)
            self._frame(0x1B, bytes([SPACECRAFT_ID, 1, mid >> 8, mid & 0xFF,
                                     ok, self.sensor_mask, self.vcc_frozen, 0]),
                        clear=True)
        elif apid == 0x1C:  # SC_INJECT
            self._sc(d)
        elif apid == 0x1D:  # FDIR_CONFIG
            self._fdir_cfg(d)
        elif apid == 0x1E:  # SCHED
            self._sched_cmd(d)
        elif apid == 0x1F:  # OTA
            self._ota_cmd(d)
        elif apid == 0x20:  # TC_STATS
            if len(d) >= 1 and d[0] == 1:
                self.tcs = {"n": 0, "rssi": [], "snr": [], "ferr": [],
                            "last_apid": 0}
                self._frame(0x20, bytes([SPACECRAFT_ID, 1, 1, 0]), clear=True)
                return
            n = max(1, len(self.tcs["rssi"]))
            avg = lambda xs: sum(xs) / n if xs else 0
            tm = bytes([SPACECRAFT_ID, 0, len(self.tcs["rssi"])])
            tm += struct.pack("<hhhhh", int(avg(self.tcs["rssi"])),
                              int(avg(self.tcs["snr"]) * 10),
                              int(avg(self.tcs["ferr"])),
                              min(self.tcs["rssi"]) if self.tcs["rssi"] else 0,
                              max(self.tcs["rssi"]) if self.tcs["rssi"] else 0)
            tm += bytes([1 if self.def_flags & DEF_RADIO_CRC else 0,
                         self.tcs["last_apid"] >> 8, self.tcs["last_apid"] & 0xFF])
            tm += struct.pack("<H", self.tm_counter)
            self._frame(0x20, tm, clear=True)
        elif apid == 0x21:  # PADDING_CONFIG
            if len(d) < 1:
                self._err("PAD FORMAT")
                return
            if d[0] <= 2:
                self.pad_mode = d[0]
            self._frame(0x21, bytes([SPACECRAFT_ID, self.pad_mode])
                        + struct.pack(">H", len(self.covert_q))
                        + bytes([1 if self.def_flags & DEF_CLOAK else 0, 0]),
                        clear=True)
        elif apid == 0x22:  # COVERT_ENQ
            if len(self.covert_q) + len(d) <= 1024:
                self.covert_q += d
                ok = 1
            else:
                ok = 0
            self._frame(0x22, bytes([SPACECRAFT_ID, ok])
                        + struct.pack(">H", len(self.covert_q))
                        + bytes([self.pad_mode, 0, 0, 0]), clear=True)
        elif apid == 0x23:  # PAYLOAD_SNAP
            self._snap(d)
        elif apid == 0x24:  # HEATER
            if len(d) < 2:
                self._err("HEATER FORMAT")
                return
            if d[0] < 4:
                self.mm["heaters"][d[0]] = bool(d[1])
            self._frame(0x24, bytes([SPACECRAFT_ID, d[0], d[1]])
                        + struct.pack("<HHH", int(self.mm["pct"]) & 0xFF,
                                      int(self.mm["bus_v"] * 100),
                                      int(self.mm["power_w"] * 100))[:6]
                        + bytes([0, 0]), clear=True)
        elif apid == 0x25:  # DEFENSES_CONFIG
            self._defenses(d, via)
        elif apid == 0x26:  # LAB_STATUS -- full state blob (bench harness)
            self._lab_status()
        elif apid == 0x27:  # LAB_CTRL -- radio inject bridge / power cycle
            self._lab_ctrl(d, via)
        else:
            self._err("FDIR SUB?")

    def _lab_status(self):
        """Mirror of hLabStatus(): 53-byte cleartext state blob, LE."""
        st = 1 if self.secure else 0
        st |= 2 if self.usb_debug else 0
        st |= 4 if self.gs_mode else 0
        st |= 8 if self._gs_session_active() else 0
        st |= 16 if self.payload_armed else 0
        f2 = 1 if self.sdls_enabled else 0
        f2 |= 2 if self.arc_relaxed else 0
        f2 |= 4 if self.mm["detumble"] else 0
        f2 |= 8 if self.mm["eclipse"] else 0
        f2 |= 16 if self.mm["brownout"] else 0
        tm = bytes([SPACECRAFT_ID, 0, st, self.mode, self.pad_mode,
                    self.def_flags])
        tm += struct.pack("<H", self.gps["reject"] & 0xFFFF)
        tm += bytes([self.gps["sats"], 1 if self.gps["fix"] else 0])
        tm += struct.pack("<IIIf", self.boot_count, self.now_ms & 0xFFFFFFFF,
                          self.gs_challenge, self.mm["bus_v"])
        tm += self.flash["ota"]["hash"][:8]
        tm += bytes([self.flash["ota"]["pending_boot"]])
        tm += bytes([min(64, len(self.tcs["rssi"]))])
        tm += struct.pack("<I", self.arc_last)
        tm += bytes([f2, int(self.mm["pct"]) & 0xFF])
        tm += struct.pack("<ff", self.mm["power_w"], self.mm["tilt"])
        tm += bytes(3)
        assert len(tm) == 53, len(tm)
        self._frame(0x26, tm, clear=True)

    def _lab_ctrl(self, d, via):
        if via != "usb":
            self._err("LAB USB ONLY")
            return
        if len(d) < 1:
            self._err("LAB FORMAT")
            return
        sub = d[0]
        if sub == 1:  # INJECT a raw radio frame through the full pipeline
            if len(d) < 7:
                self._err("LAB INJ FORMAT")
                return
            if d[5] & 1:
                self._stats_ovr = ((int(d[1]) + 128) % 256 - 128,
                                   float(d[2]),
                                   float(struct.unpack("<h", d[3:5])[0]))
            else:
                self._stats_ovr = None
            self._frame(0x27, bytes([SPACECRAFT_ID, 1, len(d) - 7, 0x4B]),
                        clear=True)
            self._handle(d[7:], "radio")
        elif sub == 2:  # power cycle: scratch wiped, boot count restarts
            self.powercycle()
            self._frame(0x02, bytes([SPACECRAFT_ID, 0, 0, 0x42]), clear=True)
        elif sub == 3:  # soft reboot: scratch survives
            self._tm_resetc()
        else:
            self._err("LAB SUB?")

    # ------------------------------------------------- ext helpers
    def sdls_window(self):
        return 15 if self.arc_relaxed else self.arc_win

    # ---------------- memory service
    def _mem_read(self, addr, ln):
        if ln == 0 or ln > 200:
            return None
        end = addr + ln
        if not ((MRAM_BASE <= addr and end <= MRAM_END)
                or (XIP_BASE <= addr and end <= XIP_END)
                or (0x40000000 <= addr and end <= 0x40100000)
                or (0xE0000000 <= addr and end <= 0xE0100000)):
            return None
        out = bytearray()
        for a in range(addr, end):
            out.append(self._mem_byte(a))
        return bytes(out)

    def _mem_byte(self, addr):
        # named symbols with live values
        if SYM_GS_CHALLENGE <= addr < SYM_GS_CHALLENGE + 4:
            return (self.gs_challenge >> (8 * (addr - SYM_GS_CHALLENGE))) & 0xFF
        if SYM_SA0_KEY <= addr < SYM_SA0_KEY + 16:
            return self.sa[0]["key"][addr - SYM_SA0_KEY]
        if SYM_ARC_LAST <= addr < SYM_ARC_LAST + 4:
            return (self.arc_last >> (8 * (addr - SYM_ARC_LAST))) & 0xFF
        if SYM_LOG_NAME <= addr < SYM_LOG_NAME + 40:
            return self.log_name[addr - SYM_LOG_NAME]
        if SYM_MASTER_KEYS <= addr < SYM_MASTER_KEYS + 2048:
            return self.master_keys[(addr - SYM_MASTER_KEYS) // 16][(addr - SYM_MASTER_KEYS) % 16]
        if SYM_LEAK_POOL <= addr < SYM_LEAK_POOL + 256:
            return self.leak[addr - SYM_LEAK_POOL]
        if addr == ADDR_VTOR or (ADDR_VTOR + 1 <= addr < ADDR_VTOR + 4):
            return (self.vtor >> (8 * (addr - ADDR_VTOR))) & 0xFF
        if ADDR_WDT_SCRATCH <= addr < ADDR_WDT_SCRATCH + 32:
            idx = (addr - ADDR_WDT_SCRATCH) // 4
            return (self.scratch[idx] >> (8 * ((addr - ADDR_WDT_SCRATCH) % 4))) & 0xFF
        if XIP_BASE <= addr < XIP_END:
            off = addr - XIP_BASE
            return IMAGE_DATA[off % len(IMAGE_DATA)]
        if addr in self.ram:
            return self.ram[addr]
        h = hashlib.sha256(b"ram" + addr.to_bytes(4, "big")).digest()
        return h[0]

    def _mem_write(self, addr, val):
        self.ram[addr] = val
        if ADDR_VTOR <= addr < ADDR_VTOR + 4:
            shift = (addr - ADDR_VTOR) * 8
            self.vtor = ((self.vtor & ~(0xFF << shift)) | (val << shift)) \
                & 0xFFFFFFFF
            for name, a in SYMBOLS.items():
                if a == self.vtor:
                    self._rce(name)
        if ADDR_WDT_SCRATCH <= addr < ADDR_WDT_SCRATCH + 32:
            idx = (addr - ADDR_WDT_SCRATCH) // 4
            b = (addr - ADDR_WDT_SCRATCH) % 4
            self.scratch[idx] = (self.scratch[idx] & ~(0xFF << (8 * b))) \
                | (val << (8 * b))
        if ADDR_GPIO <= addr < ADDR_GPIO + 0x100:
            self.gps["kill"] = True

    def _mem_read_u32(self, addr):
        return struct.unpack("<I", bytes(self._mem_byte(a)
                                         for a in range(addr, addr + 4)))[0]

    def _mem_copy(self, src, dst, ln):
        if ln == 0 or ln > 200:
            return False
        if self._mem_read(src, ln) is None:
            return False
        end = dst + ln
        if not ((MRAM_BASE <= dst and end <= MRAM_END)
                or (0x40000000 <= dst and end <= 0x40100000)
                or (0xE0000000 <= dst and end <= 0xE0100000)):
            return False
        data = self._mem_read(src, ln)
        for i, b in enumerate(data):
            self._mem_write(dst + i, b)
        return True

    def _rce(self, name):
        tm = bytes([SPACECRAFT_ID, 1, 0, 0]) + b"RCE\x00"
        if name == "labFnDetumble":
            self.mm["detumble"] = True
        elif name == "labFnGsModeOff":
            self.gs_mode = False
            self.gs_session = False
        elif name == "labFnBeaconFlood":
            self.beacon_interval = 0
            self.beacon_changed = True
        elif name == "labFnSecureLinkOff":
            self.secure = False
        self._frame(0x18, tm, clear=True)

    # ---------------- V-13 overflow
    def _set_log_name(self, name: bytes):
        i = 0
        while i < 250:
            b = name[i] if i < len(name) else 0
            if i < 32:
                self.log_name[i] = b
            else:
                off = i - 32
                if off == 0:
                    self.usb_debug = b != 0
                elif off == 1:
                    self.secure = b != 0
                elif off == 2:
                    self.gs_mode = b != 0
                    if not b:
                        self.gs_session = False
                elif off == 3:
                    self.payload_armed = b != 0
            i += 1
            if b == 0:
                break

    # ---------------- SB
    def _sb_publish(self, mid, data, src):
        if self.sb_auth:
            if len(data) < 4 or data[:4] != b"\xc0\xfe\xee\x11":
                return 0
            data = data[4:]
        self.sb_stats[mid] = dict(count=self.sb_stats.get(mid, {}).get("count", 0) + 1,
                                  src=src, last=data[:32])
        if mid == 0x102 and len(data) >= 6:
            rx, ry, rz = struct.unpack("<hhh", data[:6])
            self.mm["rate"] = [rx / 100.0, ry / 100.0, rz / 100.0]
        elif mid == 0x103 and len(data) >= 1:
            self.sensor_mask = data[0]
        elif mid == 0x104 and len(data) >= 2 and data[0] < 4:
            self.mm["heaters"][data[0]] = bool(data[1])
        elif mid == 0x105 and len(data) >= 1:
            self.mm["pct"] = float(data[0])
            self.mm["bus_v"] = 21.0 + 3.0 * data[0] / 100.0
        elif mid == 0x106 and len(data) >= 2:
            self.t_thr = [data[0], data[1]]
        return 1

    # ---------------- SpaceCAN
    def _sc(self, d):
        if len(d) < 1:
            self._err("SC FORMAT")
            return
        mode = d[0]
        status = 0
        if mode == 0 and len(d) >= 6:
            cid = struct.unpack(">I", d[1:5])[0]
            dlc = d[5]
            data = d[6:6 + dlc]
            status = self._sc_dispatch(cid, dlc, data)
        elif mode == 1:
            n = d[1] if len(d) > 1 else 32
            for _ in range(max(1, n)):
                self._sc_track()
            status = 1 if self.sc["congested"] else 0
        elif mode == 4:
            # reassembly overflow: 43 fragments of 6 -> offset 42*6+6=258
            status = 1
            self.sc["reasm_corrupt"] = True
        elif mode == 3 and len(d) >= 6:
            nid = struct.unpack(">I", d[1:5])[0] & 0x7F
            if nid in self.sc["nodes"]:
                self.sc["nodes"][nid].update(err=0, off=False)
                status = 1
        mask = 0
        if self.sc["nodes"][0x04]["off"]:
            mask |= 1
        if self.sc["nodes"][0x07]["off"]:
            mask |= 2
        if self.sc["nodes"][0x01]["off"]:
            mask |= 4
        err = max((n["err"] for n in self.sc["nodes"].values()), default=0)
        self.sc["last_err"] = err
        self._frame(0x1C, bytes([SPACECRAFT_ID, mode, status, mask,
                                 1 if self.sc["congested"] else 0,
                                 err & 0xFF, err >> 8, 0]), clear=True)

    def _sc_track(self):
        self.sc["frames_ts"].append(self.now_ms)
        self.sc["frames_ts"] = [t for t in self.sc["frames_ts"]
                                if self.now_ms - t <= 1000][-5:]
        if len(self.sc["frames_ts"]) >= 5:
            self.sc["congested"] = True

    def _sc_dispatch(self, cid, dlc, data):
        self._sc_track()
        func = cid & 0x780
        nid = cid & 0x7F
        if func != 0x280:
            return 0
        node = self.sc["nodes"].get(nid)
        if node is None:
            return 0
        if node["off"]:
            return 2
        if dlc < 2 or (len(data) >= 1 and data[0] != 0x01):
            node["err"] = min(256, node["err"] + 8)
            if node["err"] >= 256:
                node["off"] = True
            return 1
        node["err"] = 0
        pw = data[1] if len(data) > 1 else 0
        if nid == 0x04:
            self.t_thr[0] = pw
            self.mm["rate"][0] += 0.3 * pw / 255.0
        elif nid == 0x07:
            self.sc["charge"] = pw
            self.mm["pct"] = float(pw)
            self.mm["bus_v"] = 21.0 + 3.0 * pw / 100.0
        return 1

    # ---------------- FDIR
    def _safe_enter(self, cause):
        self.fdir_safe = True
        self.fdir_entry = self.now_ms
        self.fdir_triggers += 1
        self.fdir_cause = cause
        self.mode = 0x00
        self.t_thr = [0, 0]
        self.arc_relaxed = True
        self.secure = False
        # contingency dictionary (V-20): flash-resident, tamperable
        for e in self.flash["fdict"]:
            if e["apid"]:
                self._dispatch(e["apid"], e["payload"], "internal")

    def _safe_exit(self):
        if not self.fdir_safe:
            return False, "NOT SAFE"
        if self.now_ms - self.fdir_entry < FDIR_RELEASE_MS:
            return False, "RELEASE WINDOW"
        if self.mm["tilt"] > FDIR_TILT or self.mm["bus_v"] < FDIR_BUS_SAFE_V:
            return False, "TRIGGER ACTIVE"
        self.fdir_safe = False
        self.arc_relaxed = False
        self.mode = 0x01
        return True, ""

    def _fdir_cfg(self, d):
        if len(d) < 1:
            self._err("FDIR FORMAT")
            return
        sub = d[0]
        mm = self.mm
        if sub == 0:
            tm = bytes([SPACECRAFT_ID, 0, self.fdir_safe, self.fdir_armed])
            tm += struct.pack(">I", self.fdir_triggers)
            tm += struct.pack("<HHH", int(min(0xFFFF, mm["tilt"] * 100)),
                              int(mm["bus_v"] * 100), int(mm["power_w"] * 100))
            tm += bytes([mm["eclipse"], self.anom_alarm, self.anom_last_ch])
            tm += bytes([int(min(255, self.orbit_s))])
            self._frame(0x1D, tm, clear=True)
        elif sub == 1 and len(d) >= 2:
            self.fdir_armed = bool(d[1])
            self._frame(0x1D, bytes([SPACECRAFT_ID, 1, d[1], 0]), clear=True)
        elif sub == 2:
            if not self.fdir_safe and self.fdir_armed:
                self._safe_enter("REMOTE")
            self._frame(0x1D, bytes([SPACECRAFT_ID, 2, self.fdir_safe, 0]),
                        clear=True)
        elif sub == 3:
            ok, why = self._safe_exit()
            self._frame(0x1D, bytes([SPACECRAFT_ID, 3, ok, 0]), clear=True)
            if not ok and why:
                self._err(why)
        elif sub == 4:
            self.anom_alarm = False
            self._frame(0x1D, bytes([SPACECRAFT_ID, 4,
                                     1 if self.def_flags & DEF_ANOMALY_EN else 0,
                                     self.anom_alarm]), clear=True)
        elif sub == 5 and len(d) >= 5:
            idx = d[1]
            fapid = struct.unpack(">H", d[2:4])[0]
            ln = d[4]
            ok = self._fdict_set(idx, fapid, d[5:5 + ln])
            self._frame(0x1D, bytes([SPACECRAFT_ID, 5, idx, ok,
                                     self.flash["fdict_locked"], 0]),
                        clear=True)
        elif sub == 6:
            idx = d[1] if len(d) > 1 else 0
            e = self.flash["fdict"][idx]
            if e["apid"]:
                self._frame(0x1D, bytes([SPACECRAFT_ID, 6, e["apid"] >> 8,
                                         e["apid"] & 0xFF, e["payload"][0] if e["payload"] else 0])
                            + e["payload"], clear=True)
            else:
                self._err("FDICT IDX")
        elif sub == 7:
            blob = b"".join(bytes([e["apid"] >> 8, e["apid"] & 0xFF]) + e["payload"]
                            for e in self.flash["fdict"] if e["apid"])
            self.flash["fdict_hash"] = fnv_digest(blob)
            self.flash["fdict_locked"] = True
            self._frame(0x1D, bytes([SPACECRAFT_ID, 7, 1])
                        + self.flash["fdict_hash"]
                        + bytes([1]), clear=True)
        elif sub == 8 and len(d) >= 2:
            z = d[1] / 10.0
            if 2.5 <= z <= 10.0:
                self.anom_z = z
                self.flash["anom_z"] = z
            self._frame(0x1D, bytes([SPACECRAFT_ID, 8, d[1], 0]), clear=True)
        elif sub == 9 and len(d) >= 2:
            self.mm["detumble"] = bool(d[1])
            self._frame(0x1D, bytes([SPACECRAFT_ID, 9, d[1], 0]), clear=True)
        elif sub == 10 and len(d) >= 3:
            self.time_scale = struct.unpack(">H", d[1:3])[0] / 10.0
            self._frame(0x1D, bytes([SPACECRAFT_ID, 10]) + d[1:3], clear=True)
        elif sub == 11:
            # FDICT factory reset (harness prologue, V-20 bench parity):
            # the burned hash lock is flash-persisted and has no wire
            # unlock (the burned lock IS the V-20 finding), so the
            # prologue restores the cold-boot reference after every PoC:
            # default table, hash wiped, lock released.
            self.flash["fdict"] = [
                {"apid": 0x04, "payload": bytes([0, 0, 0])},
                {"apid": 0x05, "payload": bytes([10, 0])},
            ] + [{"apid": None, "payload": b""} for _ in range(6)]
            self.flash["fdict_hash"] = bytes(8)
            self.flash["fdict_locked"] = False
            self._frame(0x1D, bytes([SPACECRAFT_ID, 11, 1, 0]), clear=True)
        else:
            self._err("FDIR SUB?")

    def _fdict_set(self, idx, fapid, payload):
        if self.flash["fdict_locked"]:
            return 0
        self.flash["fdict"][idx] = dict(apid=fapid, payload=payload)
        return 1

    # ---------------- sched (V-19)
    def _sched_cmd(self, d):
        if len(d) < 1:
            self._err("SCHED FORMAT")
            return
        sub = d[0]
        if sub == 0 and len(d) >= 8:
            every = struct.unpack(">I", d[1:5])[0]
            sapid = struct.unpack(">H", d[5:7])[0]
            ln = d[7]
            ok = 0
            if len(self.flash["sched"]) < 16 and ln <= 64:
                self.flash["sched"].append(dict(
                    every=every, apid=sapid, payload=d[8:8 + ln],
                    due=self.now_ms // 1000 + (every if every else 1)))
                ok = 1
            self._frame(0x1E, bytes([SPACECRAFT_ID, 0, ok,
                                     len(self.flash["sched"]),
                                     1 if self.flash["sched"] else 0, 0]),
                        clear=True)
        elif sub == 1:
            self.flash["sched"] = []
            self._frame(0x1E, bytes([SPACECRAFT_ID, 1, 1, 0, 0]), clear=True)
        elif sub == 2:
            tm = bytes([SPACECRAFT_ID, 2, len(self.flash["sched"])])
            for e in self.flash["sched"]:
                tm += struct.pack("<H", e["every"] & 0xFFFF)
                tm += bytes([e["apid"] >> 8, e["apid"] & 0xFF, len(e["payload"])])
            self._frame(0x1E, tm, clear=True)
        else:
            self._err("SCHED SUB?")

    def _sched_due(self):
        now_s = self.now_ms // 1000
        done = []
        for idx, e in enumerate(self.flash["sched"]):
            if e.get("done"):
                continue
            if now_s >= e["due"]:
                self._dispatch(e["apid"], e["payload"], "internal")
                if e["every"]:
                    e["due"] = now_s + e["every"]
                else:
                    e["done"] = True

    # ---------------- OTA (V-18/V-38)
    def _ota_cmd(self, d):
        if len(d) < 1:
            self._err("OTA FORMAT")
            return
        ota = self.flash["ota"]
        sub = d[0]
        if sub == 0 and len(d) >= 8:
            off = struct.unpack(">I", d[1:5])[0]
            ln = d[5]
            crc = struct.unpack(">H", d[6:8])[0]
            data = d[8:8 + ln]
            ok = 0
            if ln and crc16_ccitt(data) == crc:
                if off == 0:
                    ota["_acc"] = b""
                ota["_acc"] = ota.get("_acc", b"") + data
                ok = 1
            self._frame(0x1F, bytes([SPACECRAFT_ID, 0, ok, 0, 0]), clear=True)
        elif sub == 1:
            blob = ota.get("_acc", b"")
            ota["hash"] = fnv_digest(blob)
            ota["size"] = len(blob)
            ok = 1
            if ota["sig_required"] and ota["hash"] != ota["sig"]:
                ok = 0
            if ok:
                ota["pending_boot"] = 1
                ota["boot_try"] = 0
            self._frame(0x1F, bytes([SPACECRAFT_ID, 1, ok, 0]), clear=True)
        elif sub == 2:
            ok = 0
            if ota["booted_slot"] == 1:
                ota.update(boot_try=0, pending_boot=0, active_slot=1)
                ok = 1
            self._frame(0x1F, bytes([SPACECRAFT_ID, 2, ok, 0]), clear=True)
        elif sub == 3:
            tm = bytes([SPACECRAFT_ID, 3, ota["active_slot"], ota["pending_boot"],
                        ota["boot_try"], ota["booted_slot"]])
            tm += struct.pack(">I", ota["arwc"])
            tm += bytes([ota["arwc_enforce"], ota["sig_required"]])
            tm += ota["sig"] + ota["hash"]
            tm += struct.pack(">I", ota["size"])
            self._frame(0x1F, tm, clear=True)
        elif sub == 4 and len(d) >= 5:
            ota["arwc"] = struct.unpack(">I", d[1:5])[0]
            self._frame(0x1F, bytes([SPACECRAFT_ID, 4, 1, 0]), clear=True)
        elif sub == 5:
            ota.update(active_slot=0, pending_boot=0, boot_try=0,
                       booted_slot=0)
            self._frame(0x1F, bytes([SPACECRAFT_ID, 5, 1, 0]), clear=True)
        elif sub == 6 and len(d) >= 14:
            ota["sig"] = d[1:9]
            ota["arwc"] = struct.unpack(">I", d[9:13])[0]
            ota["sig_required"] = 1 if d[13] else 0
            self._frame(0x1F, bytes([SPACECRAFT_ID, 6, 1, 0]), clear=True)
        elif sub == 7 and len(d) >= 2:
            ota["arwc_enforce"] = 1 if d[1] else 0
            self._frame(0x1F, bytes([SPACECRAFT_ID, 7, ota["arwc_enforce"], 0]),
                        clear=True)
        else:
            self._err("OTA SUB?")

    # ---------------- snap (V-31)
    def _snap(self, d):
        if len(d) < 1:
            self._err("SNAP FORMAT")
            return
        sub = d[0]
        if sub == 1:
            if len(d) < 2:
                self._err("SNAP FORMAT")
                return
            self.vcc_frozen = bool(d[1])
            self._frame(0x23, bytes([SPACECRAFT_ID, 1, self.vcc_frozen])
                        + struct.pack(">H", self.vcc), clear=True)
            return
        if sub == 2:
            take = bytes(self.covert_q[:64])
            del self.covert_q[:len(take)]
            self._frame(0x23, bytes([SPACECRAFT_ID, 2, len(take)]) + take,
                        clear=True)
            return
        img = bytearray(32)
        img[0:4] = b"IMG1"
        struct.pack_into("<I", img, 4, self.now_ms & 0xFFFFFFFF)
        import math
        t = 25.0 + 0.5 * math.sin(self.now_ms / 50000.0)
        struct.pack_into("<h", img, 8, int(t * 100))
        struct.pack_into("<H", img, 10, int(1013.0 * 10))
        struct.pack_into("<h", img, 12, int(620.0 * 10))
        struct.pack_into("<H", img, 14, int(45.0 * 100))
        struct.pack_into("<H", img, 16, int(min(0xFFFF, self.mm["tilt"] * 100)))
        struct.pack_into("<H", img, 18, int(self.mm["bus_v"] * 100))
        img[20] = int(self.mm["pct"])
        struct.pack_into("<H", img, 21, self.tm_counter)
        struct.pack_into("<H", img, 23, self.vcc)
        img[25] = self.mm["eclipse"]
        img[26] = self.fdir_safe
        img[27:30] = b"PWN"
        struct.pack_into("<H", img, 30, int(self.mm["power_w"] * 100))
        if not self.vcc_frozen:
            self.vcc += 1
        self.covert_q += bytes(img)
        self._frame(0x23, bytes([SPACECRAFT_ID, 0, self.vcc_frozen]) + bytes(img),
                    clear=True)

    # ---------------- defenses
    def _defenses(self, d, via):
        if len(d) < 1:
            self._err("DEF FORMAT")
            return
        sub = d[0]
        if sub == 0 and len(d) >= 2:
            self.def_flags = d[1]
            self.flash["tclog_enabled"] = bool(d[1] & DEF_LOG_ENABLE)
            self._frame(0x25, bytes([SPACECRAFT_ID, 0, self.def_flags, 0]),
                        clear=True)
        elif sub == 1:
            self._frame(0x25, bytes([SPACECRAFT_ID, 1, self.def_flags,
                                     len(self.flash["tclog"]) & 0xFF,
                                     self.flash["tclog_evicted"] >> 8,
                                     self.flash["tclog_evicted"] & 0xFF]),
                        clear=True)
        elif sub == 2 and len(d) >= 4:
            start = struct.unpack(">H", d[1:3])[0]
            cnt = d[3]
            tm = bytes([SPACECRAFT_ID, 2, len(self.flash["tclog"]) & 0xFF, 0])
            got = 0
            for i in range(cnt):
                if start + i >= len(self.flash["tclog"]):
                    break
                e = self.flash["tclog"][start + i]
                tm += struct.pack("<I", e["ms"]) + bytes(
                    [e["apid"] >> 8, e["apid"] & 0xFF, e["seq"] >> 8,
                     e["seq"] & 0xFF, len(e["payload"])]) + e["payload"]
                got += 1
            tm = tm[:3] + bytes([got]) + tm[4:]
            self._frame(0x25, tm, clear=True)
        elif sub == 3:
            self.def_flags = DEF_ANOMALY_EN
            self.flash["tclog_enabled"] = False
            self._frame(0x25, bytes([SPACECRAFT_ID, 3, self.def_flags, 0]),
                        clear=True)
        elif sub == 4 and len(d) >= 2:
            self.sb_auth = bool(d[1])
            self._frame(0x25, bytes([SPACECRAFT_ID, 4, self.sb_auth, 0]),
                        clear=True)
        else:
            self._err("DEF SUB?")

    # ---------------- anomaly
    def _feed_anomaly(self):
        if not (self.def_flags & DEF_ANOMALY_EN):
            return
        vals = [self.mm["tilt"], float(self.tc_seen), self.mm["power_w"],
                self.mm["bus_v"] * 100]
        self.tc_seen = 0
        for ch, x in enumerate(vals):
            e = self.anom[ch]
            if e is None:
                self.anom[ch] = {"mu": x, "var": 0.0}
                continue
            diff = x - e["mu"]
            e["mu"] += 0.05 * diff
            e["var"] = 0.95 * (e["var"] + 0.05 * diff * diff)
            resid = x - e["mu"]
            sigma = e["var"] ** 0.5
            if sigma > 1e-6 and abs(resid) > self.anom_z * sigma:
                self.anom_alarm = True
                self.anom_last_ch = ch


# --------------------------------------------------------------------------
# self test
# --------------------------------------------------------------------------
def _selftest():
    ok = True
    # FIPS-197 B.1 / F.1.11
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = aes_ecb_encrypt(key, pt)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()
    assert aes_ecb_decrypt(key, ct) == pt
    # SP800-38B CMAC AES-128 K=2b7e151628aed2a6abf7158809cf4f3c
    ck = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert cmac(ck, b"").hex() == "bb1d6929e95937287fa37d129b756746"
    m1 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    assert cmac(ck, m1).hex() == "070a16b46b4d4144f79bdd9dd04a287c"
    m2 = m1 + bytes.fromhex("ae2d9a571c09ac546bc4ab040d451199")
    # cross-checked against `cryptography` CMAC (len 0/16/32/46/64)
    m46 = (m1 * 3)[:46]
    m64 = m1 * 4
    assert cmac(ck, m2).hex() == "930049e4703915d522be4c7ced4c7365"
    assert cmac(ck, m46).hex() == "a3817191d90a6225bbb2b6d587b94045"
    assert cmac(ck, m64).hex() == "a2b582856129faeb7108b4725081a7f4"
    # SP800-38A CTR-AES128 vector 1
    ctr_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    ctr0 = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    pt1 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a") + \
        bytes.fromhex("ae2d9a571c09ac546bc4ab040d451199")
    assert ctr_xor(ctr_key, ctr0, pt1) == bytes.fromhex(
        "874d6191b620e3261bef6864990db6ce9806e66b7b7afd377364dcd3f1156237")
    # secure-link encode/decode roundtrip
    sim = FlatSatSim()
    enc = sim.sl_encode(b"STATUS\x00")
    assert sim.sl_decode(enc) == b"STATUS\x00"
    # SDLS: SA table default state per the course numbers
    assert sum(1 for sa in sim.sa if sa["ast"] == 0) == 43
    assert sim.sa[44]["ast"] == 0 and sim.sa[44]["est"] == 0
    # OTAR null master key installs attacker key
    attacker_key = bytes(range(16))
    ct = aes_ecb_encrypt(bytes(16), attacker_key)
    # secure-link is ON by default: radio TCs travel ECB-wrapped under the
    # hardcoded link key (the baseline V0-02 premise)
    body = sim.sl_encode(bytes([0, 64, 0]) + ct)
    frames = sim.send(spp_pack(0x16, body, 1), via="radio")
    # extension TMs go out cleartext (force_cleartext), like the firmware
    body_out = spp_unpack(frames[0][1:])["data"]
    assert body_out[:2] == bytes([SPACECRAFT_ID, 0]) and body_out[2] == 1
    assert sim.sa[0]["key"] == attacker_key
    print("SELFTEST OK: FIPS-197 ECB, SP800-38A CTR, SP800-38B CMAC, "
          "secure-link, SDLS 43/64 null SAs, null-master-key OTAR")
    return ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json-state", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        _selftest()
    if args.json_state:
        print(json.dumps(FlatSatSim().flash, indent=2, default=str))
