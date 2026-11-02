#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
harness.py -- browser instrumentation for the flatsat-electr0sm0g lab demo.

This module is INJECTED into the Pyodide MEMFS (written by tools/build_web_demo.py,
never modified at runtime) and imported by web/worker.js after the real repo
sources have been written to /repo/ with the exact repository layout:

    /repo/simulator/flatsat_sim.py   (unmodified)
    /repo/poc/lib/fslab.py           (unmodified)
    /repo/poc/vNNN_*.py              (56 unmodified PoCs)
    /repo/web/harness.py             (this file)

It monkey-patches three call sites -- flatSatSim.send (one host->device SPP
exchange: TC on the wire + every TM the device emits), FlatSatSim.advance
(mission-time ticks) and fslab.Evidence.log (the evidence transcript) -- so the
UI can render the real protocol stream and the real spacecraft state while the
UNMODIFIED PoC code drives the UNMODIFIED simulator, exactly like the CI sweep:

    runpy.run_path(poc, run_name="__main__")   with  sys.argv=[poc, "--no-save"]

After each PoC, the captured transcript (evidence lines only) is normalised
(wall-clock "[  1.234]" prefixes stripped) and md5-hashed; the build script
embeds the same digest of the committed evidence/<poc>.txt, so a match proves
the browser run reproduced the committed evidence byte-for-byte (modulo
timestamps).

Events are pushed to the host page via the worker global  __emit(json_string)
set by web/worker.js  (see web/app.js for the event schema).
"""
from __future__ import annotations

import builtins
import contextlib
import hashlib
import io
import json
import math
import re
import runpy
import sys
import time
import traceback

REPO = "/repo"
if REPO + "/simulator" not in sys.path:
    sys.path.insert(0, REPO + "/simulator")
if REPO + "/poc/lib" not in sys.path:
    sys.path.insert(0, REPO + "/poc/lib")

import flatsat_sim as fs  # noqa: E402
import fslab  # noqa: E402

LINK_KEY = fs.LINK_KEY
TS_RE = re.compile(r"^\[\s*\d+\.\d{3}\] (.*)$")


def _js_safe(obj):
    """Recursively map non-finite floats to None. Python's json module would
    otherwise emit bare NaN/Infinity tokens (invalid JSON) and the worker's
    JSON.parse would silently drop the whole event."""
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    if isinstance(obj, dict):
        return {k: _js_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_js_safe(v) for v in obj]
    return obj


def _capture_emit():
    """Resolve the worker->page emitter. web/worker.js stores it in the
    builtins namespace during init (builtins.__worker_emit, taken from the
    `import js` context that worker.js controls); fall back to a fresh
    `import js` if the module was imported standalone (host tests)."""
    fn = getattr(builtins, "__worker_emit", None)
    if fn is not None:
        return fn
    try:
        import js  # type: ignore
        return js.__emit
    except Exception:
        return None


_EMIT = _capture_emit()

# APID -> human name (mirrors FlatSatSim._dispatch / _ext in
# simulator/flatsat_sim.py; unknown APIDs fall back to the raw hex).
APID_NAMES = {
    0x01: "PING/BEACON", 0x02: "RESETC", 0x03: "SEND_FW", 0x04: "SET_THRUSTER",
    0x05: "SET_BEACON_RATE", 0x06: "BROADCAST_MSG", 0x07: "FLASH_DUMP",
    0x08: "SENSORS", 0x09: "ERROR", 0x0A: "AES_CONFIG", 0x0B: "FLASH_READ",
    0x0C: "GET_STATUS", 0x0D: "SET_MISSION_MODE", 0x0E: "GET_NAV",
    0x0F: "PWN_STATUS", 0x10: "USB_DEBUG", 0x11: "GS_MODE", 0x12: "GS_ACCESS",
    0x13: "GS_STATUS", 0x14: "GPS_OVERRIDE", 0x15: "SDLS_CONFIG",
    0x16: "SDLS_OTA", 0x17: "KEY_VERIFY", 0x18: "MEMCPY", 0x19: "MEM_READ",
    0x1A: "SET_LOG_NAME", 0x1B: "SB_PUBLISH", 0x1C: "SC_INJECT",
    0x1D: "FDIR_CONFIG", 0x1E: "SCHED", 0x1F: "OTA", 0x20: "TC_STATS",
    0x21: "PADDING_CONFIG", 0x22: "COVERT_ENQ", 0x23: "PAYLOAD_SNAP",
    0x24: "HEATER", 0x25: "DEFENSES_CONFIG", 0x26: "LAB_STATUS",
    0x27: "LAB_CTRL", 0x3FF: "IDLE_BEACON",
}


def _apid_name(apid: int) -> str:
    if 0xF0 <= apid <= 0xFF:
        return "TESTMODE"
    return APID_NAMES.get(apid, "")


class Bus:
    """Event queue + per-run transcript capture."""

    def __init__(self) -> None:
        self.q: list[dict] = []
        self.running = False            # inside run_poc()
        self.evidence: list[str] = []   # evidence lines of the current run
        self.fno = 0                    # frame counter (per run)
        self.sim = None                 # most recently seen FlatSatSim
        self._last_snap_ms = -10 ** 9
        self._last_state = None
        self._out_partial = ""
        self.last_err = None            # last emission failure (diagnostics)
        self.orbit = False              # inside run_orbit(): free-flight mode,
                                        # the wire-tap frame events are suppressed
                                        # (state snapshots / orbit_state still flow)

    # -- event sink -------------------------------------------------------
    def emit(self, t: str, **kw) -> None:
        ev = {"t": t}
        ev.update(kw)
        self.q.append(ev)
        if _EMIT is None:
            return
        try:
            _EMIT(json.dumps(_js_safe(ev), separators=(",", ":")))
            self.last_err = None
        except Exception:
            # a delivery hiccup must never crash a PoC mid-run; the event
            # stays in q (drainable) and the failure is recorded
            self.last_err = traceback.format_exc()

    def drain(self) -> list[dict]:
        q, self.q = self.q, []
        return q

    # -- stdout capture (PoC-level prints, e.g. the final "POC OK") -------
    def out_write(self, s: str) -> None:
        if not s:
            return
        self._out_partial += s
        while "\n" in self._out_partial:
            ln, self._out_partial = self._out_partial.split("\n", 1)
            if self.running and ln:
                self.emit("line", text=ln, ev=False)

    def out_flush(self) -> None:
        if self.running and self._out_partial:
            self.emit("line", text=self._out_partial, ev=False)
        self._out_partial = ""


BUS = Bus()

_ORIG_EV_LOG = fslab.Evidence.log
_ORIG_PRINT = builtins.print


class _Sink(io.TextIOBase):
    """sys.stdout during a PoC run: lines become console events, nothing
    leaks into the worker's own console."""

    def write(self, s: str) -> int:
        if s:
            BUS.out_write(s)
        return len(s)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


# --------------------------------------------------------------------------
# wire taps
# --------------------------------------------------------------------------
def _tm_decode(sim: "fs.FlatSatSim", raw: bytes) -> dict:
    """One device->host frame as the UI sees it. Mirrors fslab.Device._decode
    exactly (0xAA strip, spp_unpack incl. the off-by-one, ECB unwrap when the
    secure-link shadow says so)."""
    body = raw[1:] if raw[:1] == b"\xAA" else raw
    pkt = fs.spp_unpack(body)
    if pkt is None:
        return {"wire": raw.hex(), "bad": True}
    data = pkt["data"]
    plain = None
    pmode = ""
    if (sim.secure and not sim.usb_debug and len(data) % 16 == 0 and data):
        # mirror _frame()'s TM policy exactly: CTR keystream when the
        # DEF_TM_CTR defense bit is set, otherwise the ECB link wrap
        if sim.def_flags & fs.DEF_TM_CTR and sim.sa:
            ctr = bytes(12) + (pkt["seq"] & 0xFFFFFFFF).to_bytes(4, "big")
            body = fs.ctr_xor(sim.sa[0]["key"], ctr, data)
            plen = int.from_bytes(body[:2], "big")
            if plen <= len(data) - 2 and plen <= 200:
                plain, pmode = body[2:2 + plen], "ctr"
        if plain is None:
            plain = fs.sl_decode_key(LINK_KEY, data)
            if plain is not None:
                pmode = "ecb"
    return {
        "wire": raw.hex(),
        "apid": pkt["apid"], "apid_name": _apid_name(pkt["apid"]),
        "seq": pkt["seq"], "flags": pkt["flags"],
        "ptype": pkt["type"], "sechdr": pkt["sechdr"], "len": pkt["len"],
        "wrapped": plain is not None, "pmode": pmode,
        "plain": (plain.hex() if plain is not None else None),
    }


_ORIG_SEND = fs.FlatSatSim.send
_ORIG_ADVANCE = fs.FlatSatSim.advance


def _send_tap(self: "fs.FlatSatSim", raw: bytes, via: str = "radio"):
    BUS.sim = self
    BUS.fno += 1
    pkt = fs.spp_unpack(raw)
    if pkt is not None and not BUS.orbit:
        tc_plain = None
        if self.secure and not (via == "usb" and self.usb_debug):
            tc_plain = self.sl_decode(pkt["data"])
        BUS.emit(
            "frame", dir="tc", fno=BUS.fno, t_ms=self.now_ms, via=via,
            apid=pkt["apid"], apid_name=_apid_name(pkt["apid"]),
            seq=pkt["seq"], flags=pkt["flags"], ptype=pkt["type"],
            sechdr=pkt["sechdr"], len=pkt["len"], wire=raw.hex(),
            wrapped=tc_plain is not None,
            plain=(tc_plain.hex() if tc_plain is not None else None),
        )
    out = _ORIG_SEND(self, raw, via)
    if BUS.running and not BUS.orbit:
        for fr in out:
            BUS.fno += 1
            d = _tm_decode(self, fr)
            d.update(t_ms=self.now_ms, fno=BUS.fno)
            BUS.emit("frame", dir="tm", **d)
    _snap(self, force=True)
    return out


def _advance_tap(self: "fs.FlatSatSim", ms: int):
    BUS.sim = self
    out = _ORIG_ADVANCE(self, ms)
    if BUS.running and not BUS.orbit:
        for fr in out:
            BUS.fno += 1
            d = _tm_decode(self, fr)
            d.update(t_ms=self.now_ms, fno=BUS.fno)
            BUS.emit("frame", dir="tm", **d)
    _snap(self, force=(self.state != BUS._last_state))
    return out


# --------------------------------------------------------------------------
# state snapshot (everything introspectable on FlatSatSim)
# --------------------------------------------------------------------------
def _h(b: bytes, n: int = 8) -> str:
    return bytes(b[:n]).hex()


def _snap(sim: "fs.FlatSatSim", force: bool = False) -> None:
    if not BUS.running:
        return
    st = sim.state
    if not force and st == BUS._last_state \
            and sim.now_ms - BUS._last_snap_ms < 1000:
        return
    BUS._last_snap_ms = sim.now_ms
    BUS._last_state = st
    ota = sim.flash["ota"]
    nav = sim._gps_nav()
    try:
        dist = sim._gs_dist_m(nav)
    except Exception:
        dist = -1.0
    sa_null = sum(1 for sa in sim.sa if sa["ast"] == 0)
    BUS.emit("state", t_ms=sim.now_ms, s={
        "state": st, "mode": sim.mode, "boot_count": sim.boot_count,
        "secure": sim.secure, "usb_debug": sim.usb_debug,
        "payload_armed": sim.payload_armed, "persist_cookie": sim.persist_cookie,
        "tm_counter": sim.tm_counter, "tc_counter": sim.tc_counter,
        "def_flags": sim.def_flags, "vtor": sim.vtor,
        "time_scale": sim.time_scale, "orbit_s": sim.orbit_s,
        "gs": {
            "mode": sim.gs_mode, "session": sim._gs_session_active(),
            "session_ttl_s": max(0, (sim.gs_session_exp - sim.now_ms + 999)
                                  // 1000) if sim.gs_session else 0,
            "pending": sim._gs_pending_active(),
            "pending_ttl_s": max(0, (sim.gs_challenge_exp - sim.now_ms + 999)
                                  // 1000) if sim.gs_pending else 0,
            "challenge": sim.gs_challenge,
            "dist_m": dist, "gate": sim._gs_gate_open(nav),
            "status": sim._gs_status_byte(nav),
        },
        "gps": {
            "fix": nav["fix"], "kill": sim.gps["kill"], "ovr": sim.gps["ovr"],
            "sats": nav["sats"], "lat": nav["lat"], "lon": nav["lon"],
            "alt_cm": nav["alt_cm"], "reject": sim.gps["reject"],
            "status": sim._gps_status_byte(nav),
        },
        "sdls": {
            "enabled": sim.sdls_enabled, "arc_bits": sim.arc_bits,
            "arc_win": sim.arc_win, "relaxed": sim.arc_relaxed,
            "arc_last": sim.arc_last, "null_sas": sa_null,
            "sa0_key": _h(sim.sa[0]["key"], 4) + "…",
        },
        "fdir": {
            "armed": sim.fdir_armed, "safe": sim.fdir_safe,
            "cause": sim.fdir_cause, "triggers": sim.fdir_triggers,
            "entry": sim.fdir_entry,
        },
        "mm": {
            "rate": [round(x, 4) for x in sim.mm["rate"]],
            "euler": [round(x, 3) for x in sim.mm["euler"]],
            "tilt": round(sim.mm["tilt"], 4), "detumble": sim.mm["detumble"],
            "bus_v": round(sim.mm["bus_v"], 3), "pct": round(sim.mm["pct"], 2),
            "heaters": list(sim.mm["heaters"]), "eclipse": sim.mm["eclipse"],
            "power_w": round(sim.mm["power_w"], 2),
            "brownout": sim.mm["brownout"], "t_thr": list(sim.t_thr),
        },
        "flash": {
            "active_slot": ota["active_slot"], "pending_boot": ota["pending_boot"],
            "boot_try": ota["boot_try"], "booted_slot": ota["booted_slot"],
            "arwc": ota["arwc"], "arwc_enforce": ota["arwc_enforce"],
            "sig_required": ota["sig_required"], "size": ota["size"],
            "sig": _h(ota["sig"]), "hash": _h(ota["hash"]),
            "sched_n": len(sim.flash["sched"]),
            "sched": [
                {"every": e["every"], "apid": e["apid"],
                 "ln": len(e["payload"]), "done": bool(e.get("done"))}
                for e in sim.flash["sched"][:16]
            ],
            "tclog_n": len(sim.flash["tclog"]),
            "tclog_enabled": sim.flash["tclog_enabled"],
            "tclog_evicted": sim.flash["tclog_evicted"],
            "fdict_locked": sim.flash["fdict_locked"],
            "fdict_hash": _h(sim.flash["fdict_hash"]),
        },
        "scratch": list(sim.scratch),
        "sc": {
            "nodes": {
                n["name"]: {"err": n["err"], "off": n["off"]}
                for n in sim.sc["nodes"].values()
            },
            "congested": sim.sc["congested"], "charge": sim.sc["charge"],
            "last_err": sim.sc["last_err"],
        },
        "covert": {
            "pad_mode": sim.pad_mode, "q_len": len(sim.covert_q),
            "vcc": sim.vcc, "vcc_frozen": sim.vcc_frozen,
            "leak_pos": sim.leak_pos,
        },
        "tcs": {
            "n": sim.tcs["n"], "last_apid": sim.tcs["last_apid"],
            "rssi": sim.tcs["rssi"][-1] if sim.tcs["rssi"] else None,
            "snr": sim.tcs["snr"][-1] if sim.tcs["snr"] else None,
        },
        "anom": {
            "alarm": sim.anom_alarm, "z": sim.anom_z,
            "last_ch": sim.anom_last_ch, "tc_seen": sim.tc_seen,
        },
        "sb": {"auth": sim.sb_auth, "sensor_mask": sim.sensor_mask},
    })


def _install_log_tap() -> None:
    def _ev_log(self: fslab.Evidence, s: str) -> None:
        # byte-identical to the original Evidence.log (format string copied
        # verbatim); the printed line becomes a console event instead of a
        # raw print so the UI stream and the transcript share one source.
        line = f"[{time.time() - self.t0:8.3f}] {s}"
        self.lines.append(line)
        if BUS.running:
            BUS.evidence.append(line)
            BUS.emit("line", text=line, ev=True)
        elif self.verbose:
            _ORIG_PRINT(line)
    fslab.Evidence.log = _ev_log


# --------------------------------------------------------------------------
# public entry points (called from web/worker.js)
# --------------------------------------------------------------------------
def install() -> None:
    """Install the taps once (idempotent)."""
    if getattr(fs, "_harness_installed", False):
        return
    fs.FlatSatSim.send = _send_tap
    fs.FlatSatSim.advance = _advance_tap
    _install_log_tap()
    fs._harness_installed = True


def _norm(lines: list[str]) -> str:
    """Normalise exactly like tools/build_web_demo.py: work on PHYSICAL
    lines (a single Evidence.log call may embed newlines), strip the
    wall-clock prefix wherever it appears, rejoin. Transcript-digest
    parity depends on both sides using the same algorithm."""
    out = []
    for pl in "\n".join(lines).splitlines():
        m = TS_RE.match(pl)
        out.append(m.group(1) if m else pl)
    return "\n".join(out)


def run_poc(poc_file: str, expect_md5: str) -> None:
    """Run one unmodified PoC exactly like CI (runpy, --no-save), stream the
    transcript, then emit the verdict with the normalised-transcript md5."""
    path = REPO + "/poc/" + poc_file
    BUS.running = True
    BUS.evidence = []
    BUS.fno = 0
    BUS._last_snap_ms = -10 ** 9
    BUS._last_state = None
    BUS._out_partial = ""
    old_argv = sys.argv
    old_stdout = sys.stdout
    sys.argv = [path, "--no-save"]
    sys.stdout = _Sink()
    t0 = time.time()
    code = 0
    try:
        runpy.run_path(path, run_name="__main__")
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except BaseException:
        BUS.evidence.append("POC ERROR:\n" + traceback.format_exc())
        code = 1
    finally:
        BUS.out_flush()
        sys.stdout = old_stdout
        sys.argv = old_argv
        BUS.running = False
    wall = round(time.time() - t0, 3)
    md5 = hashlib.md5(_norm(BUS.evidence).encode("utf-8")).hexdigest()
    match = md5 == expect_md5
    BUS.emit("verdict", poc=poc_file, ok=(code == 0), code=code,
             md5=md5, md5_exp=expect_md5, match=match,
             nlines=len(BUS.evidence), frames=BUS.fno, wall_s=wall)


def run_sweep(poc_files: list[str], expect: dict[str, str]) -> dict:
    """Full 56-PoC sweep in one worker session (reuses the interpreter)."""
    t0 = time.time()
    ok, bad = 0, []
    for i, p in enumerate(poc_files, 1):
        BUS.emit("poc_start", poc=p, i=i, n=len(poc_files))
        run_poc(p, expect.get(p, ""))
        if BUS.q and BUS.q[-1]["t"] == "verdict":
            if BUS.q[-1]["ok"] and BUS.q[-1]["match"]:
                ok += 1
            else:
                bad.append(p)
    BUS.emit("sweep_done", ok=ok, bad=bad,
             wall_s=round(time.time() - t0, 1))
    return {"ok": ok, "bad": bad}


def idle_state() -> None:
    """Paint the OPS tiles once from a live simulator — or a pristine one.

    The idle craft is real too: one forced ``_snap`` emits the same
    ``state`` snapshot a run would, so the state panel is readable from
    the first second, not only once something has been executed."""
    sim = BUS.sim or fs.FlatSatSim(seed=42)
    BUS.sim = sim
    BUS.running = True
    try:
        _snap(sim, force=True)
    finally:
        BUS.running = False


def run_orbit(orbits: int = 3) -> None:
    """Free-fly the REAL simulator for the overview range-scope canvas.

    A fresh ``FlatSatSim(seed=42)`` is advanced in 500 ms mission-time steps
    (the unmodified ``advance``; every 100 ms tick of the real workers model
    runs). ``BUS.orbit`` suppresses the wire-frame events in the taps so the
    page only sees ``orbit_state`` snapshots — the same real state the
    spacecraft exposes (distance/bearing to the ground station, gate, eclipse,
    orbit phase, power, attitude). No frames are faked: nothing is emitted
    that does not come out of the unmodified simulator."""
    sim = fs.FlatSatSim(seed=42)
    BUS.sim = sim
    BUS.orbit = True
    BUS.fno = 0
    step_ms = 500
    steps = max(1, int(round(orbits * 95.0 * 1000 / step_ms)))
    t0 = time.time()
    try:
        for _ in range(steps):
            sim.advance(step_ms)
            nav = sim._gps_nav()
            try:
                dist = sim._gs_dist_m(nav)
            except Exception:
                dist = -1.0
            BUS.emit("orbit_state",
                     t_ms=sim.now_ms, orbit_s=sim.orbit_s,
                     state=sim.state, mode=sim.mode,
                     lat=nav["lat"], lon=nav["lon"], alt_cm=nav["alt_cm"],
                     fix=nav["fix"], dist_m=dist, gate=sim._gs_gate_open(nav),
                     gs_mode=sim.gs_mode,
                     eclipse=sim.mm["eclipse"],
                     pct=round(sim.mm["pct"], 2),
                     power_w=round(sim.mm["power_w"], 2),
                     tilt=round(sim.mm["tilt"], 4))
    finally:
        BUS.orbit = False
        BUS.sim = None
    BUS.emit("orbit_done", orbits=orbits, steps=steps,
             wall_s=round(time.time() - t0, 3))


def do_selftest() -> str:
    """Run the real simulator self-test (FIPS-197 / SP800-38A/B / SDLS / OTAR)
    and return its output."""
    buf = io.StringIO()
    old_stdout, old_argv = sys.stdout, sys.argv
    sys.stdout = buf
    sys.argv = [REPO + "/simulator/flatsat_sim.py", "--selftest"]
    try:
        with contextlib.suppress(SystemExit):
            runpy.run_path(REPO + "/simulator/flatsat_sim.py",
                           run_name="__main__")
    finally:
        sys.stdout = old_stdout
        sys.argv = old_argv
    return buf.getvalue().strip()


def source_md5(poc_file: str) -> str:
    with open(REPO + "/poc/" + poc_file, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()
