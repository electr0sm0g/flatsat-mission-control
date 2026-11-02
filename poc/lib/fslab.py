#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
fslab.py -- shared PoC driver for the flatsat-lab vulnerable firmware.

Every poc_*.py uses this library. Default transport is the byte-for-byte
Python simulator (flatsat-lab/simulator/flatsat_sim.py); ``--usb --port``
switches to a physical FlatSat over the USB-CDC bridge (2-byte big-endian
length framing, as sent by usbCDC.cpp).

The library handles the one rule every PoC must respect: with secure-link
ON (the default), TC payloads travel AES-128-ECB wrapped under the
*hardcoded* key -- which is the whole point of the exercise (V0-02): the
attacker knows the key from the firmware image, so they can talk to the
spacecraft; what they cannot do (before the new attacks) is stop it,
prove freshness, or stop privilege confusion.

Each PoC prints an evidence transcript to stdout (also saved under
flatsat-lab/evidence/ by the runner), ends with "POC OK" on success and
exits non-zero on failure.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "simulator"))

import flatsat_sim as fs  # noqa: E402

LINK_KEY = fs.LINK_KEY

# Telecommand APIDs whose handling can flip the board's AES engine or
# USB-debug flag WITHOUT an ack carrying the new value: safe-mode entry
# (0x1D[2]) and internal FDIR trips (forged SpaceCAN / SB MIDs) switch
# the engine OFF silently; a RESETC (0x02) reboot lands on cold-boot
# defaults a few seconds later. The next tc() lazily re-syncs the host
# shadow from a LAB_STATUS query before its wrap decision
# (UsbDevice._resync_state). 0x0A/0x10/0x1A are included for completeness:
# their acks are mirrored by _track_state(), so a seen ack costs nothing
# (the resync only fires when the ack was not observed in the window).
# 0x18 (MEMCPY) is flip-capable too: a VTOR retarget onto labFnSecureLinkOff
# executes the secure-link-OFF hook with no ack carrying the new engine
# state, so the NEXT tc() must re-sync before its wrap decision (the sim
# re-syncs after every transfer and never goes stale -- which is why the
# bug only showed on hardware: the post-RCE MEM_READ arrived AES-wrapped
# into a board that was already in cleartext mode and came back garbled).
_FLIP_CAPABLE = frozenset({0x02, 0x04, 0x0A, 0x0D, 0x10, 0x1A, 0x1B, 0x1C,
                           0x1D, 0x18})

# TC apids whose ANSWER is a TM carrying the SAME apid (verified against
# flatsat_sim.py's TC->TM map: 0x0A/0x10/0x1A config acks, 0x0B flash
# read, 0x0C status, 0x1D FDIR_CONFIG, 0x24 heater, 0x25 defenses).
# tc() asks _read_frames to stop as soon as that TM is walked (stop_on):
# on hardware the post-answer silence window (~0.45 s) otherwise leaks
# into the PoC's wall clock -- inside a rate_phase cadence that is a
# pacer gap the board's 1 Hz EWMA counts as a rate dip the simulator's
# virtual clock can never produce (v124 latch, V-24 bench parity).
# If the same-apid TM never arrives the normal silence logic applies, so
# this is a fast path, never a semantics change.
_SELF_ANSWER = frozenset({0x01, 0x0A, 0x0B, 0x0C, 0x10, 0x1A, 0x1D,
                          0x24, 0x25})
# NB: 0x27 is NOT self-answering here: the 0x27 ack is followed by the
# INNER frame's TM on radio-inject (sub 1), and tc() callers rely on the
# full verdict window (the pre-answer silence logic still applies).

# TC apids that produce NO ack and NO response TM (0x05 SET_BEACON_RATE:
# the handler applies the interval silently, board and sim alike).  Their
# tc() must use a SHORT read window instead of the 4 s board-latency
# first-wait: with the board's 1 s beacon cadence the long window collects
# and DISCARDS the very beacons the PoC's advance() windows are written
# to catch (v130: six 1 s beacons fired inside tc(0x05)'s ~6.5 s read and
# drained the 63 B covert queue; the PoC's two advance(1100) windows then
# saw zero padding and CHECK FAILED, while the simulator -- where tc() is
# instant -- books exactly one beacon per window and passes).  Pairing
# with the firmware's `previous = millis()` arm in the 0x05 handler (see
# worker.cpp), the first board beacon lands one interval AFTER the
# command, exactly like the sim's virtual clock: one beacon per advance
# window on both benches.
_NO_TM_APIDS = frozenset({0x05})


class Tm:
    def __init__(self, apid, seq, payload, wrapped):
        self.apid = apid
        self.seq = seq
        self.payload = payload
        self.wrapped = wrapped  # was this TM secure-link wrapped on the wire?

    def u8(self, i=0):
        return self.payload[i]

    def be16(self, i):
        return struct.unpack(">H", self.payload[i:i + 2])[0]

    def le16(self, i):
        return struct.unpack("<H", self.payload[i:i + 2])[0]

    def le32(self, i):
        return struct.unpack("<I", self.payload[i:i + 4])[0]

    def le32s(self, i):
        return struct.unpack("<i", self.payload[i:i + 4])[0]

    def __repr__(self):
        return (f"Tm(apid=0x{self.apid:02X} len={len(self.payload)} "
                f"{self.payload[:24].hex()}{'...' if len(self.payload) > 24 else ''})")


class Device:
    """Transport-agnostic FlatSat v2 driver (USB framing compatible)."""

    hw = False

    def __init__(self, evidence):
        self.ev = evidence
        self.secure = True
        self.usb_debug = False
        # Set by tc() after a flip-capable APID: the next tc() must ask
        # the target for its live secure/usb-debug flags first (hw only).
        self._state_dirty = False

    @property
    def silent(self):
        """True when the board stopped answering (crash/hang on --usb)."""
        return False

    # -- subclasses / sim implement ------------------------------------
    def _xfer(self, frame: bytes, via: str, want=None) -> list:
        raise NotImplementedError

    # -- public API ------------------------------------------------------
    def tc(self, apid: int, payload: bytes = b"", via: str = "radio",
           encrypt=None, seq=None):
        """Send one telecommand; returns the list of emitted TMs (decoded).

        encrypt: None = auto (wrap when secure-link is active on this path)
        """
        if encrypt is None:
            if self.hw and self._state_dirty:
                self._resync_state()
            encrypt = self.secure and not (via == "usb" and self.usb_debug)
        body = fs.aes_ecb_encrypt_wrap(LINK_KEY, payload) if encrypt else payload
        frame = fs.spp_pack(apid, body, 1)
        self.ev.log(f"--> TC apid=0x{apid:02X} via={via} "
                    f"{'AES ' if encrypt else 'clear'} payload={payload.hex() or '-'}")
        # NOTE: no automatic want= here -- many APIDs answer under a
        # different TM (GPS -> NAV, thruster -> mission TM). PoCs that need
        # a specific TM pass want= to _xfer explicitly.
        raw_frames = self._xfer(frame, via,
                                stop_on=apid if apid in _SELF_ANSWER
                                else None,
                                fast=apid in _NO_TM_APIDS)
        tms = self._decode_all(raw_frames)
        if self.hw and encrypt:
            # V-15 bench transport hygiene (v115): during a TC flood the
            # board spends most of its time in the 3.2 s per-error blink
            # and a WRAPPED frame riding the USB ring through that stall
            # can come back with mangled ciphertext -- the board then
            # answers "AES DECRYPT FAIL" for a frame the harness wrapped
            # correctly (v115's 0x28 canary). A valid ciphertext fails to
            # decrypt only if it was corrupted in transit, so re-send the
            # same frame a few times. Cleartext frames are never re-sent:
            # the flood's junk TCs are meant to fail AES -- that IS the
            # finding (the PoC counts those failures).
            for _retry in range(1, 4):
                if Device.err_text(tms) != "AES DECRYPT FAIL":
                    break
                self.ev.log(f"--> TC apid=0x{apid:02X} via={via} "
                            f"AES retry={_retry} (transit-corrupt re-send)")
                raw_frames = self._xfer(frame, via,
                                        stop_on=apid if apid in _SELF_ANSWER
                                        else None,
                                        fast=apid in _NO_TM_APIDS)
                tms = self._decode_all(raw_frames)
        if self.hw:
            # This TC may have flipped the board's AES engine / debug flag
            # (safe mode, internal FDIR, RESETC boot window, ...): mark the
            # shadow dirty so the NEXT tc() re-syncs it from the target
            # before deciding how to wrap (see _FLIP_CAPABLE / _resync_state).
            self._state_dirty = apid in _FLIP_CAPABLE
        return tms

    def advance(self, ms: int):
        self.ev.log(f"--> advance({ms} ms)")
        return self._decode_all(self._advance(ms))

    def rate_phase(self, n: int, apid: int = 0x01, payload: bytes = b"",
                   via: str = "radio", ms: int = 1000):
        """Send `n` telecommands of `apid` spread evenly over a `ms`
        window (i.e. at the intended rate of `n` per second), then wait
        out the window. Returns the frames received inside it.

        Bench parity for rate-based PoCs (V-24): the on-board EWMA
        samples the number of radio TCs that ARRIVED per real second.
        A host that blocks on every ack paces itself at ~2 TC/s no
        matter what `n` is, which would flatten the TC-rate channel on
        silicon, while the simulator books all `n` TCs inside one
        virtual second. The sim variant below keeps exactly the latter;
        the hardware variant below paces the frames on the wire at
        ms/n intervals (pacer thread) while the window elapses in real
        time, so the board's 1 Hz feed also sees ~n per second."""
        raise NotImplementedError

    def _tc_ack(self, apid, body, want_tm, tries=4):
        """USB TC that must be acknowledged under `want_tm`. On hardware the
        beacon-flood windows drop USB frames (a lost SDLS setup silently
        disables the security pipeline); the simulator never drops, so it
        goes through the plain path."""
        if not getattr(self, "hw", False):
            return self.tc(apid, body, via="usb")
        r = []
        for _ in range(tries):
            r = self.tc(apid, body, via="usb")
            if self.find(r, want_tm):
                return r
        return r

    def _advance(self, ms: int):
        raise NotImplementedError

    def _resync_state(self):
        """Re-sync the secure/usb-debug shadow from the target's live
        state. No-op on the simulator: SimDevice._xfer re-syncs after
        every transfer, so the shadow can never go stale there."""

    def _decode_all(self, raw_frames):
        out = []
        for fr in raw_frames:
            out.append(self._decode(fr))
        return out

    def _decode(self, raw: bytes) -> Tm:
        pkt = fs.spp_unpack(raw[1:] if raw[:1] == b"\xAA" else raw)
        data = pkt["data"]
        # TMs are either secure-wrapped (baseline family) or forced
        # cleartext (the v2 extension family). Try the unwrap and keep
        # whichever interpretation is structurally valid.
        if self.secure and not self.usb_debug and len(data) % 16 == 0 and data:
            plain = fs.sl_decode_key(LINK_KEY, data)
            if plain is not None:
                self.ev.log(f"<-- TM apid=0x{pkt['apid']:02X} AES len={len(plain)}")
                return Tm(pkt["apid"], pkt["seq"], plain, True)
        self.ev.log(f"<-- TM apid=0x{pkt['apid']:02X} clear len={len(data)}")
        return Tm(pkt["apid"], pkt["seq"], data, False)

    # -- helpers ----------------------------------------------------------
    def probe_alive(self) -> bool:
        """Crash indicator independent of the command being tested: on the
        simulator it reads the model state, on hardware it asks the bench
        transport (LAB_STATUS), which a wedged core0 can never answer."""
        return self.sim.state != "CRASHED"

    @staticmethod
    def find(tms, apid):
        return [t for t in tms if t.apid == apid]

    @staticmethod
    def errors(tms):
        out = []
        for t in tms:
            if t.apid == 0x09:
                out.append(t.payload.rstrip(b"\x00").decode("latin-1"))
        return out

    @staticmethod
    def err_text(tms):
        e = Device.errors(tms)
        return e[0] if e else None


class SimDevice(Device):
    def __init__(self, evidence, seed=42):
        super().__init__(evidence)
        self.sim = fs.FlatSatSim(seed=seed)

    def sync_state(self):
        self.secure = self.sim.secure
        self.usb_debug = self.sim.usb_debug

    @property
    def silent(self):
        return self.sim.state in ("CRASHED", "HANGED")

    def _xfer(self, frame, via, want=None, stop_on=None, fast=False):
        frames = self.sim.send(frame, via=via)
        self.sync_state()
        return frames

    def _advance(self, ms):
        frames = self.sim.advance(ms)
        self.sync_state()
        return frames

    def rate_phase(self, n, apid=0x01, payload=b"", via="radio", ms=1000):
        # All `n` TCs are issued at the current sim time, then the
        # window elapses: the 1 Hz services see ~n of them per virtual
        # second -- what the hardware pacer achieves on the wire.
        for _ in range(n):
            self.tc(apid, payload, via=via)
        return self.advance(ms)

    # extras used by some PoCs -------------------------------------------
    def resetc(self, via="radio"):
        """Unauthenticated soft reset (V0-08): SRAM dies, flash + watchdog
        scratch survive."""
        tms = self.tc(0x02, b"", via=via, encrypt=False)
        self.sync_state()
        return tms

    def powercycle(self):
        self.ev.log("--> POWER CYCLE (scratch + SRAM die, flash survives)")
        self.sim.powercycle()
        self.sync_state()


def _resolve_bridge_port(port):
    """The binary bridge lives on the SECOND CDC interface (if02,
    'USBRadioLink'); the first one is the human console. Given any
    interface of a PwnSat/FlatSat composite, return a STABLE handle to the
    bridge: the /dev/serial/by-id symlink, which survives the tty
    renumbering that every reboot triggers (a raw /dev/ttyACMs would go
    stale and the console sibling could then never be re-attached)."""
    import glob
    import os

    def real(p):
        try:
            return os.path.realpath(p)
        except OSError:
            return p

    if port.startswith("/dev/serial/by-id/"):
        return port
    target = real(port)
    for link in glob.glob("/dev/serial/by-id/*"):
        if real(link) == target:
            if link.endswith("if02"):
                return link          # already the bridge
            if link.endswith("if00"):
                sib = link[:-4] + "if02"
                if os.path.exists(sib):
                    return sib
            break
    for pat in ("*lat*if02", "*wnsat*if02", "*satsat*if02"):
        links = sorted(glob.glob("/dev/serial/by-id/" + pat))
        if links:
            return links[0]
    return port                      # hope for the best


class UsbDevice(Device):
    """Physical board: USB-CDC bridge on interface if02.

    Wire format (usbCDC.cpp): host->device ``AA 55 BE16_LEN <spp frame>``;
    device->host ``AA <spp frame>`` where the spp primary header carries
    the length. Radio telecommands ride the LAB_CTRL bridge (0x27 sub 1)
    which re-enters the full radio pipeline on-device, and the ``dev.sim``
    introspection used by the PoCs is served by LAB_STATUS (0x26).
    """

    hw = True

    def __init__(self, evidence, port, baud=115200):
        super().__init__(evidence, )
        import serial  # lazy: only needed with --usb
        self.port = _resolve_bridge_port(port)
        self.baud = baud
        self.ser = serial_open_retry(port, baud)
        self._silent = False
        self._port_gone = False
        self.sim = RemoteSim(self)
        # The real firmware parks core0 in `while(!Serial)` at boot: the
        # mission loop (and the USB TC drain) only runs once a host holds
        # DTR on the CONSOLE interface (if00). Keep it open -- as a side
        # benefit the console log lands in our hands as extra evidence.
        self.console = None
        self.open_console()
        # Drain anything the board queued before we listened (boot TMs):
        # an undrained IN pipe makes the device NAK our OUT transfers and
        # a bare ser.write() would then block forever.
        try:
            self.ser.reset_input_buffer()
        except Exception:
            pass
        time.sleep(0.3)          # let both DTR signals propagate
        # core0's mission loop logs through the console CDC with blocking
        # writes: if the host stops reading if00, Serial.printf fills the
        # TinyUSB IN fifo and STALLS core0 -- which then also stops
        # draining our bridge ring (mysterious "board silent" hangs). A
        # dedicated reader thread keeps the console pipe always open.
        self._con_buf = bytearray()
        self._con_lock = threading.Lock()
        self._con_thread = None
        if self.console is not None:
            self._con_thread = threading.Thread(target=self._console_pump,
                                                daemon=True)
            self._con_thread.start()
        # Keep the BRIDGE port drained at all times, not only while a
        # _request waits: when the host stops reading, the RP2040's CDC
        # TX ring fills and the mission loop stalls inside a blocking
        # Serial.write -- the "zombie port" state (enumerated, deaf).
        # A permanent reader thread accumulates every byte; _read_frames
        # consumes from that queue instead of touching self.ser directly.
        self._rx = bytearray()
        self._rx_lock = threading.Lock()
        self._rx_gen = 0
        self._start_rx()
        # Adopt the board's REAL secure/usb-debug state before any TC is
        # shaped (the AES-wrap decision of tc() depends on it).
        self.sync_from_board()

    def _pump_trace(self, tag, n):
        # Diagnostic (FSLAB_PUMP_TRACE=/path): per-pump deposit timestamps,
        # written as "<epoch> <con|rx> <bytes>" lines. Env-gated and inert
        # by default; kept (zero-cost when off) after it proved the bridge
        # delivered frames in real time during the "silent" windows that
        # sank the v106 stall hunt -- transcript "<-- TM" lines are
        # log-time (tc()/advance() return), not arrival-time, so only this
        # trace shows true wire cadence.
        import os
        p = os.environ.get("FSLAB_PUMP_TRACE")
        if not p or n == 0:
            return
        try:
            with open(p, "a") as f:
                f.write(f"{time.time():.3f} {tag} {n}\n")
        except Exception:
            pass

    def _console_pump(self):
        import serial
        while True:
            try:
                if self.console is None or not self.console.is_open:
                    time.sleep(0.2)
                    continue
                d = self.console.read(4096)
                self._pump_trace("con", len(d))
                if d:
                    with self._con_lock:
                        self._con_buf += d
                        if len(self._con_buf) > 400000:
                            del self._con_buf[:len(self._con_buf) - 200000]
            except serial.SerialException:
                time.sleep(0.3)   # re-enumeration in progress: wait it out
            except Exception:
                time.sleep(0.1)

    def sync_from_board(self):
        """Mirror the board's secure-link / usb-debug flags into the host
        view (silent-on-hardware == silent-on-sim requires the same
        encryption decisions on both sides)."""
        try:
            self.secure = self.sim.secure
            self.usb_debug = self.sim.usb_debug
        except Exception:
            pass

    def _resync_state(self):
        """Lazy state re-sync (bench-parity twin of SimDevice.sync_state,
        which the sim runs after EVERY transfer).

        The board can flip its AES engine / usb-debug flag without any ack
        carrying the new value: safe-mode entry (0x1D[2]) and internal FDIR
        trips (forged SpaceCAN / SB MIDs via 0x1B/0x1C) switch the engine
        OFF; a RESETC (0x02) reboot lands on cold-boot defaults only a few
        seconds later. A stale shadow makes tc() wrap the wrong way -- with
        the engine off the board passes wrapped payloads through UNDECODED
        (secureLinkDecodeInPlace), so the ciphertext becomes the TC body:
        garbage sub-commands, "MEM READ FAULT", lost post-RESETC follow-ups.
        Fetch a fresh LAB_STATUS and adopt the board's live flags; when the
        board is still booting, wait it out (<= 20 s: fetch_status itself
        retries 5x ~7-10 s when the board is silent)."""
        self._state_dirty = False
        if self._silent:
            return
        t0 = time.time()
        while time.time() - t0 < 20.0:
            try:
                self.sim.invalidate()
                d = self.sim._need()
                self.secure = bool(d[2] & 1)
                self.usb_debug = bool(d[2] & 2)
                return
            except Exception:
                time.sleep(0.5)

    def open_console(self):
        """Open (or reopen) the console CDC sibling of the bridge port."""
        import glob
        import os
        import serial
        if self.console is not None:
            try:
                self.console.close()
            except Exception:
                pass
        self.console = None
        target = os.path.realpath(self.port)
        sib = None
        if self.port.endswith("if02"):
            cand = self.port[:-4] + "if00"
            if os.path.exists(cand):
                sib = cand
        if sib is None:
            for link in glob.glob("/dev/serial/by-id/*"):
                if os.path.realpath(link) == target and link.endswith("if02"):
                    cand = link[:-4] + "if00"
                    if os.path.exists(cand):
                        sib = cand
                    break
        if sib is None:
            return
        t0 = time.time()
        while time.time() - t0 < 15.0:
            try:
                self.console = _serial_open_bounded(sib, self.baud,
                                                    timeout=0.05,
                                                    write_timeout=2.0)
                break
            except Exception:
                time.sleep(0.3)
        if self.console is None:
            return
        # core0 is parked in while(!Serial) until DTR lands; give it a
        # moment, then the mission loop (USB drain) starts.
        time.sleep(0.5)
        # Exit the stock PWNSAT console menu ('3' = quiet mode): while the
        # menu waits for a selection the craft throttles its telemetry
        # worker and can even wedge the USB stack under load (bench hang /
        # zombie port). The bench always wants quiet mode.
        try:
            self.console.reset_input_buffer()
            self.console.write(b"3")
            self.console.flush()
            time.sleep(0.3)
            self.console.read(4096)
        except Exception:
            pass

    def console_tail(self, n=4000):
        """Console log accumulated since the last call (from the pump)."""
        with self._con_lock:
            out = bytes(self._con_buf[-n:]) if n else bytes(self._con_buf)
            self._con_buf.clear()
            return out

    # -- low-level framing ------------------------------------------------
    def _start_rx(self):
        self._rx_gen += 1
        threading.Thread(target=self._rx_pump, args=(self._rx_gen,),
                         daemon=True).start()

    def _rx_pump(self, gen):
        # Follows self.ser across reopens: a stale thread merely idles on
        # the exception path until gen != self._rx_gen or the new object
        # is published; both cases are safe because bytes always land in
        # the one shared queue.
        import serial
        while gen == self._rx_gen:
            try:
                # Port timeout is 50 ms (see serial_open_retry): read()
                # returns within 50 ms with whatever has arrived, so this
                # loop is a ~20 Hz poller with no extra batching. Frames
                # are deposited in the queue as they arrive -- cadence PoCs
                # (v106) rely on that sub-100 ms attribution.
                d = self.ser.read(8192)
                self._pump_trace("rx", len(d))
                if d:
                    with self._rx_lock:
                        self._rx += d
                        if len(self._rx) > 2_000_000:
                            del self._rx[:len(self._rx) - 1_000_000]
            except serial.SerialException:
                time.sleep(0.2)     # re-enumeration in progress
            except Exception:
                time.sleep(0.05)

    def _qread(self, n, timeout):
        """Take up to n bytes from the pump queue, waiting up to timeout.

        Returns EARLY once the queue is drained (we hold everything the
        pump has deposited so far); the full `timeout` wait only happens
        while the queue stays empty.  The bulk-walker `_read_frames`
        relies on this: with the old "wait the full window unless n
        bytes arrived" semantics, a 20-byte ack forced the full
        first_wait+settle+idle_wait (~6 s) on every tc(), inflating the
        bench setup phase ~3x."""
        out = bytearray()
        deadline = time.time() + timeout
        while True:
            got = False
            with self._rx_lock:
                take = min(n - len(out), len(self._rx))
                if take:
                    out += bytes(self._rx[:take])
                    del self._rx[:take]
                    got = True
                    if len(out) >= n:
                        return bytes(out)
            if not got and out:
                return bytes(out)          # queue drained: return early
            if time.time() >= deadline:
                return bytes(out)
            time.sleep(0.01)

    def _read_frames(self, quiet_s=0.25, first_wait=4.0, settle=1.5,
                     idle_wait=0.4, stop_on=None):
        # stop_on (bench parity, V-24): verdict TCs whose answer is a TM of
        # the SAME apid (status/config reads) return the moment that TM is
        # walked -- no trailing idle_wait.  Without this every 0x1D/0x25
        # checkpoint cost ~0.45 s of post-answer silence, which sat INSIDE
        # the pacer cadence and showed the board's 1 Hz EWMA a full-second
        # rate dip the simulator (virtual clock) can never see.  When the
        # expected TM never arrives the normal silence/deadline logic runs
        # unchanged, so worst case == previous behaviour.
        out = []
        # Physical board latency (radio pipeline + 100 ms worker ticks) is
        # far above the simulator's: wait generously for the FIRST byte of
        # a reply, then close on a shorter inter-frame silence.  A global
        # deadline is mandatory: when the craft floods telemetry (beacon
        # bug, sched spam) the queue never goes quiet and a gap-based loop
        # would spin forever.
        # _advance() passes TIGHT graces (~20 ms) instead: cadence PoCs
        # need each frame attributed to the 1 s window it actually arrived
        # in.  (History: v106's "16/12 s alternation" was two bench
        # artifacts, not the board -- the bridge port's timeout=2 batched
        # ~2 s of arrivals per pump deposit, and the byte-grind drain lagged
        # the 1 s beacon stream; the board truly runs 14.00/22.00/30.00/
        # 1.00 s, see docs/HARDWARE-USB-TEST.md §4bis.7.)
        # BULK walker: the old byte-at-a-time sync probe (one _qread(1)
        # per wire byte, 10-20 ms sleeps whenever the pump queue was
        # momentarily empty) cost ~150-200 ms PER FRAME while walking
        # headers/frames. Against the 1 s beacon stream (post-0x05[1])
        # that made the _advance() drain fall behind ~0.2 s every second,
        # so mission/nav/sync/idle TMs were booked ~1-2 s late and v106's
        # cadence min-gaps measured 13/21 s instead of 14/22 s (the
        # board itself runs exactly 14.00/22.00/30.00/1.00 s -- verified
        # by arrival-time booking: 0x08 gaps 13.97-14.07 s). Reading in
        # 512-byte chunks and walking in memory costs ~0 ms per frame.
        t_start = time.time()
        deadline = t_start + 12.0
        while time.time() < deadline and len(out) < 4000:
            first = not out and time.time() - t_start < first_wait
            wait = (max(quiet_s, first_wait) if not out
                    else max(quiet_s, settle) if first
                    else max(min(quiet_s, 1.0), idle_wait))
            chunk = self._qread(512, wait)
            if not chunk:
                break                      # quiet window elapsed
            n_before = len(out)
            # Rebuild tail from ONLY the carried partial frame + this chunk.
            # Accumulating chunks across iterations and re-walking from i=0
            # re-emits every frame already emitted in an earlier iteration
            # (each arriving deposit re-emitted the whole tail: the bench
            # "radio loopback" mystery -- 16 board chunks read back as 152,
            # copy counts 17,16,...,2; the pump trace proved the port
            # delivered each byte exactly once). _rx_tail holds only the
            # trailing incomplete frame, so nothing complete is re-walked.
            tail = bytearray(getattr(self, "_rx_tail", b"")) + chunk
            i = 0
            n = len(tail)
            partial_at = None
            while i < n and len(out) < 4000:
                j = tail.find(b"\xAA", i)
                if j < 0:
                    break                  # no sync left: remainder is junk
                if n < j + 7:
                    partial_at = j
                    break                  # header incomplete: need more
                ln = struct.unpack(">H", tail[j + 5:j + 7])[0]
                if ln > 1024:
                    i = j + 1              # bogus length: resync
                    continue
                total = 1 + 6 + (ln + 1)   # sync + SPP hdr + data field
                if n < j + total:
                    partial_at = j
                    break                  # frame incomplete: need more
                out.append(bytes(tail[j:j + total]))
                i = j + total
            if partial_at is not None and partial_at >= i:
                self._rx_tail = bytearray(tail[partial_at:][-4096:])
            else:
                self._rx_tail = bytearray()
            if stop_on is not None and len(out) > n_before:
                for fr in out[n_before:]:
                    pkt = fs.spp_unpack(fr[1:])
                    if pkt and pkt["apid"] == stop_on:
                        return out
        return out

    def _request(self, frame, quiet_s=0.25, stop_on=None, fast=False,
                 via="usb"):
        payload = b"\xAA\x55" + struct.pack(">H", len(frame)) + frame
        try:
            self.ser.write(payload)
        except Exception:
            # stale handle behind us (the craft rebooted mid-session):
            # reopen the bridge and retry once, else report silence.
            # A RE-ENTRANT stale hit (the revival's own resync/rearm/GPS
            # frames failing on the same dead handle) must not re-run the
            # whole revival: the outer call owns it; just get the (lab)
            # frame out on the freshly reopened port.
            if getattr(self, "_reviving", False):
                try:
                    self.ser.write(payload)
                except Exception:
                    self._port_gone = True
                    return []
            else:
                self._reviving = True
                try:
                    self.ser = serial_open_retry(self.port, self.baud,
                                                 timeout=15.0)
                    self.open_console()
                    self._port_gone = False
                    self._silent = False
                    # Shadow as it was when the frame was built (pre-revival):
                    old_secure, old_dbg = self.secure, self.usb_debug
                    # V-34: re-sync the secure/usb-debug shadow from the
                    # board's LIVE flags. A mid-PoC brownout reboot lands the
                    # board on its cold-boot secure default (engine ON) while
                    # the harness shadow is stale OFF -- re-sending the
                    # original cleartext frame then reads "AES DECRYPT FAIL"
                    # (v134's post-reset 0x0C) and the PoC's find()[0] blows
                    # up. The board's static default is ON; only a V-21
                    # scratch cookie (wiped by the brownout) forces it OFF.
                    self._resync_state()
                    # The craft just rebooted under us: re-arm its model/FDIR/
                    # schedule/FEED phase to the revival instant (V-19 bench
                    # parity) before the PoC's next verdict.
                    self._maybe_rearm("board rebooted mid-session")
                    # And restore the simulator's cold-boot GPS fix (the sim
                    # boots with an attached u-blox holding a fix; the bench
                    # board has no u-blox on UART, so a mid-PoC reset would
                    # otherwise leave it fix-less where the sim is fixed --
                    # v126's "GPS back after power cycle" check).
                    self._bench_gps_fix()
                    # Re-encode the original frame's body for the board's
                    # POST-revival secure state (it was built against the
                    # stale shadow); written LAST so the final _read_frames
                    # owns the answer.
                    frame = self._rewrap_after_revive(frame, via,
                                                      old_secure, old_dbg)
                    payload = (b"\xAA\x55"
                               + struct.pack(">H", len(frame)) + frame)
                    self.ser.write(payload)
                except Exception:
                    self._port_gone = True
                    return []
                finally:
                    self._reviving = False
        if fast:
            # No ack, no response TM (see _NO_TM_APIDS): the 4 s
            # board-latency first-wait would collect and discard the
            # board's periodic TMs that the PoC's advance() windows are
            # written to catch (v130). Wait only for a quick quiet.
            return self._read_frames(quiet_s=0.05, first_wait=0.45,
                                     settle=0.05, idle_wait=0.05,
                                     stop_on=stop_on)
        return self._read_frames(quiet_s, stop_on=stop_on)

    def _rewrap_after_revive(self, frame, via, old_secure, old_dbg):
        """Re-encode a revived frame's body for the board's POST-revival
        secure state (v134 bench parity).

        The frame was built against the PRE-revival shadow (old_secure/
        old_dbg). A mid-PoC brownout reboot lands the board on its cold-boot
        secure default (engine ON) while the harness shadow was OFF, so the
        original CLEARTEXT body is then rejected with "AES DECRYPT FAIL".
        _resync_state() has just re-adopted the board's live flags, so the
        body must be re-encoded to match:
          * body wrapped under the old shadow  -> unwrap to the plaintext;
          * new shadow wants wrap (incl. an EMPTY body -> the 16-B len=0
            block, exactly what the simulator always emits) -> re-wrap;
          * new shadow wants cleartext        -> send the plaintext.
        Lab frames (0x26 LAB_STATUS / 0x27 LAB_CTRL) ride the trusted USB
        bus in the clear on BOTH benches (PER-0002) and the firmware exempts
        them from the secure link -- never re-encode them."""
        pkt = fs.spp_unpack(frame)
        if not pkt or pkt["apid"] in (0x26, 0x27):
            return frame
        # spp_unpack pads the data field to length+1 (the V-24 off-by-one),
        # so an EMPTY-payload frame (exactly 6 bytes, no data field) reads
        # back as a phantom 0xFF byte. The true payload is empty in that
        # case -- re-wrapping the phantom would hand the board a 1-byte
        # body where the simulator hands it a 0-byte one.
        body = b"" if len(frame) == 6 else pkt["data"]
        plain = body
        if old_secure and not (via == "usb" and old_dbg):
            dec = fs.sl_decode_key(LINK_KEY, body)
            if dec is not None:
                plain = dec
        if self.secure and not (via == "usb" and self.usb_debug):
            new_body = fs.aes_ecb_encrypt_wrap(LINK_KEY, plain)
        else:
            new_body = plain
        if new_body == body:
            return frame
        return fs.spp_pack(pkt["apid"], new_body, pkt["seq"],
                           ptype=pkt["type"], flags=pkt["flags"],
                           sechdr=pkt["sechdr"])

    # -- Device API ---------------------------------------------------------
    def _xfer(self, frame, via, want=None, stop_on=None, fast=False):
        if want is not None and self.hw:
            # Verdict-driven reads must not race stale answers of the
            # PREVIOUS command sitting in the OS buffer: drain to silence.
            try:
                t_q = time.time()
                while time.time() - t_q < 3.0:
                    if not self._read_frames(0.6):
                        break
            except Exception:
                pass
        if via == "radio":
            frame = self._lab_ctrl(bytes([1, 0, 0, 0, 0, 0, 0]) + frame)
        try:
            frames = self._request(frame, stop_on=stop_on, fast=fast,
                                   via=via)
        except Exception:
            # The board just rebooted/crashed under us (e.g. an enumerated
            # REBOOT_C): wait for the bridge to come back, no TMs for the
            # fatal command itself.
            try:
                self.ser = serial_open_retry(self.port, self.baud,
                                             wait_gone=5.0, timeout=40.0)
                self.open_console()
                self._port_gone = False
            except Exception:
                self._port_gone = True
            frames = []
        # The real answer to a command can trail unrelated frames well
        # beyond the first window on silicon (radio-injected TC answers
        # arrive after the lab ack; a late ack of the PREVIOUS command can
        # also poison the first window). When the caller tells us which TM
        # it expects (`want`), keep the window open until we see it.
        def _chatter(f):
            pkt = fs.spp_unpack(f[1:]) if f[:1] == b"\xAA" else fs.spp_unpack(f)
            if not pkt:
                return True
            if pkt["apid"] in (0x08, 0x0E, 0x3FF):
                return True
            if pkt["apid"] == 0x01 and pkt["len"] > 16:   # padded beacon TM
                return True
            if pkt["apid"] == 0x27:   # lab inject/status ack: the real
                return True           # answer to an injected TC follows it
            if pkt["apid"] > 0x28 and pkt["apid"] != 0x3FF:
                return True           # radio loopback garbage (0x305 etc.)
            return False
        want_set = None
        if want is not None:
            want_set = {want} if isinstance(want, int) else set(want)
            def _hit(fr_list):
                for f in fr_list:
                    pkt = (fs.spp_unpack(f[1:]) if f[:1] == b"\xAA"
                           else fs.spp_unpack(f))
                    if pkt and pkt["apid"] in want_set and not _chatter(f):
                        return True
                return False
            deadline = time.time() + 15.0
            while time.time() < deadline and not _hit(frames):
                frames.extend(self._read_frames(0.3))
        elif (not fast) and frames and all(_chatter(f) for f in frames):
            deadline = time.time() + 5.0
            while time.time() < deadline:
                more = self._read_frames(0.3)
                if more and not all(_chatter(f) for f in more):
                    frames.extend(more)
                    break
                frames.extend(more)
        # Transport hygiene: the firmware acks EVERY LAB_CTRL (0x27) frame
        # (radio-inject / power-cycle) with a small 0x27 TM. That ack is a
        # bench-transport artifact -- the simulator never emits 0x27 -- so
        # drop it from the verdict window, mirroring the _chatter() class
        # above. Without this, `not r` hang assertions (v109) see the ack
        # and fail on hardware while passing in the simulator.
        def _lab_ack(f):
            pkt = (fs.spp_unpack(f[1:]) if f[:1] == b"\xAA"
                   else fs.spp_unpack(f))
            return bool(pkt) and pkt["apid"] == 0x27
        frames = [f for f in frames if not _lab_ack(f)]
        self._silent = not frames
        self.sim.invalidate()
        self._track_state(frames)
        return frames

    def _track_state(self, raw_frames):
        """Mirror secure/usb-debug flips from their ack TMs (0x0A/0x10/0x1A).
        Try both wire interpretations (the device flips state before it
        emits the ack, so the local view may disagree either way).

        0x1A (SET_LOG_NAME) matters because V-13's overflow flips the live
        flags from INSIDE the log-name TC: the firmware stops decoding
        secure TCs (secureLinkDecodeInPlace passes wrapped payloads through
        in the clear when the engine is off), so a bench that keeps
        wrapping after the flip sends ciphertext as the TC body (V-13's
        post-overflow MEM_READ read a garbage address and faulted on the
        board while the sim -- whose device re-syncs after every transfer
        -- sent it in the clear).  The 0x1A ack layout is identical on
        both transports: [SCID, usb_debug, secure, gs_mode, pad_mode, ...]."""
        for fr in raw_frames:
            pkt = fs.spp_unpack(fr[1:]) if fr[:1] == b"\xAA" else fs.spp_unpack(fr)
            if not pkt or pkt["apid"] not in (0x0A, 0x10, 0x1A):
                continue
            data = pkt["data"]
            cands = ([fs.sl_decode_key(LINK_KEY, data)]
                     if len(data) % 16 == 0 and data else [])
            cands.append(data)
            for pl in cands:
                if not (pl and len(pl) >= 3 and pl[0] == fs.SPACECRAFT_ID):
                    continue
                if pkt["apid"] == 0x1A:
                    if pl[1] in (0, 1) and pl[2] in (0, 1):
                        self.usb_debug = bool(pl[1])
                        self.secure = bool(pl[2])
                        break
                    continue
                if pl[1] in (0, 1):
                    if pkt["apid"] == 0x0A:
                        self.secure = bool(pl[1])
                    else:
                        self.usb_debug = bool(pl[1])
                    break

    def _advance(self, ms):
        # Bench parity with the simulator: advance() is a TIME WINDOW of
        # exactly `ms` -- the PoC treats every call as one equal tick and
        # books each returned frame at the window end (dev.sim.now_ms //
        # 1000), exactly like the simulator books frames at their virtual
        # emission tick.
        #
        # The craft clock runs at 1.0x time scale (pinned by
        # _bench_defaults), so board seconds == real seconds: the window
        # is a fixed host-wall span and the virtual clock below is the
        # craft clock anchored to it. Two rules keep the cadence math
        # exact (v106 asserts min-gap == 14/22/20/30 s):
        #  * now_ms is the EXACT grid t0 + k*ms (window k), never a
        #    jittery per-window board read -- like the sim's virtual
        #    counter, no phase noise;
        #  * frames are drained continuously (~20 ms polls, no 4 s
        #    reply-grace) so each frame is attributed to the window it
        #    actually arrives in. The old early-return-on-first-frame
        #    compressed several 1 s ticks into one board second (cadence
        #    PoCs measured 0 s intervals and saw "duplicate" frames).
        out = []
        if not hasattr(self, "_adv_anchor") or self._adv_anchor is None:
            # first advance OR a revival (hard_reset / powercycle /
            # reboot / mid-session reboot set _adv_anchor = None): re-
            # anchor the virtual grid on the board's live clock and
            # restart the window counter, exactly like the simulator's
            # clock restart after its cold boot.
            self.sim.invalidate()
            try:
                self._adv_anchor = (self.sim.now_ms, time.time())
            except Exception:
                self._adv_anchor = None
            self._adv_k = 0
        self._adv_k += 1
        # V-19 bench parity: open the board's FEED window for this
        # advance() span (LAB_CTRL sub 6 FEED_START, fire-and-forget at
        # window START, mirroring the SYNC write at window end below).
        # While the window is open the board's bench epoch clock runs 1:1
        # with wall time and the mission model / FDIR / schedule queue /
        # periodic radio TM workers advance ONLY on that clock -- exactly
        # where the simulator's _workers_tick does (its model advances
        # only inside advance()). The board self-terminates the window
        # after `ms` of bench time (deadline enforced in labTickWorkers),
        # so this write never needs a reply and never blocks the window.
        try:
            frm = self._lab_ctrl(bytes([6]) + struct.pack("<I", ms))
            self.ser.write(b"\xAA\x55"
                           + struct.pack(">H", len(frm)) + frm)
        except Exception:
            pass
        t_end = time.time() + ms / 1000.0
        while time.time() < t_end:
            out.extend(self._read_frames(0.01, first_wait=0.02,
                                         settle=0.02, idle_wait=0.02))
        if self._adv_anchor is not None:
            t0, _h0 = self._adv_anchor
            blob = getattr(self.sim, "_d", None)
            if blob is not None:
                now = (t0 + self._adv_k * ms) & 0xFFFFFFFF
                patch = bytearray(blob)
                patch[14:18] = struct.pack("<I", now)
                self.sim._d = bytes(patch)
                # V-28 bench parity: inject the SAME grid into the board's
                # ground-station sync (LAB_CTRL sub 5 ->
                # labMarkLabStatusSync) so groundStationGenerateChallenge
                # seeds from the exact instant the PoC's virtual clock
                # predicts from (v128: the board seeded from its own
                # millis(), 37 s off the PoC's grid, and the predicted
                # challenge could never match on silicon). Fire-and-forget
                # write at window end: the 0x27 ack (a bench-transport
                # artifact the simulator never emits) rides to the next
                # read and is stripped by _lab_ack / the PoC's apid
                # filters -- the cadence window itself must never block.
                try:
                    frm = self._lab_ctrl(bytes([5]) + struct.pack("<I", now))
                    self.ser.write(b"\xAA\x55"
                                   + struct.pack(">H", len(frm)) + frm)
                except Exception:
                    pass
        return out

    @property
    def silent(self):
        return self._silent

    def rate_phase(self, n, apid=0x01, payload=b"", via="radio", ms=1000):
        """See Device.rate_phase. Hardware variant: a pacer thread
        releases the wire frames at ms/n intervals (a USB write is ~1 ms
        and the board's radio pipeline consumes frames as fast as its
        worker loop turns -- labInjectFrameAsRadio has no per-frame
        delay), while the main thread waits out the window in _advance
        exactly as usual. All `n` frames go out before the window ends
        ((n-1)*ms/n < ms), so the board's 1 Hz feed counts ~n of them
        per second, like the simulator's virtual clock does."""
        self.ev.log(f"--> rate_phase: {n} x apid=0x{apid:02X} over {ms} ms")
        encrypt = self.secure and not (via == "usb" and self.usb_debug)
        body = fs.aes_ecb_encrypt_wrap(LINK_KEY, payload) if encrypt else payload
        frame = fs.spp_pack(apid, body, 1)
        if via == "radio":
            frame = self._lab_ctrl(bytes([1, 0, 0, 0, 0, 0, 0]) + frame)
        wire = b"\xAA\x55" + struct.pack(">H", len(frame)) + frame
        done = threading.Event()

        def _pacer():
            # Diagnostic (FSLAB_PACER_TRACE=/path): timestamp every pacer
            # write that takes >20 ms. A fast write means the frame hit
            # the wire; a slow one means the device NAKed the EP RX
            # (board-side backlog) and the write stalled in the kernel.
            # Splits "frames lost board-side" from "frames stuck
            # host-side" without touching the healthy path.
            import os
            pt = os.environ.get("FSLAB_PACER_TRACE")
            gap = ms / 1000.0 / n
            for i in range(n):
                t0 = time.time()
                try:
                    self.ser.write(wire)
                except Exception:
                    done.set()
                    return
                dt = time.time() - t0
                if pt and dt > 0.02:
                    try:
                        with open(pt, "a") as f:
                            f.write(f"{t0:.3f} n={n} i={i} "
                                    f"took={dt * 1000:.1f}ms\n")
                    except Exception:
                        pass
                done.wait(gap)

        p = threading.Thread(target=_pacer, daemon=True)
        p.start()
        try:
            frames = self._advance(ms)
        finally:
            done.set()
            p.join(timeout=ms / 1000.0 + 5.0)
        return self._decode_all(frames)

    # -- lab services -------------------------------------------------------
    def _lab_ctrl(self, cmd_body):
        # USB is the trusted bus: the firmware (and the simulator) parse
        # the LAB_CTRL body in the clear; AES belongs to the INNER frame.
        return fs.spp_pack(0x27, cmd_body, 1)

    def fetch_status(self, quiet_s=0.3):
        """LAB_STATUS query. The bench transport is cleartext on the trusted
        USB bus (PER-0002), on the board and in the simulator alike.
        Spontaneous traffic (beacons, boot TMs) interleaves on the wire, so
        keep asking until the 0x26 blob shows up; only total silence counts
        as an unreachable board."""
        for attempt in range(5):
            frames = self._request(fs.spp_pack(0x26, b"", 1),
                                   quiet_s=quiet_s if attempt == 0 else 1.0,
                                   stop_on=0x26)
            for fr in frames:
                pkt = fs.spp_unpack(fr[1:])
                if pkt and pkt["apid"] == 0x26 and len(pkt["data"]) >= 53:
                    self._silent = False
                    return pkt["data"]
            if frames:
                continue               # board alive, answer interleaved/late
            self._silent = True
            time.sleep(0.4)
        self._silent = True
        return None

    def probe_alive(self):
        self.sim.invalidate()
        try:
            _ = self.sim.secure
            return True
        except Exception:
            return False

    def _maybe_rearm(self, why=""):
        """V-19 bench parity: after every board revival (the pre-PoC
        hard_reset, a mid-PoC RESETC that reboots the craft under us, a
        POWERCYCLE, a REBOOT), re-arm the board's mission model / FDIR /
        schedule / FEED phase to the revival instant (LAB_CTRL sub 4,
        extcmds.cpp): thrusters back to the volatile idle 10/10, attitude
        reset, FDIR cold re-arm WITHOUT the release-window gate, the
        flash-resident schedule grid due-now (first fire on the next 1 Hz
        tick) and the FEED phase pinned so its first tick lands at exactly
        +1000 ms. The simulator's _cold_boot restarts the virtual clock
        at the reset instant; the real board boots ~5 s of model time at
        the 1.0x bench scale, so without the re-arm the board's FDIR
        release window, schedule 'due' grid and 1 Hz FEED phase are
        offset from the simulator's by the boot duration (v119: the
        flash-resident 2 s entry replayed, but on the board's own grid,
        and the post-reset verdict read missed the thruster=255 window).
        Success gate: the sub 4 'R' ack TM -- the board-side proof the
        re-arm ran. Returns False if the board stays silent; the caller's
        next request then surfaces the failure as usual."""
        if getattr(self, "_rearm_in_progress", False):
            return False
        if why:
            self.ev.log(f"--> REARM (bench parity: {why})")
        self._rearm_in_progress = True
        try:
            t0 = time.time()
            while time.time() - t0 < 10.0:
                try:
                    frames = self._request(self._lab_ctrl(bytes([4])),
                                           quiet_s=0.05, stop_on=0x27)
                    for f in frames:
                        pkt = (fs.spp_unpack(f[1:]) if f[:1] == b"\xAA"
                               else fs.spp_unpack(f))
                        if pkt and pkt["apid"] == 0x27:
                            self.sim.invalidate()
                            self._adv_anchor = None
                            return True
                except Exception:
                    pass
                time.sleep(0.5)
            return False
        finally:
            self._rearm_in_progress = False

    def _flash_recovery(self):
        """Bench recovery for a board whose core0 is wedged (no response
        to the LAB control channel): the 1200-baud touch re-enters BOOTSEL,
        the lab image is re-flashed, and the craft comes back in its
        powered-on state -- the bench equivalent of pulling the rails."""
        import glob
        import subprocess

        import serial
        root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        uf2 = os.environ.get("FLATSAT_UF2") or os.path.join(
            root, "firmware", ".pio", "build", "pico_tinyusb", "firmware.uf2")
        if not os.path.exists(uf2):
            return False
        self.ev.log(">> bench recovery: re-flashing the lab image via BOOTSEL")
        # Two gotchas, both hit live by v109:
        #  * the auto-reset RC circuit hangs off the CONSOLE interface
        #    (if00) DTR/RTS -- a touch on the radio-link interface (if02)
        #    does nothing, and the by-id readdir order is NOT stable, so
        #    pick if00 explicitly;
        #  * the kernel's cdc_acm sends SET_CONTROL_LINE_STATE only on the
        #    FIRST open / LAST close of a port: while our console-pump
        #    handle holds if00 open, a touch handle's open/close generates
        #    no USB control request at all -> no DTR/RTS pulse -> no
        #    reset.  Release the pump console first (the pump thread ids
        #    safely on the is_open check), then restore it after the flash.
        console = None
        for p in glob.glob("/dev/serial/by-id/*"):
            if p.endswith("if00"):
                console = os.path.realpath(p)
                break
        if console is None:
            return False
        pump_console = self.console
        self.console = None
        if pump_console is not None:
            try:
                pump_console.dtr = False
                pump_console.rts = False
                pump_console.close()
            except Exception:
                pass
            time.sleep(0.3)     # let the auto-reset RC network settle
        seen_bootsel = False
        for _ in range(6):
            try:
                s = _serial_open_bounded(console, 1200, timeout=1,
                                         write_timeout=1.0, max_wait=8.0)
                s.close()
            except Exception:
                pass
            time.sleep(1.5)
            if "2e8a:0003" in subprocess.run(["lsusb"], capture_output=True,
                                             text=True).stdout:
                seen_bootsel = True
                break
        if not seen_bootsel:
            return False
        dev = None
        t0 = time.time()
        while time.time() - t0 < 25:
            out = subprocess.run(["lsblk", "-d", "-o", "NAME,VENDOR"],
                                 capture_output=True, text=True).stdout
            for line in out.splitlines():
                if "RPI" in line:
                    dev = "/dev/" + line.split()[0]
                    break
            if dev:
                break
            time.sleep(1.0)
        if dev is None:
            return False
        subprocess.run(["sudo", "umount", "/mnt/rp2"], capture_output=True)
        mounted = False
        for part in (dev + "1", dev):
            if subprocess.run(["sudo", "mount", part, "/mnt/rp2"],
                              capture_output=True).returncode == 0:
                mounted = True
                break
        if not mounted:
            return False
        subprocess.run(["sudo", "cp", uf2, "/mnt/rp2/"], capture_output=True)
        subprocess.run(["sync"])
        subprocess.run(["sudo", "umount", "/mnt/rp2"], capture_output=True)
        time.sleep(8)
        try:
            self.ser = serial_open_retry(self.port, self.baud, timeout=60.0)
            self.open_console()
            self._silent = False
            self._port_gone = False
            self.sim.invalidate()
            self.sync_from_board()
            return True
        except Exception:
            return False

    # -- lifecycle ----------------------------------------------------------
    def hard_reset(self):
        """Pre-PoC bench parity: brownout-reset the board (LAB_CTRL sub 2)
        so every PoC starts from a freshly powered-on state, exactly like
        each simulator run starts from a fresh sim. No interactive prompt:
        on a dead port the caller's first request surfaces the failure."""
        self.ev.log("--> HARD RESET (bench parity: fresh board per PoC)")
        try:
            self._request(self._lab_ctrl(bytes([2])), quiet_s=0.5)
        except Exception:
            pass
        time.sleep(1.0)
        revived = False
        try:
            self.ser = serial_open_retry(self.port, self.baud,
                                         wait_gone=4.0, timeout=40.0)
            self.open_console()
            self._silent = False
            self._port_gone = False
            self.sim.invalidate()
            self.sync_from_board()     # resync after the reboot
            revived = True
            with self._rx_lock:
                del self._rx[:]        # drop pre-reboot bytes: stale frames
                                       # would poison the first verdict window
                self._rx_tail = bytearray()   # and any half-walked frame,
                                              # or it would prepend to the
                                              # next session's first bytes
        except Exception:
            # brownout reboot did not resurrect the craft (wedged core0):
            # escalate to the BOOTSEL re-flash, then to a power cycle wait
            revived = (self._flash_recovery() or self._wait_for_revive())
            self._port_gone = not revived
        if revived:
            # Force the simulator boot defaults over the trusted USB bus:
            # scratch cookies, FDIR state or leftover config from a previous
            # PoC must not leak into this one (the simulator instance is
            # always fresh, the board is not).
            self._bench_defaults()
            self._bench_gps_fix()      # bench parity: attached-u-blox state
            # The real boot just integrated ~5 s of model time at the 1.0x
            # bench scale: re-arm the model/FDIR/schedule/FEED phase to
            # "now" so the board starts the PoC exactly where the fresh
            # simulator starts (V-19 bench parity).
            self._maybe_rearm("fresh board, pre-PoC")

    def _bench_defaults(self):
        """Drive the craft back to the simulator's boot defaults through the
        trusted USB path (cleartext parses whether or not the secure link is
        up). Ends with the secure link re-enabled, mirroring a fresh sim."""
        # The sequence below explicitly (re)sets every state and verifies
        # the end result: it IS the resync, so suppress per-TC resyncs.
        self._state_dirty = False
        seq = [
            (0x0A, b"\x00", None),         # secure off (wrap iff link is ON --
                                           # self.secure mirrors the board)
            (0x1D, bytes([1, 1]), False),  # FDIR armed
            (0x11, b"\x00", False),        # GS mode off
            (0x15, b"\x00\x10\x05", False),  # SDLS off, ARC 16 bits / window 5
            (0x0D, b"\x01", False),        # mission mode NOMINAL
            (0x1D, bytes([3]), False),     # exit safe mode if a mission-model
                                           # trigger caught the craft before
                                           # the defaults landed (relaxed ARC
                                           # and null-cipher would skew the PoC)
            (0x1D, bytes([10, 2, 0x58]), False),  # mission time scale
                                                # 0x0258/10 = 60.0x = the
                                                # simulator's cold-boot
                                                # default (sim time_scale
                                                # 60.0). The old 1.0x pin was
                                                # a workaround for the
                                                # continuous-model problem:
                                                # at 60x, running in real
                                                # time outside the windows,
                                                # FDIR fired minutes after
                                                # every boot. Now safe: the
                                                # board's model dynamics are
                                                # gated to the FEED windows
                                                # (LAB_CTRL sub 6, sent by
                                                # _advance), so the 60x rate
                                                # only plays out inside
                                                # advance() -- identical to
                                                # the simulator.
            (0x10, b"\x00", False),        # USB debug off
            (0x21, b"\x00", False),        # covert padding off
            (0x24, b"\x00\x00", False), (0x24, b"\x01\x00", False),  # heaters
            (0x24, b"\x02\x00", False), (0x24, b"\x03\x00", False),
            (0x25, bytes([0, 0x80]), False),  # defenses: anomaly monitor only
            (0x1E, bytes([1]), False),        # wipe NOR-persisted sched
                                              # queue (V-19 leftovers flood
                                              # the craft after every boot)
            (0x1D, bytes([11]), False),       # FDICT factory reset (V-20
                                              # bench parity): the burned
                                              # contingency-dictionary hash
                                              # lock is flash-persisted and
                                              # has NO wire unlock (the
                                              # burned lock IS the finding),
                                              # so the prologue restores the
                                              # simulator's cold-boot
                                              # reference after every PoC:
                                              # default table, hash wiped,
                                              # lock released.
            (0x05, bytes([18]), False),    # beacon cadence back to the sim
                                           # boot default (18 s). (This 1-byte
                                           # TC arrived as interval 0 -- a
                                           # 500/s beacon storm -- while the
                                           # spp 1-byte unpack bug was in the
                                           # firmware; the fix makes [18] land
                                           # exactly like the simulator's.)
            # OTA flash state back to the sim cold boot (V-38 bench parity):
            # the ARWC counter lives in the board's meta sector and every
            # v138 run zeroes it, so without this restore the NEXT PoC's
            # boot carries arwc=0 and v138's "counter starts at 7" check
            # fails. Written while the secure engine is still OFF (the
            # final 0x0A below re-enables it) so both TCs parse in clear.
            # The sub-6 MANIFEST [6][sig8][arwc BE32][require] restores
            # arwc=7 AND sig_required=0 in one TC (sim cold boot: arwc 7,
            # active_slot 0, sig_required 0). A prior OTA PoC left
            # sig_required=1 in the board's meta sector, so without this the
            # board rejects v138's unsigned old-image finalize (ok=0) where
            # the simulator accepts it.
            (0x1F, bytes([6]) + bytes(8) + struct.pack(">I", 7)
                  + bytes([0]), False),       # MANIFEST: arwc=7, sig_req=0
            (0x1F, bytes([5]), False),        # rollback: slot A / no pending
            (0x0A, b"\x01", False),        # secure link back ON (sim default)
        ]
        for apid, body, enc in seq:
            try:
                if apid in (0x15, 0x1D):  # ack-verified: these silently
                    r = self._tc_ack(apid, body, apid)  # drop under flood
                else:
                    r = self.tc(apid, body, via="usb", encrypt=enc)
            except Exception:
                pass
        # Flood servo: on silicon the beacon cadence occasionally latches a
        # storm state (beacon every worker tick). It is fully silentable via
        # SET_BEACON_RATE, so measure and re-arm if the craft is flooding.
        for _ in range(3):
            try:
                n, t1 = 0, time.time()
                while time.time() - t1 < 5.0:
                    for f in self._read_frames(0.4):
                        pkt = (fs.spp_unpack(f[1:]) if f[:1] == b"\xAA"
                               else fs.spp_unpack(f))
                        if pkt and pkt["apid"] == 0x01 and pkt["len"] == 64:
                            n += 1
                if n < 25:
                    break
                self.ev.log(f"--> beacon flood ({n / 5.0:.0f}/s): "
                            f"re-arming cadence")
                self.tc(0x05, bytes([18]), via="usb", encrypt=False)
            except Exception:
                break
        # The last default (secure link ON) is the one TC that MUST land:
        # every later AES-wrapped command becomes a garbage sub-byte on a
        # board whose link is still off (silent "SDLS OTA SUB?" failures).
        # Verify the REAL board state and re-issue in the clear if needed.
        for _ in range(4):
            try:
                st = self.sim._need()
                if st[2] & 1:
                    break
                self.ev.log("--> secure link not up on board: re-issuing AES_CONFIG(1)")
                self.tc(0x0A, b"\x01", via="usb", encrypt=False)
                time.sleep(0.5)
            except Exception:
                break
        try:
            self.secure = bool(self.sim._need()[2] & 1)
        except Exception:
            pass
        if not self.secure:
            self.ev.log("--> WARN: board secure link stuck OFF (flood losses); "
                        f"this PoC may run against a plaintext pipeline")
        self.usb_debug = False
        self.sim.invalidate()

    def _bench_gps_fix(self):
        """The simulator boots with an attached GPS holding a fix near the
        ground station; the bench board usually has no u-blox on UART and
        falls back to zero coordinates -- which silently trips every GPS
        gate (GS auth, V-05 reject counting). Inject the simulator's boot
        fix through the GPS_OVERRIDE TC so both targets start identical."""
        import struct as _st
        body = _st.pack("<iiiB", 361000000, -1152000000, 400000, 8)
        try:
            self.tc(0x14, body, via="usb")
        except Exception:
            pass

    def _wait_for_revive(self, timeout=600.0):
        """A hard-hung RP2040 (both cores wedged) is deaf to every
        software reset: only a power event saves it. Poll until the
        operator unplug/replugs the cable and the craft answers again."""
        self.ev.log(">> board dead: awaiting a PHYSICAL power cycle "
                    "(unplug/replug the USB cable), up to 10 min")
        try:
            self.ser.close()
        except Exception:
            pass
        t0 = time.time()
        while time.time() - t0 < timeout:
            time.sleep(2.0)
            try:
                self.ser = serial_open_retry(self.port, self.baud, timeout=3.0)
                self.open_console()
                self.sim.invalidate()
                if self.probe_alive():
                    self._silent = False
                    self._port_gone = False
                    self.ev.log(">> board is back -- power cycle confirmed")
                    return True
            except Exception:
                pass
        return False

    def powercycle(self):
        self.ev.log("--> POWER CYCLE (scratch + SRAM die, flash survives)")
        alive = True
        if self._silent:            # crashed boards answer to nobody
            alive = False
        else:
            try:
                self._request(self._lab_ctrl(bytes([2])), quiet_s=0.4)
            except Exception:
                alive = False
        if not alive:
            if not self._flash_recovery():
                if not self._wait_for_revive():
                    raise RuntimeError(
                        "board is dead: no recovery and no power cycle")
        else:
            self.ser = serial_open_retry(self.port, self.baud, wait_gone=6.0)
            self.open_console()
        self.secure = True
        self.usb_debug = False
        self._silent = False
        self.sim.invalidate()
        self._adv_anchor = None        # fresh virtual grid per revival
        # The craft is mid-reboot: the next tc() must re-sync (and wait out
        # the boot window) before wrapping.
        self._state_dirty = True
        self._maybe_rearm("post-POWERCYCLE")
        # Simulator cold boot holds an attached-u-blox fix; the bench board
        # has no u-blox on UART, so re-inject the bench fix after every
        # power event (v126: "GPS back after power cycle (RAM-only effect)").
        self._bench_gps_fix()

    def reboot(self):
        """Soft reboot via LAB_CTRL sub 3 (watchdog scratch survives)."""
        try:
            self._request(self._lab_ctrl(bytes([3])), quiet_s=0.5)
        except Exception:
            pass
        self.ser = serial_open_retry(self.port, self.baud, wait_gone=6.0)
        self.open_console()
        self.sim.invalidate()
        self._adv_anchor = None        # fresh virtual grid per revival
        self._maybe_rearm("post-REBOOT")
        self._bench_gps_fix()          # sim cold boot keeps the u-blox fix


def _serial_open_bounded(port, baud, timeout=0.05, write_timeout=5.0,
                         max_wait=12.0):
    """serial.Serial() can block INDEFINITELY inside the kernel when the
    device NAKs its control transfers (post-boot window after a brownout
    reboot, or the zombie state of V0-03/V0-15): cdc_acm's open() then
    spins on port activation with no timeout, and every retry loop that
    calls it wedges the whole PoC (observed: 420 s hangs with a healthy
    device on the bus). Open in a worker thread and abandon the attempt
    after max_wait: the caller's retry loop iterates (and can log)
    instead of the process stalling in-kernel. On a real zombie the
    abandoned attempts just leak daemon threads -- the documented
    recovery (power cycle) is unchanged."""
    import serial
    box = {}

    def _worker():
        try:
            box["s"] = serial.Serial(port, baud, timeout=timeout,
                                     write_timeout=write_timeout)
        except Exception as e:  # noqa: BLE001
            box["err"] = e

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(max_wait)
    if not t.is_alive():
        if "err" in box:
            raise box["err"]
        return box["s"]
    raise serial.SerialException(
        f"port {port} open blocked in kernel > {max_wait:.0f} s "
        f"(device not ready or zombie state?)")


def serial_open_retry(port, baud, wait_gone=0.0, timeout=30.0):
    """Re-open the CDC bridge port across a device reboot/re-enumeration."""
    import serial
    t0 = time.time()
    if wait_gone:
        tg = time.time()
        while time.time() - tg < wait_gone:
            try:
                s = _serial_open_bounded(_resolve_bridge_port(port), baud,
                                         timeout=1, write_timeout=1.0,
                                         max_wait=8.0)
                s.close()
                time.sleep(0.2)          # still there -> not gone yet
            except Exception:
                break                     # gone: proceed to wait for return
    while time.time() - t0 < timeout:
        try:
            # timeout=0.05 (NOT 2): _rx_pump() does read(8192) on this port,
            # and pyserial's read(n) waits up to the port timeout for n
            # bytes even when data has already arrived.  With timeout=2 the
            # pump batched every ~2 s of arrivals into one queue deposit,
            # which (a) made 1 s beacons appear in 0 ms "pairs" every
            # 2.000 s on the wire log and (b) shifted individual frames up
            # to ~2 s later than their true arrival, so v106's cadence
            # gaps measured nominal-1 s.  50 ms makes the pump a tight
            # poller: attribution error <= ~70 ms (pump + 20 ms drain).
            # _serial_open_bounded: the kernel open itself can block
            # indefinitely (device NAKing control transfers); abandon
            # after 12 s so this loop actually retries.
            s = _serial_open_bounded(_resolve_bridge_port(port), baud,
                                     timeout=0.05, write_timeout=5.0)
            # Never let a write block forever: the device NAKs OUT while its
            # drain is stalled (console DTR lost, reboot in flight); fail
            # fast so _xfer can reopen instead of wedging the PoC.
            s.write_timeout = 5
            time.sleep(0.3)
            s.reset_input_buffer()
            return s
        except Exception:
            time.sleep(0.4)
    raise RuntimeError(f"port {port} did not come back within {timeout}s")


class _DictView:
    def __init__(self, getter):
        self._g = getter

    def __getitem__(self, k):
        return self._g()[k]


class RemoteSim:
    """dev.sim replacement over the wire, backed by LAB_STATUS."""

    def __init__(self, dev):
        self.dev = dev
        self._d = None

    def invalidate(self):
        self._d = None

    def _f(self):
        if self._d is None:
            self._d = self.dev.fetch_status()
        return self._d

    def _need(self):
        d = self._f()
        if d is None:
            raise AssertionError("LAB_STATUS unreachable (board silent?)")
        return d

    # plain sim attribute parity -------------------------------------------
    @property
    def state(self):
        d = self._f()
        if d is None:
            return "NO RESPONSE"
        return ("RUN", "CRASHED", "HANGED")[d[1] % 3]

    @property
    def secure(self):
        return bool(self._need()[2] & 1)

    @property
    def usb_debug(self):
        return bool(self._need()[2] & 2)

    @property
    def sdls_enabled(self):
        # LAB_STATUS offset 40 = flags2 (bit0 = SDLS enabled)
        return bool(self._need()[40] & 1)

    @property
    def gs_mode(self):
        return bool(self._need()[2] & 4)

    @property
    def payload_armed(self):
        return bool(self._need()[2] & 16)

    def _gs_session_active(self):
        return bool(self._need()[2] & 8)

    @property
    def mode(self):
        return self._need()[3]

    @property
    def pad_mode(self):
        return self._need()[4]

    @property
    def boot_count(self):
        return struct.unpack("<I", self._need()[10:14])[0]

    @property
    def now_ms(self):
        return struct.unpack("<I", self._need()[14:18])[0]

    @property
    def gs_challenge(self):
        return struct.unpack("<I", self._need()[18:22])[0]

    @property
    def mm(self):
        return _DictView(lambda: {
            "bus_v": struct.unpack("<f", self._need()[22:26])[0],
            "pct": self._need()[41],
            "power_w": struct.unpack("<f", self._need()[42:46])[0],
            "tilt": struct.unpack("<f", self._need()[46:50])[0],
        })

    @property
    def gps(self):
        d = self._need()
        return {"reject": struct.unpack("<H", d[6:8])[0],
                "sats": d[8], "fix": bool(d[9])}

    @property
    def flash(self):
        d = self._need()
        return {"ota": {"hash": bytes(d[26:34]),
                        "pending_boot": d[34]}}

    def __repr__(self):
        return f"RemoteSim({self._f()!r})"


class Evidence:
    def __init__(self, title, verbose=True):
        self.title = title
        self.lines = []
        self.verbose = verbose
        self.t0 = time.time()

    def log(self, s):
        line = f"[{time.time() - self.t0:8.3f}] {s}"
        self.lines.append(line)
        if self.verbose:
            print(line)

    def banner(self, s):
        self.log("=" * 72)
        self.log(s)
        self.log("=" * 72)

    def dump(self, path=None):
        if path:
            with open(path, "w") as f:
                f.write("\n".join(self.lines) + "\n")
            print(f"[evidence saved to {path}]")


def default_evidence_path(poc_file, hw=False):
    # The SIM evidence (what the writeups cite) lives in evidence/; hardware
    # transcripts belong in evidence-hw/. Routing hw runs there keeps the two
    # evidence trees from clobbering each other when a sweep and a sim run
    # interleave (a hw PoC that dumped into evidence/ once made a genuine
    # hardware failure look like a "sim regression" in the verdict bookkeeping).
    ev_dir = os.path.join(_ROOT, "evidence-hw" if hw else "evidence")
    os.makedirs(ev_dir, exist_ok=True)
    name = os.path.splitext(os.path.basename(poc_file))[0]
    return os.path.join(ev_dir, name + ".txt")


def make_parser(title):
    p = argparse.ArgumentParser(description=title)
    p.add_argument("--usb", action="store_true",
                   help="use a physical FlatSat over USB-CDC")
    p.add_argument("--port", default="/dev/ttyACM0")
    p.add_argument("--no-save", action="store_true")
    p.add_argument("--quiet", action="store_true")
    return p


def open_device(args, evidence):
    if args.usb:
        return UsbDevice(evidence, args.port)
    return SimDevice(evidence)


class PocFail(AssertionError):
    pass


def check(cond, msg):
    if not cond:
        raise PocFail("CHECK FAILED: " + msg)


def run_poc(script_file, title, main_fn):
    """Boilerplate: parse args, run main(dev, ev), save evidence, verdict."""
    ap = make_parser(title)
    args = ap.parse_args()
    ev = Evidence(title, verbose=not args.quiet)
    ev.banner(title)
    ok = False
    dev = None
    try:
        dev = open_device(args, ev)
        if getattr(dev, "hw", False):
            dev.hard_reset()   # fresh powered-on board == fresh simulator
            if not dev.probe_alive():
                # the previous PoC may have hung the craft: give the
                # operator a chance to power-cycle it before bailing out
                if not dev._wait_for_revive():
                    raise RuntimeError("board unhealthy after hard reset: "
                                       "needs a power cycle before this PoC")
                dev.hard_reset()
        main_fn(dev, ev)
        ok = True
    except PocFail as e:
        ev.log(str(e))
    except Exception as e:  # noqa: BLE001
        ev.log(f"POC ERROR: {type(e).__name__}: {e}")
        import traceback
        tb = traceback.format_exc()
        for ln in tb.splitlines():
            ev.log("  " + ln)
    if dev is not None and getattr(dev, "hw", False):
        # the on-board console is the ground truth for firmware-side
        # rejections: fold its last warnings/errors into the evidence
        try:
            con = dev.console_tail(80000).decode("latin-1", "replace")
            keep = [ln.strip() for ln in con.splitlines()
                    if any(k in ln for k in ("[ERROR]", "[WARN]", "[FATAL]",
                                             "[INFO]", "[TC - SPP]"))]
            if keep:
                ev.log("-- console tail: " + " | ".join(keep[-14:]))
        except Exception:
            pass
    ev.banner("POC OK" if ok else "POC FAILED")
    if not args.no_save:
        ev.dump(default_evidence_path(script_file, hw=getattr(dev, "hw", False)))
    print("POC OK" if ok else "POC FAILED")
    return 0 if ok else 1
