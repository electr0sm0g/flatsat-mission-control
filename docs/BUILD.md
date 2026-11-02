# BUILD — building & checking the flatsat-lab artifacts

## 1. Firmware (real hardware)

Target: Raspberry Pi Pico (RP2040) + 2×SX1262 (uplink 918 MHz / downlink
916 MHz), BME280 + LIS2DH12 on I2C, GPS on UART1, WS2812 LED, 4 MB external
QSPI NOR (OTA A/B slots live there at raw offsets 0x200000 / 0x3FC000 — the
internal XIP window stays the stock 2 MB image, see `platformio.ini` notes).

```bash
cd firmware
pio run                    # env pico_tinyusb (earlephilhower core, USE_TINYUSB)
pio run -t upload          # UF2 path unchanged from upstream v1.0.3
```

> **Verified 2026-10-30**: `pio run` SUCCESS on the full v2 tree
> (RAM 21.7 %, Flash 7.3 %, UF2 at `.pio/build/pico_tinyusb/firmware.uf2`).
> This hardware build exposed and fixed three real-silicon bugs that the
> host syntax gate could not see: an `ARDUINO_ARCH_RP2042` macro typo that
> silently disabled watchdog scratch / VTOR / reboot paths, two `volatile`
> pointer casts in `memserv.cpp`, and a 34-vs-35-byte off-by-one in the
> PAYLOAD_SNAP response (`hSnap`). Bench services `LAB_STATUS` (0x26) and
> `LAB_CTRL` (0x27, USB-only radio-injection + power-cycle) were added for
> the hardware PoC sweep -- see `docs/HARDWARE-USB-TEST.md`.

> **Verified 2026-10-31 (sweep pass 2)**: the live USB validation of all 56
> PoCs against the board exposed three more silicon/simulator divergences,
> each fixed in firmware and re-validated on both transports:
> (a) `spp_unpack_packet` dropped 1-byte payloads to zero (data copy gated
> on `length > 0`, but a 1-byte frame has `length == 0`) — the root cause
> of the on-board beacon storm and the lost 1-byte SDLS ARC reset;
> (b) the worker's beacon worker now enforces the simulator's 100 ms
> floor (bench parity for interval-0 "chatty beacon", which the uncapped
> silicon loop turned into a ~500 Hz core0 saturating storm);
> (c) the SDLS MAC tag was compared little-endian on silicon against the
> big-endian pipeline output. Clean-build rule: `rm -rf .pio/build &&
> pio run` — a genuine build produces 362 `.o` files; verify timestamps
> before flashing. Full notes: `docs/HARDWARE-USB-TEST.md` §4bis.

> **Verified 2026-10-31 (sweep pass 3)**: two more real-silicon fixes:
> (d) a multi-core TinyUSB CDC race — core1 polling the bridge RX while
> core0 wrote TMs on the same CDC wedged core1 after the first MEM_READ
> (craft telemetered but deaf to TCs until power cycle); USB RX parsing
> moved to core0 (`loop()`), core1 now only ticks a liveness counter
> (`CORE1 STALLED` console alarm), plus a 50 ms bridge-CDC read timeout;
> (e) `memservRead`/`memservCopy` now serve the simulator's symbolic
> address windows (GS challenge, SA0 key, ARC counter, log name, leak
> pool, master keys) from the live lab state — the read-side twin of
> `modelledPeripheralWrite()` — so v105's `sa0_key == LINK_KEY` check
> passes on hardware. The 14-address MEM_READ ladder (including v105's
> exact kill sequence) completes with the board alive.

> **Verified 2026-10-31 (sweep pass 4)**: no further firmware changes —
> v106 (pass cadence) and v109 (SPI hang) resolved as bench-transport
> artifacts, both fixed in `poc/lib/fslab.py`: (f) the bridge port
> `timeout=0.05` (pyserial's `read(n)` waits the full port timeout even
> with data present — `timeout=2` batched ~2 s of arrivals per pump
> deposit) plus the bulk-walker `_read_frames` (512-byte chunks, partial
> tail carried across calls) and early-return `_qread` — the byte-grind
> drain had lagged the 1 s beacon stream ~0.2 s/s and booked cadence TMs
> 1–2 s late; the board itself was measured exact (1.0000× clock,
> 14.00/22.00/30.00/1.00 s by raw arrival-time booking); v106 now
> asserts N±1 s per gap + mean (the bench books frames in the 1 s window
> they arrive in; the sim still measures exactly 14/22/20/30);
> (g) `_flash_recovery` now touches the console interface (if00)
> explicitly and releases the pump console's DTR/RTS before the 1200-baud
> touch (cdc_acm does not resend `SET_CONTROL_LINE_STATE` while another
> handle holds the port) — v109 recovers in-PoC via BOOTSEL re-flash, or
> by operator replug when the fault wedges the USB IRQ itself. Full
> notes: `docs/HARDWARE-USB-TEST.md` §4bis.7–8.

 > **Verified 2026-10-31 (sweep pass 5)**: the V-11/V-24/V-28/V-30…V-37
 > hardware re-run exposed four more silicon/simulator divergences, each
 > fixed in firmware (semantics preserved; the simulator is unchanged and
 > re-swept 56/56 green) plus one harness bug:
 > (h) DEF_TM_CTR now applies to EVERY TM from the common builder
 > `telemetrySPPBuildPacketEx` (counter = `sppTmCounterPeek()`), not only
 > the lab-TM path — before, the 0x0C status / periodic TMs stayed ECB on
 > silicon while the reference model was "CTR everywhere" (v111);
 > (i) the GS challenge is seeded from `labLastLabSyncMs()` (the
 > GS-synced mission clock, `millis()` cold fallback) with the UTC term
 > derived from it — the bench GPS is frozen (no NMEA), so the live-nav
 > seed broke the ground station's challenge prediction (v128 / V-28);
 > (j) the anomaly detector's TC-rate channel is fed by
 > `labCountRadioTc()` for radio-source TCs only (simulator `tc_seen`
 > parity) and the 0x1D sub-0 TM is 18 bytes with the orbit-clock second
 > at offset 17, so `rate_phase()` — virtual loop in sim, pacer thread on
 > hardware — drives the V-24 ramp identically on both transports (v124);
 > (k) `secureLinkDecodeInPlace` encodes an empty AES plaintext as the
 > `0xFFFF` sentinel so `PL` folds to 0 — the 0-byte/1-byte ambiguity of
 > the SPP length field (`payload_len - 1`) had turned every no-arg radio
 > TC into a phantom 1-byte frame (empty 0x22 enqueued a spurious covert
 > byte; v130);
 > (l) one shared VCC forward counter: `covertVccBumpUnconditional()` on
 > the 0x06 broadcast path (ungated, like the simulator) and 0x0C/0x0F
 > now expose `covertVcc()` — before, broadcast and snap bumped two
 > different counters and the telemetry showed only the broadcast one
 > (v131/v132);
 > (m) the 0x06 handler now `obcUSBTransmitFrame()`s the broadcast TM to
 > the host before the physical radio TX (the simulator's
 > `self._frame(0x06, msg)` echo was missing on silicon — v132/v135);
 > (n) the 0x07 flash dump dispatches non-blocking — the blocking radio
 > TX fails on the bench and used to break the 16-chunk loop after chunk 0
 > (v137).
 > Harness: the "radio loopback" ghost (0x06 doubling, 0x07 136–152 frames
 > from 16) was the bulk-walker `_read_frames` re-walking its accumulated
 > `tail` from `i=0` on every deposit and re-emitting every frame it had
 > already emitted — proven by the console (exactly 16 TM chunks) and
 > `FSLAB_PUMP_TRACE` (the port delivered each byte exactly once); `tail`
 > is now rebuilt from the partial-frame carry + the new chunk only.
 > Live probe on the flashed board: empty 0x22 → depth 0; vcc/last_freq
 > track snap+broadcast; exactly one 0x06 TM per broadcast TC; 16 chunks /
 > 255 B flash image with both build strings. Full notes:
 > `docs/HARDWARE-USB-TEST.md` §4bis.9–16.

> **Verified 2026-10-31 (sweep pass 6)**: seven more silicon/simulator
> divergences fixed in firmware (semantics preserved) plus three
> harness fixes — v124, the last blocker, is green on hardware, and the
> simulator was re-swept 56/56 after the harness changes:
> (o) `{ota, sched, fdict}` + fdict hash/lock now persist in a CRC16-
> guarded meta struct in the LAST 4 KB sector of the RP2040 boot flash
> (offset `0x1FC000` XIP-relative, 1792 B padded program) — the exact
> survival matrix (watchdog/NVIC/power) of the simulator's flash dict
> that V-18/19/20 assert (`flashstore.cpp`);
> (p) the SB transport tag was `0xC0FFEE11`, one `E` short of the
> reference model's `0xC0FEEE11` — the signed defence rejected the
> reference tag on hardware only (`sb.cpp`);
> (q) the 0x0C GET_STATUS TM gained the simulator's v2 extension byte
> (`flags2` at the tail) and is now the identical 27-byte TM
> (`extcmds.cpp`);
> (r) the `[TC - SPP]` console log is gated on
> `Serial.availableForWrite() < 96` — a backpressured console used to
> block core0's bridge-RX drain at the v124 ramp's 20–45 TC/s
> (`worker.cpp`);
> (s) the uplink RX handler's blocking `ledBlink(8)` (≈3.2 s of
> `delay()` per physical RX event) became `ledBlinkRequest(8, BLUE)`
> (serviced from `ledBlinkTick()`), and `getPacketLength()` is clamped
> to 0..255 (`ruplink.cpp`).
> Harness (`poc/lib/fslab.py`): (t) `_read_frames(..., stop_on=apid)`
> returns as soon as the expected same-apid TM is walked (`_SELF_ANSWER`
> = 0x01/0x0A/0x0B/0x0C/0x10/0x1A/0x1D/0x24/0x25; 0x27 excluded) — v124's
> EWMA dip was the t+60 checkpoint's ~0.9 s verdict-read overhead opening
> a real 0.93 s pacer gap the simulator's virtual clock can never
> produce, NOT firmware count loss (proven by the new cumulative `tot=`
> counter on the `[LAB] FEED` line: board tot 3072 ≈ wire 0x01 total
> 3066); the 0x1D verdict read dropped 460 ms → 51 ms and v124 is green
> on hardware (t+60/120/200 alarm=0, step→45 latches ch=1);
> (u) `0x18` (MEMCPY) joins `_FLIP_CAPABLE` — a forged FDIR trip can
> switch the AES engine OFF with no ack carrying the new value;
> (v) `_serial_open_bounded()` (worker-thread open, abandon after
> `max_wait`) replaces all four raw `serial.Serial(` sites — the kernel
> `open()/write()/close()` can block indefinitely when the device NAKs
> control transfers, and an ad-hoc port session right before a brownout
> run wedges the bridge EP so that only a physical replug recovers (the
> V0-03/V0-15 finding);
> (w) the meta-sector `flash_range_erase`/`flash_range_program` in
> `fsMetaSave` is wrapped in `rp2040.idleOtherCore()` /
> `resumeOtherCore()` (the arduino-pico framework's own RAM-resident
> core parking) + `save_and_disable_interrupts()` — a naked call
> killed the board on the FIRST meta write after boot (2/2), and the
> first fix attempt with pico-sdk's `multicore_lockout_victim_init`
> BRICKED boot by silently overwriting the framework's SIO FIFO IRQ
> vector (`flashstore.cpp`);
> (x) the VTOR readback is now served by a byte-wise software model
> initialised from a real WORD read — the Cortex-M0+ SCB registers are
> word-access only, so the raw byte-wise MEMCPY/MEM_READ PPB path never
> lands on the real `SCB->VTOR` (a byte MEM_READ of the whole
> CPUID/IPC/VTOR/AIRCR block returned `00 00 00 00`), while the
> simulator's `self.vtor` model always does (`memserv.cpp`).
> Full notes:
> `docs/HARDWARE-USB-TEST.md` §4bis.17–24.

 > **Verified 2026-10-31 (sweep pass 7, image E)**: the five remaining
 > silicon divergences behind the four board-killer-era failures (v119 /
 > v126 / v128 / v133 / v134) plus v130, each fixed in firmware and/or
 > harness with the finding semantics preserved (the simulator is
 > unchanged; the 15 affected PoCs re-swept green on both benches, 15/15):
 > (y) **v130's beacon catch-up stream** (`worker.cpp`, `poc/lib/fslab.py`):
 > the 0x05 SET_BEACON_RATE handler left `t_radio_beacon.previous` stale
 > (boot 0 / the last 12 s prologue beacon), so right after the PoC's
 > `0x05 01` the silicon fired a 1/s catch-up stream (six frames over the
 > tc read window) while the simulator's virtual clock books the first
 > beacon one tick AFTER the command; the harness' ~6.5 s tc(0x05) read
 > (4 s board-latency first-wait while periodic TMs flow) consumed the
 > stream — on the failing run six 1 s beacons drained the 63 B covert
 > FIFO before the PoC's two advance(1100) windows, which then saw only
 > zero padding (live probe 5 first proved the board DOES emit beacons —
 > `[TM - SPP] APID=0x001 LEN=80` console lines pre- and post-0x05 — so it
 > was the catch-up + long window, not a transport fault; the evidence
 > "9-frame burst in 9 ms" is a log-time artifact: tc() logs its collected
 > frames at return, not at wire arrival). Fix: the handler arms
 > `t_radio_beacon.previous = millis()` (first fire exactly one interval
 > after the command) and tc() now uses a short read profile for
 > `_NO_TM_APIDS = {0x05}` (a TC with NO ack and NO response TM: 0.45 s
 > first-wait, tight idle, no chatter extension) so it can never eat the
 > PoC's beacons. Live probe 6: tc(0x05 01) returns in 0.15 s, exactly one
 > beacon per 1.1 s window (Δmillis 1001), the full 63 B message recovered
 > from the padding — identical to the simulator's one-beacon-per-window
 > booking.
 > (z) **REARM (LAB_CTRL sub 4) + revival re-arm** (`extcmds.cpp`,
 > `poc/lib/fslab.py`, v119): the simulator's _cold_boot restarts its
 > virtual clock at the reset instant; the real board boots ~5 s of model
 > time at the 1.0x bench scale, leaving the FDIR release window, the flash
 > schedule "due" grid and the 1 Hz FEED phase offset from the simulator's
 > (v119: the planted 2 s flash-resident entry replayed, but on the board's
 > own grid the post-reset verdict read missed the thruster=255 window).
 > New sub 4 restores the just-after-reset reference state: thrusters back
 > to the volatile idle 10/10, `missionModelRearmAttitude()` (rate/euler/
 > tilt 0, detumble off), `fdirRearmColdBoot()` WITHOUT the
 > fdirRequestExit() release-window gate, `schedRearm(now)` (queue due
 > now, first fire on the next 1 Hz tick, 0xFFFF tombstones skipped) and
 > the FEED phase pinned (`s_anom_last_ms = now`, first tick exactly
 > +1000 ms) — `s_anom_last_ms` is therefore declared before `hLabCtrl`
 > (build break otherwise). The harness' `_maybe_rearm()` (success-gated on
 > the sub 4 'R' ack TM, ≤10 s loop, re-entry-guarded) runs at every
 > revival point — the pre-PoC `hard_reset()`, the `_request` stale-handle
 > retry (a mid-PoC RESETC that reboots the craft under us),
 > `powercycle()`, `reboot()` — and sets `_adv_anchor = None` per revival
 > so the next `_advance` re-anchors the virtual grid on the board's live
 > clock (`_advance` now treats a `None` anchor as "re-anchor" — the old
 > `hasattr`-only guard skipped the `_adv_k` initialisation and crashed on
 > the first post-revival advance).
 > (aa) **SYNC (LAB_CTRL sub 5) grid injection in `_advance`** (v128): the
 > GS challenge is seeded from `labLastLabStatusSync` (the GS-synced
 > mission clock), but the harness' virtual-grid patch only rewrote the
 > host-side 0x26 blob — the board seeded from its own `millis()` (seed
 > 34944 vs grid 71944, delta 37000 s), so the PoC's predicted challenge
 > could never match on silicon. `_advance` now injects the SAME grid
 > (u32 LE) into `labMarkLabStatusSync` via a fire-and-forget sub 5 write
 > right after the blob patch — the 0x27 ack is a bench-transport artifact
 > (the simulator never emits 0x27) stripped by `_lab_ack` / the PoC's
 > apid filters, and the cadence window itself never blocks. The grid blob
 > patch itself stays (v106 cadence attribution).
 > (ab) **GPS kill** (`sensors.cpp` / `memserv.cpp`, v126): `labGpsKill()`
 > — a RAM-only flag whose branch runs FIRST in `gpsRead` (`memset(nav,0)`
 > + `hasDateTime = true` → GPS status 0x10, TIME_VALID preserved, the
 > simulator's exact zeroing of uart/conn/nmea/fix + data) — triggered from
 > the MGPIO byte-write branch, with the raw-store skip for 0x40014000
 > (= the USBCTRL base on RP2040, not a GPIO) so the write lands as the
 > bus-injection semantics, not as a register store.
 > (ac) **per-TC thruster impulse** (`worker.cpp`, v133): both 0x04
 > branches now apply `rate[tid] += 0.3 * pw / 255` guarded by
 > `power != 0` (the simulator's `if pw:` semantics) — the 30 cheap TCs
 > integrate 9.0 deg/s and trip FDIR on the board, as in the simulator.
 > (ad) **`battery_pct` as float** (`mission_model.*` / `extcmds.cpp`,
 > v134): the mission model now integrates the battery unrounded (float)
 > with the brownout trip at `<= 0.0f`; quantisation to the reported
 > uint8 happens only at report time (the `img[20]` cast, the 0x24
 > brace-init and the 0x26 blob — all `int(pct) & 0xFF` like the sim),
 > removing the integer-truncation fixed point at pct≈33 that used to
 > stop the rail drain before the reset.
 > UF2: 334848 B, md5 `6e9ae2dc0816acc2fc995a586d16fed4` (image E). Full
 > notes: `docs/HARDWARE-USB-TEST.md` §4bis.25.

 > **Verified 2026-10-31 (sweep pass 8, image G)**: the four remaining
 > silicon divergences behind the image-F 17-item re-sweep failures (v119
 > / v130 / v106 / v120), each fixed in firmware and/or harness with the
 > finding semantics preserved (the PoC code is unchanged; the full 56-item
 > simulator sweep re-ran 56/56 green; the hardware sweep on image G is the
 > new `evidence-hw/` baseline — v003 and v015 excepted (the two PoCs that
 > drive the V0-03 poisoned-broadcast crash: v015 is its no-watchdog
 > sibling). On image G that crash deterministically takes down the USB
 > stack itself (3/3 total wedges for v003; 1/1 for v015, DTR NAK'd,
 > replug-only) so the PoCs need the operator's physical replug inside
 > their 10-min revival window; their `evidence-hw/` transcripts are the
 > image-E/F runs where that replug landed in time (v003: BOOTSEL recovery
 > failed, "board is back -- power cycle confirmed", POC OK in 540 s;
 > v015: 5 silent minutes, POC OK in 618 s) — the findings'
 > transport-level semantics (crash -> craft permanently deaf -> no
 > watchdog recovery -> only a power cycle restores it) are unchanged, and
 > image G if anything sharpens the impact: the wild copy now kills the
 > whole board, not just the mission core):
 > (ae) **the image-F fixes, re-validated** — carried forward from the
 > image-E era and confirmed on the 17-item re-sweep: the non-blocking
 > `ledBlinkRequest(8, ...)` for the SPP-unpack error path (v014; the v115
 > AES-FAIL blink stays BLOCKING — that IS the finding's DoS), the detumble
 > `damp = want * 10.0f` (v133), the per-error `tc()` re-send on "AES
 > DECRYPT FAIL" (v115, ≤3 retries), the `_request` stale-handle revival
 > (resync shadow → re-arm → GPS fix → rewrap the original frame, v134),
 > and the `_bench_defaults` OTA restore (sub-6 MANIFEST arwc=7 +
 > sig_required=0, sub-5 rollback, v138). Full notes:
 > `docs/HARDWARE-USB-TEST.md` §4bis.26.
 > (af) **bench dynamics on a window-only clock (v119 / v130 / v106)** —
 > the simulator's `_workers_tick` (mission model, FDIR, schedule queue,
 > periodic radio TMs) advances ONLY inside `advance()`; the board ran all
 > of it in real `millis()` time — plus a prologue time-scale gap (the
 > prologue pinned 1.0x, the sim's cold boot is 60.0x, and `run_poc` runs
 > the prologue on hw only). At 1.0x the v119 planted 2 s queue's t1=255
 > torque nets ~+0.02 deg/s per 100 ms tick (+0.3 kick per 2 s fire) and
 > never reaches the 5.0 deg/s FDIR TUMBLE threshold inside the PoC's
 > windows; at 60.0x it crosses in ~0.5 s of model time and latches TUMBLE
 > ~0.9 s into the final window. Fix: a window-only EPOCH clock. New LAB
 > CTRL sub 6 `FEED_START [6][u32 LE window_ms]` (written fire-and-forget
 > by `_advance` at window START, mirroring the window-END SYNC sub 5):
 > `s_bench_ms` advances 1:1 with wall time ONLY while the window is open,
 > and the window self-terminates at its bench deadline (the trailing SYNC
 > write carries USB latency and would run the model past the window end).
 > The mission model (`missionModelTick` + `missionModelTickReset()`), FDIR
 > (`fdirTick`: TUMBLE 2000 ms / safe-entry / release window all in
 > bench-ms), the schedule queue (due on the bench-second grid, run on
 > bench-second boundary crossings; removed from the real-time 1 Hz
 > anomaly block, which stays unchanged for v124 EWMA parity) and all five
 > periodic radio workers (`telemetryRadioWorker` gated on
 > `labFeedActive()`, all `.previous` fields bench-ms stamps; the 0x05
 > handler arms `previous = labBenchMs()`) now advance only on that clock
 > — exactly where the simulator does. A cold-boot replay or harness REARM
 > (sub 4) marks the queue PENDING (`s_sched_epoch_pending`); the first
 > FEED after it consumes the epoch: bench clock restarts at 0, queue due
 > at the epoch second, radio worker phase re-zeroed
 > (`labResetRadioWorkerPhase`) — the sim's `_cold_boot`
 > (`e["due"] = now_ms//1000`, `t_prev = 0`) on the same clock. The
 > prologue time scale is restored to the sim cold-boot 60.0
 > (`[10, 0x02, 0x58]`): the old 1.0x pin was a workaround for the
 > continuous-model problem and is safe once gated. Live: v119 POC OK
 > (FDIR TUMBLE latches ~0.9–1.0 s into the final 2500 ms window — sim:
 > 0.9 s; t1 zeroed, and the post-latch cleartext beacons resync the stale
 > harness shadow so the final 0x0C lands cleartext); v130 POC OK (no
 > stray out-of-window beacon drains the covert FIFO before the 2.2 s
 > drain window); v106 POC OK (measured cadence 14.0/20.0/22.0/30.0 s —
 > was mean 21.3/22.5/21.4 s + ~0.6 s phase wander).
 > (ag) **FDICT factory reset (v120)** — the burned contingency-dictionary
 > hash lock lives in the same flash sector as the table (last 4 KB at
 > 0x1FC000; a UF2 flash overwrites only the app area, never that sector)
 > and there is deliberately no unlock telecommand (the burned lock IS the
 > finding), so the first v120 run permanently locked the board's
 > dictionary and every later v120 run failed "trojan accepted while
 > dictionary unlocked". New 0x1D sub 11 = FDICT factory reset
 > (`fdictFactoryReset()`: default table, hash zeroed, lock released,
 > `fsCommit()`; the sim handler restores the same cold-boot reference),
 > sent by the prologue after every PoC. Live: v120 POC OK.
 > UF2: 335872 B, md5 `181c603e573ec10c6ddb213f2ca8a6ab` (image G).
 > Full notes: `docs/HARDWARE-USB-TEST.md` §4bis.26–27.

  > **Verified 2026-11-02 (sweep pass 9, image H)**: the one remaining
  > silicon divergence — v117 (SB forged MID 0x105 battery report): the
  > simulator's `_sb_publish` sets `mm["bus_v"] = 21.0 + 3.0*pct/100` in
  > the same statement as `mm["pct"]` (immediate), while the board's
  > `missionModelBatteryOverride` set only `battery_pct` and the derived
  > `bus_voltage` was recomputed on the next `missionModelTick` — now
  > gated to the FEED windows (image G) — so v117's no-advance 0x1D sub-0
  > read right after the forged BATT_REPORT saw the stale rail ("CHECK
  > FAILED: bus voltage now from forged battery (22.2 V)"). Fix (one
  > line in `missionModelBatteryOverride`): update `bus_voltage` at
  > publish time, exactly mirroring the simulator — the finding's
  > semantics are preserved (a forged BATT_REPORT is trusted verbatim,
  > immediately, with no model tick in between). Live on image H: v117
  > POC OK in 35 s (the forged 22.2 V is visible in the no-advance 0x1D
  > read); the bench-timing-sensitive PoCs re-validated on image H
  > (v106 14.0/20.0/22.0/30.0 s cadence, v119 FDIR TUMBLE latch, v130
  > stego drain); v136/v137/v138 POC OK (first hardware runs). Sweep
  > note (v135): the beacon-flood saturation total-wedged the board's
  > USB stack once on image H (910 s timeout, DTR NAK'd, replug-only —
  > the documented v109-family total wedge); the finding IS the
  > downlink saturation, so a total wedge under flood is
  > impact-consistent, not a regression, and the 2026-10-31 22:41
  > image-G run (POC OK in 107 s) is the kept `evidence-hw/`
  > transcript. UF2: 335872 B, md5 `bfc145c93039177b7393147978cdd432`
  > (image H; the only delta vs image G is the v117 line). Full notes:
  > `docs/HARDWARE-USB-TEST.md` §4bis.27.

Dependencies are pinned in `firmware/platformio.ini` (RadioLib ≥6.6,
NeoPixelBus, SparkFun LIS2DH12, Adafruit BME280). The v2 lab modules
(`cmac, sdls_sim, memserv, sb, covert, anomaly, fdir, flashstore,
mission_model, extcmds, spacecan, secure_link` + patched `worker.cpp` and
`mission.h`) are plain C++ in-tree — **no new libraries**.

Hardware not present on the board (ADCS, EPS, CAN, eclipse sensor) is
virtualised in `mission_model.cpp` / `spacecan.cpp`: power, battery, tilt,
heaters and the SpaceCAN bus exist as firmware state that the wire can read
and write exactly like real subsystems — the honest model of what the course
attacks operate on.

## 2. Host syntax gate (no Arduino toolchain needed)

```bash
tests/host/run_host_checks.sh
```

* `g++ -fsyntax-only -std=gnu++17` over every v2 source against the minimal
  Arduino shim (`tests/host/shim`, self-contained) — unchanged
  upstream vendor-dependent files (`led, rdownlink, ruplink, sensors,
  usbCDC`) are marked N/A. Result: `evidence/HOST-02-firmware-compile.txt`.
* The simulator's crypto self-test doubles as the algorithmic parity gate
  between the firmware AES/CMAC stack and the Python twin: FIPS-197 ECB
  vectors, SP800-38A CTR, SP800-38B CMAC (0/16/32/46/64 B messages),
  secure-link round-trip, SDLS 43/64-Clear default table, null-master OTAR.
  Result: `evidence/HOST-01-crypto-vectors-sim-selftest.txt`.

## 3. Simulator + PoCs

Python 3 ≥ 3.9, stdlib only (the AES implementation is pure Python inside
`flatsat_sim.py`).

```bash
python3 simulator/flatsat_sim.py --selftest   # must print SELFTEST OK
python3 poc/v101_send_fw_inventory.py          # run against simulator
python3 poc/v101_send_fw_inventory.py --usb /dev/ttyACM0   # real craft
for f in poc/v0*.py poc/v1*.py; do python3 "$f" --quiet || break; done
```

PoCs default to `--sim`; `--usb` talks SPP framing over pyserial to the
firmware's debug console (same wire semantics as the radio path). Evidence
transcripts land in `evidence/`.
