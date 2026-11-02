# Testing the 56 PoCs on real hardware over USB (PwnSat / FlatSat)

This runs **every PoC against the real firmware binary on the board**, over
the USB-CDC bridge — no simulator. The PoC code is unchanged between the two
transports: `--usb` swaps the `SimDevice` for a `UsbDevice` that talks the
same bytes over the serial wire.

## 1. Install dependencies

```bash
python3 -m pip install --user platformio pyserial     # or: uv tool install platformio
```

## 2. Build + flash the vulnerable firmware

```bash
cd flatsat-lab/firmware
rm -rf .pio/build && pio run      # ALWAYS a clean build (see BUILD.md)
pio run -t upload                 # with the BOOTSEL button held
```

Non-interactive flash (what the bench uses): touch the console interface
(if00) at 1200 baud to reboot the RP2040 into BOOTSEL, wait for the
`2e8a:0003` RPI-RP2 mass-storage device, mount it, and copy the UF2:

```bash
# 1200-baud touch on if00 -> BOOTSEL (2e8a:0003), then:
mount /dev/sdX /mnt/rp2 && cp .pio/build/pico_tinyusb/firmware.uf2 /mnt/rp2/
sync && sleep 8 && umount /mnt/rp2
```

**Verify the build is real** before flashing: `find .pio/build -name '*.o'
| wc -l` must return **362** and `spp.cpp.o` / `worker.cpp.o` must carry
the current timestamp — a stale cache once flashed an image without the
fix and cost a full validation cycle.

The UF2 lands at `firmware/.pio/build/pico_tinyusb/firmware.uf2`.

## 3. Run the sweep

```bash
cd flatsat-lab
# use the STABLE by-id symlink (the raw ttyACM numbers reshuffle on every
# reboot; the console sibling can then be re-attached on the wrong port):
PORT=/dev/serial/by-id/usb-Pwnsat_Pwnsat_-_Flatsat_fsat-if02
./tests/hw/run_all_usb.sh $PORT            # all 56, evidence-hw/
python3 poc/v012_usb_debug_bypass.py --usb --port $PORT   # one PoC
```

Per-PoC evidence: `evidence-hw/vNNN_*.txt` (same format as the simulator
evidence under `evidence/`, so each writeup's walkthrough maps 1:1).
Both sweep scripts run a **health gate** (`tests/hw/health_gate.py`) before
each PoC: if the board is wedged (zombie, see §5) the sweep stops with
"BOARD DEAD … replug needed" instead of waiting out a 10-minute revive
timeout per doomed PoC.

## 4. What is different on hardware (and why it is honest)

| Aspect | Simulator | Real board over USB |
|---|---|---|
| Radio TCs | `sim.send(via="radio")` | the frame rides **LAB_CTRL 0x27 sub 1** and re-enters the *full* on-device radio pipeline (SDLS, secure link, GS gate, TC stats) — the wire bytes and code path are identical to an on-air TC |
| `dev.sim.*` introspection | Python internals | **LAB_STATUS 0x26**: a 53-byte cleartext state blob served by the firmware itself (also a deliberate info-leak, SPARTA DE-0003.06) |
| `advance(ms)` | virtual clock | real wall time (a 60 s window really waits 60 s) |
| `powercycle()` | scratch wipe + reboot | LAB_CTRL sub 2 does the same (scratch wipe + watchdog reboot + CDC re-enumeration). If the board is *crashed/hung* the runner **prompts you to unplug/replug** — that IS the finding (V0-03 / V0-15: no recovery without power) |
| RSSI / freq-error oracles (V-03, V-29) | seeded random | LAB_INJECT carries synthetic stats when no second LoRa modem is present; with a real second radio, the SX1262's own PHY measurements are used |
| Crash/hang state read-back | `sim.state` | detected as *no response* (`dev.silent`); the three crash PoCs assert accordingly on both transports |
| GS gate | same logic | same logic — 0x26/0x27 are USB-only exemptions, documented as a PER-0002 debug backdoor |

Two hardware-reality notes found *by this very validation*:

- `s_gps_reject_count`, watchdog scratch and VTOR are now the **real**
  registers (the earlier build had an `ARDUINO_ARCH_RP2042` typo that
  silently disabled them); V-14's RCE, V-21's cookie survival and V-36's
  reject counter therefore exercise actual silicon.
- Timing-sensitive thresholds (ARC wrap, brownout ramp, SPI hang count) are
  deterministic in the simulator and *approximately* real-time on hardware:
  the PoCs assert the observable effect, not a fixed tick count.

### 4bis. Silicon-vs-simulator divergences found (and fixed) during the sweep

The first full hardware pass exposed four real firmware bugs that the
simulator — by construction — never showed. Each was fixed **in the
firmware** (the simulator is the reference the 56 writeups are written
against), rebuilt, re-flashed, and re-validated on both transports:

1. **1-byte SPP payloads dropped to zero** (`firmware/spp.cpp`,
   `spp_unpack_packet`). The data-field copy was gated on
   `header.length > 0`, but a 1-byte payload has `length == 0` in the SPP
   length field — so every 1-byte TC arrived with `D[0] = 0` on silicon:
   `0x05[18]` became `SET_BEACON_RATE(0)` (beacon every worker tick, a
   ~500/s storm that saturated core0 so other TCs waited minutes), and
   `0x16[03]` (SDLS ARC reset) hit sub 0 ("OTAR FORMAT") instead of
   resetting the counter. The simulator's `spp_unpack` copies `ln+1`
   unconditionally and never had the bug — which is why v107 passed in sim
   and failed on the board with a "all deltas accepted" symptom that was
   really a *lost* ARC reset. Fix: copy `header.length + 1` bytes whenever
   `buffer_len > SPP_PRIMARY_HEADER_LEN` (the length==200 un-bounded
   201-byte memcpy — the V-16 off-by-one — is deliberately kept).
   Verified on hardware: `0x16[03]` → TM 0x16 ack, `0x05[18]` →
   `beacon_s=18` in TM 0x0C, zero beacons in 10 s.
2. **100 ms beacon floor** (`firmware/worker.cpp`,
   `telemetryRadioWorker`). The simulator can only fire the beacon once per
   100 ms worker tick, which caps an interval-0 "chatty beacon" at 10 Hz;
   the uncapped silicon loop ran at ~500 Hz and saturated core0. The
   firmware now enforces the same 100 ms floor on the effective gap —
   bench parity without changing v102's semantics.
3. **SDLS MAC byte order** (`firmware/sdls_sim.cpp`). The MAC comparison
   read the stored tag little-endian on silicon while the secure-link
   pipeline emits big-endian, so every MAC'd frame was rejected until the
   fix. Verified: MAC'd GET_STATUS answers TM 0x0C; wrong key →
   "MAC FAIL".
4. **Zombie boards = CDC backpressure, not a firmware crash**
   (`firmware/usbCDC.cpp` + bench side). core0 logs through the console
   CDC with *blocking* writes; when the host stops reading if00 the
   TinyUSB IN fifo fills and core0 stalls — which then also stops draining
   the bridge ring (the "board silent" symptom). The bench keeps both
   pipes drained permanently (rx pump thread + console '3' quiet mode +
   `write_timeouts` on both CDCs), which keeps a board alive indefinitely;
   a board killed mid-run (e.g. by a host reboot) still needs a physical
   replug — that is the V0-03/V0-15 finding in action.

Bench-side hardening that this pass added to `poc/lib/fslab.py` (transport
honesty — the PoC code itself is unchanged): queue-based `_read_frames`
with a 12 s global deadline + 4000-frame cap (no infinite loop under a
beacon flood), `_tc_ack()` for setup TCs that must be acknowledged (0x15/
0x1D — an unacknowledged SDLS setup silently disables the security
pipeline and fakes "all deltas accepted"), a `sdls_enabled` guard read
from LAB_STATUS offset 40 (bit0) so setup failures fail fast, a post-
defaults secure-link verification loop (re-issues cleartext
`AES_CONFIG(1)` if the board reports it OFF), and a beacon-flood servo
(5 s sample ×3, re-arms `0x05[18]` if >25 beacons/s). `_bench_defaults`
also pins mission time scale to 1.0x (`0x1D[10,0,10]`) so bench wall-time
waits equal the simulator's `advance()`, and exits safe mode
(`0x1D[3]`) before normalizing. Two more transport-parity fixes came out
of the second hardware pass: (a) `_xfer` now strips the firmware's 0x27
LAB_CTRL ack frames from the verdict list — a bench-transport artifact
the simulator never emits, which otherwise made `not r` hang
assertions (v109) fail on hardware while passing in the simulator;
(b) `_advance(ms)` now consumes the full `ms` time window instead of
returning on the first frame — the old early-return collapsed several
PoC "1 s ticks" into one board second, so cadence PoCs (v106) measured
0 s intervals and double-counted frames.

5. **Multi-core TinyUSB CDC race** (`firmware/firmware.ino`,
   `worker.cpp`). core1 polled the bridge CDC (RX) while core0 wrote TMs
   on the *same* TinyUSB CDC (TX) — and TinyUSB is not multicore-safe
   (the firmware's own comment only forbids core1 *writing* the console
   CDC). The race wedged core1 deterministically right after the first
   MEM_READ (0x19) TC was processed: the craft kept telemetering (core0
   workers) but went deaf to every TC until a power cycle — "zombie"
   boards that look alive in `lsusb` and answer nothing. Fix: USB RX
   parsing (`obcUSBRecv`) moved from `loop1()` (core1) to `loop()`
   (core0), so parse+drain run single-core, exactly like the
   single-context simulator; core1 now only ticks a liveness counter and
   core0's console worker prints `CORE1 STALLED` every 10 s if that
   counter stops (silent while healthy). The bridge CDC got a 50 ms read
   timeout so the single-core `readBytes` never stalls the mission loop.
   Verified: the 14-address MEM_READ ladder (including v105's exact
   kill sequence) now completes with the board alive.
6. **MEM_READ symbol map** (`firmware/memserv.cpp`). The simulator serves
   the virtualised subsystem state at fixed symbolic addresses
   (`SYM_GS_CHALLENGE` 0x20002100, `SYM_SA0_KEY` 0x20002200,
   `SYM_ARC_LAST` 0x20002300, `SYM_LOG_NAME` 0x20002000,
   `SYM_LEAK_POOL` 0x20002800, `SYM_MASTER_KEYS` 0x20003000); on silicon
   those are plain SRAM addresses, so v105's `sa0_key == LINK_KEY` check
   could never pass. `memservRead`/`memservCopy` now serve those windows
   from the live lab state (GS challenge, SDLS SA0 key, ARC counter, log
   name, leak pool, master-key table) — the read-side twin of
   `modelledPeripheralWrite()`, which already did this for VTOR /
   watchdog-scratch writes. Everything outside the windows stays a raw
   hardware read (SRAM, XIP, real peripherals), so V-05's "arbitrary
   in-bounds read" semantics are unchanged.
7. **v106's cadence "mystery": two bench-transport artifacts, not the
   board clock** (`poc/lib/fslab.py` only; the firmware was exonerated by
   direct measurement). Two stacked transport bugs made the 1 s beacon /
   14 s mission TM / 22 s nav TM stream look shifted or batched in the
   wire log: (a) *pump batching* — the bridge port was opened with
   `timeout=2`, and pyserial's `read(n)` waits up to the port timeout even
   when bytes have already arrived, so the RX pump deposited ~2 s of
   arrivals at a time: 1 s beacons appeared as 0 ms "pairs" on a 2.000 s
   period and individual frames shifted up to ~2 s late (v106's gaps
   measured nominal-1 s). Fix: the bridge port opens with `timeout=0.05` —
   the pump is a ~20 Hz poller, attribution error ≤ ~70 ms. (b) *byte-grind
   drain* — the old `_read_frames` probed the stream one byte at a time
   (a `_qread(1)` per wire byte, 10–20 ms sleeps whenever the pump queue
   was momentarily empty), costing ~150–200 ms PER FRAME; against the 1 s
   beacon stream the `_advance()` drain fell behind ~0.2 s every second and
   the mission/nav/sync/idle TMs booked 1–2 s late (min gaps measured
   13/21 s instead of 14/22 s). Fix: the bulk-walker `_read_frames` reads
   512-byte chunks and walks frames in memory (partial-frame tail carried
   across calls, same wait values / 12 s deadline / 4000-frame cap), and
   `_qread` returns early the moment the pump queue is drained so a 20-byte
   ack no longer burns the whole first_wait+settle+idle_wait budget of a
   tc() (which was inflating the bench setup phase ~3x). Board ground
   truth, measured directly instead of through the bench framing:
   `LAB_STATUS now_ms` is plain `millis()` and runs at 1.0000× host time
   (10501/10501 ms probe); a clean 150 s observation (no bench TCs) gives
   0x08 = 14.00±0.05 s, 0x0E = 22.00±0.03 s, 0x3FF = 30.00±0.05 s, beacon
   = 1.00 s; the console (if00) `[TM - SPP]` lines prove the firmware
   builds exactly one beacon per second with distinct seq counts.
   Residual, honestly documented: the bench books each frame in the 1 s
   window it ARRIVES in (the simulator books at the exact emission tick),
   so a nominal-N cadence reads as N±1 s per individual gap on hardware.
   v106 therefore asserts the contact plan over the whole contact: every
   gap within N±1 and the mean within max(0.5, 1/n) s of nominal — the
   SAME PoC code on both transports (the simulator still measures exactly
   14/22/20/30), and v106 also filters the 18-byte GPS-override ack out of
   the 0x0E cadence (on the bench it can land late, inside the window).
8. **BOOTSEL revival: touch the right port, release the control lines
   first** (`poc/lib/fslab.py`, `_flash_recovery`). The in-PoC revival
   (1200-baud touch on the console interface → the board's auto-reset RC
   network → BOOTSEL → UF2 copy) had two live bugs, both hit by v109: it
   touched `nodes[0]` of the `/dev/serial/by-id` glob — readdir order is
   not stable and it resolved to the *radio-link* interface (if02), which
   has no auto-reset circuit; and while the console-pump handle holds if00
   open the kernel's cdc_acm does not resend `SET_CONTROL_LINE_STATE` on a
   second open, so the touch produced no DTR/RTS edge at all. Fix: select
   if00 explicitly, release the pump console (DTR/RTS low) before the
   touch, restore the console after the flash. The revival is conditional
   on scope: the 1200-baud touch rides on the CDC control line, which a
   *totally* wedged chip (both cores + the USB IRQ dead — the v109
   SPI-9000 fault does exactly this; DTR requests get NAK'd) can no longer
   serve. For such boards the bench falls through to `_wait_for_revive()`
   — a physical unplug/replug inside the 10-minute window — which is the
   finding itself (only a power cycle recovers).

9. **DEF_TM_CTR must apply to EVERY TM, not only lab TMs** (`firmware/worker.cpp`,
   `telemetrySPPBuildPacketEx`). The AES-128-CTR "defense" (V-11 substrate: the
   counter block is the TM sequence number itself — trivially re-used after any
   reset, which is the keystream-reuse hole the KEY_VERIFY oracle exploits)
   existed only on the lab-TM path (`labTmSend`), so the 0x0C status and the
   periodic mission TMs stayed on the ECB path on silicon while the reference
   model applies CTR to every TM (base family + lab extensions). Fix: the CTR
   decision moved into the common builder (counter = `sppTmCounterPeek()`,
   the same seq the frame is stamped with), with the existing bypass semantics
   (`usbDebugEnabled` / forced cleartext) untouched. Verified: with DEF_TM_CTR
   set, the 0x0C TM round-trips the CTR branch and v111's reuse oracle works
   on both transports.
10. **GS challenge seeded from the GS-synced mission clock, not the bench GPS**
    (`firmware/worker.cpp`, `groundStationGenerateChallenge`). The V-28 PoC
    makes the ground station PREDICT the challenge from its own (synced)
    mission clock; the simulator derives the seed from `now_ms` and the UTC
    term from `int(now_ms/1000)%60`. The bench craft has no NMEA feed, so its
    GPS state is frozen (`utcSecond = 0`, lat/lon 0) and seeding from the live
    nav broke the prediction by the top seed byte. Fix: seed from
    `labLastLabSyncMs()` (the last LAB_STATUS sync — what the ground station's
    clock tracks) with `millis()` as cold fallback, and derive the UTC term
    from that synced clock exactly like the simulator's `nav["utc"]`.
    Verified: v128's challenge→handshake flow matches on both transports.
11. **Anomaly TC-rate channel + 18-byte 0x1D sub-0 + `rate_phase` pacer**
    (`firmware/worker.cpp` `commandApidHandler`, `firmware/extcmds.cpp`,
    `firmware/mission_model.cpp`, `poc/lib/fslab.py`). The V-24
    EWMA-ramp-evasion path had two bench gaps: (a) the anomaly detector's
    TC-rate channel is fed by `labCountRadioTc()` for RADIO-source TCs only —
    mirroring the simulator's `tc_seen`, which its radio-stats block bumps;
    without it the board's channel was permanently 0 and the TC-rate residual
    could never trip on silicon; (b) the 0x1D sub-0 TM grew to 18 bytes and
    now carries the orbit-clock second
    (`tm[17] = (uint8_t)(missionModelOrbitClock() + 0.5f)`) so the PoC can
    pace its ramp against the eclipse window like the simulator. The harness
    side adds `rate_phase(n, apid, ...)` — a virtual-time loop on the
    simulator, a pacer thread spreading TCs over a wall-clock window on
    hardware — so the SAME PoC code drives the ramp on both transports.
12. **Empty secure plaintexts became phantom 1-byte frames**
    (`firmware/worker.cpp`, `secureLinkDecodeInPlace`). The SPP length field
    is `payload_len - 1`, so a genuinely empty plaintext — the AES-ECB wrap of
    `b""`, i.e. every no-argument radio TC (v002/v003/v008/v010/v012/v015/
    v101/v103/v130...) — decodes to 0 bytes in the simulator but landed on
    silicon as `header.length = 0` → `PL = 1` → a phantom byte: an empty 0x22
    COVERT_ENQ enqueued a spurious byte into the covert FIFO (v130's baseline
    depth read 1, not 0) and every handler saw `PL` off by one. The 0-byte and
    1-byte plaintexts are genuinely indistinguishable in the length field, so
    the fix encodes the empty case as the `0xFFFF` sentinel: the `PL` macro
    `((uint16_t)(length + 1))` folds it to 0 and handlers see a true
    zero-length payload, while a 1-byte plaintext still encodes length 0
    (PL 1), unchanged. Blast radius audited: no empty-radio APID in the
    catalog has a `PL < 1` guard or `D[0]` read, and the only post-decode
    length consumers (`PL`, `tclAppend`'s `(uint8_t)(length + 1)` cast,
    `groundStationCommandAllowed`'s `data_len`) all wrap 0xFFFF → 0.
    Verified: empty 0x22 → depth 0, 63-byte 0x22 → depth 63.
13. **ONE shared VCC forward counter, exposed at 0x0C/0x0F**
    (`firmware/worker.cpp` 0x06/0x0C/0x0F + `firmware/covert.cpp`). The
    reference model keeps a single `self.vcc` ("payloadForwardCount") bumped
    by the 0x06 broadcast (ungated) AND the 0x23 snap (freeze-gated), exposed
    at 0x0C offset 8 and 0x0F offset 6. The firmware split it into two
    counters — broadcast → `mission_ctx.payloadForwardCount`, snap →
    `covertVcc()` — and 0x0C/0x0F exposed only the broadcast one, so v131's
    "audit counter increments per capture" read 0 → 0 and v132's
    broadcast-count check could never observe the counter the snap bumps.
    Fix: `covertVccBumpUnconditional()` (ungated `s_vcc++`, no freeze gate)
    on the 0x06 path; `telemetrySPPTransmitMissionStatus` (0x0C) and
    `telemetrySPPTransmitPayloadStatus` (0x0F) now expose `covertVcc()`.
    Verified: snap → vcc+1; VCC_FREEZE → counter stuck while captures
    continue; broadcast → vcc+1 and `last_freq` updated.
14. **The 0x06 broadcast TM must come back to the host**
    (`firmware/worker.cpp`, 0x06 handler). The reference model echoes the
    broadcast TM on the downlink (`self._frame(0x06, msg)`); the board only
    did the physical radio1 TX (`downlinkRadioTransmitBroadcast`) —
    unobservable on the bench — so v132's "broadcast accepted" and v135's
    storm count both saw zero TMs. Fix: `obcUSBTransmitFrame()` the built TM
    before the radio TX (the secure-link policy is still applied by
    `telemetrySPPBuildPacket`, exactly like the simulator's `_frame`).
    Verified: exactly one 0x06 TM per broadcast TC.
15. **The 0x07 flash dump must use the non-blocking dispatch**
    (`firmware/worker.cpp`, `telemetrySPPTransmitFlash`). The dump loop used
    `dispatchTelemetryPacket(&tm, true)` — the blocking path does a real
    `radio1.transmit()`, which fails on the bench (no usable downlink) and
    returns false, so the loop broke after chunk 0 and the host got 1×16 B
    instead of 16 chunks / 255 B. The non-blocking path
    (`downlinkRadioTransmitNBlock`) is fire-and-forget
    (`startTransmit`, failure only sets a state flag) and can never break the
    loop. Fix: the dump now dispatches with `false`; the USB half
    (`obcUSBTransmitFrame`) is unchanged. Verified: 16 chunks, 255 B image,
    both embedded build strings (`"2020 Follo..."`, `"Whte Rabit"`)
    recovered from the dump.
16. **The "radio loopback mystery" was a bench-framing bug, not radio**
    (`poc/lib/fslab.py`, `_read_frames`). After the item-14/15 fixes, a live
    probe showed a 0x06 TC echoing TWICE and a single 0x07 TC producing
    136–152 TM frames instead of 16 — with a suspicious copy-count pattern
    (17, 16, 15, ..., 2 across the 16 chunk seqs) that first looked like a
    bench RF loopback (downlink TX picked up by the uplink RX and
    re-dispatched). It was not: the board's console (if00) logged exactly one
    TC dispatch and exactly 16 TM chunks, and an `FSLAB_PUMP_TRACE` run
    proved the port delivered every byte exactly once (778 B total, where 152
    real frames would need ~3.5 KB). The real bug: the bulk-walker
    `_read_frames` accumulated every 512 B chunk into a local `tail` across
    outer-loop iterations and re-walked it from `i = 0` — re-appending every
    frame it had already emitted on each later deposit within the same read
    window (frame k's copy count = 1 + number of later deposits — exactly the
    observed 17..2; a single-frame TC doubled only when another frame landed
    in the same window, which is why it looked intermittent). Fix: `tail` is
    rebuilt each iteration from only the carried partial-frame tail
    (`_rx_tail`) plus the new chunk, so already-emitted bytes are never
    re-walked. Same wait values / 12 s deadline / 4000-frame cap; the
    simulator path is untouched.
17. **Flash state must actually live in flash: the meta sector on the
    RP2040 boot flash** (`firmware/flashstore.cpp`). The simulator keeps
    `flash["ota"] / ["sched"] / ["fdict"]` across virtual resets (resetc /
    powercycle / brownout), and the reference PoCs assert against that
    survival (V-18 pending slot-B boot, V-19 queue replay after RESETC,
    V-20 contingency table). On silicon the same `{ota, sched, fdict}`
    state plus the fdict hash / hash-lock bytes are now serialised into a
    CRC16-guarded `'FSLM'` meta struct written to the LAST 4 KB sector of
    the RP2040 boot flash (offset `0x1FC000` XIP-relative, abs
    `0x101FC000` — the image occupies the first ~150 KB, so the tail
    sector is untouched) via the pico-sdk
    `flash_range_erase/flash_range_program` API, with a 1792 B (7 × 256 B
    pages) padded program. That sector survives watchdog resets, NVIC
    resets AND power cycles — the exact survival matrix of the
    simulator's flash dict. (The external QSPI NOR layout in
    `flashstore.h` — `FS_SLOT_B_ADDR` / `FS_META_ADDR` — is the in-orbit
    mapping; the bench craft parks the meta in boot flash.)
18. **SB transport tag typo + the missing 0x0C v2 extension byte**
    (`firmware/sb.cpp`, `firmware/extcmds.cpp`). (a) The SpaceCAN/SB
    transport tag on silicon was `0xC0FFEE11`, one `E` short of the
    reference model's `0xC0FEEE11` (`flatsat_sim.py` `_sb_publish`, V-17
    writeup) — the signed-defence path rejected the reference tag on
    hardware only, so the forged-MID byte stream never matched. Fixed to
    the simulator's constant. (b) The silicon 0x0C GET_STATUS TM was 26 B
    and missing the v2 extension byte the reference model appends:
    `flags2` at the tail (bit0 sdls_enabled, bit1 arc_relaxed, bit2
    detumble, bit3 eclipse, bit4 brownout_armed). The firmware now emits
    the same 27-byte TM (offset 12 = `millis/1000` LE32, verified by a
    direct host probe) so any PoC that parses 0x0C sees identical bytes
    on both transports.
19. **V-24's board-side fixes: gated TC log, non-blocking uplink LED,
    clamped `recvLen`** (`firmware/worker.cpp` `logger_spp_tc`,
    `firmware/ruplink.cpp`). Three hot-loop stalls that only show at the
    20–45 TC/s the v124 ramp drives: (a) the `[TC - SPP]` console print
    ran with *blocking* console-CDC writes on core0 — the same core that
    drains the bridge RX. A backpressured console (host pump momentarily
    busy) stalled the whole RX path, dropping pacer frames and zeroing
    the anomaly TC channel; the line is now dropped instead of blocking
    when `Serial.availableForWrite() < 96`. (b) the uplink (radio0) RX
    handler called the *blocking* `ledBlink(8)` ≈ 3.2 s of `delay()`
    inline once per physical RX event, starving the bridge-CDC drain for
    the duration; it is now `ledBlinkRequest(8, LED_COLOR_BLUE)` — same
    visual effect, serviced from `ledBlinkTick()` in `loop()`. (c)
    `radio0.getPacketLength()` is now clamped (`recvLen <= 0 || > 255`
    dropped) before the length is fed to `readData` / `hexStringToBytes`.
20. **v124's EWMA "rate dip" was harness checkpoint overhead, not the
    firmware — fixed with a `stop_on` verdict fast path + a `tot=`
    counter** (`poc/lib/fslab.py`, `firmware/extcmds.cpp`). Symptom: the
    ramp latched mid-phase on the board (x≈1200 at t+60/t+120) while the
    simulator stayed green; the board's 1 Hz EWMA TC channel saw a real
    x=2.0 one-second dip. Diagnosis: a cumulative radio-TC counter
    (`s_tc_total`, printed as `tot=` on the `[LAB] FEED` line next to the
    per-second `tc=`) showed the board's cumulative count (3072) equals
    the wire 0x01 ack total (3066) — zero count loss anywhere in the
    firmware; the dip was real ON THE WIRE. The real-time t+60
    checkpoint (0x26 resync + 0x1D verdict read ≈ 0.9 s, each paying the
    `_read_frames` trailing `idle_wait` ≈ 0.4 s) sat inside the pacer
    cadence and opened a 0.93 s gap between two back-to-back 1 s pacer
    windows — a rate dip the simulator's virtual clock can never
    produce. Fix, harness-only (PoC code and firmware semantics
    unchanged): `_read_frames(..., stop_on=None)` returns the moment the
    expected same-apid TM is walked; `tc()` passes `stop_on=apid` for
    `_SELF_ANSWER = {0x01, 0x0A, 0x0B, 0x0C, 0x10, 0x1A, 0x1D, 0x24,
    0x25}` (verified against the simulator's TC→TM map; 0x27 is
    deliberately excluded — its ack is followed by the inner frame's
    TM), and `fetch_status` uses `stop_on=0x26`. If the expected TM never
    arrives the normal silence/deadline logic runs, so worst case ==
    previous behaviour. The 0x1D verdict read dropped 460 ms → 51 ms and
    v124 is green on hardware: t+60/120/200 alarm=0, the step to 45 TC/s
    latches `ch=1 x=4100 mu100=3202` → alarm=1.
21. **`_FLIP_CAPABLE` gains 0x18 (MEMCPY)** (`poc/lib/fslab.py`). A
    MEMCPY of a forged FDIR/SB word into the modelled peripheral region
    can trip the internal FDIR and switch the AES engine OFF without any
    ack carrying the new value — the same stale-shadow class as the
    safe-mode / RESETC flips that already made `0x0D/0x0A/0x10/...`
    flip-capable. With a stale `self.secure` the next `tc()` wraps the
    wrong way (the board passes undecoded ciphertext through
    `secureLinkDecodeInPlace`), so `0x18` joins `_FLIP_CAPABLE` and the
    next transfer re-syncs from a fresh `LAB_STATUS`.
22. **Kernel serial wedge: bounded `open()` + the ad-hoc pre-brownout
    rule** (`poc/lib/fslab.py`). `serial.Serial()` `open()/write()/close()`
    can block INDEFINITELY inside the kernel when the device NAKs its
    control transfers (the post-boot window after a brownout reboot, or
    the V0-03/V0-15 zombie state): cdc_acm's `open()` then spins on port
    activation with no timeout, and any retry loop that calls it wedges
    the whole PoC (observed: 420 s hangs with a healthy device on the
    bus). Fix: `_serial_open_bounded()` opens in a worker thread and
    abandons the attempt after `max_wait`, so the caller's retry loop
    iterates instead of the process stalling in-kernel (abandoned
    attempts on a real zombie leak daemon threads — the documented
    power-cycle recovery is unchanged). It replaces all four raw
    `serial.Serial(` sites (`open_console`, the `_flash_recovery`
    1200-baud touch, `serial_open_retry`'s `wait_gone` probe and main
    open). Operational rule learned the hard way: an AD-HOC port session
    right before a harness run that does a brownout (`hard_reset`)
    corrupts the device's TinyUSB state, so the subsequent
    brownout-reconnect wedges the bridge EP (kernel write/close block
    forever). Wedge signature: kernel `usb 3-4: can't set config #1,
    error -110` on every rebind; `usbreset` → "No such device found";
    `authorized=0` write → "Connection timed out". Software recovery is
    proven ineffective (sysfs unbind/bind ×2, usbreset, authorized
    toggle) — only a physical replug works, which is the V0-03/V0-15
    finding itself. Rule: run the harness directly on a freshly powered
    board; never open the ports ad-hoc right before a brownout run.
23. **The meta-sector flash write is a dual-core + IRQ hazard: core1
    must be parked in RAM and core0 IRQs masked around the
    `flash_range_erase`/`flash_range_program` of the meta sector**
    (`firmware/flashstore.cpp`, `fsMetaSave`). pico-sdk's `flash.h`
    states these calls are *unsafe* while the other core executes from
    flash (XIP is disconnected for the whole operation — the erase
    runs from ROM, but the XIP port is off), and *unsafe* with an
    XIP-resident interrupt vector table. The v1 (item 17) firmware
    called them naked, so on the first `fsCommit` after boot — the
    0x1E sched wipe in the bench defaults, the only meta write in that
    sequence — an IRQ vector fetch (SysTick/USB) or core1's XIP fetch
    in `loop1()` hit the dead XIP port and the core lockup'd: zombie
    board, only a power cycle recovers, 2/2 reproducible (v114 died at
    t≈19 s both times, mid-defaults; its PoC logic never even ran —
    no 0x1A/0x18 TCs in the trace). The fix parks core1 and masks
    core0 IRQs around the ~46 ms operation (`erase=43991us
    prog=2104us` measured), timed with `time_us_32` because `millis()`
    is SysTick-IRQ-driven and frozen under masked IRQs. **First fix
    attempt (pico-sdk `multicore_lockout_*` +
    `multicore_lockout_victim_init` on both cores) BRICKED BOOT**: the
    arduino-pico framework already claimed the very same SIO FIFO IRQ
    on both cores (`_MFIFO::registerCore`, run from `main()` before
    `setup()` for its `idleOtherCore`/`resumeOtherCore` core-parking)
    and `irq_set_exclusive_handler` silently overwrote the
    framework's RAM-resident `_irq` vector — the board attached (D+
    pull-up from TinyUSB init) then NAKed every EP0 transfer (kernel:
    `device descriptor read/64, error -110`, xhci port power cycle,
    then total silence; 3/3 after flash). The final design therefore
    uses the framework's OWN mechanism — `rp2040.idleOtherCore()`
    parks core1 in the framework's RAM-resident `_irq` handler
    (documented for exactly flash writes in `RP2040Support.h`),
    `resumeOtherCore()` releases it — plus
    `save_and_disable_interrupts()` on core0; pico-sdk's lockout API
    is deliberately NOT used (`fsLockoutInit` is a documented no-op
    keeping the call sites). Verified: 0x1E probe — bench defaults +
    wipe ACK'd (TM 0x1E), 4 meta writes, `LAB_STATUS alive=True
    secure=True`, FSWRITE line present; the 17-item sweep (v114 first)
    is the official fresh-boot green.
24. **The Cortex-M0+ SCB registers are word-access only: the byte-wise
    MEMCPY/MEM_READ PPB path never lands on the real `SCB->VTOR`**
    (`firmware/memserv.cpp`). Measured on the PwnSat: a MEM_READ of
    the whole `0xE000ED00..0xE000ED0F` block (CPUID, IPC, VTOR,
    AIRCR) reads `00 00 00 00 ...` and byte stores are ignored — so
    v114's VTOR readback check saw `0x00000000` on silicon while the
    simulator's byte-granular `self.vtor` model returned the written
    value (`CHECK FAILED: vector table redirected`, 2026-10-31 sweep;
    the RCE marker ack and both hook effects already fired correctly —
    `labVtorRedirectCheck()` fires the takeover in software by design).
    Fix: VTOR is modelled in software, byte-wise, exactly like the
    simulator's `_mem_write`/`_mem_byte`: initial value = a real WORD
    read of the register (the M0+ does answer word accesses — it
    returned `0x20000000`, the arduino-pico RAM-resident vector
    table), updated per byte in `modelledPeripheralWrite()` (which now
    also runs the takeover check per byte, single-fire-on-completion
    exactly like the sim's `_rce()` — replacing the old 4-byte
    post-loop check), served per byte by `symByte()`; raw stores to
    the VTOR window are skipped (they are no-ops on silicon).
    Verified: roundtrip probe — memcpy → readback `0x10012740` == the
    hook, RCE marker in the ack, board alive; the 17-item sweep re-run
    is the official fresh-boot green.

 25. **The five board-killer-era divergences + v130's beacon catch-up
     stream: REARM/SYNC bench services, GPS kill, thruster impulse, float
     battery, and the no-TM fast tc(0x05)** (image E, 2026-10-31). The
     sweep pass 6 board (image D) still failed v119/v126/v128/v133/v134
     (all pre-existing, none caused by the flash/VTOR work) and v130
     failed for a sixth, subtler reason:
     * **v130** — the 0x05 handler left `t_radio_beacon.previous` stale
       (boot 0 / the last 12 s prologue beacon), so after the PoC's
       `0x05 01` the silicon fired a 1/s catch-up stream (6 frames over
       the tc read window) that the harness' ~6.5 s tc(0x05) read (4 s
       first-wait while periodic TMs flow) consumed: six 1 s beacons
       drained the 63 B covert FIFO before the PoC's two advance(1100)
       windows, which then saw only zero padding. Probes 1–5 ruled out
       the red herrings: the prologue wall gaps are harness read loops
       (sensor TMs stayed on their 14 s grid), the 0x26 blob carries no
       beacon-interval field (a blob diff cannot prove 0x05 unapplied),
       and probe 5's console (`[TM - SPP] APID=0x001 LEN=80` lines,
       1 pre-0x05 at the prologue's 12 s cadence, 14 post) proved the
       board DOES emit beacons — the evidence "burst of 8–9 frames in 9
       ms" is a log-time artifact (tc() logs its collected frames at
       return, not at wire arrival). Fix: `t_radio_beacon.previous =
       millis()` in the 0x05 handler (first fire exactly one interval
       after the command — the simulator's virtual-clock booking) plus a
       short read profile for `_NO_TM_APIDS = {0x05}` in tc() (0.45 s
       first-wait, tight idle, no chatter extension — a TC with no ack
       and no response TM must never collect the PoC's periodic TMs).
       Live: tc(0x05 01) returns in 0.15 s, exactly one beacon per 1.1 s
       window (Δmillis 1001), full 63 B message recovered from the
       padding — one-beacon-per-window on both benches.
     * **v119 REARM** — new LAB_CTRL sub 4 restores the simulator's
       just-after-reset reference state (thrusters 10/10, attitude
       reset, `fdirRearmColdBoot()` without the release-window gate,
       `schedRearm(now)`, FEED phase pinned so the first tick is exactly
       +1000 ms): the board's real boot integrates ~5 s of model time at
       the 1.0x bench scale, offsetting FDIR/schedule/FEED phase from the
       fresh sim. The harness' `_maybe_rearm()` (gated on the sub 4 'R'
       ack, ≤10 s, re-entry-guarded) runs at every revival point
       (pre-PoC `hard_reset`, `_request` stale-handle retry,
       `powercycle`, `reboot`) and re-anchors the virtual grid
       (`_adv_anchor = None` → `_advance` re-anchors on the board's live
       `now_ms`, like the sim's cold boot).
     * **v128 SYNC** — `_advance` injects its virtual grid (u32 LE) into
       the board's GS sync (LAB_CTRL sub 5 →
       `labMarkLabStatusSync`) right after the host-side blob patch:
       the GS challenge seeds from the GS-synced mission clock, and the
       board used to seed from its own `millis()` (seed 34944 vs grid
       71944, delta 37000 s) so the PoC's prediction could never match.
       Fire-and-forget write; the 0x27 ack is a bench-transport artifact
       stripped by `_lab_ack`/the PoC's apid filters; the grid blob patch
       stays (v106 cadence attribution).
     * **v126 GPS kill** — `labGpsKill()` (RAM-only flag, kill branch
       FIRST in `gpsRead`: `memset(nav,0)` + `hasDateTime = true` →
       status 0x10, TIME_VALID preserved, the sim's exact zeroing),
       triggered from the MGPIO byte-write branch of `memserv.cpp`, with
       the raw-store skip for 0x40014000 (= USBCTRL base on RP2040).
     * **v133 thruster impulse** — both 0x04 branches apply
       `rate[tid] += 0.3 * pw / 255` guarded by `power != 0` (the sim's
       `if pw:`): 30 cheap TCs integrate 9.0 deg/s and trip FDIR on the
       board.
     * **v134 float battery** — `battery_pct` is a float integrated
       unrounded, brownout at `<= 0.0f`, quantised to uint8 only at
       report time (three cast sites: `img[20]`, the 0x24 brace-init,
       the 0x26 blob) — the integer-truncation fixed point at pct≈33 that
       stopped the drain before the reset is gone.
     Verified: simulator re-swept 15/15 green (v119/v126/v128/v130/v133/
     v134/v135/v137/v138 + v014/v102/v104/v106/v115/v120 — all tc(0x05)
     users and the five fixes), live probe 6 (REARM t1=10 after
     hard_reset; v130 semantics PASS on the board, above), UF2 334848 B
     md5 `6e9ae2dc0816acc2fc995a586d16fed4` (image E). Build note:
     `s_anom_last_ms` moved above `hLabCtrl` (sub 4 pins the FEED phase,
     so the declaration must precede the handler).

  26. **Image F: the six image-E failures -- a blocking SPP-unpack blink,
      the detumble x10 gap, a transit-corrupt re-send, the stale-handle
      secure-shadow rewrap, and the OTA sig_required flash residue**
      (image F, 2026-10-31). The image-E 17-item sweep passed 11/17; the
      six failures each had a distinct root cause, none a PoC bug:
      * **v014 (SPP-unpack blink)** -- a rare host/USB desync while the
        loop is stalled makes the board parse a bogus frame; `spp_unpack`
        = -4 (SPP_ERROR_VERSION) and `commandHandlerInternal` ran the
        BLOCKING `ledBlink(8, YELLOW)` = 3.2 s of `delay()` on core0's
        single loop, eating ~30 of the 100 ms beacon gates in the flood
        window (18 < 20). The CDC TX/RX rings are 256 B and
        `Adafruit_USBD_CDC::write()` is blocking (spins `yield()`), so a
        stalled loop buffers beacons and desyncs. Fix: the non-blocking
        `ledBlinkRequest(8, ...)` (serviced by `ledBlinkTick()` in loop()
        -- the same V-24 pattern as the uplink RX handler); the v115
        AES-FAIL blink (worker.cpp:1960) stays BLOCKING (finding DoS
        semantics). Live: 49 beacons/5 s POC OK (was flaky, not
        deterministic).
      * **v133 (detumble x10)** -- the detumble branch applied
        `damp * dt_orbit` while the passive branch and the reference model
        both apply `damp * dt_orbit * 10`; the saturated B-dot authority
        (0.25) sat BELOW the latched thruster torque (0.3) so the board's
        tilt crept UP through the recovery window (13.35 -> 13.40) where
        the sim decays at 0.22 deg/s^2. Fix: `damp = want * 10.0f`
        (mirrors sim). Live: 13.09 -> 10.87 deg/s = 0.222 deg/s^2.
      * **v115 (transit-corrupt re-send)** -- during the flood the board
        spends most of its time in the 3.2 s per-error blink; a WRAPPED
        frame riding the USB ring through that stall can come back with
        mangled ciphertext and read "AES DECRYPT FAIL" for a frame the
        harness wrapped correctly (v115's 0x28 canary -- a desync also
        showed up as one junk frame PING-acked). A valid ciphertext fails
        to decrypt only if it was corrupted in transit, so `tc()` re-sends
        a wrapped TC on "AES DECRYPT FAIL" (<=3 retries, logged as
        `AES retry=N`). Cleartext junk frames are never re-sent (they are
        meant to fail AES -- that IS the finding). Live: 0x28 attempt 1 =
        17 B "AES DECRYPT FAIL", retry = 19 B "Error Unknown APID".
      * **v134 (stale-handle rewrap)** -- a mid-PoC brownout reboot lands
        the board on its cold-boot secure default (engine ON; only a V-21
        scratch cookie -- wiped by the brownout -- forces it OFF) while
        the harness shadow is stale OFF, so the re-sent cleartext 0x0C
        reads "AES DECRYPT FAIL" and the PoC's `find()[0]` blows up.
        Fix: the `_request` stale path now re-syncs the shadow
        (`_resync_state`) before re-arming/GPS and re-encodes the original
        frame's body for the post-revival state (`_rewrap_after_revive`:
        unwrap if it was wrapped under the old shadow, re-wrap for the new
        -- including an EMPTY body -> the 16-B len=0 block the sim always
        emits; lab frames 0x26/0x27 are never re-wrapped). A `_reviving`
        re-entrancy guard stops the revival's own resync/rearm/GPS frames
        from re-running the whole revival.
      * **v138 (OTA sig_required flash residue)** -- the board's meta
        sector persisted `sig_required=1` from a prior OTA PoC, so
        `otaActivate()` rejected v138's unsigned old-image finalize
        (ok=0) where the sim (cold-boot sig_required=0) accepts it. Fix:
        `_bench_defaults` restores the OTA flash state to the sim cold
        boot (arwc=7 AND sig_required=0) via one sub-6 MANIFEST TC
        (`[6][sig8][arwc BE32][require]`), then the sub-5 rollback.
      Verified: simulator re-swept green (v115/v133/v134/v138/v014/v126
      all POC OK), all six failures POC OK on image F, UF2 335360 B md5
      `da98f219e75c4314a2463497fe83522d` (image F).

   27. **Image G: bench dynamics on a window-only clock -- the FEED
       window (LAB_CTRL sub 6), the 60.0x prologue time scale, and the
       FDICT factory reset (0x1D sub 11)** (image G, 2026-10-31). The
       image-F 17-item re-sweep passed 13/17; the four failures were one
       structural bench gap plus three state-restoration gaps, none a PoC
       bug (the PoC code is unchanged -- all fixes live in firmware and/or
       the harness, and every finding's semantics is preserved):
       * **v119 (time scale + continuous dynamics)** -- `run_poc` runs the
         prologue (`hard_reset` + `_bench_defaults`) ONLY for hw devices;
         the sim never runs it and stays at its cold-boot `time_scale =
         60.0`, while the board prologue pinned 1.0x. At 1.0x the planted
         2 s queue's t1=255 torque nets ~+0.02 deg/s per 100 ms tick
         (+0.3 kick per 2 s fire) and never reaches the 5.0 deg/s FDIR
         TUMBLE threshold inside the PoC's windows (t1 stays stuck at 255
         after the queue clear -> final check fails); at the sim's 60.0x
         it crosses in ~0.5 s of model time and latches TUMBLE ~0.9 s
         into the final window (sim ground truth: adv4, now_ms 8500).
         Second, structural gap: the sim's `_workers_tick` (model, FDIR,
         sched, radio TMs) advances ONLY inside `advance()`; the board ran
         all of it in real `millis()` time, including between windows.
         Fix: a window-only EPOCH clock. New LAB_CTRL sub 6 `FEED_START
         [6][u32 LE window_ms]` is written fire-and-forget by `_advance`
         at window START (mirroring the window-end SYNC sub 5): the board
         sets `s_feed_active` + a bench deadline, and `s_bench_ms`
         (`labTickWorkers`) advances 1:1 with wall time ONLY while the
         window is open, self-terminating at the deadline (the trailing
         SYNC write has USB latency and would run the model past the
         window end the simulator never sees). The mission model
         (`missionModelTick` anchored by `missionModelTickReset()`), FDIR
         (`fdirTick`: TUMBLE 2000 ms + safe-entry + release window all in
         bench-ms uint32 stamps), the schedule queue (due on the
         bench-second grid, run on bench-second boundary crossings in
         `labTickWorkers` -- removed from the real-time 1 Hz anomaly
         block, which stays unchanged for v124 EWMA parity) and all five
         periodic radio workers (`telemetryRadioWorker` returns early
         when `!labFeedActive()`, all `.previous` fields bench-ms stamps)
         now advance only on that clock -- exactly where the simulator's
         `_workers_tick` does. A cold-boot replay or harness REARM
         (sub 4) marks the queue PENDING (`s_sched_epoch_pending`,
         flashstore.cpp static); the first FEED_START after it consumes
         the epoch: bench clock restarts at 0, queue due at the epoch
         second, radio worker phase re-zeroed (`labResetRadioWorkerPhase`)
         -- the sim's `_cold_boot` (`e["due"] = now_ms//1000`,
         `t_prev = 0`) on the same clock. Prologue time scale restored to
         the sim cold-boot 60.0 (`[10, 0x02, 0x58]` = 0x0258/10): the old
         1.0x pin was a workaround for the continuous-model problem
         ("60x made FDIR fire minutes after boot") and is safe once the
         model is gated to the windows. Live: v119 POC OK -- FDIR TUMBLE
         latches ~0.9-1.0 s into the final 2500 ms window (sim: 0.9 s),
         engine OFF + t1 zeroed mid-window, the post-latch cleartext
         beacons resync the stale harness shadow so the final 0x0C lands
         cleartext and reads t1=0.
       * **v130 (stray beacons outside the windows)** -- the 1 s beacon
         worker fired in real time even between `advance()` windows, so a
         beacon during the TC phase drained the 63 B covert FIFO before
         the PoC's 2.2 s drain window -> the windows saw only zero
         padding. Fix: the radio-worker gating above (beacon fires only
         inside windows, on the bench grid) + the 0x05 handler arming
         `previous = labBenchMs()` (the sim's `tw["beacon"] = now_ms` in
         model time). Live: v130 POC OK.
       * **v106 (real-time cadence wander)** -- the 14/20/22/30 s radio
         workers ran on real `millis()` outside the windows: measured
         wall gaps 21.32/22.51/21.40 s for nav (mean 21.3 vs nominal 22,
         failing `|mean-nom| <= max(0.5, 1/n)` over 3 gaps) + ~0.6 s phase
         wander. Fix: the same radio-worker gating -- all five workers on
         the bench clock fire at exact bench multiples, booked gaps
         exactly {N, N+1}, deterministic cadence like the sim. Live:
         v106 POC OK with measured 14.0/20.0/22.0/30.0 s.
       * **v120 (fdict lock is flash-persisted with no unlock TC)** --
         the burned dictionary hash lock lives in the same flash sector as
         the table (last 4 KB at 0x1FC000; a UF2 flash overwrites only
         the app area, never this sector) and there is deliberately no
         unlock telecommand (the burned lock IS the finding). The first
         v120 run (~17:40, image-E era) locked it -> every later v120 run
         failed "trojan accepted while dictionary unlocked". Fix: new 0x1D
         sub 11 = FDICT factory reset (`fdictFactoryReset()`: default
         table, hash zeroed, lock released, `fsCommit()`; TM
         `{id,11,1,0}`; the sim handler restores the same cold-boot
         reference), sent by the prologue after every PoC (next to the
         0x1E queue wipe). Live: v120 POC OK.
       Verified: full 56-item simulator sweep green (56/56, no
       regressions), all four failures POC OK on image G, UF2 335872 B
       md5 `181c603e573ec10c6ddb213f2ca8a6ab` (image G).
       Sweep note (v003 + v015): on image G the V0-03 poisoned-broadcast
       crash's wild memcpy now lands on the USB stack itself (the new
       .bss statics shifted the RAM layout) -- v003 3/3 and v015 1/1
       total-wedge the board (DTR NAK'd, replug-only, the documented
       v109-family total wedge), so both crash PoCs need the operator's
       physical replug inside their 10-min revival window. Their
       evidence-hw/ transcripts are the image-E/F runs where that replug
       landed in time (v003: BOOTSEL recovery failed, "board is back --
       power cycle confirmed", POC OK in 540 s; v015: 5 silent minutes
       "NO RESPONSE" then power-cycle recovery, POC OK in 618 s); the
       findings' transport-level semantics are unchanged (image G
       sharpens the impact: the whole board dies, not just the mission
       core).
       Sweep note (v117, image H, 2026-11-02): the SB forged-MID battery
       check read the derived bus voltage one model tick late -- the
       simulator sets mm["bus_v"] in the SAME statement as mm["pct"] in
       _sb_publish, while the board derived it only in
       missionModelTick (gated to the FEED windows since image G), so
       v117's no-advance 0x1D sub-0 read after the forged 0x105 saw the
       stale rail ("CHECK FAILED: bus voltage now from forged battery
       (22.2 V)"). One-line fix in missionModelBatteryOverride (update
       bus_voltage at publish time, the exact sim mirror -- a forged
       BATT_REPORT stays trusted verbatim and immediately): v117 POC OK
       on image H in 35 s; bench-timing spot-checks re-validated (v106
       14.0/20.0/22.0/30.0 s, v119 FDIR TUMBLE latch, v130 stego
       drain); v136/v137/v138 POC OK (first hardware runs). UF2 335872 B
       md5 `bfc145c93039177b7393147978cdd432` (image H; the sole delta
       vs image G is this line).
       Sweep note (v135, image H, 2026-11-02): the beacon-flood
       saturation total-wedged the board's USB stack once (910 s
       timeout, DTR NAK'd, replug-only -- the documented v109-family
       total wedge). The finding IS the downlink saturation, so a total
       wedge under the flood is impact-consistent with it (same
       resource-exhaustion class, sharper impact), not a regression; the
       2026-10-31 22:41 image-G run (POC OK in 107 s,
       evidence-hw/v135_beacon_broadcast_saturation.txt) is the kept
       transcript.

Harmless chatter: the radio RX path periodically logs
"Unpacking SPP: -2/-4" and loopbacks apid 0x305 frames (~7 s cadence) —
room radio traffic picked up by the SX1262; the bench classifies it via
`_chatter` (apid > 0x28 and != 0x3FF) so it never pollutes a verdict.

## 5. Troubleshooting

- `port busy` — close minicom/PlatformIO monitor; the PoC opens the port alone.
- board disappears mid-run — normal for reset/power-cycle PoCs; the runner
  waits (30 s) for re-enumeration, then continues.
- **zombie board** (reads return 0 bytes, writes time out, the console is
  silent): the CDC pipes wedged (see §4bis.4 and §4bis.5 — the latter was
  the deterministic MEM_READ-after killer; it is fixed in the current
  firmware, but an old flashed image still wedges this way). It does
  **not** recover from software — unplug and replug the USB cable, then
  rerun. A BOOTSEL re-flash (see §2) revives a wedged board without
  unplugging — as long as the chip still serves the USB control line (the
  1200-baud touch rides on it); a *total* wedge (v109's SPI-9000 fault
  kills the USB IRQ too — DTR requests get NAK'd) is replug-only, see
  §4bis.8. The sweep's health gate detects this in ~6–90 s and stops the
  batch so you only replug once.
- **host reboot / SSH drop mid-run** kills the reader threads, which wedges
  the board exactly like the zombie above — replug before the next run.
  (Continuous host draining is what keeps a board alive; a killed reader
  is a power event as far as the bench is concerned.)
- `unplug/replug prompt` — for the three crash/hang PoCs; replug and ENTER.
- permissions — `sudo usermod -aG dialout $USER`, re-login.
- if the board enumerates as `RP2 BOOTLUMP` — it stayed in BOOTSEL; flash
  the UF2 again.
- **stale build cache** — if a fix "does not take" after flashing, check
  §2's verification (362 `.o` files + fresh `spp.cpp.o`); always
  `rm -rf .pio/build` before `pio run`.

## 6. Evidence bookkeeping

- `evidence/`     = simulator transcripts (authoritative, 56/56 green).
- `evidence-hw/`  = hardware transcripts, produced by `run_all_usb.sh` /
  `run_list_usb.sh` (each line of a retry list: one PoC basename).
- `evidence/HOST-01/02` = crypto KATs + host compile gate.
