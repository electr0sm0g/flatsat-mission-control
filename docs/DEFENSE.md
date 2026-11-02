# DEFENSE — what a real flight-software team must do

The lab is vulnerable *by design*. This document is the blue-team companion:
for each of the 9 attack-surface groups, the control that was deliberately
broken, the countermeasure, and the standard to check it against. Use it as
the remediation checklist for a genuine CubeSat program — or as the answer
sheet when you audit this lab.

Companion reading: the offensive side lives in
[`RAPPORT-FIRMWARE-VULNERABLE-FLATSAT.md`](RAPPORT-FIRMWARE-VULNERABLE-FLATSAT.md)
and the per-finding writeups in [`writeups/`](writeups).

---

## 1. Recon & leakage (V0-01, V0-09, V0-18, V-01…V-03, V-06, V-29, V-37)

**Broken control:** anything worth knowing (version, inventory, crypto
state, battery, eclipse phase, station coordinates, RF fingerprint) answers
an unauthenticated poll.

**Countermeasures**

- Beacon minimisation: publish mission status only; mode, battery and
  eclipse are ground-decision data and belong in an authenticated TM.
- APID allow-list: `SEND_FW`, `FLASH_READ`, `GS_STATUS` and diagnostic
  APIDs execute only inside an authenticated session.
- No coordinates or operational geometry in any unauthenticated APID.
- Version pinning *after* authentication, never in a banner.

**Check against:** CCSDS 355.0-B-2 (secure TM/TC), SPARTA v3.2 REC-technique
mitigations.

## 2. Crypto & link integrity (V0-02, V0-06, V0-07, V0-10, V0-11, V0-12, V-07, V-08, V-10, V-11)

**Broken control:** one static link key compiled into the image, ECB mode,
16-bit wrapping ARC, 43 of 64 SDLS associations defaulting to Clear, OTAR
with NULL master keys, and an over-the-air switch that disables the whole
crypto layer.

**Countermeasures**

- Key provisioning at manufacture (one-time, out-of-band); the image must
  not contain the link key.
- AEAD (e.g. AES-CTR + CMAC, or GCM) over the SPP frame — integrity first;
  ECB is not a transport mode.
- 64-bit ARC (or nonce) with a replay window; reject stale ARC
  monotonically.
- SDLS default-deny: associations start Clear only when the mission
  profile says so, and the profile change is authenticated.
- OTAR: master key never NULL; key hierarchy verified against a root
  of trust.
- Crypto state changes (enable/disable/mode) require the highest
  authentication tier and are journaled.

**Check against:** NIST SP 800-38B (CMAC), CCSDS 355.0-B-2 key management,
SPARTA v3.2 PER-0004 (Replace Cryptographic Keys).

## 3. Spoofing & command tampering (V0-04, V0-05, V0-17, V-12, V-36)

**Broken control:** actuators and navigation accept unauthenticated or
integrity-free input — `SET_THRUSTER` from raw radio, NMEA without
checksum, strtok column handling, APID re-routing + ECB splice.

**Countermeasures**

- Actuator commands (thrusters, heaters, mode) execute only inside an
  authenticated session *and* inside the plausibility envelope.
- NMEA: checksum verification at the parser **and** fix-vs-propagator
  cross-check (predict the pass, reject disagreement beyond a bound);
  plausibility threshold at a physically sane value (LEO ground-track
  ≈ 7.6 km/s, not 500 km/s).
- Fixed APID→command map; APID re-routing is not a feature.
- Integrity over the whole frame (CMAC), not per-block ECB (no splice
  surface).
- GPS anti-spoof (multi-antenna / null-steering) is the expensive
  option; cross-checking is the cheap one — do the cheap one first.

**Check against:** SPARTA v3.2 EX-0014.04 (Position, Navigation, and Timing (PNT) Spoofing), ESTCube-1 ICP
posture (Didelot et al.).

## 4. Memory corruption & RCE (V0-03, V0-16, V-04, V-05, V-09, V-13, V-14)

**Broken control:** every external input reaches a `memcpy`/table with
bounds that do not hold — the 0xFFFD underflow, SPP off-by-one,
Heartbleed-style padding, arbitrary `MEM_READ`, OOB SPI table reads,
`SET_LOG_NAME` overflow, and the VTOR-redirect `memcpy` RCE.

**Countermeasures**

- Bounded input at the frame layer: SPP length validated *before* any
  copy; reject, never clamp silently.
- Code region flash-locked (VTOR immutable after boot); data stores in
  separate, non-executable regions.
- Stack canaries + bounded `strncpy` for every name/label field.
- **Fuzz the frame parser in CI.** V0-03 is a fuzzer-discovered bug; a
  small corpus-driven harness against the simulator is a standing part of
  this lab's CI philosophy — do the same in your program.
- Treat every "debug" APID (`MEM_READ`, `SPI` raw) as a control-plane
  endpoint: authenticated, rate-limited, journaled.

**Check against:** CWE-787/785/416/125, the flight-software safety case
(DO-178C-adjacent practices for smallsat: bounds-checked I/O, locked VTOR).

## 5. Ground segment & downlink abuse (V-28, V-30, V-31, V-32)

**Broken control:** the GS handshake is offline-computable (no TRNG), the
downlink can be squatted, TM padding carries a stego channel, payload
arming is unauthorized and audit counters are frozen.

**Countermeasures**

- Challenge from a TRNG, CMAC challenge-response with a fresh nonce per
  session (fixes V-28 and V0-06 in one move).
- Downlink frequency/schedule changes require the highest auth tier;
  BROADCAST-style squatting must not reassign TM parameters.
- No reserved, attacker-writable TM padding (stego channel removed by
  construction).
- Payload arming: two-person rule on the ground side *and* an
  authenticated, monotonically incrementing audit counter on the craft.

**Check against:** SPARTA v3.2 IA-0008.01 (Rogue Ground Station),
EXF-technique mitigations.

## 6. Bus, sensors & FDIR (V-17, V-24, V-25, V-26, V-27)

**Broken control:** the SpaceCAN bridge is unauthenticated, the anomaly
detector is evadable, and FDIR *consumes* the same bus it is supposed to
watch — the safety loop can be laundered.

**Countermeasures**

- Per-MID integrity (CMAC tag on each bus frame, or an authenticated
  bridge); unknown MID = reject + anomaly feed.
- Anomaly detector robust to slow ramps (derivative-aware, not EWMA-only);
  feed sensor plausibility (fix-vs-TLE, range-rate) into the detector.
- FDIR inputs validated at the boundary: FDIR must not treat
  attacker-influenced MIDs as ground truth.
- Sensor masks / GPIO overrides writable only in the highest auth tier,
  and journaled.

**Check against:** SPARTA v3.2 DE-0003.12 (Modify On-Board Values:
Flight Software), CM0032.

## 7. Persistence (V-19, V-20, V-21, V-38)

**Broken control:** everything that survives a reboot is writable by a
telecommand — scheduled task queue, FDICT contingency dictionary, watchdog
scratch cookie, anti-rollback counter.

**Countermeasures**

- Flash stores: signature required (the CRC-16 is a checksum, not a
  signature); task queue bounded in size and authenticated per entry.
- Watchdog scratch not writable from the TC path.
- ARWC monotonic, upgradable only by the signed-OTA path; downgrades
  rejected.
- Any persistence state change emits an authenticated audit record.

**Check against:** SPARTA v3.2 PER-0002 (Software Backdoor),
PER-0002.02 course numbering.

## 8. OTA & protection downgrade (V-16, V-18, V-22, V-23)

**Broken control:** OTA images are verified with CRC-16 only; forced safe
mode *persists* a protection downgrade; the TC journal is off by default;
the TEST APID window opens in safe mode.

**Countermeasures**

- Signed OTA: asymmetric signature (ECDSA/RSA) verified before flash,
  CRC as the last step.
- Safe mode is a runtime state, not a persisted configuration; exiting it
  requires the highest auth tier.
- TC journal ON by default; disabling it is an audited, authenticated act.
- TEST APID window (0xF0–0xFF) closed by default; opens only in a
  physically attested bench state.

**Check against:** SPARTA v3.2 EX-0009.02 course numbering
(Exploit Code Flaws: Operating System), CCSDS OTA guidance.

## 9. DoS & impact (V0-08, V0-13…V0-15, V-15, V-33…V-35)

**Broken control:** no watchdog, no rate limits, unbounded floods — one
`RESETC` reboots the craft, junk storms drive the bus OFF, beacon floods
freeze the mission loop, momentum spam saturates detumble, heater drain
wipes state at brownout.

**Countermeasures**

- Watchdog with clean-restart semantics (state survives a reset, not a
  power cycle).
- Per-APID rate limits (token bucket per source); reject-and-alarm above
  budget instead of queueing unboundedly.
- Beacon/downlink scheduler with a fairness budget; BROADCAST-style
  saturation cannot starve mission TM.
- Detumble authority bound: momentum-spam torque capped below the
  detumble authority so the loop always wins.
- Power budget monitoring with a safe-state trip before brownout; heater
  duty-cycle limited outside eclipse prediction.
- `RESETC` and any one-shot reboot APID: authenticated + journaled.

**Check against:** SPARTA v4.0 IMP-0013 (Resource Exhaustion or
Contention), vehicle FDIR requirements (FDIR tree per mission standard).

---

## The verification loop (why the lab can *prove* its fixes)

A fix is only as good as its proof. This lab's answer:

1. **Bench parity:** the simulator is the behavioural reference; the
   firmware's FEED-window clock (`LAB_CTRL 0x27 sub 6`) makes board time
   deterministic — a fix is proven on *both* targets with the *same* PoC.
2. **Catalog gate:** `tests/host/check_catalog.py` fails if a finding,
   PoC, writeup or transcript drifts — a fix that "makes the PoC pass"
   must keep the evidence story coherent.
3. **Reproducibility:** `make check` re-runs self-test, the 56-PoC sweep,
   host crypto vectors and the catalog gate; the firmware digest
   (`md5sum`) pins the exact image being tested.

That loop — deterministic time, one PoC per finding, machine-checked
catalog — is the part worth copying into a real program.
