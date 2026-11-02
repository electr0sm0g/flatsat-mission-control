# REALISM — how real are the 56 findings?

The obvious question: is this what you would actually find in orbit? The
honest answer is **yes for the defect classes, no for the configuration**.
Every one of the 56 is an instance of a flaw class documented in real smallsat
flight software; the *configuration* — every class broken at once, several
triggers lab-facilitated — is a pedagogical amplifier, not a snapshot of any
orbital asset. Nothing in this repository describes or targets a real
satellite.

## The three tiers

### Tier 1 — the flaw class is documented in real flight software

Named real-world precedents (incidents, post-mortems, or standards that exist
precisely because the class keeps recurring):

| Flaw class | Findings (examples) | Real-world precedent |
|---|---|---|
| Unauthenticated / weakly-authenticated uplink | V0-04, V0-06, V0-08, V-12 | **ACTS1** (Surrey, 2020): unencrypted, unauthenticated uplink — the craft was hijacked by an external researcher. The canonical proof of this class |
| Hardcoded / weak link keys, ECB transport | V0-02, V0-11, V0-10 | key-recovery analyses of real smallsat links; the **ESTCube-1** (ESA) crypto posture before its ICP hardening |
| No replay protection | V0-07, V-07 | documented gap in real SDLS deployments; CCSDS 501.0-B requires what smallsats often lack |
| Unauthenticated sensor / PNT input | V0-05, V0-17 | the **LEO PNT/GNSS spoofing** research line (multiple university demonstrations against flying CubeSats) — the architecture the V-36 chain exercises |
| Unbounded parsers / memory bugs | V0-03, V0-16, V-13, V-04 | the canonical findings of **firmware-fuzzing studies** on real smallsat code; the VTOR-redirect primitive (V-14) is standard on the Cortex-M0+ class that flies |
| Unsigned OTA, rollback, persisted downgrade | V-18, V-38, V-22 | the #1 cited weakness in the smallsat OTA literature — "a checksum is not a signature" is the audit finding, verbatim |
| Flash-resident stores writable by TC | V0-09, V-05, V-19, V-20 | debug/service APIDs left enabled in flight firmware — a recurring audit finding |
| Downlink / ground-segment exposure | V0-18, V0-14, V-32, V-35 | station-coordinate leaks via TM and downlink-schedule squatting — documented smallsat exposure |
| No watchdog / hang | V0-15 | the classic smallsat failure mode: hung until a physical power cycle |

### Tier 2 — realistic mechanism, lab-facilitated trigger

The mechanism is real; the trigger is maximized or lab-facilitated so the PoC
is deterministic and provable on both targets:

- **V-36 (the flagship chain).** The `GPS_OVERRIDE` TC (`0x14`) does not exist
  on a real satellite — it is the keystone that makes the chain testable. What
  is real is the *architecture*: a range gate fed by unvalidated sensor data,
  a static-XOR handshake, and a plausibility defense whose threshold is
  miscalibrated (500 km/s ≈ 65× the LEO ground-track speed). The RF side — a
  GPS spoofer at the antenna — needs no lab TC at all; that half of the chain
  is a pure in-orbit vector.
- **V-14 (memcpy RCE).** dst/src/len all taken from the frame is the
  maximized form; real systems at least partially bound the copy. The class —
  unbounded frame-layer copy + a writable vector table on Cortex-M0+ — is
  what fuzzers actually find.
- **V-28 (session hijack).** Seeding the challenge from the mission clock
  instead of a TRNG is a real (and common) smallsat choice; combined with the
  static XOR the handshake becomes fully offline-computable. Real programs
  usually fail one of the two, not both.
- **V-24 / V-27 (safety-loop laundering).** An unauthenticated bus is a
  documented gap; the slow-ramp EWMA evasion demonstrates *miscalibrated*
  detectors — the common case in the field.
- **v003 / v015 / v135 (the crash PoCs).** The impact is real — no watchdog
  means the vehicle stays down until a power-cycle opportunity. The
  *deterministic wedge over USB* is a bench artifact of the lab transport.
- **V0-12 (USB debug bypass).** The bench APID family (`0x26`/`0x27`) is a
  by-design lab service (trust boundary B5). In orbit it is absent — not an
  in-orbit vector. The class it models (service APIDs left enabled) is real.
- **The oracles (V-03, V-04, V-11, V-29, V-37).** Side-channel / leakage
  measurement is a documented space-security research line; the lab exposes
  each one over the bench so it is *measured*, not asserted.
- **V-30 (stego TM padding).** A capacity-study artifact: covert channels in
  telemetry are a research topic, not a defect you "find" in the field.

### Tier 3 — by-design laboratory constructs (test instrumentation)

Present so the study is deterministic and reproducible; documented as
lab-only, absent from the flight code path:

- the **FEED-window epoch clock** (`LAB_CTRL 0x27 sub 6`) and the 60.0×
  cold-boot scale — the bench-parity mechanism itself;
- the **bench APID family** (`0x26`/`0x27`) and the USB CDC transport;
- **deliberately maximized parameters**: the 500 km/s plausibility threshold,
  43 of 64 SDLS associations defaulting to Clear, NULL master keys, the static
  XOR;
- **the superset itself**: no real program ships all 56 at once — a real
  audit would typically surface 5–10 of these classes, not the full catalog.

## What "in orbit" means for this catalog

In orbit the only attack surface is the **RF uplink** (the downlink is
passive; there is no USB, no SWD, no physical access). Mapping the 56 onto
that surface:

- **RF-reachable (the large majority):** every TC APID family — recon polls,
  the crypto layer, actuator TCs, persistence stores, the OTA path, downlink
  scheduling, and the DoS floods (groups 1, 2, 3, 4, 5, 7, 8 plus the
  TC-driven parts of 6 and 9).
- **The PNT side of V-36** (RF spoofing at the GPS antenna) needs no lab TC
  at all.
- **Bench/physical-only:** V0-12 and the Tier-3 instrumentation — these exist
  so the lab can *prove* sim ≡ silicon parity, not as orbital vectors.

So the claim this repository can honestly make: **an attacker with an
ISM-band transmitter in RF range could execute the large majority of the
catalog against this firmware as it would fly** — minus the bench-only paths.

## Real-world anchors

- **ACTS1** (Surrey, 2020) — unencrypted, unauthenticated uplink, hijacked by
  an external researcher; followed by the *Hack-a-CubeSat* exercise run on
  real smallsat firmware.
- **ESTCube-1 ICP** (Didelot et al.) — Estonia's first satellite (an ESA-supported student project); its documented
  crypto posture and later hardening are the reference for what real smallsat
  cryptography looks like, gaps included.
- **CCSDS 501.0-B / 355.0-B-2** — space-mission security requirements and the
  Space Data Link Security standard: what real programs are *supposed* to do;
  several lab findings are exactly the gap between the requirement and
  typical smallsat practice.
- **SPARTA v3.2** — The Aerospace Corporation's threat/countermeasure taxonomy for real
  spacecraft; the whole catalog is mapped to it
  (`SPARTA_MAPPING.md`), which is why the mapping is checkable line by line.
- **Firmware-fuzzing studies** on real smallsat code — buffer overflows of the
  V0-03 / V0-16 class are the canonical findings.
- **LEO PNT/GNSS spoofing** — a standing research line with public
  demonstrations against flying CubeSats.

## The honest sentence

> The **flaw classes and the exploitation primitives** are realistic and
> documented in real smallsat flight software. The **exact configuration** —
> every class broken at once, several triggers lab-facilitated — is a
> **pedagogical amplifier**, not a snapshot of any orbital asset. This
> repository makes no claim about, and targets no, real satellite.

Companion reading: [`THREAT-MODEL.md`](THREAT-MODEL.md) (adversary model +
trust boundaries), [`DEFENSE.md`](DEFENSE.md) (the countermeasures, group by
group), [`VERIFICATION.md`](VERIFICATION.md) (every claim → evidence →
command).
