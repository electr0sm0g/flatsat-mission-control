# Kill chain walkthrough — V-36: GPS spoof → GS gate bypass → privileged control

The flagship chain of the lab: **complete unauthenticated initial access**
to a CubeSat. One unauthenticated uplink, three TCs, and the vehicle is in
PAYLOAD mode under attacker control. This document is the standalone
narrative; the machine-checked writeup is
[`writeups/V-36_gps_spoof_chain.md`](writeups/V-36_gps_spoof_chain.md), the
executable proof is `poc/v136_gps_spoof_chain.py`.

## Objective

Take control of the vehicle's privileged command set (mission-mode changes)
from an unauthenticated radio, using only off-the-shelf SDR + RP2040-class
hardware and public information from the firmware image.

## Preconditions (all passive / public)

- Firmware image analysis: the GS gate arms only within `GS_RADIUS_M =
  35000` of the station position (`_gs_within` in `flatsat_sim.py`; on the board, `gs_station_radius_m` / `groundStationGateOpen()` in `worker.cpp`), and the
  position comes from the GPS/NMEA path.
- The NMEA override TC `0x14` is accepted **without checksum or source
  authentication** (V0-05) — the keystone.
- The GS handshake is `challenge XOR 0xC0DEFACE` (static key, V0-06).
- The station coordinates are themselves leakable (V0-18, `GS_STATUS`).

## The chain

```mermaid
sequenceDiagram
    participant A as Attacker (unauthenticated uplink)
    participant C as Craft (OBC)
    Note over C: vehicle parked, GS gate closed to strangers
    A->>C: TC 0x14 GPS_OVERRIDE = Tokyo (35.68N 139.69E)
    C-->>A: TM 0x0E — fix adopted, no checksum demanded
    A->>C: TC 0x11 GS_MODE(ON)
    C-->>A: error TM: GS RANGE LOCK (out of footprint — gate holds)
    A->>C: TC 0x25 enable GPS_PLAUS defense
    A->>C: instant Tokyo→GS hop (logged 9500 km; geodesic ~8900 km)
    C-->>A: REJECTED (plausibility counter +1)
    A->>C: same hop spread over 60 s (≈158 km/s < 500 km/s)
    C-->>A: accepted — vehicle back inside the 35 km gate
    A->>C: TC 0x11 GS_MODE(ON) → armed
    A->>C: TC 0x12 GS_ACCESS → challenge
    A->>C: challenge ^ 0xC0DEFACE → session granted
    A->>C: TC 0x0D SET_MISSION_MODE(PAYLOAD)
    C-->>A: PAYLOAD mode armed — privileged control achieved
```

### Step 1 — Spoof the position (V0-05)

`TC 0x14 payload=<le32 lat_e7, le32 lon_e7, le32 alt, u8 sats>` =
`00564415 a0004353 801a0600 09` → Tokyo, 9 sats. The craft adopts the fix
and echoes it — no checksum, no source authentication.

### Step 2 — Prove the gate exists (and is spoofable)

`TC 0x11` (arm GS mode) fails with `GS RANGE LOCK` — the arming itself is
range-gated, so a vehicle parked in Tokyo cannot talk to the station. The
gate is real; its position input is the attacker's.

### Step 3 — Defeat the one active defense (measured, not assumed)

Enable the optional plausibility gate (`TC 0x25`, `DEF_GPS_PLAUS`). The
instant ~9,500 km hop (as logged) is **rejected**. The *same* hop spread over 60 s —
≈ 158 km/s, still 65× above LEO ground-track plausibility (~7.6 km/s) —
walks straight through the 500 km/s threshold. The craft reports 0 m from
the station.

### Step 4 — Answer the handshake offline (V0-06 / V-28)

Plain `0x0C` poll now returns `GS AUTH REQUIRED`. `TC 0x12 payload=00`
yields the challenge; the reply is `challenge ^ 0xC0DEFACE` — computable
offline from the firmware image (and, with V-28's no-TRNG challenge
seeding, predictable in advance).

### Step 5 — Privileged control

`TC 0x0D payload=02` = `SET_MISSION_MODE(PAYLOAD)` executes. The chain is
complete: **NMEA spoof → range gate dissolved → XOR auth → privileged
mode, all from an unauthenticated uplink.**

## Evidence

The PoC asserts every link (`GS RANGE LOCK`, plausibility reject ≥ 1,
acceptance of the 158 km/s hop, `GS AUTH REQUIRED`, handshake granted,
mode = PAYLOAD) and ends with `POC OK` — on the simulator and on the real
board:

- [`evidence/v136_gps_spoof_chain.txt`](../evidence/v136_gps_spoof_chain.txt) (simulator)
- [`evidence-hw/v136_gps_spoof_chain.txt`](../evidence-hw/v136_gps_spoof_chain.txt) (FlatSat 1 over USB)

```
[   0.000] spoofed fix: Tokyo (lat_e7=356800000) accepted without any checksum or source authentication
[   0.001] GS_MODE(ON) -> 'GS RANGE LOCK': the arming itself is range-gated
[   0.002] with plausibility gate: reject counter=1 (position held in Tokyo)
[   0.023] 9500 km in 60 s accepted -> vehicle back inside the footprint (GS range field now 0 m)
[   0.026] GS AUTH REQUIRED on a plain GET_STATUS -> session needed
[   0.028] chain complete: NMEA spoof -> range dissolved -> XOR auth -> PAYLOAD mode armed, all from an unauthenticated uplink
```

## Impact

- **The security model's keystone is sensor data.** One unauthenticated TC
  family (or an RF spoofer at the GPS antenna) turns the "physical
  presence" ground-station control into attacker-chosen truth, and
  privileged commanding follows.
- **The only active defense is miscalibrated:** 500 km/s ≈ 65× the LEO
  ground-track speed; enabled or not, it stops only instantaneous hops.
- **Chaining multiplier:** with V-28 the handshake becomes passive
  (predictable challenge); with V-35 the attacker can then saturate the
  downlink *authenticated*.

## Reproduce

```bash
python3 poc/v136_gps_spoof_chain.py            # simulator (default)
python3 poc/v136_gps_spoof_chain.py --usb      # real FlatSat 1 over USB
```

## Remediation (see [`DEFENSE.md`](DEFENSE.md), group 3)

1. NMEA checksum at the parser + fix-vs-propagator cross-check (the
   ESTCube-1 ICP approach); plausibility threshold at a physically sane
   bound (~10 km/s, not 500 km/s).
2. Treat fix-vs-TLE disagreement as an anomaly feed (CM0032 / DE-0003.12)
   instead of trusting either source alone.
3. Replace XOR auth with a CMAC challenge-response with a fresh nonce —
   fixes V-36's handshake and V-28 together.

## SPARTA mapping

EX-0014.04 · Spoofing: PNT Spoofing (primary); IA-0008.01 Rogue Ground
Station; EX-0003 Modify Authentication Process; EX-0014.03 Sensor Data —
SPARTA v3.2, see the V-36 row in [`SPARTA_MAPPING.md`](SPARTA_MAPPING.md).
