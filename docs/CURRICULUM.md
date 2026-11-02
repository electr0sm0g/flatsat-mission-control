# CURRICULUM — three tracks through the lab

One repo, three entry points. All tracks run on the simulator first (no
hardware needed, `--no-save` keeps the committed evidence clean); hardware
is the graduation path. The 56 findings are grouped into the 9 attack
surfaces below (the same grouping as the report's `affected_surface` classification, exposed in the REPORT view).

## The 9 attack-surface groups

| # | Group | Findings | Entry point |
|---|---|---|---|
| 1 | Recon & leakage | V0-01, V0-09, V0-18, V-01…V-03, V-06, V-29, V-37 (9) | `poc/v101_send_fw_inventory.py` |
| 2 | Crypto & link integrity | V0-02, V0-06, V0-07, V0-10, V0-11, V0-12, V-07, V-08, V-10, V-11 (10) | `poc/v111_key_verify_oracle.py` |
| 3 | Spoofing & command tampering | V0-04, V0-05, V0-17, V-12, V-36 (5) | `poc/v136_gps_spoof_chain.py` |
| 4 | Memory corruption & RCE | V0-03, V0-16, V-04, V-05, V-09, V-13, V-14 (7) | `poc/v114_memcpy_rce.py` |
| 5 | Ground segment & downlink | V-28, V-30, V-31, V-32 (4) | `poc/v130_stego_padding_channel.py` |
| 6 | Bus, sensors & FDIR | V-17, V-24…V-27 (5) | `poc/v127_fdir_consumes_forged_mids.py` |
| 7 | Persistence | V-19…V-21, V-38 (4) | `poc/v119_sched_persistence.py` |
| 8 | OTA & protection downgrade | V-16, V-18, V-22, V-23 (4) | `poc/v118_ota_unsigned.py` |
| 9 | DoS & impact | V0-08, V0-13…V0-15, V-15, V-33…V-35 (8) | `poc/v003_broadcast_underflow_crash.py` |

## Track A — 1 hour (the hook)

**Goal:** run the lab, break it twice, understand the bench-parity trick.

1. (10 min) Clone, read the README top-to-catalog, run the self-test:
   `python3 simulator/flatsat_sim.py --selftest`.
2. (15 min) **Recon:** run `poc/v101_send_fw_inventory.py`, read its
   writeup, then read the beacon (`poc/v102_chatty_beacon.py`). Question:
   *what can a passive eavesdropper do with this alone?*
3. (20 min) **Break it twice:** `poc/v009_flash_read_hardcoded_tag.py`
   (read flash behind a magic tag) and `poc/v114_memcpy_rce.py` (the RCE).
   For each: read the writeup *before* re-running, predict the transcript.
4. (15 min) **The parity trick:** open `docs/KILLCHAIN-V36.md`, run
   `poc/v136_gps_spoof_chain.py`, then read the two Mermaid diagrams in the
   README *Bench parity* section. Question: *why does the firmware need a
   window-only clock?*

Exit: 5 PoCs run, 3 writeups read, one kill chain understood.

## Track B — half day (one full kill chain, SPARTA-framed)

**Goal:** walk a complete chain from recon to impact, mapped to SPARTA v3.2.

1. (30 min) **Recon phase (REC):** groups 1 — V-01, V-02, V-03, V-06, V-37.
   Build the CPE picture; note what the SPARTA row says the adversary can
   *do* with each leak.
2. (60 min) **Initial access (IA/EX):** the V-36 flagship — read
   `docs/KILLCHAIN-V36.md` cover to cover, run the PoC, then re-run with
   the `GPS_PLAUS` defense *disabled* and *enabled* (the PoC measures both).
3. (45 min) **Execution & persistence (EX/PER):** `poc/v118_ota_unsigned.py`
   (unsigned OTA), then `poc/v120_fdict_contingency.py` (flash-resident
   trojan), then `poc/v119_sched_persistence.py` (replays after reboot).
   Question: *which of the three survives a factory reset, and why?*
4. (30 min) **Defense review:** close each finding against
   `docs/DEFENSE.md` — the blue-team answer sheet. Write one paragraph:
   *the single control whose absence makes this chain possible.*

Exit: one chain executed end-to-end (recon → spoof → auth bypass →
privileged control → persistence), every step cited to SPARTA v3.2 and a
writeup.

## Track C — one week (all 9 surfaces, sim → hardware)

**Goal:** own the full catalog; graduate to the board.

- **Days 1–2 — surfaces 1–4 (recon, crypto, spoofing, memory):** 31
  findings. For each: PoC on sim, writeup, SPARTA row. Deliverable: a
  one-page note per surface — *the invariant the firmware breaks*.
- **Days 3–4 — surfaces 5–9 (ground segment, bus/FDIR, persistence, OTA,
  DoS):** 25 findings, same method. Deliverable: the chain map from
  `docs/THREAT-MODEL.md` redrawn by hand.
- **Day 5 — the impact session (hardware).** Flash the board
  (`docs/HARDWARE-USB-TEST.md`), run the health gate, then the sweep:
  `tests/hw/run_all_usb.sh`. Watch the three crash PoCs (v003, v015, v135)
  wedge the board for real — that is the finding, not a bug; replug and
  resume. Deliverable: your own `hw_pass.txt`-style pass list + the
  md5 of your flashed image (must equal `bfc145c9…` or you are not on
  image H).
- **Day 6 — defense & reporting.** Write the remediation plan for the
  56 findings using `docs/DEFENSE.md` as the scaffold; produce a short
  report in the style of `reports/FlatSat-Electr0sm0g-Lab-Pentest-Report.pdf`.
- **Day 7 — contribution.** Add one finding end-to-end
  (`CONTRIBUTING.md`): firmware + sim + PoC + writeup + SPARTA row +
  `FINDINGS.json` regeneration, `make check` green.

## Rules of engagement

- The radio side of the board talks ISM-band LoRa — **never point it at a
  network you don't own** (README *Safety*).
- `--no-save` for practice runs; the committed transcripts in
  `evidence/` / `evidence-hw/` are the deliverable and must not be
  overwritten.
- A wedged board (DTR NAK'd) needs a physical USB replug — plan for it, it
  is part of the DoS findings.
