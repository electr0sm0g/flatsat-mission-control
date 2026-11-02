# VERIFICATION — every claim in this repo, and how to reproduce it

The README makes claims; this page is the audit table. Every row is
reproducible from a fresh clone with the commands shown. The CI
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) re-runs rows
1–3, 5 and 10 automatically on every push to main (row 4 needs the physical board — CI only re-checks its committed transcripts; rows 6–9 are on-demand); the release workflow re-runs row 3 on
every tag.

| # | Claim | Evidence in repo | Reproduce |
|---|---|---|---|
| 1 | The simulator is the authoritative behavioural twin: FIPS-197 ECB, SP800-38A CTR, SP800-38B CMAC, secure-link, SDLS 43/64 NULL SAs, NULL-master-key OTAR | `evidence/HOST-01-crypto-vectors-sim-selftest.txt` | `python3 simulator/flatsat_sim.py --selftest` |
| 2 | 56 PoCs pass 56/56 on the simulator (one PoC per finding) | 56 transcripts in [`evidence/`](../evidence), each ending in `POC OK` | `for f in poc/v0*.py poc/v1*.py; do python3 "$f" --quiet --no-save \|\| break; done` |
| 3 | The committed firmware is the final bench image (H); the kept hardware transcripts span images E–H as annotated in `hw_pass.txt` | UF2 335872 B, md5 `bfc145c93039177b7393147978cdd432` (stated in [`hw_pass.txt`](../hw_pass.txt), `docs/BUILD.md`, tag `v1.0.0`) | `cd firmware && pio run && md5sum .pio/build/pico_tinyusb/firmware.uf2` |
| 4 | 56 PoCs pass 56/56 on real FlatSat 1 hardware over USB | 56 transcripts in [`evidence-hw/`](../evidence-hw) + [`hw_pass.txt`](../hw_pass.txt); annotated items (v003/v015 = images E/F evidence, v135 = image G) named in `hw_pass.txt` | `tests/hw/run_all_usb.sh` (requires a flashed board; the health gate stops the sweep on a wedged board) |
| 5 | Catalog integrity: 56 matrix rows ↔ 56 PoCs ↔ 56 writeups ↔ 112 transcripts, ID↔number mapping, `FINDINGS.json` in sync, README links resolve | [`FINDINGS.json`](../FINDINGS.json), `docs/SPARTA_MAPPING.md`, `tests/host/check_catalog.py` | `python3 tests/host/check_catalog.py` (fails the build on any drift) |
| 6 | Host crypto vectors + firmware syntax gate | `tests/host/run_host_checks.sh` | `bash tests/host/run_host_checks.sh` |
| 7 | SPARTA mapping pinned to v3.2 (The Aerospace Corporation, 2026-03-11), technique IDs and notional-risk scores verified against sparta.aerospace.org | `docs/SPARTA_MAPPING.md` (header states the verification method) | manual: compare rows against the technique pages on sparta.aerospace.org |
| 8 | Bench parity mechanism: FEED-window epoch clock, 60.0× cold-boot scale, re-arm between PoCs | `firmware/extcmds.cpp` (`hLabCtrl`, `labTickWorkers`), `docs/BUILD.md` (sweep passes 8–9), README *Bench parity* section incl. the two diagrams | read the code paths; the sweep transcripts in `evidence-hw/` carry bench-ms phase stamps |
| 9 | Crash PoCs are by-design impacts (v003/v015 wedge the board, DTR NAK'd, replug-only; v135 can wedge under the flood) | `docs/HARDWARE-USB-TEST.md` item 27, `hw_pass.txt` annotations | the transcripts in `evidence-hw/` show the wedge sequence |
| 10 | The in-browser console (OVERVIEW A-to-Z explanation + dashboard / OPS mission control / INDEX of the 56 step-by-step writeups / REPORT from `pentest-report.json` / REPO byte-identical source browser) runs the **unmodified** simulator + PoCs (Pyodide/CPython-WASM): live SPP frame stream, state introspection, live PoC transcript, V-36 killchain lit by evidence anchors, and hash-verified transcripts | `web/dist/index.html` (sources + writeups + report + repo files + APID attack surface + killchain anchors + ground-station constants baked in at build), `web/harness.py` (wire taps + free-flight), `web/app.js` (5 views), CI job `web-demo` (headless Chromium asserts boot, self-test, `POC OK` + md5 match, ≥10 frames, ≥2000 B tiles, 56 index cards, telemetry points, 5/5 killchain stages, 8+ explanation blocks, 56 report cards + PDF, 150+ repo files, evidence deep-link) | `make web-demo`, serve `web/dist/` (e.g. `python3 -m http.server 8931 --directory web/dist`), open the console — OVERVIEW to understand the site, OPS to RUN a PoC (verdict shows the transcript md5 vs `evidence/<poc>.txt`), INDEX to read + RUN LIVE any writeup, REPORT/REPO for the full report and every committed source |

## What "bench parity" means, operationally

One PoC, two targets:

```bash
python3 poc/v114_memcpy_rce.py            # simulator
python3 poc/v114_memcpy_rce.py --usb      # real FlatSat 1
```

The same driver (`poc/lib/fslab.py`), the same assertions, the same
expected transcript. The simulator advances its workers only inside
`advance()`; the firmware's bench epoch clock (`s_bench_ms`) advances only
inside a `LAB_CTRL 0x27 sub 6 FEED_START` window — so both targets tick
their model / FDIR / schedule / radio workers at the same instants.

## Adding a finding (keeps the table true)

The contract is in [`../CONTRIBUTING.md`](../CONTRIBUTING.md): implement it
in the firmware, mirror it in the simulator, write the PoC + writeup, add
the SPARTA row, regenerate `FINDINGS.json`, and `make check` must stay
green on both targets.
