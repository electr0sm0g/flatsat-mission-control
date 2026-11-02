# Contributing to the FlatSat electr0sm0g Lab

The lab is a *contract*, not a code dump: 56 findings, each with exactly
one PoC, one writeup, one SPARTA row, and two transcripts (simulator +
hardware). `tests/host/check_catalog.py` enforces the contract on every
push — a contribution that breaks the catalog is not merged.

## The contract (what a complete finding needs)

A finding is complete when **all** of the following hold:

1. **Firmware** (`firmware/`): the vulnerability is implemented in the real
   firmware (vulnerable by design — no shims, no `#if LAB` escapes that
   weaken the finding).
2. **Simulator** (`simulator/flatsat_sim.py`): mirrored bit-for-bit — the
   simulator is the authoritative behavioural reference.
3. **PoC** (`poc/vNNN_*.py`): executable, uses `poc/lib/fslab.py`, runs
   unchanged on both targets (`python3 poc/vNNN_*.py` and `--usb`), ends
   with `POC OK`.
4. **Writeup** (`docs/writeups/V-NN_slug.md`): summary, root cause,
   mechanism, exploitation walkthrough with real transcript excerpts,
   impact, mitigations, references.
5. **SPARTA row** (`docs/SPARTA_MAPPING.md`): primary technique, notional
   risk, secondary techniques, PoC/evidence ref — pinned to SPARTA v3.2.
6. **Evidence**: `evidence/vNNN_*.txt` (sim) + `evidence-hw/vNNN_*.txt`
   (hardware), both ending in `POC OK`.
7. **Catalog**: `FINDINGS.json` regenerated (`python3
   tests/host/gen_findings.py`) and `make check` green.

Numbering: `V0-xx` = baseline v1.0 findings (PoC `v0xx_*`), `V-xx` = v2 lab
findings (PoC `v1xx_*`). The ID↔number mapping is checked by the catalog
gate — do not rename.

## Workflow

```bash
git clone <repo-url> && cd flatsat-mission-control
make check          # baseline green (selftest + 56-PoC sweep + gates)
# ... your change ...
make check          # still green?
python3 poc/vNNN_*.py            # sim: POC OK
python3 poc/vNNN_*.py --usb      # hardware: POC OK (if you have the board)
python3 tests/host/gen_findings.py
git add -A && git commit -m "V-NN: <title> (firmware+sim+PoC+writeup+SPARTA)"
```

## Parity rules (the hard part)

- **Do not change the PoC to make a firmware change pass.** The PoC is the
  spec; if the firmware changes behaviour, the fix belongs in firmware +
  simulator together, and the change is documented in `docs/BUILD.md` as a
  sweep pass with date, image digest and rationale (see passes 8–9).
- **Deterministic time.** The firmware's workers advance only inside the
  FEED window (`LAB_CTRL 0x27 sub 6`); the simulator advances only inside
  `advance()`. Any new timing-dependent behaviour must respect both.
- **Evidence hygiene.** Transcripts are committed deliverables. Practice
  with `--no-save`; never `git add` an over-written transcript without
  re-verifying the `POC OK` tail and the image digest.

## What good looks like

- `docs/KILLCHAIN-V36.md` — a full chain narrative with evidence excerpts.
- `docs/DEFENSE.md` — the blue-team companion to any group of findings.
- `docs/BUILD.md` — the parity-fix history (the honest engineering log).

## House rules

- The lab is intentionally vulnerable. **Never point the board's radio at a
  network you don't own.**
- Crash PoCs (v003, v015, v135) wedge real hardware by design — expect a
  physical USB replug; the health gate in `tests/hw/run_all_usb.sh` stops
  a doomed sweep early.
- License: GPL-2.0-or-later (matches upstream FlatSat firmware). New files
  carry the matching `SPDX-License-Identifier` header.
- Use the issue templates: `bug` (PoC/sim/HW regression), `parity`
  (sim↔HW divergence), `new-finding` (a complete candidate finding).
