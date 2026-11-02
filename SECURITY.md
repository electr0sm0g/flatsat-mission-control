# Security policy

## Intentionally vulnerable code

This repository is a **vulnerable-by-design training laboratory**. Every one of the
56 findings (see `docs/SPARTA_MAPPING.md`) is present in the firmware *on purpose*
— hardcoded cryptographic keys, unauthenticated telecommands, exploitable memory
corruption, missing replay protection, and so on.

- **Do not** run this firmware on any network or radio environment you do not
  control.
- **Do not** modify the PoCs into live attacks against systems that are not part
  of an authorized assessment.
- The only safe targets are the Python simulator (`simulator/flatsat_sim.py`) and
  an isolated bench PwnSat/FlatSat with its radio side kept off hostile networks.

## Vulnerability reports

Reports about the lab itself (build breakage, simulator/firmware parity drift,
PoC failures, evidence gaps) are welcome as GitHub issues. Use the labels
`bug`, `parity`, or `docs` as appropriate. Findings *inside the lab firmware* are
not vulnerabilities to report — they are the curriculum.

## Safe usage checklist

1. Build the firmware in a clean environment: `cd firmware && pio run`.
2. Flash only your own bench PwnSat (1200-baud BOOTSEL recipe,
   `docs/HARDWARE-USB-TEST.md` §2).
3. Keep the SX1262 LoRa modules disconnected or out of range of any network you
   do not own.
4. Crash PoCs (`v003`, `v015`, and under load `v135`) permanently wedge the board
   by design — recovery is a physical USB replug. Expect this; it is the finding.
