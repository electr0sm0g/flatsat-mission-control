#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Hardware USB sweep: run every PoC against a REAL flashed FlatSat/PwnSat.
#
#   ./tests/hw/run_all_usb.sh [bridge-port] [poc-filter]
#
# Evidence is written to evidence-hw/ (the simulator evidence in evidence/
# stays untouched). A per-PoC health gate (tests/hw/health_gate.py) stops
# the sweep early if the board is wedged (zombie = CDC backpressure;
# replug-only — see docs/HARDWARE-USB-TEST.md) instead of burning 10+
# minutes per doomed PoC inside the bootstrap's _wait_for_revive.
set -u
# pipefail: the health gate's `python | tail -1` must inherit python's
# exit code, not tail's.
set -o pipefail
cd "$(dirname "$0")/../.."
PORT="${1:-/dev/serial/by-id/usb-Pwnsat_Pwnsat_-_Flatsat_fsat-if02}"
FILTER="${2:-v}"
EVD="evidence-hw"
mkdir -p "$EVD"
P=0; F=0; FAILED=()
for f in poc/${FILTER}*.py; do
  name=$(basename "$f" .py)
  printf '%-44s' "$name"
  if ! timeout 180 python3 tests/hw/health_gate.py "$PORT" | tail -1; then
    echo "BOARD DEAD (health gate) -- sweep stopped, replug needed"
    break
  fi
  # generous timeout: v015 advances 5 real minutes, V-21 waits 120 s
  if timeout 1800 env PYTHONUNBUFFERED=1 python3 "$f" --usb --port "$PORT" > "$EVD/$name.txt" 2>&1; then
    P=$((P+1)); echo "PASS"
  else
    F=$((F+1)); FAILED+=("$name"); echo "FAIL (see $EVD/$name.txt)"
  fi
done
echo "-------------------------------------------------------------"
echo "USB SWEEP: PASS=$P FAIL=$F"
[ ${#FAILED[@]} -gt 0 ] && printf 'failed: %s\n' "${FAILED[@]}"
[ $F -eq 0 ]
