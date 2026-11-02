#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Run an explicit list of PoCs (one basename per line) against the board.
# A per-PoC health gate stops the sweep early if the board is wedged
# (replug needed) instead of burning 10+ minutes per doomed PoC inside
# the bootstrap's _wait_for_revive.
set -u
# pipefail: the health gate's `python | tail -1` must inherit python's
# exit code, not tail's (a DEAD board once sailed through the gate).
set -o pipefail
cd "$(dirname "$0")/../.."
PORT="${1:-/dev/serial/by-id/usb-Pwnsat_Pwnsat_-_Flatsat_fsat-if02}"
LIST="$2"
EVD="evidence-hw"
mkdir -p "$EVD"
pass=0; fail=0; skip=0
while read -r name; do
  [ -z "$name" ] && continue
  printf '%-44s ' "$name"
  if ! timeout 180 python3 tests/hw/health_gate.py "$PORT" | tail -1; then
    echo "BOARD DEAD (health gate) -- sweep stopped, replug needed"
    skip=$((skip+1))
    break
  fi
  if timeout 1800 env PYTHONUNBUFFERED=1 python3 "poc/$name.py" --usb --port "$PORT" > "$EVD/$name.txt" 2>&1; then
    echo PASS; pass=$((pass+1)); else
    echo "FAIL (see $EVD/$name.txt)"; fail=$((fail+1));
  fi
done < "$LIST"
echo "SWEEP LIST DONE pass=$pass fail=$fail skipped=$skip"
