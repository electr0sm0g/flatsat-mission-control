#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Host-side evidence gate: crypto vectors (sim selftest) + firmware syntax.
set -u
cd "$(dirname "$0")/../.."
SHIM="$PWD/tests/host/shim"

python3 simulator/flatsat_sim.py --selftest > evidence/HOST-01-crypto-vectors-sim-selftest.txt 2>&1
S1=$?

{ echo "# HOST-02 - firmware syntax check (g++ -fsyntax-only -std=gnu++17, Arduino shim)"
  echo "# v2 modules + patched worker compile against the host shim; upstream"
  echo "# radio/USB/sensor drivers (RadioLib, NeoPixelBus, TinyUSB, SparkFun)"
  echo "# are not host-compilable here -- they ARE covered by the real RP2040"
  echo "# build: cd firmware && pio run  (verified SUCCESS, see BUILD.md)."
  echo
  ok=1
  for f in firmware/*.cpp; do
    case "$f" in
      *led.cpp|*rdownlink.cpp|*ruplink.cpp|*sensors.cpp|*usbCDC.cpp)
        echo "N/A  $f  (upstream v1.0.3 based; per-file patches: docs/LICENSING.md; needs vendor lib headers)"; continue;;
    esac
    if g++ -fsyntax-only -std=gnu++17 -w -I"$SHIM" -Ifirmware "$f" 2>/tmp/host_err.txt; then
      echo "OK   $f"
    else
      echo "FAIL $f"; head -5 /tmp/host_err.txt; ok=0
    fi
  done
  echo
  [ "$ok" = 1 ] && echo "RESULT: all v2 firmware sources syntax-clean on host" || echo "RESULT: errors present"
} > evidence/HOST-02-firmware-compile.txt
S2=$?
grep -q "^RESULT: all v2" evidence/HOST-02-firmware-compile.txt || S2=1
[ $S1 = 0 ] && [ $S2 = 0 ] && echo "HOST CHECKS: PASS" || echo "HOST CHECKS: FAIL ($S1 $S2)"
exit $((S1+S2))
