<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Licensing & third-party credits

This repository is **GPL-2.0-or-later** as a whole because it contains derivative works of the
FlatSat firmware. Each source file carries its own `SPDX-License-Identifier`. Where this document
and a component's own license text disagree, the component's license text governs.

## Upstream platform — the origin of this lab

| | |
|---|---|
| Project | **FlatSat** — open-hardware CubeSat teaching platform |
| Authors | [PwnSat](https://github.com/Pwnsat) × [Electronic Cats](https://electroniccats.com) |
| Repository | [github.com/Pwnsat/FlatSat](https://github.com/Pwnsat/FlatSat) (upstream v1.0.3 used here) |
| Firmware license | GPL-2.0-or-later |
| Hardware license | CERN Open Hardware Licence v1.2 |

The `firmware/` tree is a FlatSat v1.0.3-based build:

- **carried from upstream** (host-compile N/A, identifiable in `evidence/HOST-02-firmware-compile.txt`; a few carry minimal documented bench/lab patches, e.g. the V-24 blink fix in `led.cpp` — the in-file comments say so)
  by their `N/A` host-compile status — they are upstream files needing vendor-lib headers):
  `led.cpp`, `rdownlink.cpp`, `ruplink.cpp`, `sensors.cpp`, `usbCDC.cpp`;
- **patched baseline** — upstream handlers extended where a finding requires it (e.g.
  `worker.cpp`, `spp.cpp`, `spacecan.cpp`, `secure_link.cpp`): upstream logic retained, lab
  additions marked;
- **new lab modules** — written for this engagement: `anomaly`, `cmac`, `covert`, `extcmds`,
  `fdir`, `flashstore`, `memserv`, `mission_model`, `sb`, `sdls_sim`, `labhooks.h`.

File headers follow a single lab convention (`By astrobyte`) for the lab build; the upstream
copyright for derived files is declared here and in the README, as required by GPL-2.0 §2.
*PwnSat* and *Electronic Cats* are registered trademarks of their owners.

## Third-party components

| Component | License | Where | How used |
|---|---|---|---|
| [Pyodide](https://pyodide.org) 0.27.4 (CPython/WASM) | MPL-2.0 | CDN, pinned (`web/worker.js`) | runs the unmodified simulator + 56 PoCs in the browser |
| [mermaid](https://mermaid.js.org) 11.4.1 | MIT | vendored (`web/vendor/`, license included) | renders the attack diagrams offline |
| RadioLib, NeoPixelBus, TinyUSB, SparkFun libraries | MIT / BSD-3 | PlatformIO-managed (`firmware/platformio.ini`) | firmware build on RP2040 (never vendored here) |
| Inter, JetBrains Mono | SIL Open Font License 1.1 | Google Fonts CDN | console typography |
| [SPARTA](https://sparta.aerospace.org) | © The Aerospace Corporation | `docs/SPARTA_MAPPING.md` | threat taxonomy; technique IDs and notional risks quoted for analysis |

The simulator (`simulator/flatsat_sim.py`), the PoCs (`poc/`), the harness, the mission control
and the documentation were authored for this engagement and are offered under the same
GPL-2.0-or-later terms.
