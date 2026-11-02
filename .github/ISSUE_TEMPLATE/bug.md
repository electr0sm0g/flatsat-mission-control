name: Bug report
about: A PoC, the simulator or the firmware no longer behaves as documented
title: "[bug] "
labels: [bug]
assignees: []

---

**Finding(s) affected** (e.g. V-14 / v114_memcpy_rce):

**Target** (check all that apply):

- [ ] simulator (`python3 poc/vNNN_*.py`)
- [ ] hardware (`python3 poc/vNNN_*.py --usb`)
- [ ] CI (which job: sim-sweep / firmware-build / host-checks)

**What happened:**

**Expected (per writeup / evidence transcript):**

**Image digest** (hardware only — `md5sum .pio/build/pico_tinyusb/firmware.uf2`):

> image H reference: `bfc145c93039177b7393147978cdd432` (335872 B)

**Transcript excerpt** (the failing part, keep it short):

```
```

**Does `make check` pass on your machine?** (yes/no + output of the failing step)
