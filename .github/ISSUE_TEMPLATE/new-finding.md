name: New finding candidate
about: Propose a new vulnerability for the catalog (complete = all 7 contract items)
title: "[finding] "
labels: [new-finding]
assignees: []

---

**Proposed ID** (V-NN, next free number — see FINDINGS.json):

**One-line description:**

**Attack surface group** (1 recon · 2 crypto · 3 spoofing · 4 memory · 5 ground
segment · 6 bus/FDIR · 7 persistence · 8 OTA · 9 DoS):

**SPARTA v3.2 mapping** (primary technique + notional risk + secondary —
verify against sparta.aerospace.org and cite what you checked):

**Root cause** (which firmware file/function, which invariant it breaks):

**Contract status** (be honest — a candidate is fine at partial status):

- [ ] firmware implemented (vulnerable by design, no shims)
- [ ] simulator mirrored bit-for-bit
- [ ] PoC executable, ends `POC OK` on both targets
- [ ] writeup drafted (summary / root cause / mechanism / walkthrough / impact / mitigations)
- [ ] SPARTA row added
- [ ] evidence transcripts (sim + HW)
- [ ] FINDINGS.json regenerated, `make check` green

**PoC sketch or transcript excerpt:**

```
```
