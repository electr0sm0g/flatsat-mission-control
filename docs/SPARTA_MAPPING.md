# SPARTA mapping — FlatSat v1.0 vulnerable firmware (56 findings)

Framework version pinned: **SPARTA v3.2** (The Aerospace Corporation, released
2026-03-11), the numbering this catalog is pinned to (the matrix has since
moved to v4.0 / v4.0.1, Aug 2026 — re-numbered techniques are explicitly
labelled `(v4.0)` below), of the
Space Attack Research and Tactic Analysis (SPARTA) matrix, created and maintained by
The Aerospace Corporation — the space-domain counterpart of the MITRE ATT&CK methodology. Technique IDs, names,
sub-technique lists and *Notional Risk (High | Medium | Low)* scores below
were verified against `sparta.aerospace.org` (technique pages, the v3.2
archive, and the v3.2 changelog). `—` means the site did not expose a
notional-risk triple for that ID at mapping time.

Note on versions: the course material cites some techniques with older numbering
(e.g. `EX-0007.02` for *Modify On-Board Values: Science/Payload Data*, which
has no sub-techniques in any released version). Where the course ID differs from
v3.2, both are shown (`v3.2 ID ← course ID`).

Tactic prefixes: REC (Reconnaissance, ST0001), RD (Resource Development,
ST0002), IA (Initial Access, ST0003), EX (Execution, ST0004), PER
(Persistence, ST0005), DE (Defense Evasion, ST0006), LM (Lateral Movement,
ST0007), EXF (Exfiltration, ST0008), IMP (Impact, ST0009).

## Baseline findings (v1.0.3, V0-01 … V0-18)

| ID | Finding | Primary SPARTA technique | Notional risk H\|M\|L | Secondary SPARTA | PoC / evidence |
|----|---------|--------------------------|------------------|------------------|----------------|
| V0-01 | Unauthenticated SEND_FW + APID surface enumeration (CPE fingerprint) | REC-0001.01 · Gather Spacecraft Design Information: Software Design | 6\|4\|2 (REC-0002) | REC-0002.01 Identifiers; REC-0001.02 Firmware | `poc/v001_send_fw_cpe.py` / `evidence/v001_send_fw_cpe.txt` |
| V0-02 | Hardcoded AES-128 ECB link key `PWNsatLabKey1234` in image | REC-0001.03 · Gather Spacecraft Design Information: Cryptographic Algorithms | — | PER-0004 Replace Cryptographic Keys | `poc/v002_hardcoded_ecb_key.py` / `evidence/v002_hardcoded_ecb_key.txt` |
| V0-03 | BROADCAST_MSG length underflow → worker crash (silent death) | EX-0009.01 · Exploit Code Flaws: Flight Software | 24\|21\|17 | IMP-0003 · Denial (v4.0: IMP-0013 Resource Exhaustion or Contention) | `poc/v003_broadcast_underflow_crash.py` |
| V0-04 | SET_THRUSTER accepted from raw radio, no authentication | EX-0005.02 · Exploit Hardware/Firmware Corruption: Malicious Use of Hardware Commands | — | EX-0012.07 Propulsion Subsystem; IMP-0007 Native Functionality Abuse (v4.0) | `poc/v004_set_thruster_noauth.py` |
| V0-05 | GPS NMEA accepted without checksum → position spoofing | EX-0014.04 · Spoofing: Position, Navigation, and Timing (PNT) Spoofing | — | EX-0014.03 Sensor Data | `poc/v005_gps_no_checksum.py` |
| V0-06 | GS authentication = challenge XOR static key (offline-computable) | EX-0003 · Modify Authentication Process (weak scheme) | — | IA-0008.01 Rogue Ground Station; DE-0004 Masquerading | `poc/v006_gs_auth_xor_static.py` |
| V0-07 | No anti-replay protection on telecommands | EX-0001.01 · Replay: Command Packets | 25\|24\|21 | EXF-0001 Replay (observational) | `poc/v007_no_replay_protection.py` |
| V0-08 | RESETC unauthenticated → one-TC reboot DoS, window loss | EX-0005.02 · Malicious Use of Hardware Commands | — | DE-0002 Disrupt or Deceive Downlink (.01 Inhibit Ground System Functionality) | `poc/v008_resetc_unauth_dos.py` |
| V0-09 | FLASH_READ guarded only by a hardcoded magic tag | REC-0001.02 · Gather Spacecraft Design Information: Firmware | — | EXF-0003.02 Signal Interception: Downlink Exfiltration | `poc/v009_flash_read_hardcoded_tag.py` |
| V0-10 | Crypto-bypass: AES engine can be switched OFF over the air | EX-0006 · Disable/Bypass Encryption | 24\|21\|17 | DE-0003.07 On-Board Values Obfuscation: Cryptographic Modes (18\|15\|11) | `poc/v010_cleartext_downgrade.py` |
| V0-11 | AES-ECB malleability: TC bit-flip without any integrity check | EX-0009.01 · Exploit Code Flaws: Flight Software | 24\|21\|17 | EX-0012.02 Internal Routing Tables (APID re-routing); EX-0006 | `poc/v011_ecb_bitflip.py` |
| V0-12 | USB debug mode bypasses link authentication | IA-0011 · Auxiliary Device Compromise | — | CM0037 Disable Physical Ports (countermeasure gap) | `poc/v012_usb_debug_bypass.py` |
| V0-13 | SpaceCAN bridge: junk storm drives nodes BUS-OFF (bus jam) | LM-0002 · Exploit Lack of Bus Segregation | 24\|21\|17 | EX-0013.02 Flooding: Erroneous Input (25\|24\|21) | `poc/v013_spacecan_busoff.py` |
| V0-14 | Beacon-flood (SET_BEACON_RATE) freezes the mission loop | EX-0013 · Flooding | 25\|24\|21 | DE-0002 Disrupt or Deceive Downlink; IMP Denial | `poc/v014_beacon_flood.py` |
| V0-15 | No watchdog: hang/crash survives indefinitely until power cycle | EX-0009.01 · Exploit Code Flaws: Flight Software | 24\|21\|17 | DE-0003.11 Watchdog Timer (WDT) for Evasion (missing WDT = abuse surface) | `poc/v015_no_watchdog.py` |
| V0-16 | SPP unpack off-by-one: TM payload over-read (RAM byte leak) | EX-0009.01 · Exploit Code Flaws: Flight Software | 24\|21\|17 | EXF-0003.02 Downlink Exfiltration | `poc/v016_spp_offbyone.py` |
| V0-17 | GPS parser `strtok` column handling → forged sentences accepted | EX-0014.03 · Spoofing: Sensor Data | — | EX-0009.01 (parser defect) | `poc/v017_gps_strtok_columns.py` |
| V0-18 | GS_STATUS leaks ground-station coordinates to any poller | REC-0003 · Gather Spacecraft Communications Information | — | REC-0003.02 Commanding Details; EXF-0003.02 | `poc/v018_gs_status_station_leak.py` |

## New findings (v2 firmware lab extension, V-01 … V-38)

| ID | Finding | Primary SPARTA technique | Notional risk H\|M\|L | Secondary SPARTA | PoC / evidence |
|----|---------|--------------------------|------------------|------------------|----------------|
| V-01 | SEND_FW unauthenticated inventory/version leak (CPE match to CVE catalogue) | REC-0001.01 · Gather Spacecraft Design Information: Software Design | — | REC-0002.01 Identifiers | `poc/v101_send_fw_inventory.py` |
| V-02 | Over-talkative beacon discloses mode, crypto state, battery, eclipse | REC-0003 · Gather Spacecraft Communications Information | — | REC-0007 Monitor for Safe-Mode Indicators (15\|11\|5); EXF-0003.02 | `poc/v102_chatty_beacon.py` |
| V-03 | Per-TC RSSI/SNR/APID oracle exported unauthenticated | REC-0005 · Eavesdropping (.01 Uplink Intercept Eavesdropping) | — | DE-0003.04 Command Receivers Received Signal Strength | `poc/v103_tc_rssi_oracle.py` |
| V-04 | Heartbleed-style RAM leak inside TM 'padding' (GS challenge disclosed) | EX-0009.01 · Exploit Code Flaws: Flight Software | 24\|21\|17 | EXF-0003.02 Downlink Exfiltration | `poc/v104_leak_padding.py` |
| V-05 | Arbitrary MEM_READ: SA table + GS challenge walk out over raw radio | EX-0012.03 · Modify On-Board Values: Memory Write/Loads | 19\|14\|9 (EX-0012) | EXF-0003.02; REC-0001.03 | `poc/v105_mem_read.py` |
| V-06 | TM cadence + beacon eclipse bit reveal operator pass plan and orbit phase | REC-0003.02 · Gather Spacecraft Communications Information: Commanding Details | — | REC-0002.03 Operations | `poc/v106_pass_cadence.py` |
| V-07 | 16-bit volatile anti-replay counter, W=5 window, wraps at 65536 | EX-0001.01 · Replay: Command Packets | 25\|24\|21 | DE-0003.11 WDT/counter-reset interaction | `poc/v107_arc_replay.py` |
| V-08 | 43 of 64 SDLS security associations default to Clear (auth-free) | EX-0006 · Disable/Bypass Encryption | 24\|21\|17 | DE-0003.07 Cryptographic Modes (18\|15\|11) | `poc/v108_sdls_clear_sas.py` |
| V-09 | Unbounded SPI: OOB table read passes; SPI 9000 hangs the worker | EX-0009.01 · Exploit Code Flaws: Flight Software | 24\|21\|17 | EX-0013.02 Erroneous Input; V0-15 chain (no WDT) | `poc/v109_spi_oob.py` |
| V-10 | OTAR with 128 NULL master keys: attacker installs his own SA key | PER-0004 · Replace Cryptographic Keys | — | IA-0008.01 Rogue Ground Station; EX-0003 | `poc/v110_otar_null_key.py` |
| V-11 | KEY_VERIFY key-confirmation oracle + CTR keystream recoverable from clear header | REC-0001.03 · Gather Spacecraft Design Information: Cryptographic Algorithms | — | EX-0006 Disable/Bypass Encryption | `poc/v111_key_verify_oracle.py` |
| V-12 | Silent TC tampering: clear-header APID re-routing + ECB block splice | EX-0012.02 · Modify On-Board Values: Internal Routing Tables | 19\|14\|9 (EX-0012) | EX-0009.01; EX-0006 | `poc/v112_tc_bitflip.py` |
| V-13 | SET_LOG_NAME unbounded copy overwrites protection-state guard variables | EX-0009.01 · Exploit Code Flaws: Flight Software | 24\|21\|17 | DE-0003.07 Cryptographic Modes | `poc/v113_log_name_overflow.py` |
| V-14 | MEMCPY TC → write-what-where → VTOR redirect → RP2040 RCE | EX-0009.01 · Exploit Code Flaws: Flight Software | 24\|21\|17 | EX-0012.03 Memory Write/Loads; EX-0010 Malicious Code (implant-ready) | `poc/v114_memcpy_rce.py` |
| V-15 | Uplink flood (blocking ledBlink + error TMs) starves telemetry | EX-0013.02 · Flooding: Erroneous Input | 25\|24\|21 | IMP Denial (v4.0: IMP-0013 Resource Exhaustion or Contention) | `poc/v115_uplink_starvation.py` |
| V-16 | TEST APID window (0xF0–0xFF) opens in safe mode, no own auth | EX-0011 · Exploit Reduced Protections During Safe-Mode | 24\|21\|17 | IA-0010 Unauthorized Access During Safe-Mode; REC-0007 (15\|11\|5) | `poc/v116_priv_confusion.py` |
| V-17 | Forged software-bus MIDs (cFS SB analogue) consumed as truth | EX-0014.02 · Spoofing: Bus Traffic Spoofing | — | LM-0002 Exploit Lack of Bus Segregation (24\|21\|17); EX-0012.10 Command & Data Handling Subsystem | `poc/v117_sb_forged_mids.py` |
| V-18 | Unsigned OTA image push + slot activation (CRC-16 only) | EX-0010 · Malicious Code (installed via unverified on-orbit update) | — | IA-0007.02 Malicious Commanding via Valid GS (update path); CM0010 Update Software | `poc/v118_ota_unsigned.py` |
| V-19 | Flash-resident scheduled task queue replays after any reboot | PER-0002.02 · Software Backdoor  | 24\|21\|17 | EX-0012.05 Scheduling Algorithm | `poc/v119_sched_persistence.py` |
| V-20 | FDIR contingency dictionary = flash-resident executable trojan | PER-0002.02 · Software Backdoor | 24\|21\|17 | EX-0011 (runs on safe entry); REC-0001.09 Fault Management | `poc/v120_fdict_contingency.py` |
| V-21 | Persistence cookie in RP2040 watchdog scratch registers (boot policy) | PER-0001 · Memory Compromise | — | DE-0003.11 Watchdog Timer (WDT) for Evasion; EX-0012.11 Watchdog Timer (WDT) | `poc/v121_watchdog_cookie.py` |
| V-22 | Forced safe mode = protection downgrade (crypto off, ARC 5→15, persists) | DE-0005 · Subvert Protections via Safe-Mode | — | EX-0011 (24\|21\|17); DE-0003.07 (18\|15\|11) | `poc/v122_forced_safe_downgrade.py` |
| V-23 | No TC journal by default; optional log capped at 128 entries | DE-0003.08 · On-Board Values Obfuscation: Received Commands | — | Overflow Audit Log (DE family); attribution gap | `poc/v123_tc_logging_absent.py` |
| V-24 | On-board EWMA anomaly detector evadable by slow ramp | DE-0003.12 · Poison AI/ML Training for Evasion (detector tuning/staleness) | — | Targeted Deception of Onboard Sensors (DE family) | `poc/v124_ewma_ramp_evasion.py` |
| V-25 | Full unauthenticated SpaceCAN bus over the radio bridge (jam/spoof/overflow) | LM-0002 · Exploit Lack of Bus Segregation | 24\|21\|17 | EX-0013.01 Valid Commands; EX-0014.02 Bus Traffic Spoofing | `poc/v125_spacecan_full_bus.py` |
| V-26 | Radio→I2C bridge: sensor mask rewrite + GPS blinding via GPIO write | LM-0002 · Exploit Lack of Bus Segregation | 24\|21\|17 | EX-0014.03 Sensor Data; EX-0012.01 Registers | `poc/v126_sensor_bus_injection.py` |
| V-27 | FDIR consumes forged MIDs → attacker-launders control of the safety loop | EX-0014.03 · Spoofing: Sensor Data | — | DE-0001 Disable Fault Management (24\|21\|17); EX-0012.08 ADCS | `poc/v127_fdir_consumes_forged_mids.py` |
| V-28 | GS challenge has no TRNG (millis ^ GPS) → predicted-challenge session hijack | EX-0003 · Modify Authentication Process | — | IA-0008.01 Rogue Ground Station; DE-0004 Masquerading | `poc/v128_gs_session_hijack.py` |
| V-29 | 64-sample RF fingerprint export (RSSI/SNR/freq-error) usable for LR detector | REC-0005 · Eavesdropping | — | DE-0003.04 RSSI; REC-0005.01 | `poc/v129_rf_fingerprint.py` |
| V-30 | Covert channel inside TM padding drains a FIFO over the legitimate downlink | EXF-0004 · Out-of-Band Communications Link (covert variant) | — | EXF-0003.02 Downlink Exfiltration (22\|19\|14 EXF-0001 class) | `poc/v130_stego_padding_channel.py` |
| V-31 | Unauthorized payload snap + VCC audit-counter freeze | DE-0003.01 · On-Board Values Obfuscation: Vehicle Command Counter (VCC) | — | EXF-0003.02 Downlink Exfiltration (data capture) | `poc/v131_payload_snap_audit.py` |
| V-32 | Downlink frequency squat via BROADCAST_MSG operator-frequency field | DE-0003.06 · On-Board Values Obfuscation: Telemetry Downlink Modes | — | IMP-0008 State or Mode Manipulation (v4.0); IMP Denial (lost contact) | `poc/v132_freq_squat.py` |
| V-33 | ADCS momentum spam (30 valid thruster TCs) → TUMBLE safe + detumble saturation | EX-0012.08 · Modify On-Board Values: Attitude Determination & Control Subsystem | 19\|14\|9 (EX-0012) | EX-0013.01 Valid Commands (25\|24\|21); IMP Degradation | `poc/v133_adcstumble_saturation.py` |
| V-34 | Heater/eclipse power drain → brownout reset wipes ARC, cookie, crypto state | EX-0012.09 · Modify On-Board Values: Electrical Power Subsystem | 19\|14\|9 (EX-0012) | IMP Degradation/Denial; state-reset chain into V-07/V-21 | `poc/v134_brownout_drain.py` |
| V-35 | Beacon/broadcast downlink saturation (service_control analogue) | EX-0013.01 · Flooding: Valid Commands | 25\|24\|21 | DE-0002 Disrupt or Deceive Downlink; IMP Denial | `poc/v135_beacon_broadcast_saturation.py` |
| V-36 | GPS spoof → range-lock dissolve → XOR auth → privileged control (full chain) | EX-0014.04 · Spoofing: Position, Navigation, and Timing (PNT) Spoofing | — | IA-0008.01; EX-0003; EX-0014.03 | `poc/v136_gps_spoof_chain.py` |
| V-37 | Unauthenticated FLASH dump + banner TMs pin the open-source fork and version | REC-0001.01 · Gather Spacecraft Design Information: Software Design (.02 Firmware) | — | EXF-0003.02; REC-0002.01 | `poc/v137_build_metadata.py` |
| V-38 | Anti-rollback counter writable by TC → patch level unenforceable | EX-0009.03 · Exploit Code Flaws: Known Vulnerability (COTS/FOSS) | 24\|21\|17 | CM0010 Update Software (countermeasure defeated); IMP-0007 Native Functionality Abuse (v4.0) | `poc/v138_arwc_rollback.py` |

## Coverage by tactic

- **REC (Reconnaissance)** — V0-01, V0-09, V0-18, V-01, V-02, V-03, V-05, V-06, V-11, V-29, V-37
- **IA (Initial Access)** — V0-05, V0-12, V-16, V-28, V-36 (chain entry points)
- **EX (Execution)** — V0-03, V0-04, V0-06, V0-07, V0-08, V0-10, V0-11, V0-13, V0-14, V0-15, V0-16, V0-17, V-04, V-07, V-08, V-09, V-12, V-13, V-14, V-15, V-17, V-18, V-22, V-27, V-32, V-33, V-34, V-35, V-38
- **PER (Persistence)** — V-10 (key replacement), V-18, V-19, V-20, V-21
- **DE (Defense Evasion)** — V0-15, V-05, V-21, V-22, V-23, V-24, V-26, V-27, V-31, V-32
- **LM (Lateral Movement)** — V0-13, V-17, V-25, V-26, V-27 (radio↔bus bridges)
- **EXF (Exfiltration)** — V0-09, V0-16, V-04, V-05, V-30, V-31, V-37
- **IMP (Impact)** — V0-08, V0-14, V-15, V-32, V-33, V-34, V-35 (denial/degradation outcomes of EX techniques)

## Verification notes

- IDs, names and sub-technique lists verified against SPARTA v3.2 pages:
  EX-0001(.01/.02), EX-0003, EX-0005(.02), EX-0006, EX-0009(.01/.02/.03),
  EX-0010, EX-0011, EX-0012(.01–.13), EX-0013(.01/.02), EX-0014(.01–.05),
  PER-0001, PER-0002(.01/.02), PER-0004, DE-0001, DE-0002(.01–.03),
  DE-0003(.01–.12; .13 exists from v4.0), DE-0004, DE-0005, LM-0002, IA-0007(.02), IA-0008(.01/.02),
  IA-0010, IA-0011, REC-0001(.01/.02/.03/.07/.08/.09), REC-0002(.01–.03),
  REC-0003(.02), REC-0005(.01), REC-0007, EXF-0001–0005,
  IMP-0003 (Denial). Note: any IMP-0007 / IMP-0008 / IMP-0013 citation in this
  repo is **v4.0** numbering (v3.2 Impact stops at IMP-0006) and is labelled
  `(v4.0)` where used.
- Notional-risk triples quoted only where the technique page exposed them.
- Course-numbering deltas are flagged inline (`← course ID`).
