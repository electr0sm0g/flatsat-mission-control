#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate one real mermaid attack diagram per finding, inserted into each
docs/writeups/*.md as a '## Attack diagram' section (idempotent).

The diagrams are not decoration: every node comes from the finding's actual
mechanics — the entry channel from its Interface field, the real firmware
sinks (commandApidHandler, gpsUpdate, VTOR, the SDLS SA table, the FDIR
dictionary, watchdog scratch, QSPI slots...), the guard that fails, and the
consequence the committed transcript shows. V-14 and V-36 are staged chains
(sequenceDiagram); everything else is a one-view flowchart. Severity colors
match the console palette; GitHub renders the blocks natively and the mission
control renders them offline (vendored mermaid, web/vendor/).

Regenerate:  python3 tools/gen_attack_diagrams.py
Contract:    tests/host/check_catalog.py enforces one mermaid block per writeup.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WDIR = os.path.join(ROOT, "docs", "writeups")

# Source nodes by entry channel (from each writeup's Interface row)
SRC = {
    "rf":   'Adversary — 918 MHz transceiver on the raw uplink<br/>no key, no auth, no session',
    "rftm": 'Adversary — records the downlink, transmits on the uplink<br/>(no privileged position)',
    "tm":   'Passive — downlink receiver only, never transmits',
    "gps":  'GPS spoof — forged NMEA (UART1, lab hook TC 0x14)',
    "usb":  'Physical — USB-C debug port (TinyUSB 239A:CAFE)',
    "bus":  'Adversary via the radio bridge — forged bus frames<br/>(TC 0x1B/0x1C — MID is the only credential)',
}

# id: (kind, chan, edge-label from source, firmware sink, guard that fails,
#      outcome, severity)   — kind "flow"
# or  (kind "seq", src-label, [(a,b,msg)...], outcome, severity, participants)
F = {
 "V0-01": ("flow","rf","sweep TC APIDs 0x01–0x13, plausible payloads",
   "commandApidHandler — answers every APID","no challenge, no session, no rate gate",
   "full command map + firmware fingerprint (CPE)","med"),
 "V0-02": ("flow","rftm","harvest known-plaintext beacon blocks",
   "AES-128-ECB link — key PWNsatLabKey1234","key hardcoded in firmware: no IV, no rotation",
   "decrypt and forge every wrapped TC and TM","high"),
 "V0-03": ("flow","rf","TC 0x06 BROADCAST_MSG length field = 0",
   "ECHO task memcpy(len - hdr) underflows to ~SIZE_MAX","no floor check on the length field",
   "hard fault — board crash, no watchdog (V0-15)","crit"),
 "V0-04": ("flow","rf","TC 0x04 SET_THRUSTER fired from the raw radio",
   "ADCS virtual model on the internal bus","privileged command, zero auth state",
   "thrusters fire under adversary control","high"),
 "V0-05": ("flow","gps","forged NMEA fix — checksum absent or wrong",
   "gpsUpdate() stores lat/lon as truth","no checksum required, no plausibility gate",
   "craft believes any position — GS gate fooled (V-36)","high"),
 "V0-06": ("flow","rf","listen challenge on TM 0x13, reply = XOR(ch, K)",
   "GS handshake — static XOR key","challenge leaked, key static, no entropy",
   "authenticated as ground station from a transceiver","crit"),
 "V0-07": ("flow","rf","record a valid TC, resend it later",
   "dispatcher — zero freshness check","no nonce, no timestamp, no ARC",
   "any past command re-executes at will","high"),
 "V0-08": ("flow","rf","TC 0x02 RESETC from the raw uplink",
   "core0 reset — mission state rewinds","reboot command needs no authority",
   "instant DoS + state rewind on every pass","high"),
 "V0-09": ("flow","rf","TC 0x0B FLASH_READ carrying the hardcoded tag",
   "flash reader — the magic tag is the only credential","tag is fixed in the image (leaks with it)",
   "flash dump over the radio: keys, strings, layout","high"),
 "V0-10": ("flow","rf","TC 0x0A AES_CONFIG sent in cleartext",
   "secure-link module toggles its own crypto off","the downgrade command is not gated by crypto",
   "link silently reverts to plaintext, both directions","crit"),
 "V0-11": ("flow","rf","rewrite the CLEAR SPP header, splice 16 B ECB blocks",
   "spp_unpack + ECB — no MAC anywhere","routing fields unauthenticated, ECB malleable",
   "TCs reroute between APIDs · payloads bit-flip","high"),
 "V0-12": ("flow","usb","TC 0x10 DEBUG_CONFIG, no radio needed",
   "TinyUSB path — bypasses link crypto entirely","debug port live, zero authentication",
   "full TC/TM access from the connector","high"),
 "V0-13": ("flow","bus","SC_INJECT storm of junk frames (TC 0x1C)",
   "SpaceCAN error management — TEC/REC counters","any host on the bridge may transmit",
   "all nodes BUS-OFF — actuators deaf (bus jam)","high"),
 "V0-14": ("flow","rf","TC 0x05 SET_BEACON_RATE with period = 0",
   "beacon scheduler — period consumed unchecked","no range validation on the rate",
   "permanent beacon flood — downlink freezes","high"),
 "V0-15": ("flow","rf","after any crash (e.g. V0-03): nothing happens",
   "main loop — hardware watchdog never armed","no recovery path exists on silicon",
   "zombie craft until a physical power cycle","crit"),
 "V0-16": ("flow","rf","one 200-byte SPP frame (parser reads 201)",
   "spp_unpack_packet — off-by-one read","frame length trusted implicitly",
   "adjacent RAM byte rides the TM downlink","med"),
 "V0-17": ("flow","gps","NMEA line with empty fields — strtok collapses them",
   "gpsSplitLine — columns shift left","tokenizer assumes perfectly filled sentences",
   "position/fix fields shift — parser steered, spoof enabler","med"),
 "V0-18": ("flow","tm","read TM 0x13 GS_STATUS — no poller check",
   "GS status frame embeds station lat/lon","telemetry readable by anyone",
   "ground-station coordinates leaked to the world","med"),
 "V-01": ("flow","rf","TC 0x03 SEND_FW, no auth state",
   "CPE inventory responder","inventory served unauthenticated",
   "full hardware+software parts list — targeted follow-ons","med"),
 "V-02": ("flow","tm","passive sniff of the 64-byte beacon TM 0x01",
   "beacon content: mode, eclipse, counters","beacon discloses far more than needed",
   "pass windows + craft state predictable offline","med"),
 "V-03": ("flow","rf","send TCs, read TM 0x20 TC_STATS",
   "per-TC RSSI/SNR export","radio statistics exported on request",
   "uplink oracle — direction and distance of the antenna","med"),
 "V-04": ("flow","tm","read beacon pad bytes 21..63, frame after frame",
   "beacon packer leaves the 43-byte pad uninitialized","pad never zeroed before TX",
   "RAM contents leak every beacon — heartbleed channel","high"),
 "V-05": ("flow","rf","TC 0x19 MEM_READ: any addr, any size",
   "direct RAM read — bounds unchecked","no ACL on the readable region",
   "arbitrary memory read: keys, state, stacks","crit"),
 "V-06": ("flow","tm","long-window cadence analysis of TM 0x08/0x0E/0x01/0x3FF",
   "TM traffic pattern as a side channel","cadence correlates with mission phases",
   "pass, maneuver and eclipse windows derived from the ground","med"),
 "V-07": ("flow","rf","replay a secured TC inside the ±5 ARC window",
   "SDLS anti-replay: 16-bit ARC, volatile, W=5","ARC zeroed by RESETC and wraps at 65536",
   "every reboot silently reopens replays","high"),
 "V-08": ("flow","rf","set the SPP sec-header flag with a low SPI",
   "SA table: 43 of 64 associations configured Clear","default-cleartext SAs accepted",
   "the secured channel silently deauthenticates","high"),
 "V-09": ("flow","rf","SDLS header with SPI 65535",
   "SA lookup indexes past the table","16-bit SPI never bounds-checked",
   "out-of-bounds pass or single-frame hang (CryptoLib analogue)","high"),
 "V-10": ("flow","rf","TC 0x16 SDLS_OTA sub 0 with a null master key",
   "OTAR installs the delivered SA key","no entropy check on key material",
   "adversary's own key now guards the secured TCs","crit"),
 "V-11": ("flow","rf","TC 0x17 KEY_VERIFY chosen plaintext, read header on 0x01",
   "key-check oracle + CTR keystream derivable from headers","oracle exposed and IV reused",
   "keystream reuse — traffic decryptable past and future","high"),
 "V-12": ("flow","rf","edit the clear ident field mid-flight, splice blocks",
   "routing + ECB payload integrity: none","no MAC on fields the attacker controls",
   "commands execute tampered, silently","high"),
 "V-13": ("flow","rf","TC 0x1A SET_LOG_NAME with a 52-byte name",
   "strcpy into a 32-byte stack buffer — globals rewritten","no bound on the log name",
   "protection state in RAM flipped (auth/SDLS flags)","crit"),
 "V-14": ("seq","crit"),
 "V-15": ("flow","rf","flood raw TCs (0x01/0x28) through the whole pass",
   "command super-loop starves the downlink scheduler","no rate limit on uplink intake",
   "telemetry lost — craft alive but invisible","high"),
 "V-16": ("flow","rf","TEST APIDs 0xF0–0xFF on the open uplink",
   "handlers gated only by the safe-mode flag","privilege implied by APID range, no principal",
   "ops-level commands for whoever owns the radio","high"),
 "V-17": ("flow","bus","TC 0x1B SB_PUBLISH forges MIDs 0x102–0x106",
   "internal pub/sub bus treats MID as credential","internal messages unsigned by construction",
   "housekeeping and commands forged across the trust boundary","high"),
 "V-18": ("flow","rf","TC 0x1F OTA_PUSH image then activate slot",
   "A/B slot activation — finalize checks no signature","no signature verified on update",
   "malicious firmware confirmed in a boot slot","crit"),
 "V-19": ("flow","rf","TC 0x1E SCHED_ADD writes the flash task queue",
   "scheduler reloads the queue at every boot","persistent config replayed post-reboot",
   "adversary command executes on every boot","high"),
 "V-20": ("flow","rf","TC 0x1D subs 5/6 rewrite FDIR contingency entries",
   "recovery path executes the attacker-written dictionary","dict writable; hash-lock optional",
   "safe-mode entry runs attacker-chosen actions (backdoor)","crit"),
 "V-21": ("flow","rf","MEMCPY (0x18) writes watchdog scratch[7] — survives reset",
   "boot policy reads the scratch register","security state outlives the session that set it",
   "hidden boot-policy cookie across resets","high"),
 "V-22": ("flow","rf","TC 0x1D sub 2 forces FDIR safe entry",
   "relaxation table: crypto OFF, ARC window 5→15 — persists","forced state never restores",
   "permanent protection downgrade from one TC","crit"),
 "V-23": ("flow","rf","execute TCs freely, then probe the journal (0x25)",
   "TC journal off by default; ring capped at 128 entries","no mandatory audit trail",
   "adversary actions leave no evidence for forensics","med"),
 "V-24": ("flow","rf","ramp the anomaly metric slowly under the EWMA threshold",
   "onboard detector anomaly.cpp (EWMA)","staleness by construction — slow deltas never alarm",
   "sustained anomaly stays invisible on board","high"),
 "V-25": ("flow","bus","SC_INJECT (0x1C) frames to MOTOR 0x04 / BATTERY 0x07",
   "SpaceCAN segment: no segregation, no message auth","radio path lands directly on the bus",
   "actuators and EPS controllable from the uplink","crit"),
 "V-26": ("flow","bus","forged MID 0x103 sensor mask + MEMCPY onto GPIO block",
   "I2C sensor bus — devices have no identity","shared bus, blind masters, no auth",
   "sensors masked, GPS blinded at will (mask & 0x01)","high"),
 "V-27": ("flow","bus","forge MIDs 0x102 (rate) and 0x105 (battery)",
   "FDIR consumes bus values as truth","fault management trusts spoofed telemetry",
   "adversary steers safe-mode and detumble decisions","high"),
 "V-28": ("flow","rf","predict the challenge (counter only) + XOR key",
   "GS handshake — no TRNG behind the challenge","zero entropy in the anti-replay field",
   "session hijacked as the ground station, anywhere","crit"),
 "V-29": ("flow","rf","TC_STATS export + reset (0x20), read clear TM",
   "per-TC RF samples exported in the clear","physical-layer data leaves the box",
   "RF fingerprint of the ground segment, passive-style","med"),
 "V-30": ("flow","rf","queue bits via 0x22, widen pad via 0x21",
   "TM beacon pad carries queued bits (5 b/frame)","unwritten pad doubles as a channel",
   "covert uplink-to-downlink channel — 10 % of the rate","med"),
 "V-31": ("flow","rf","TC 0x23 PAYLOAD_SNAP sub 0/1 — capture then freeze VCC",
   "payload snapshot + GET_STATUS VCC audit field","snap unauthenticated; audit counter freezable",
   "silent payload exfil with the audit counter frozen","high"),
 "V-32": ("flow","rf","BROADCAST_MSG with an off-band operator frequency",
   "radio retunes on broadcast — no range check","frequency field consumed unchecked",
   "downlink squat: the craft answers on the adversary's frequency","high"),
 "V-33": ("flow","rf","thruster spam (0x04) past the 5°/s FDIR threshold",
   "virtual ADCS momentum model","no auth and no budget cap on the command",
   "attitude-control authority exhausted or saturated","high"),
 "V-34": ("flow","rf","TC 0x24 HEATER on + lab time base to fast-forward",
   "power model: drain → brownout → reset","load control needs no authority",
   "brownout reset — boot reason 'B' (0x42), state reset","high"),
 "V-35": ("flow","rf","SET_BEACON_RATE 0 plus BROADCAST echo floods",
   "downlink scheduler: beacon (0x01) starves science (0x08)","unauthenticated service control",
   "downlink denial — science telemetry squeezed out","high"),
 "V-36": ("seq","crit2"),
 "V-37": ("flow","rf","SEND_FW (0x03) + unauth FLASH dump (0x07) + sync tags",
   "build metadata — exact software base","version and CPE exposed unauthenticated",
   "CVE match against the exact firmware base","med"),
 "V-38": ("flow","rf","TC 0x1F sub 4 ARWC_SET lowers the counter, then revert + 0x02",
   "anti-rollback counter — writable by telecommand","the rollback gate itself is unlocked (SPR-215 inverted)",
   "older vulnerable firmware reinstalls","crit"),
}

SEQ = {
 # V-14: staged RCE (writeup: MEMCPY write-what-where -> VTOR -> vector fetch)
 "V-14": (
   ['participant A as Adversary — raw radio (TC only)',
    'participant L as SET_LOG_NAME 0x1A',
    'participant M as MEMCPY TC 0x18',
    'participant V as core0 vector table (VTOR)'],
   [('A','L','stage payload bytes in the log-name buffer'),
    ('A','M','write-what-where: overwrite VTOR with staged address'),
    ('V','V','next exception fetches the handler from ADVERSARY memory'),
    ('V','V','attacker code executes on core0 (RCE)')],
   "remote code execution on the OBC — the whole protection model collapses"),
 # V-36: the five killchain stages (docs/KILLCHAIN-V36.md)
 "V-36": (
   ['participant A as Adversary — GPS spoof + radio',
    'participant G as mission model (GPS + position)',
    'participant S as GS gate + handshake',
    'participant C as privileged commanding'],
   [('A','G','stage 1 — TC 0x14: forged NMEA fix inside GS range'),
    ('G','S','stage 2 — distance-to-GS drops below the 35 km gate'),
    ('A','S','stage 3 — GS_MODE (0x11) now accepted: gate open'),
    ('A','S','stage 4 — GS_ACCESS (0x12): challenge XOR forged (V0-06 / V-28)'),
    ('A','C','stage 5 — privileged telecommands execute')],
   "full initial access: spoof → gate bypass → authenticated control"),
}

SEV_CLASS = {"crit": "crit", "crit2": "crit", "high": "high", "med": "med"}

CLASSES = (
 "    classDef crit fill:#2a0a12,stroke:#ff4d6d,color:#ffd9e2;\n"
 "    classDef high fill:#2a160a,stroke:#ff8a5c,color:#ffe2d1;\n"
 "    classDef med fill:#2a2408,stroke:#ffd23f,color:#fff3c9;\n"
 "    classDef src fill:#12203a,stroke:#4cc9f0,color:#dbe6f5;\n"
 "    classDef ev fill:#0b1526,stroke:#3d6f9e,color:#9cc6ea;\n")


def q(s):
    return '"' + s.replace('"', "'") + '"'


def flow_md(mid, sev, chan, step, sink, guard, outcome, evfile):
    c = SEV_CLASS[sev]
    return (
     "flowchart LR\n"
     f"    A[{q(SRC[chan])}]:::src\n"
     f"    A -- {q(step)} --> B[{q(sink)}]\n"
     f"    B -- {q(guard)} --> X[{q(outcome)}]:::{c}\n"
     f"    E[{q('verified on simulator + FlatSat 1 image H — ' + evfile)}]:::ev -.-> B\n"
     + CLASSES)


def seq_md(mid, sev, parts, msgs, outcome, evfile):
    c = SEV_CLASS[sev]
    lines = ["sequenceDiagram", "    participant E as evidence"]
    lines += ["    " + p for p in parts]
    lines += [f"    {a}->>{b}: {m}" for a, b, m in msgs]
    lines.append(f"    Note over E: {evfile} — POC OK on simulator AND FlatSat 1")
    return "\n".join(lines)


def build():
    ids = {}
    for fn in os.listdir(WDIR):
        m = re.match(r"^(V0-\d+|V-\d+)_", fn)
        if m:
            ids[m.group(1)] = fn
    n = 0
    for fid, fn in sorted(ids.items()):
        path = os.path.join(WDIR, fn)
        src = open(path, encoding="utf-8").read()
        mm = re.search(r"`poc/([a-z0-9_]+\.py)` — evidence `evidence/([a-z0-9_]+\.txt)`", src)
        evfile = "evidence/" + mm.group(2) if mm else "evidence/…"
        sev = re.search(r"Severity \| (\w+)", src).group(1).lower()[:4]
        sev = {"crit": "crit", "high": "high", "medi": "med", "low": "med"}[sev]
        spec = F[fid]
        if spec[0] == "flow":
            _, chan, step, sink, guard, outcome, _sev = spec
            body = flow_md(fid, sev, chan, step, sink, guard, outcome, evfile)
        else:
            parts, msgs, outcome = SEQ[fid]
            body = seq_md(fid, sev, parts, msgs, outcome, evfile)
        if not body.endswith("\n"):
            body += "\n"   # closing fence must own its line
        section = "## Attack diagram\n\n```mermaid\n" + body + "```\n\n"
        # idempotent insert/replace directly before ## Root cause
        pat = re.compile(r"(?:## Attack diagram\n\n```mermaid\n.*?```\n\n)?(?=## Root cause)", re.S)
        assert re.search(r"## Root cause", src), fid
        new = pat.sub(section, src, count=1)
        if new != src:
            open(path, "w", encoding="utf-8").write(new)
            n += 1
    print(f"gen_attack_diagrams: {n} writeups updated, {len(ids)} total")
    return 0


if __name__ == "__main__":
    sys.exit(build())
