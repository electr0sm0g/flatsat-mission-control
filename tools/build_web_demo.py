#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
build_web_demo.py -- build the in-browser mission-control demo.

Reads the committed repo files (simulator, fslab, the 56 PoCs, their 56
evidence transcripts, FINDINGS.json, the 56 writeups, KILLCHAIN-V36.md) and
produces a static artifact:

    web/dist/index.html    (self-contained page: sources + catalog + digests)
    web/dist/worker.js     (Pyodide host, pinned CDN)

Nothing is forked or ported: the demo runs the byte-identical sources.
For every PoC the normalized (timestamp-stripped) md5 of the committed
evidence/<poc>.txt is baked in so the browser run can prove transcript
parity at runtime.

Dashboard extras baked in (all derived from committed repo files):
  * writeups  -- the 56 educational writeups (docs/writeups/*.md), keyed by
                 PoC file, rendered by the in-page index view;
  * severity / summary -- parsed from each writeup meta table / Summary;
  * risk triples -- parsed from FINDINGS.json sparta_risk;
  * apid_surface / poc_apids -- every APID touched by every committed
                 evidence transcript (TC uplink / TM downlink), i.e. the
                 attack surface as the 56 PoCs actually exercised it;
  * killchain -- the 5 stages of docs/KILLCHAIN-V36.md with the exact
                 evidence anchor each one lights up (verified at build);
  * gs -- ground-station coordinates + gate radius, parsed from the
                 committed simulator source (never re-typed).

  * report -- reports/pentest-report.json verbatim (for the REPORT view);
  * repo -- the remaining interesting repo files as byte-identical text
            (docs/*.md, evidence/*.txt, firmware sources, FINDINGS.json,
            README, CONTRIBUTING, the talk, the PDF as base64) for the
            REPO source-browser view.

Usage:  python3 tools/build_web_demo.py [--root /path/to/repo]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))

TS_RE = re.compile(r"^\[\s*\d+\.\d{3}\] (.*)$")
PYODIDE_VERSION = "0.27.4"
HEROES = {
    "v003_broadcast_underflow_crash.py",
    "v101_send_fw_inventory.py",
    "v114_memcpy_rce.py",
    "v120_fdict_contingency.py",
    "v136_gps_spoof_chain.py",
}
HERO_NOTES = {
    "v003_broadcast_underflow_crash.py":
        "A malformed BROADCAST_MSG length underflows the beacon worker and "
        "kills the spacecraft — silently, no auth, no checksum.",
    "v101_send_fw_inventory.py":
        "One empty SEND_FW over the raw radio returns the exact firmware "
        "version plus a live 20-APID responder map: zero-credential CPE inventory.",
    "v114_memcpy_rce.py":
        "The unauthenticated MEMCPY telecommand becomes write-what-where: "
        "VTOR redirect, RP2040 RCE.",
    "v120_fdict_contingency.py":
        "The FDIR contingency dictionary is attacker-writable flash: a "
        "reboot-persistent trojan on the safety path.",
    "v136_gps_spoof_chain.py":
        "GPS spoof → range-lock dissolve → XOR auth → PAYLOAD mode. Full "
        "unauthenticated privileged control, measured end to end.",
}
GROUP_LABELS = {
    "REC": "Reconnaissance & eavesdropping",
    "EX": "Exploitation",
    "LM": "Lack of bus segregation",
    "IA": "Auxiliary device compromise",
    "DE": "Defensive system subversion",
    "PER": "Persistent access",
    "EXF": "Exfiltration / covert channels",
    "IMP": "Impact",
}
# APID -> human name (mirrors web/harness.py APID_NAMES, which mirrors
# simulator/flatsat_sim.py dispatch).
APID_NAMES = {
    0x01: "PING/BEACON", 0x02: "RESETC", 0x03: "SEND_FW", 0x04: "SET_THRUSTER",
    0x05: "SET_BEACON_RATE", 0x06: "BROADCAST_MSG", 0x07: "FLASH_DUMP",
    0x08: "SENSORS", 0x09: "ERROR", 0x0A: "AES_CONFIG", 0x0B: "FLASH_READ",
    0x0C: "GET_STATUS", 0x0D: "SET_MISSION_MODE", 0x0E: "GET_NAV",
    0x0F: "PWN_STATUS", 0x10: "USB_DEBUG", 0x11: "GS_MODE", 0x12: "GS_ACCESS",
    0x13: "GS_STATUS", 0x14: "GPS_OVERRIDE", 0x15: "SDLS_CONFIG",
    0x16: "SDLS_OTA", 0x17: "KEY_VERIFY", 0x18: "MEMCPY", 0x19: "MEM_READ",
    0x1A: "SET_LOG_NAME", 0x1B: "SB_PUBLISH", 0x1C: "SC_INJECT",
    0x1D: "FDIR_CONFIG", 0x1E: "SCHED", 0x1F: "OTA", 0x20: "TC_STATS",
    0x21: "PADDING_CONFIG", 0x22: "COVERT_ENQ", 0x23: "PAYLOAD_SNAP",
    0x24: "HEATER", 0x25: "DEFENSES_CONFIG", 0x26: "LAB_STATUS",
    0x27: "LAB_CTRL", 0x3FF: "IDLE_BEACON",
}
# The flagship chain: stage title (docs/KILLCHAIN-V36.md), one-line desc, and
# the exact committed-evidence substring that lights the stage up live
# (evidence/v136_gps_spoof_chain.txt). Anchors are verified at build time.
KILLCHAIN = [
    {"title": "Spoof the position (V0-05)",
     "desc": "TC 0x14 injects a Tokyo NMEA fix. The vehicle adopts it — no "
             "checksum, no source authentication.",
     "anchor": "spoofed fix: Tokyo"},
    {"title": "Prove the gate exists",
     "desc": "Arming GS mode (TC 0x11) fails with GS RANGE LOCK: the gate is "
             "real, and its position input is the attacker's.",
     "anchor": "the arming itself is range-gated"},
    {"title": "Defeat the one active defense",
     "desc": "With DEF_GPS_PLAUS armed, the ~8,900 km Tokyo→GS hop (the PoC log "
             "prints 9500 km) spread over 60 s walks through the plausibility gate — "
             "the craft reports 0 m.",
     "anchor": "9500 km in 60 s accepted"},
    {"title": "Answer the handshake offline (V0-06 / V-28)",
     "desc": "A plain poll now returns GS AUTH REQUIRED. The reply is "
             "challenge XOR 0xC0DEFACE — computable from the firmware image.",
     "anchor": "GS AUTH REQUIRED on a plain GET_STATUS"},
    {"title": "Privileged control",
     "desc": "SET_MISSION_MODE(PAYLOAD) executes from the unauthenticated "
             "uplink. The chain is complete.",
     "anchor": "chain complete:"},
]
# Verification anchor (docs/BUILD.md, docs/VERIFICATION.md): firmware image H.
IMAGE_MD5 = "bfc145c93039177b7393147978cdd432"
IMAGE_SIZE = 335872

TC_APID_RE = re.compile(r"TC apid=0x([0-9A-Fa-f]{2,3})")
TM_APID_RE = re.compile(r"TM apid=0x([0-9A-Fa-f]{2,3})")
SEV_RE = re.compile(r"^\|\s*Severity\s*\|\s*(.+?)\s*\|\s*$", re.M)
RISK_RE = re.compile(r"^(\d+)\|(\d+)\|(\d+)(?:\s*\(([^)]+)\))?$")


def md5_b(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def read(root: str, rel: str) -> bytes:
    with open(os.path.join(root, rel), "rb") as f:
        return f.read()


def norm_md5(text: str) -> tuple[str, int]:
    """Digest of the committed transcript with wall-clock prefixes stripped
    (same normalization the browser harness applies to the fresh run)."""
    out = []
    for ln in text.splitlines():
        m = TS_RE.match(ln)
        out.append(m.group(1) if m else ln)
    joined = "\n".join(out)
    return md5_b(joined.encode("utf-8")), len(out)


def summary_of(md: str) -> str:
    """First line of the writeup's ## Summary section (educational card text)."""
    m = re.search(r"^## Summary\s*\n+(.+?)(?:\n\n|\n## )", md, re.M | re.S)
    if not m:
        return ""
    line = next((l for l in m.group(1).splitlines() if l.strip()), "")
    line = line.strip()
    if len(line) > 190:
        line = line[:187].rsplit(" ", 1)[0] + "…"
    return line


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=_ROOT, help="repo root")
    args = ap.parse_args()
    root = os.path.abspath(args.root)

    findings = json.loads(read(root, "FINDINGS.json"))["findings"]
    if len(findings) != 56:
        print(f"FATAL: FINDINGS.json has {len(findings)} findings, expected 56")
        return 1

    # -- sources (byte-identical, embedded) -------------------------------
    sim = read(root, "simulator/flatsat_sim.py")
    sim_text = sim.decode("utf-8")
    fslab = read(root, "poc/lib/fslab.py")
    harness = read(root, "web/harness.py")
    files = [
        {"path": "/repo/simulator/flatsat_sim.py",
         "content": sim_text},
        {"path": "/repo/poc/lib/fslab.py",
         "content": fslab.decode("utf-8")},
        {"path": "/repo/web/harness.py",
         "content": harness.decode("utf-8")},
    ]

    # ground station: parsed from the committed simulator source (never
    # re-typed), so the range scope always matches the code it simulates.
    m = re.search(r"^GS_STATION = \((\d+),\s*(-?\d+)\)\s*$", sim_text, re.M)
    m2 = re.search(r"^GS_RADIUS_M = (\d+)\s*$", sim_text, re.M)
    if not m or not m2:
        print("FATAL: GS_STATION / GS_RADIUS_M not found in simulator source")
        return 1
    gs = {"lat": int(m.group(1)) / 1e7, "lon": int(m.group(2)) / 1e7,
          "radius_m": int(m2.group(1))}

    # -- PoC catalog + evidence digests + dashboard extras ----------------
    pocs = []
    writeups = {}
    sev_map, sum_map, risk_map = {}, {}, {}
    apid_tc: dict[int, set] = {}
    apid_tm: dict[int, set] = {}
    poc_apids: dict[str, list] = {}
    for f in sorted(findings, key=lambda x: x["poc"].split("/")[-1]):
        base = f["poc"].split("/")[-1]
        src = read(root, f["poc"])
        ev_text = read(root, f["evidence_sim"]).decode("utf-8", "replace")
        ev_md5, ev_lines = norm_md5(ev_text)
        if "POC OK" not in ev_text:
            print(f"WARN: {f['evidence_sim']} lacks 'POC OK'")
        wu_path = f["writeup"]
        wu = read(root, wu_path).decode("utf-8")
        writeups[base] = wu
        sm = SEV_RE.search(wu)
        if not sm:
            print(f"WARN: {wu_path} has no Severity row")
        sev_map[base] = sm.group(1) if sm else ""
        sum_map[base] = summary_of(wu)
        rm = RISK_RE.match(f.get("sparta_risk", "").strip())
        risk_map[base] = (
            {"a": int(rm.group(1)), "b": int(rm.group(2)),
             "c": int(rm.group(3)), "ref": rm.group(4) or ""}
            if rm else None)
        tcs, tms = set(), set()
        for ap in TC_APID_RE.findall(ev_text):
            tcs.add(int(ap, 16))
        for ap in TM_APID_RE.findall(ev_text):
            tms.add(int(ap, 16))
        for a in tcs:
            apid_tc.setdefault(a, set()).add(base)
        for a in tms:
            apid_tm.setdefault(a, set()).add(base)
        poc_apids[base] = sorted(set(tcs) | set(tms))
        pocs.append({
            "file": base,
            "id": f["id"],
            "title": f["title"],
            "sparta": f["sparta_primary"],
            "group": f["sparta_primary"].split("-")[0],
            "severity": sev_map[base],
            "summary": sum_map[base],
            "risk": risk_map[base],
            "hero": base in HEROES,
            "src_md5": md5_b(src),
            "ev_md5": ev_md5,
            "ev_path": f["evidence_sim"],
            "ev_lines": ev_lines,
        })
        files.append({"path": "/repo/poc/" + base,
                      "content": src.decode("utf-8")})

    apid_surface = []
    for a in sorted(set(apid_tc) | set(apid_tm)):
        apid_surface.append({
            "apid": a,
            "name": APID_NAMES.get(a, ""),
            "tc": len(apid_tc.get(a, ())),
            "tm": len(apid_tm.get(a, ())),
            "pocs": sorted(set(apid_tc.get(a, ())) | set(apid_tm.get(a, ()))),
        })

    # killchain anchors must exist in the committed evidence, verbatim.
    ev136 = read(root, "evidence/v136_gps_spoof_chain.txt").decode("utf-8")
    for st in KILLCHAIN:
        if st["anchor"] not in ev136:
            print(f"FATAL: killchain anchor not in committed evidence: "
                  f"{st['anchor']!r}")
            return 1

    # image H digest is a documented verification anchor — keep it anchored.
    if IMAGE_MD5 not in read(root, "docs/BUILD.md").decode("utf-8"):
        print(f"WARN: image H md5 {IMAGE_MD5} not found in docs/BUILD.md")

    groups = {}
    for p in pocs:
        groups[p["group"]] = groups.get(p["group"], 0) + 1

    # -- REPO view: every other interesting committed file, byte-identical --
    def repo_file(sec, path, kind):
        raw = read(root, path)
        return {"sec": sec, "path": path, "name": os.path.basename(path),
                "kind": kind, "size": len(raw),
                "md5": hashlib.md5(raw).hexdigest(),
                "text": raw.decode("utf-8", "replace")}

    repo_files = [
        repo_file("GUIDE", "README.md", "md"),
        repo_file("GUIDE", "CONTRIBUTING.md", "md"),
        repo_file("GUIDE", "FINDINGS.json", "json"),
    ]
    for fn in sorted(os.listdir(os.path.join(root, "docs"))):
        if fn.endswith(".md"):
            repo_files.append(repo_file("DOCUMENTATION", "docs/" + fn, "md"))
    for fn in sorted(os.listdir(os.path.join(root, "evidence"))):
        if fn.endswith(".txt"):
            repo_files.append(repo_file("EVIDENCE", "evidence/" + fn, "txt"))
    for dp, dns, fns in os.walk(os.path.join(root, "firmware")):
        dns[:] = [d for d in dns if d != ".pio"]
        for fn in sorted(fns):
            if os.path.splitext(fn)[1] in (
                    ".h", ".c", ".cpp", ".hpp", ".ino", ".ini",
                    ".md", ".txt", ".yml", ".yaml"):
                rel = os.path.relpath(os.path.join(dp, fn), root)
                repo_files.append(repo_file(
                    "FIRMWARE", rel.replace(os.sep, "/"), "code"))
    repo_files.append(repo_file("REPORTS", "talk/index.html", "html"))

    blob = {
        "pyodide": PYODIDE_VERSION,
        "selftest": "SELFTEST OK",
        "report": json.loads(read(root, "reports/pentest-report.json")),
        "repo": repo_files,
        "pdf_b64": base64.b64encode(
            read(root, "reports/FlatSat-Electr0sm0g-Lab-Pentest-Report.pdf")).decode("ascii"),
        # mermaid 11.4.1 (MIT, web/vendor/) baked in: diagrams render offline,
        # evaluated lazily on first diagram view — zero boot cost, zero CDN
        "mermaid_src": read(root, "web/vendor/mermaid.min.js").decode("utf-8"),
        "md5": {
            "sim": md5_b(sim),
            "fslab": md5_b(fslab),
            "harness": md5_b(harness),
        },
        "groups": GROUP_LABELS,
        "group_counts": groups,
        "pocs": pocs,
        "writeups": writeups,
        "files": files,
        "kpis": {
            "findings": 56,
            "pocs_ok": 112,          # 56 simulator + 56 hardware runs
            "sim_runs": 56,
            "hw_runs": 56,
            "families": len(groups),
            "apids": len(apid_surface),
            "image_md5": IMAGE_MD5,
            "image_size": IMAGE_SIZE,
        },
        "gs": gs,
        "orbit_period": 95.0,        # simulator mission orbit (advance % 95.0)
        "apid_names": {str(a): n for a, n in APID_NAMES.items()},
        "apid_surface": apid_surface,
        "poc_apids": poc_apids,
        "killchain": KILLCHAIN,
        "heroes": [
            {"file": p["file"], "id": p["id"], "title": p["title"],
             "note": HERO_NOTES[p["file"]], "severity": p["severity"]}
            for p in pocs if p["hero"]
        ],
    }
    blob_json = json.dumps(blob, separators=(",", ":")).replace("</script", "<\\/script")

    # -- render the page ----------------------------------------------------
    web = os.path.join(root, "web")
    tpl = read(web, "index.html").decode("utf-8")
    css = read(web, "style.css").decode("utf-8")
    js = read(web, "app.js").decode("utf-8")
    for token in ("__CSS__", "__JS__", "__BLOB_JSON__"):
        if token not in tpl:
            print(f"FATAL: placeholder {token} missing in web/index.html")
            return 1

    # live figures — computed from the repo, never hand-retyped
    import subprocess as _sp
    tracked = len(_sp.run(["git", "ls-files"], cwd=root, capture_output=True,
                          text=True).stdout.split())
    ver_docs = sum(len([f for f in fs if f.endswith(".md")])
                   for _, _, fs in os.walk(os.path.join(root, "docs")))
    pdf = os.path.join(root, "reports", "FlatSat-Electr0sm0g-Lab-Pentest-Report.pdf")
    pdf_pages = max(int(x) for x in re.findall(rb"/Count (\d+)", open(pdf, "rb").read()))
    readme = open(os.path.join(root, "README.md"), encoding="utf-8").read()
    m = re.search(r"\((\d+) pages, 56 finding cards\)", readme)
    if not m or int(m.group(1)) != pdf_pages:
        print(f"FATAL: README claims ({m.group(1) if m else '?'} pages) != actual PDF "
              f"({pdf_pages} pages) — fix README.md")
        return 1

    page = tpl.replace("__CSS__", css).replace("__JS__", js).replace(
        "__BLOB_JSON__", blob_json)
    page = (page.replace("__TRACKED__", str(tracked))
                .replace("__VER_DOCS__", str(ver_docs))
                .replace("__PDF_PAGES__", str(pdf_pages)))
    for token in ("__CSS__", "__JS__", "__BLOB_JSON__", "__TRACKED__",
                  "__VER_DOCS__", "__PDF_PAGES__"):
        if token in page:
            print(f"FATAL: unresolved placeholder {token} in built page")
            return 1

    dist = os.path.join(web, "dist")
    os.makedirs(dist, exist_ok=True)
    with open(os.path.join(dist, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page)
    with open(os.path.join(dist, "CNAME"), "w", encoding="utf-8") as fh:
        fh.write("xenographic.org\n")   # custom domain for GitHub Pages
    with open(os.path.join(dist, "_headers"), "w", encoding="utf-8") as fh:
        # always revalidate the shell and the worker (etag makes it free);
        # prevents a freshly deployed bundle being shadowed by a stale cache
        fh.write("/*\n  Cache-Control: no-cache\n")
    with open(os.path.join(dist, "worker.js"), "wb") as fh:
        fh.write(read(web, "worker.js"))

    total = os.path.getsize(os.path.join(dist, "index.html")) + \
        os.path.getsize(os.path.join(dist, "worker.js"))
    print("WEB DEMO BUILD OK")
    print(f"  repo browser: {len(repo_files)} files + report.json + pdf "
          f"({len(blob['pdf_b64']) // 1024} KiB b64)")
    print(f"  dist: web/dist/ (index.html {os.path.getsize(os.path.join(dist, 'index.html')) // 1024} KiB"
          f" + worker.js) — total {total // 1024} KiB")
    print(f"  sources: flatsat_sim.py md5 {md5_b(sim)[:12]}… · fslab.py md5 {md5_b(fslab)[:12]}…")
    print(f"  PoCs embedded: {len(pocs)} (heroes: {sum(1 for p in pocs if p['hero'])}) · "
          f"Pyodide {PYODIDE_VERSION} pinned")
    print(f"  evidence digests (normalised md5): {len(pocs)} baked in for runtime parity checks")
    print(f"  dashboard: writeups {len(writeups)} · APID surface {len(apid_surface)} "
          f"· killchain {len(KILLCHAIN)} stages (anchors verified) · GS {gs['lat']}, {gs['lon']} "
          f"gate {gs['radius_m']} m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
