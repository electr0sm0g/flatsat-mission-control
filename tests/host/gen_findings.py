#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate FINDINGS.json -- the machine-readable catalog (single source of truth).

The catalog is *derived* from docs/SPARTA_MAPPING.md (the human-auditable
matrix); it is never hand-edited. After any catalog edit:

    python3 tests/host/gen_findings.py     # regenerate FINDINGS.json
    python3 tests/host/check_catalog.py    # validate the whole tree

FINDINGS.json is committed so tooling can consume the catalog without parsing
Markdown; check_catalog.py fails the build if it drifts from the matrix.

Usage:
    python3 tests/host/gen_findings.py          # write FINDINGS.json
    python3 tests/host/gen_findings.py --check  # report drift only, no write

Exit 0 = written / in sync; exit 1 = drift or parse error.

"""
import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))

MAPPING_REL = "docs/SPARTA_MAPPING.md"
OUT_REL = "FINDINGS.json"
EXPECTED_ROWS = 56

_ROW_RE = re.compile(r"^\|\s*(V0?-\d{2})\s*\|(.*)\|\s*$")
_POC_RE = re.compile(r"`(poc/v[01]\d{2}_[a-z0-9_]+\.py)`")
_EV_RE = re.compile(r"`(evidence(?:-hw)?/[^`]+\.txt)`")


def _unescape(cell):
    # Markdown table cells escape literal pipes as \|
    return cell.replace("\\|", "|")


def parse_mapping(text):
    """Parse the catalog rows of SPARTA_MAPPING.md into finding dicts.

    Raises SystemExit with a precise message on any malformed row (the
    matrix is the source of truth: it must parse cleanly or not at all).
    """
    findings = []
    for line in text.splitlines():
        m = _ROW_RE.match(line)
        if not m:
            continue
        fid, rest = m.group(1), m.group(2)
        # 5 separators -> [title, primary, risk, secondary, poc/evidence];
        # literal pipes inside cells are escaped (\|) so " | " is unambiguous
        cells = [_unescape(c.strip()) for c in rest.split(" | ")]
        if len(cells) != 5:
            raise SystemExit(f"gen_findings: row {fid} has {len(cells)} cells, expected 5")
        title, primary, risk, secondary, last = cells
        pm = _POC_RE.search(last)
        if not pm:
            raise SystemExit(f"gen_findings: row {fid} has no PoC ref: {last!r}")
        poc = pm.group(1)
        base = os.path.basename(poc)[:-3]
        ev_sim = f"evidence/{base}.txt"
        ev_hw = f"evidence-hw/{base}.txt"
        # explicit evidence refs in the matrix must agree with the naming
        # convention (both trees are 1:1 with the PoC basenames)
        for ref in _EV_RE.findall(last):
            if ref not in (ev_sim, ev_hw):
                raise SystemExit(f"gen_findings: row {fid} cites {ref!r}, expected {ev_sim!r} / {ev_hw!r}")
        findings.append({
            "id": fid,
            "title": title,
            "sparta_primary": primary,
            "sparta_risk": risk,
            "sparta_secondary": secondary,
            "poc": poc,
            "writeup": None,  # resolved by build_catalog()
            "evidence_sim": ev_sim,
            "evidence_hw": ev_hw,
        })
    if len(findings) != EXPECTED_ROWS:
        raise SystemExit(f"gen_findings: expected {EXPECTED_ROWS} rows, parsed {len(findings)}")
    ids = [f["id"] for f in findings]
    if len(set(ids)) != EXPECTED_ROWS:
        dup = sorted({i for i in ids if ids.count(i) > 1})
        raise SystemExit(f"gen_findings: duplicate IDs: {dup}")
    return findings


def build_catalog(root=_ROOT):
    """Parse the matrix and resolve each finding's writeup (unique <id>_*.md)."""
    with open(os.path.join(root, MAPPING_REL), encoding="utf-8") as f:
        findings = parse_mapping(f.read())
    wdir = os.path.join(root, "docs", "writeups")
    writeups = [w for w in os.listdir(wdir) if w.endswith(".md")]
    for f in findings:
        hits = sorted(w for w in writeups if w.startswith(f["id"] + "_"))
        if len(hits) != 1:
            raise SystemExit(f"gen_findings: writeup(s) for {f['id']}: {hits}")
        f["writeup"] = f"docs/writeups/{hits[0]}"
    return findings


def source_md5(root=_ROOT):
    with open(os.path.join(root, MAPPING_REL), "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def document(root=_ROOT):
    findings = build_catalog(root)
    return {
        "schema": "flatsat-electr0sm0g-lab/findings/1",
        "framework": "SPARTA v3.2 (Space Attack Research and Tactic Analysis, The Aerospace Corporation)",
        "source": MAPPING_REL,
        "generated_by": "tests/host/gen_findings.py",
        "source_md5": source_md5(root),
        "count": len(findings),
        "findings": findings,
    }


def main(argv):
    check_only = "--check" in argv
    try:
        doc = document(_ROOT)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 1
    out = os.path.join(_ROOT, OUT_REL)
    if check_only:
        try:
            with open(out, encoding="utf-8") as f:
                on_disk = json.load(f)
        except FileNotFoundError:
            print(f"gen_findings: {OUT_REL} missing (run without --check to create it)",
                  file=sys.stderr)
            return 1
        if on_disk != doc:
            diff = [k for k in doc if on_disk.get(k) != doc[k]]
            print(f"gen_findings: {OUT_REL} drifted from {MAPPING_REL} (fields: {diff or 'value'})",
                  file=sys.stderr)
            return 1
        print(f"gen_findings: {OUT_REL} in sync ({doc['count']} findings)")
        return 0
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"gen_findings: wrote {OUT_REL} ({doc['count']} findings, source md5 {doc['source_md5']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
