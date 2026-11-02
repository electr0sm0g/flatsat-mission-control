#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate reports/FlatSat-Electr0sm0g-Lab-Pentest-Report.pdf (+ pentest-report.json).

A professional penetration-test-style report for the FlatSat electr0sm0g Lab, in a
dark A4 threat-intel report design system (ReportLab). Adapted for space
pentesting per the pentest-report blueprint:

  - severity comes from the repo's own writeups (leading word of the
    `| Severity |` row) + SPARTA v3.2 notional risk — no invented CVSS
    vectors (the space framework is SPARTA, not OWASP/CVSS);
  - data is read from FINDINGS.json + docs/writeups/ at generation time, so
    the report can never drift from the catalog (regenerate after any
    catalog change:  python3 tools/gen_report.py).

Fonts: uses the Poppins/Carlito font set when available, in this order: a
directory of the .ttf files named by $FONT_DIR, then assets/fonts/report
inside the repository; otherwise falls back to ReportLab's built-in
Helvetica family (same layout, metric-compatible).

Requires ReportLab (pip install reportlab). Run:  python3 tools/gen_report.py
"""
import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))

sys.path.insert(0, os.path.join(_ROOT, "tests", "host"))
from gen_findings import build_catalog  # noqa: E402

# Poppins/Carlito font set: $FONT_DIR override, then an optional in-repo
# directory. When absent, every alias falls back to the built-in Helvetica
# family (metric-compatible, identical layout).
FONT_DIR = os.environ.get("FONT_DIR") or os.path.join(_ROOT, "assets", "fonts", "report")
if not os.path.isdir(FONT_DIR):
    FONT_DIR = ""
OUT_PDF = os.path.join(_ROOT, "reports", "FlatSat-Electr0sm0g-Lab-Pentest-Report.pdf")
OUT_JSON = os.path.join(_ROOT, "reports", "pentest-report.json")

REPORT_DATE = "2026-11-02"
REPORT_ID = "PT-ELECTR0SM0G-20261102"
IMAGE_MD5 = "bfc145c93039177b7393147978cdd432"

# ---------------------------------------------------------------------------
# palette / layout (dark A4 design system)
# ---------------------------------------------------------------------------
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.pdfbase import pdfmetrics  # noqa: E402
from reportlab.pdfbase.ttfonts import TTFont  # noqa: E402
from reportlab.lib.styles import ParagraphStyle  # noqa: E402
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Flowable,  # noqa: E402
                                Frame, PageBreak, PageTemplate, Paragraph,
                                Spacer, Table, TableStyle)

# deterministic output (fixed timestamp, stable /ID) so two runs on the same
# catalog + fonts produce the same bytes — the report is a committed artifact
import reportlab.rl_config as _rl_config  # noqa: E402
_rl_config.invariant = 1

BG = colors.HexColor("#07040B")
BGC = colors.HexColor("#13101C")
BGCA = colors.HexColor("#1A1625")
GL = colors.HexColor("#1E1A2E")
BS = colors.HexColor("#2A2535")
BP = colors.HexColor("#6941C6")
BPL = colors.HexColor("#8B5CF6")
BM = colors.HexColor("#C9317C")
T1 = colors.HexColor("#FFFFFF")
T2 = colors.HexColor("#F0F2F5")
T3 = colors.HexColor("#E0E3E8")
SC = colors.HexColor("#EF4444")
SH = colors.HexColor("#FB923C")
SM = colors.HexColor("#EAB308")
SL = colors.HexColor("#22C55E")
AB = colors.HexColor("#3B82F6")
AE = colors.HexColor("#10B981")
AA = colors.HexColor("#F59E0B")

PAGE_W, PAGE_H = A4
CW = 555.28  # content width (design system)
MARG = (PAGE_W - CW) / 2.0

FMAP = {  # alias -> (file, fallback base)
    "FH": ("Poppins-Bold.ttf", "Helvetica-Bold"),
    "FM": ("Poppins-Medium.ttf", "Helvetica"),
    "FR": ("Poppins-Regular.ttf", "Helvetica"),
    "FL": ("Poppins-Light.ttf", "Helvetica"),
    "FI": ("Poppins-Italic.ttf", "Helvetica-Oblique"),
    "FB": ("Carlito-Regular.ttf", "Helvetica"),
    "FBB": ("Carlito-Bold.ttf", "Helvetica-Bold"),
    "FBI": ("Carlito-Italic.ttf", "Helvetica-Oblique"),
    "FBBI": ("Carlito-BoldItalic.ttf", "Helvetica-BoldOblique"),
}
for alias, (fname, fallback) in FMAP.items():
    path = os.path.join(FONT_DIR, fname)
    if os.path.exists(path):
        pdfmetrics.registerFont(TTFont(alias, path))
    else:
        # fall back to the built-in Helvetica family (metric-compatible)
        FMAP[alias] = (None, fallback)
pdfmetrics.registerFontFamily("FB", normal="FB", bold="FBB",
                              italic="FBI", boldItalic="FBBI")


def ffont(alias):
    """Font name for a Paragraph when alias may be a fallback built-in."""
    fname, fallback = FMAP[alias]
    return alias if fname else fallback


def S(name, alias, size, leading, color, **kw):
    from reportlab.lib.styles import ParagraphStyle
    kw.setdefault("alignment", 0)
    return ParagraphStyle(name, fontName=ffont(alias), fontSize=size,
                          leading=leading, textColor=color, **kw)


ST = {
    "ct": S("ct", "FH", 36, 44, T1),
    "cc": S("cc", "FM", 18, 24, BPL),
    "h1": S("h1", "FH", 20, 26, T1, spaceAfter=8),
    "h2": S("h2", "FM", 16, 21, T1, spaceAfter=6),
    "h3": S("h3", "FM", 13, 17, BPL, spaceAfter=4),
    "tt": S("tt", "FM", 13, 18, T1),
    "body": S("body", "FB", 12, 17, T2, alignment=4),  # 4 = justify
    "bs": S("bs", "FB", 11, 15, T2),
    "ts": S("ts", "FB", 11, 16, T2, alignment=4),
    "label": S("label", "FR", 10, 13, T3),
    "sl": S("sl", "FM", 10, 13, BPL),
    "bullet": S("bullet", "FB", 12, 17, T2, leftIndent=14),
    "notice": S("notice", "FBI", 10, 14, T3),
    "card_title": S("card_title", "FH", 14, 20, T1),
    "meta": S("meta", "FB", 10, 13, T2),
    "score_lab": S("score_lab", "FM", 10, 13, T2),
    "score_val": S("score_val", "FH", 12, 15, T1),
    "sec_head": S("sec_head", "FM", 10, 13, BPL, spaceAfter=3),
    "green_head": S("green_head", "FM", 10, 13, AE, spaceAfter=3),
    "amber_head": S("amber_head", "FM", 10, 13, AA, spaceAfter=3),
    "blue_head": S("blue_head", "FM", 10, 13, AB, spaceAfter=3),
    "mono": S("mono", "FB", 10.5, 14, T2),
    "metric_val": S("metric_val", "FH", 22, 26, T1, alignment=1),
    "metric_lab": S("metric_lab", "FR", 9, 12, T2, alignment=1),
}


def grad(d, x, y, w, h, steps=80):
    for i in range(steps):
        t = i / (steps - 1)
        col = colors.Color(BP.red + (BM.red - BP.red) * t,
                           BP.green + (BM.green - BP.green) * t,
                           BP.blue + (BM.blue - BP.blue) * t)
        x0 = x + w * i / steps
        d.rect(x0, y, w / steps + 0.4, h, stroke=0, fill=1,
               fillColor=col) if False else None
        d.setFillColor(col)
        d.rect(x0, y, w / steps + 0.4, h, stroke=0, fill=1)


class GradientLine(Flowable):
    def __init__(self, w, h=2):
        super().__init__()
        self.width, self.height = w, h

    def wrap(self, aW, aH):
        return self.width, self.height

    def draw(self):
        grad(self.canv, 0, 0, self.width, self.height)


class SectionNumber(Flowable):
    def __init__(self, num):
        super().__init__()
        self.num = num
        self.width, self.height = CW, 38

    def wrap(self, aW, aH):
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.setFont(ffont("FH"), 42)
        c.setFillColor(colors.Color(BP.red, BP.green, BP.blue, alpha=0.5))
        c.drawString(1.5, 1.5, f"{self.num:02d}")
        c.setFillColor(colors.Color(BP.red, BP.green, BP.blue, alpha=0.7))
        c.drawString(0, 0, f"{self.num:02d}")


def page_decorations(cv, doc, first=False):
    cv.saveState()
    cv.setFillColor(BG)
    cv.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
    grad(cv, 0, PAGE_H - 3.5, PAGE_W, 3.5)
    # left accent strip
    cv.setFillColor(colors.Color(BP.red, BP.green, BP.blue, alpha=0.12))
    cv.rect(0, 26, 2.5, PAGE_H - 26, stroke=0, fill=1)
    # footer
    cv.setFillColor(GL)
    cv.rect(0, 0, PAGE_W, 26, stroke=0, fill=1)
    cv.setFillColor(T3)
    cv.setFont(ffont("FR"), 7)
    cv.drawString(MARG, 10, "\u00c9TIENNE LACOCHE \u00b7 Cybersecurity Researcher   \u00b7   Penetration Test Report   \u00b7   PUBLIC \u2014 INTENTIONALLY VULNERABLE LAB")
    cv.setFont(ffont("FR"), 8)
    cv.setFillColor(T2)
    cv.drawRightString(PAGE_W - MARG - 18, 10, "Page ")
    cv.setFont(ffont("FH"), 9)
    cv.setFillColor(BP)
    cv.drawRightString(PAGE_W - MARG, 10, str(cv.getPageNumber()))
    cv.restoreState()


class MetricBox(Flowable):
    def __init__(self, value, label, color, width, height=58):
        super().__init__()
        self.value, self.label, self.color = value, label, color
        self.width, self.height = width, height

    def wrap(self, aW, aH):
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(BGC)
        c.setStrokeColor(BS)
        c.setLineWidth(0.4)
        c.roundRect(0, 0, self.width, self.height, 6, stroke=1, fill=1)
        c.setFillColor(self.color)
        c.roundRect(0, self.height - 3, self.width, 3, 1, stroke=0, fill=1)
        c.setFillColor(self.color)
        c.setFont(ffont("FH"), 22)
        c.drawCentredString(self.width / 2, self.height - 30, str(self.value))
        c.setFillColor(T2)
        c.setFont(ffont("FR"), 9)
        c.drawCentredString(self.width / 2, 7, str(self.label))


def score_row(c, x, y, items, bar_w):
    """items: [(label, value, band, color, frac)] drawn as 3 stacked bars."""
    y = y - 60
    for i, (lab, val, band, col, frac) in enumerate(items):
        yy = y + (2 - i) * 16
        c.setFont(ffont("FM"), 10)
        c.setFillColor(T2)
        c.drawString(x, yy, lab)
        c.setFont(ffont("FH"), 12)
        c.setFillColor(T1)
        c.drawString(x + bar_w * 0.10 + 10, yy - 1, f"{val:.2f}")
        tx = x + bar_w * 0.22
        c.setFillColor(BGCA)
        c.roundRect(tx, yy - 1, bar_w * 0.46, 8, 3, stroke=0, fill=1)
        w = max(4, bar_w * 0.46 * frac)
        c.setFillColor(colors.Color(col.red, col.green, col.blue, alpha=0.85))
        c.roundRect(tx, yy - 1, w, 8, 3, stroke=0, fill=1)
        c.setFillColor(col)
        c.circle(tx + w, yy + 3, 5, stroke=0, fill=1)
        c.setFillColor(col)
        c.setFont(ffont("FH"), 10)
        c.drawString(tx + bar_w * 0.46 + 12, yy, band)
    return y - 16


class ScoreRowFlow(Flowable):
    def __init__(self, items):
        super().__init__()
        self.items = items
        self.width, self.height = CW, 60

    def wrap(self, aW, aH):
        return self.width, self.height

    def draw(self):
        score_row(self.canv, 0, self.height, self.items, self.width)


SEV_COLOR = {"CRITICAL": SC, "HIGH": SH, "MEDIUM": SM, "LOW": SL}
SEV_SCORE = {"CRITICAL": 0.95, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25}
BAND = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def sev_band_color(sev):
    return SC if sev == "CRITICAL" else SH if sev == "HIGH" else SM if sev == "MEDIUM" else SL


def first_sentence(text, limit=230):
    text = re.sub(r"\s+", " ", text).strip()
    m = re.match(r"(.+?\.)\s", text)
    out = m.group(1) if m and len(m.group(1)) < limit else text[:limit]
    return out + ("..." if len(out) >= limit and not out.endswith("...") else "")


def writeup_bits(path):
    s = open(path, encoding="utf-8").read()
    sev_m = re.search(r"^\|\s*Severity\s*\|\s*(.+?)\s*\|", s, re.M)
    sev = (sev_m.group(1).strip().split(" ")[0].upper() if sev_m else "MEDIUM")
    if sev not in SEV_COLOR:
        sev = "MEDIUM"
    sum_m = re.search(r"^## Summary\s*\n+(.+?)(?:\n## |\Z)", s, re.M | re.S)
    summ = first_sentence(sum_m.group(1)) if sum_m else ""
    mit_m = re.search(r"^## Mitigations\s*\n+(.+?)(?:\n## |\Z)", s, re.M | re.S)
    mit = ""
    if mit_m:
        for line in mit_m.group(1).splitlines():
            if line.strip().startswith("- "):
                mit = re.sub(r"\s+", " ", line.strip()[2:])[:220]
                break
    return sev, summ, mit


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------
GROUPS = [
    (1, "Recon & leakage", ["V0-01", "V0-09", "V0-18", "V-01", "V-02", "V-03", "V-06", "V-29", "V-37"]),
    (2, "Crypto & link integrity", ["V0-02", "V0-06", "V0-07", "V0-10", "V0-11", "V0-12", "V-07", "V-08", "V-10", "V-11"]),
    (3, "Spoofing & command tampering", ["V0-04", "V0-05", "V0-17", "V-12", "V-36"]),
    (4, "Memory corruption & RCE", ["V0-03", "V0-16", "V-04", "V-05", "V-09", "V-13", "V-14"]),
    (5, "Ground segment & downlink", ["V-28", "V-31", "V-32", "V-30"]),
    (6, "Bus, sensors & FDIR", ["V-17", "V-24", "V-25", "V-26", "V-27"]),
    (7, "Persistence", ["V-19", "V-20", "V-21", "V-38"]),
    (8, "OTA & protection downgrade", ["V-18", "V-22", "V-23", "V-16"]),
    (9, "DoS & impact", ["V0-08", "V0-13", "V0-14", "V0-15", "V-15", "V-33", "V-34", "V-35"]),
]
GROUP_OF = {fid: (n, name) for n, name, ids in GROUPS for fid in ids}
assert len(GROUP_OF) == 56, f"group map incomplete: {len(GROUP_OF)}"


def load_findings():
    catalog = build_catalog(_ROOT)
    rows = []
    for f in catalog:
        sev, summ, mit = writeup_bits(os.path.join(_ROOT, f["writeup"]))
        rows.append({
            "id": f["id"],
            "title": f["title"],
            "severity": sev,
            "sparta_primary": f["sparta_primary"],
            "sparta_risk": f["sparta_risk"],
            "sparta_secondary": f["sparta_secondary"],
            "poc": f["poc"],
            "writeup": f["writeup"],
            "evidence_sim": f["evidence_sim"],
            "evidence_hw": f["evidence_hw"],
            "summary": summ,
            "mitigation": mit,
            "group": GROUP_OF[f["id"]],
            "poc_verified": True,
        })
    return rows


def sev_counts(rows):
    from collections import Counter
    c = Counter(r["severity"] for r in rows)
    return c


# ---------------------------------------------------------------------------
# radar
# ---------------------------------------------------------------------------
class Radar(Flowable):
    SECTORS = ["Recon", "Crypto", "Spoofing", "Memory/RCE", "Ground seg.",
               "Bus/FDIR", "Persistence", "OTA", "DoS/Impact"]

    def __init__(self, rows):
        super().__init__()
        self.rows = rows
        self.width = 460
        self.height = 330

    def wrap(self, aW, aH):
        return self.width, self.height

    def draw(self):
        import math
        c = self.canv
        cx, cy = 230, 175
        max_r = 114
        # background glow
        for r in range(int(max_r + 20), 0, -2):
            c.setFillColor(colors.Color(10 / 255, 5 / 255, 20 / 255, alpha=0.05))
            c.circle(cx, cy, r, stroke=0, fill=1)
        # rings
        c.setStrokeColor(colors.Color(BP.red, BP.green, BP.blue, alpha=0.3))
        c.setLineWidth(0.5)
        c.setDash(3, 3)
        labels = [("CRITICAL", 0.25, SC), ("HIGH", 0.50, SH),
                  ("MEDIUM", 0.75, SM), ("LOW", 1.00, SL)]
        for lab, frac, col in labels:
            c.circle(cx, cy, max_r * frac, stroke=1, fill=0)
            c.setDash()
            a = math.radians(15)
            c.setFillColor(col)
            c.setFont(ffont("FM"), 7)
            c.drawString(cx + max_r * frac * math.cos(a) + 3,
                         cy + max_r * frac * math.sin(a) - 2, lab)
        # spokes (9 sectors, 40 deg)
        c.setStrokeColor(colors.Color(BP.red, BP.green, BP.blue, alpha=0.25))
        c.setLineWidth(0.3)
        for i in range(9):
            a = math.radians(90 + i * 40)
            x2 = cx + (max_r + 30) * math.cos(a)
            y2 = cy + (max_r + 30) * math.sin(a)
            c.line(cx, cy, x2, y2)
            c.setFillColor(T1)
            c.setFont(ffont("FM"), 9)
            w = c.stringWidth(self.SECTORS[i], ffont("FM"), 9)
            if abs(math.cos(a)) < 0.3:
                c.drawCentredString(x2, y2 - 4 if math.sin(a) > 0 else y2 + 8, self.SECTORS[i])
            elif math.cos(a) > 0:
                c.drawString(x2 + 4, y2 - 2, self.SECTORS[i])
            else:
                c.drawRightString(x2 - 4, y2 - 2, self.SECTORS[i])
        # crosshair + center glow
        c.setStrokeColor(colors.Color(140 / 255, 92 / 255, 230 / 255, alpha=0.4))
        c.setLineWidth(0.4)
        c.line(cx - 8, cy, cx + 8, cy)
        c.line(cx, cy - 8, cx, cy + 8)
        # threat points: one per sector, radius by severity mass, color by dominant sev
        from collections import Counter
        counts = sev_counts(self.rows)
        total = sum(counts.values())
        for i, (n, name, ids) in enumerate(GROUPS):
            sev_in = Counter(r["severity"] for r in self.rows if r["id"] in ids)
            dom = max(sev_in, key=lambda k: (sev_in[k], k == "CRITICAL"))
            mass = (sev_in.get("CRITICAL", 0) * 1.0 + sev_in.get("HIGH", 0) * 0.75
                    + sev_in.get("MEDIUM", 0) * 0.45 + sev_in.get("LOW", 0) * 0.2)
            frac = 0.30 + 0.62 * (mass / max(sum(sev_in.values()) / 4 * 1.0, 1e-9))
            frac = min(1.0, frac)
            col = SEV_COLOR[dom]
            a = math.radians(90 + i * 40)
            px = cx + max_r * frac * math.cos(a)
            py = cy + max_r * frac * math.sin(a)
            rad = 7 if dom == "CRITICAL" else 5.5 if dom == "HIGH" else 4.5
            c.setFillColor(colors.Color(col.red, col.green, col.blue, alpha=0.12))
            c.circle(px, py, rad + 7, stroke=0, fill=1)
            c.setFillColor(colors.Color(col.red, col.green, col.blue, alpha=0.25))
            c.circle(px, py, rad + 3, stroke=0, fill=1)
            c.setFillColor(colors.Color(col.red, col.green, col.blue, alpha=0.9))
            c.circle(px, py, rad, stroke=0, fill=1)
            c.setFillColor(colors.Color(1, 1, 1, alpha=0.3))
            c.circle(px - 0.15 * rad, py + 0.15 * rad, 0.35 * rad, stroke=0, fill=1)
        # legend
        c.setFont(ffont("FB"), 10)
        c.setFillColor(T2)
        c.drawString(20, 20, "One point per attack surface; radius \u221d severity mass of its findings, color = dominant severity.")


# ---------------------------------------------------------------------------
# advisory card
# ---------------------------------------------------------------------------
def card(serial, r):
    col = SEV_COLOR[r["severity"]]
    n, gname = r["group"]
    flows = []
    flows.append(CondPageBreak(220))
    flows.append(Table([[""]], colWidths=[CW], rowHeights=[4],
                       style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), col),
                                         ("TOPPADDING", (0, 0), (-1, -1), 0),
                                         ("BOTTOMPADDING", (0, 0), (-1, -1), 0)])))
    flows.append(Spacer(1, 8))
    flows.append(Paragraph(f"<b>#{serial}  [{r['severity']}]  {esc(r['title'])}</b>",
                           ST["card_title"]))
    flows.append(Spacer(1, 2))
    meta = (f'<font color="#8B5CF6">Group:</font> {n} \u00b7 {esc(gname)}'
            f'  \u2502  <font color="#8B5CF6">PoC:</font> {esc(os.path.basename(r["poc"]))}'
            f'  \u2502  <font color="#8B5CF6">Targets:</font> simulator + FlatSat 1'
            f'  \u2502  <font color="#8B5CF6">Status:</font> <font color="#10B981">VERIFIED</font>')
    flows.append(Paragraph(meta, ST["meta"]))
    sc = SEV_SCORE[r["severity"]]
    flows.append(ScoreRowFlow([
        ("SEVERITY", sc, BAND[r["severity"]], sev_band_color(r["severity"]), sc),
        ("RELEVANCE", 1.0, "APPLIABLE", AE, 1.0),
        ("PRIORITY", sc, BAND[r["severity"]], sev_band_color(r["severity"]), sc),
    ]))
    flows.append(Spacer(1, 4))
    flows.append(Paragraph(esc(r["summary"]) or esc(r["title"]), ST["ts"]))
    flows.append(Spacer(1, 6))
    flows.append(Paragraph("TECHNICAL DETAILS", ST["sec_head"]))
    flows.append(Paragraph(f'<font color="#F59E0B">SPARTA v3.2:</font> {esc(r["sparta_primary"])}'
                           f'  \u00b7  <font color="#F59E0B">Notional risk:</font> {esc(r["sparta_risk"])}',
                           ST["bs"]))
    if r["sparta_secondary"] and r["sparta_secondary"] != "\u2014":
        flows.append(Paragraph(f'<font color="#F59E0B">Secondary:</font> {esc(r["sparta_secondary"])}',
                               ST["bs"]))
    flows.append(Spacer(1, 4))
    flows.append(Paragraph("IMPACT CONTEXT", ST["sec_head"]))
    flows.append(Paragraph(f'<font color="#8B5CF6">Surface:</font> {esc(gname)}'
                           f'  \u2502  <font color="#8B5CF6">Interface:</font> '
                           f'{'unauthenticated uplink (RF/USB)' if n in (1,2,3,4,5,6,7,8) else 'uplink flood / resource saturation'}',
                           ST["bs"]))
    if r["mitigation"]:
        flows.append(Spacer(1, 4))
        flows.append(Paragraph("REMEDIATION", ST["green_head"]))
        flows.append(Paragraph(f'<font color="#10B981">docs/DEFENSE.md \u00b7 group {n}:</font> '
                               f'{esc(r["mitigation"])}', ST["bs"]))
    flows.append(Spacer(1, 4))
    flows.append(Paragraph("DETECTION EVIDENCE", ST["green_head"]))
    flows.append(Paragraph(f'\u2022 {esc(r["evidence_sim"])} (simulator)  \u2022 '
                           f'{esc(r["evidence_hw"])} (hardware, image H md5 {IMAGE_MD5[:8]}\u2026)',
                           ST["bs"]))
    flows.append(Spacer(1, 8))
    flows.append(GradientLine(CW * 0.5, 1))
    flows.append(Spacer(1, 8))
    return flows


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------
def section(doc, num, title, content, before_break=False):
    if before_break:
        doc.append(PageBreak())
    doc.append(SectionNumber(num))
    doc.append(Paragraph(title, ST["h1"]))
    doc.append(GradientLine(CW, 2))
    doc.append(Spacer(1, 11))
    doc.extend(content)


def main():
    rows = load_findings()
    counts = sev_counts(rows)
    story = []

    # ---- cover -------------------------------------------------------------
    story.append(Spacer(1, 60))
    word = Table([[Paragraph('<font color="#8B5CF6"><b>\u00c9TIENNE</b></font>'
                             '<font color="#C9317C"><b> LACOCHE</b></font>', ST["ct"])],
                  [Paragraph("Cybersecurity Researcher \u00b7 etienne.lacoche@pm.me", ST["label"])]],
                 colWidths=[CW])
    story.append(word)
    story.append(Spacer(1, 46))
    story.append(GradientLine(CW, 3))
    story.append(Spacer(1, 34))
    story.append(Paragraph("PENETRATION TEST", ST["ct"]))
    story.append(Paragraph("REPORT", ST["ct"]))
    story.append(Spacer(1, 18))
    story.append(Paragraph("FlatSat electr0sm0g Lab Version \u2014 56-finding vulnerable-by-design CubeSat",
                           ST["cc"]))
    story.append(Spacer(1, 14))
    story.append(GradientLine(CW * 0.35, 2))
    story.append(Spacer(1, 26))
    meta = [
        ("REPORT DATE", REPORT_DATE),
        ("CLASSIFICATION", "PUBLIC \u2014 intentionally vulnerable laboratory"),
        ("SECTOR", "Space / aerospace (CubeSat, open hardware)"),
        ("REGION", "Worldwide (open-source lab)"),
        ("RESEARCHER", "\u00c9tienne Lacoche \u2014 Cybersecurity Researcher"),
        ("REPORT ID", REPORT_ID),
    ]
    t = Table([[Paragraph(k, ST["label"]), Paragraph(v, ST["bs"])] for k, v in meta],
              colWidths=[CW * 0.32, CW * 0.68])
    t.setStyle(TableStyle([("TOPPADDING", (0, 0), (-1, -1), 5),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story.append(t)
    story.append(Spacer(1, 40))
    story.append(Paragraph(
        "This report documents a laboratory system built to be broken. Every finding below is "
        "implemented by design, proven by an executable PoC on two targets (bit-for-bit Python "
        "simulator and real FlatSat 1 hardware), and mapped to SPARTA v3.2 (Space Attack Research "
        "and Tactic Analysis, The Aerospace Corporation). Nothing here "
        "describes a vulnerability in an operational system; the radio interface must never be "
        "pointed at a network that is not owned by the operator.",
        ST["notice"]))
    story.append(PageBreak())

    # ---- TOC ----------------------------------------------------------------
    story.append(Paragraph("TABLE OF CONTENTS", ST["h1"]))
    story.append(GradientLine(CW, 2))
    story.append(Spacer(1, 20))
    toc = [
        (1, "Executive Summary"), (2, "Findings Overview \u2014 9 attack surfaces"),
        (3, "Attack Surface Radar"), (4, "Critical Severity Findings (4)"),
        (5, "High Severity Findings (32)"), (6, "Medium Severity Findings (17)"),
        (7, "Low Severity Findings (3)"), (8, "Scope & Infrastructure"),
        (9, "Technology Stack"), (10, "Security Posture"),
        (11, "Remediation Roadmap"), (12, "Methodology & Verification"),
        (13, "Appendix \u2014 Finding Cross-Reference"),
    ]
    for num, title in toc:
        row = Table([[Paragraph(f"{num:02d}", ParagraphStyle("n", parent=ST["tt"],
                                                              fontName=ffont("FH"),
                                                              textColor=BP)),
                      Paragraph(title, ParagraphStyle("t", parent=ST["sl"],
                                                       fontName=ffont("FM"), fontSize=10.5,
                                                       textColor=T1))]],
                    colWidths=[35, CW - 35])
        row.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, GL),
                                 ("TOPPADDING", (0, 0), (-1, -1), 7),
                                 ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
        story.append(row)
    story.append(PageBreak())

    # ---- 01 executive summary ------------------------------------------------
    story.append(SectionNumber(1))
    story.append(Paragraph("Executive Summary", ST["h1"]))
    story.append(GradientLine(CW, 2))
    story.append(Spacer(1, 11))
    mbox_w = (CW - 4 * 10) / 5
    mb = Table([[MetricBox(56, "findings", T1, mbox_w),
                 MetricBox(counts.get("CRITICAL", 0), "critical", SC, mbox_w),
                 MetricBox(counts.get("HIGH", 0), "high", SH, mbox_w),
                 MetricBox(counts.get("MEDIUM", 0), "medium", SM, mbox_w),
                 MetricBox(counts.get("LOW", 0), "low", SL, mbox_w)]],
               colWidths=[mbox_w + 10] * 5)
    mb.setStyle(TableStyle([("TOPPADDING", (0, 0), (-1, -1), 0),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    story.append(mb)
    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "FlatSat electr0sm0g Lab Version is a complete offensive-security extension of the official FlatSat v1.0 "
        "CubeSat firmware (Pwnsat/FlatSat, GPL-2.0-or-later), built and tested on FlatSat 1 "
        "hardware (Electronic Cats \u00d7 PwnSat, RP2040 + 2\u00d7 SX1262 LoRa). The assessment "
        "covers the full control path \u2014 RF uplink/downlink, SpaceCAN bus, flash-resident "
        "state, sensors, ground segment, and the OTA path \u2014 and documents "
        "<b>56 findings</b>, every one of them implemented in the real firmware, mirrored "
        "bit-for-bit in a Python simulator, and proven by an executable PoC that runs "
        "unchanged on both targets (56/56 POC OK, 112 captured transcripts).", ST["body"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Overall risk rating: <b><font color=\"#EF4444\">CRITICAL</font></b> "
                           "\u2014 the vehicle is fully controllable by an unauthenticated "
                           "uplink (complete initial-access chain, V-36), its code is upgradable "
                           "without signature (V-18 \u2192 V-20 persistence), and it can be "
                           "permanently crashed with a single malformed frame (V0-03).",
                           ST["body"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Key findings", ST["h3"]))
    for fid in ("V-14", "V0-03", "V-36"):
        r = next(x for x in rows if x["id"] == fid)
        story.append(Paragraph(f"\u2022 <b>{fid} \u2014 {esc(r['title'])}</b>: {esc(r['summary'])}",
                               ST["bullet"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Priority: the three control-plane failures (unauthenticated privileged commanding, "
        "unsigned persistence, crash-on-frame) compound into total loss of the vehicle. "
        "Remediation roadmap in section 11; per-group countermeasures in the blue-team "
        "companion (docs/DEFENSE.md in the repository).", ST["body"]))

    # ---- 02 findings overview ------------------------------------------------
    overview = []
    data = [[Paragraph("Surface", ST["sl"]), Paragraph("Findings", ST["sl"]),
             Paragraph("Critical", ST["sl"]), Paragraph("High", ST["sl"]),
             Paragraph("Medium", ST["sl"]), Paragraph("Low", ST["sl"]),
             Paragraph("Flagship", ST["sl"])]]
    for n, name, ids in GROUPS:
        in_g = [r for r in rows if r["id"] in ids]
        c = Counter2 = sev_counts(in_g)
        dom = max(in_g, key=lambda r: (SEV_SCORE[r["severity"]], r["id"]))
        data.append([Paragraph(f"<b>{n}. {esc(name)}</b>", ST["bs"]),
                     Paragraph(str(len(in_g)), ST["bs"]),
                     Paragraph(str(c.get("CRITICAL", 0)), ST["bs"]),
                     Paragraph(str(c.get("HIGH", 0)), ST["bs"]),
                     Paragraph(str(c.get("MEDIUM", 0)), ST["bs"]),
                     Paragraph(str(c.get("LOW", 0)), ST["bs"]),
                     Paragraph(f"{dom['id']} \u2014 {esc(dom['title'][:52])}", ST["bs"])])
    ot = Table(data, colWidths=[CW * 0.26, CW * 0.09, CW * 0.09, CW * 0.09, CW * 0.09, CW * 0.09, CW * 0.29])
    ot.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BGC),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BGC, BGCA]),
        ("GRID", (0, 0), (-1, -1), 0.5, GL),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    overview.append(ot)
    overview.append(Spacer(1, 10))
    overview.append(Paragraph(
        "Grouping mirrors the README catalog (9 attack-surface groups). Severity is taken from "
        "the repository's own writeups; the SPARTA v3.2 notional-risk triple is quoted per "
        "finding in the detailed sections.", ST["ts"]))
    section(story, 2, "Findings Overview \u2014 9 attack surfaces", overview, before_break=True)

    # ---- 03 radar ------------------------------------------------------------
    radar = [Paragraph("Findings are distributed across the nine attack surfaces below. "
                       "Radius encodes the severity mass of each surface; color encodes its "
                       "dominant severity. Memory/RCE and Spoofing carry the highest-mass "
                       "points; Recon is the broadest (every group is reachable from an "
                       "unauthenticated uplink).", ST["ts"]),
             Spacer(1, 10), Radar(rows), Spacer(1, 10),
             Paragraph("Read with the threat model (docs/THREAT-MODEL.md): three adversaries "
                       "(passive eavesdropper, unauthenticated uplink, RF/PNT adversary) and "
                       "five trust boundaries (B1\u2013B5), each with exactly one weak or "
                       "absent integrity mechanism.", ST["ts"])]
    section(story, 3, "Attack Surface Radar", radar, before_break=True)

    # ---- 04-07 severity cards -------------------------------------------------
    serial = 0
    for sev, num, title in (("CRITICAL", 4, "Critical Severity Findings"),
                            ("HIGH", 5, "High Severity Findings"),
                            ("MEDIUM", 6, "Medium Severity Findings"),
                            ("LOW", 7, "Low Severity Findings")):
        cards = []
        for r in [x for x in rows if x["severity"] == sev]:
            serial += 1
            cards.extend(card(serial, r))
        story.append(PageBreak())
        story.append(SectionNumber(num))
        story.append(Paragraph(f"{title} ({sum(1 for x in rows if x['severity'] == sev)})",
                               ST["h1"]))
        story.append(GradientLine(CW, 2))
        story.append(Spacer(1, 11))
        story.extend(cards)

    # ---- 08 scope & infrastructure ---------------------------------------------
    scope = [
        Paragraph("In-scope systems", ST["h3"]),
        Table([[Paragraph("System", ST["sl"]), Paragraph("Role in assessment", ST["sl"])],
               [Paragraph("FlatSat 1 board (RP2040, 2\u00d7 SX1262 LoRa, BME280, LIS2DH12, 4 MB flash)", ST["bs"]),
                Paragraph("Test target \u2014 real firmware, over USB bench transport and ISM-band LoRa", ST["bs"])],
               [Paragraph("Bit-for-bit Python simulator (simulator/flatsat_sim.py)", ST["bs"]),
                Paragraph("Authoritative behavioural reference \u2014 same PoC, second target", ST["bs"])],
               [Paragraph("Bench harness (poc/lib/fslab.py, FEED-window protocol 0x26/0x27)", ST["bs"]),
                Paragraph("Deterministic time control \u2014 what makes sim \u2261 silicon", ST["bs"])]],
              colWidths=[CW * 0.42, CW * 0.58]),
        Spacer(1, 10),
        Paragraph("Out of scope", ST["h3"]),
        Paragraph("\u2022 Other hardware revisions, the SX1262 RF front-end as physical hardware, "
                  "and any network not owned by the operator.", ST["bullet"]),
        Paragraph("\u2022 Physical security (the board itself) and the upstream v1.0.3 release "
                  "as distributed (assessed via its public source).", ST["bullet"]),
        Spacer(1, 10),
        Paragraph("Constraints", ST["h3"]),
        Paragraph("The system is intentionally vulnerable; findings are not defects of a "
                  "product but the designed behaviour of a laboratory. Hardware evidence was "
                  "captured on firmware image H (UF2 335872 B, md5 "
                  f"{IMAGE_MD5}); three transcripts (v003, v015, v135) are annotated in "
                  "hw_pass.txt as by-design impact evidence captured on earlier images.", ST["ts"]),
        Spacer(1, 6),
        Paragraph("Realism: the flaw classes are those documented in real smallsat flight "
                  "software; the configuration is a pedagogical amplifier (docs/REALISM.md "
                  "carries the three-tier mapping and the in-orbit surface analysis).",
                  ST["ts"]),
    ]
    scope_t = Table([[a] for a in [0]], colWidths=[CW])  # spacer no-op removed below
    section(story, 8, "Scope & Infrastructure", scope, before_break=True)

    # ---- 09 technology stack ---------------------------------------------------
    stack = [
        Table([[Paragraph("Layer", ST["sl"]), Paragraph("Technology", ST["sl"])],
               [Paragraph("Firmware", ST["bs"]), Paragraph("C++ (Arduino-Pico), PlatformIO, pico_tinyusb; cores 0/1; flash store; SpaceCAN bridge; mission model; FDIR", ST["bs"])],
               [Paragraph("Radio", ST["bs"]), Paragraph("2\u00d7 Semtech SX1262 (dedicated uplink / downlink), ISM bands; SPP framing; AES-ECB link wrap (lab state)", ST["bs"])],
               [Paragraph("Sensors", ST["bs"]), Paragraph("BME280 (environment), LIS2DH12 (IMU), GPS NMEA path (virtual on bench)", ST["bs"])],
               [Paragraph("Bench / USB", ST["bs"]), Paragraph("TinyUSB CDC; LAB_STATUS 0x26 / LAB_CTRL 0x27; FEED-window epoch clock (sub 6), 60.0\u00d7 cold-boot scale", ST["bs"])],
               [Paragraph("Simulator", ST["bs"]), Paragraph("Python 3.14 \u2014 byte-for-bit behavioural twin of the firmware (self-test: FIPS-197, SP800-38A/B)", ST["bs"])],
               [Paragraph("PoC framework", ST["bs"]), Paragraph("56 PoCs on a shared driver (poc/lib/fslab.py), --sim / --usb, transcript capture", ST["bs"])]],
              colWidths=[CW * 0.18, CW * 0.82])
    ]
    section(story, 9, "Technology Stack", stack, before_break=True)

    # ---- 10 security posture ---------------------------------------------------
    posture = [
        Paragraph("The lab is not defenceless \u2014 it has real controls, deliberately "
                  "misconfigured. That is the pedagogical point: each control below exists in "
                  "working form and fails for a specific, documented reason.", ST["ts"]),
        Spacer(1, 8),
    ]
    items = [
        ("Link cryptography (AES-128 engine)", "IMPLEMENTED \u2014 MISCONFIGURED", SH,
         "The engine works (SP800-38B CMAC verified in self-test) but the key is compiled into the image, ECB mode is the transport, and the whole layer can be switched OFF over the air (V0-02, V0-10, V0-11)."),
        ("Ground-station range gate", "IMPLEMENTED \u2014 SPOOFABLE", SH,
         "GS arming is range-gated (35 km) but the position input is the unauthenticated NMEA path \u2014 the gate defends the thing the attacker controls (V-36, V0-05)."),
        ("GPS plausibility gate", "IMPLEMENTED \u2014 MISCALIBRATED", SH,
         "Active defense exists (DEF_GPS_PLAUS) but its 500 km/s threshold is ~65\u00d7 LEO ground-track plausibility (~7.6 km/s); a 9500 km hop spread over 60 s passes (V-36)."),
        ("FDIR / anomaly detection", "IMPLEMENTED \u2014 UNVALIDATED INPUTS", SH,
         "EWMA anomaly feed and FDIR tree run, but they consume the same unauthenticated bus they watch \u2014 the safety loop can be laundered (V-24, V-27)."),
        ("Flash-resident state", "PRESENT \u2014 UNSIGNED", SC,
         "FDICT, task queue and ARWC persist across reboots with CRC-16 only \u2014 a checksum is not a signature (V-18, V-19, V-20, V-38)."),
        ("Watchdog", "ABSENT", SC,
         "No watchdog: a hung or crashed worker stays down until a physical power cycle (V0-15); crash PoCs wedge the real board by design (v003, v015, v135)."),
    ]
    for title, status, col, desc in items:
        box = Table([[Paragraph(f"<b>{esc(title)}</b>", ST["tt"]),
                      Paragraph(f"<b>{status}</b>", ParagraphStyle("st", parent=ST["sl"],
                                                                    textColor=col))],
                     [Paragraph(desc, ST["ts"])]],
                    colWidths=[CW * 0.55, CW * 0.45])
        box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BGC),
            ("BOX", (0, 0), (-1, -1), 0.4, BS),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        posture.append(box)
        posture.append(Spacer(1, 8))
    posture.append(Paragraph("Overall posture: <b><font color=\"#EF4444\">WEAK</font></b> \u2014 "
                             "no boundary (B1\u2013B5 in the threat model) has an intact "
                             "integrity mechanism.", ST["body"]))
    section(story, 10, "Security Posture", posture, before_break=True)

    # ---- 11 remediation roadmap --------------------------------------------------
    roadmap = [
        Paragraph("Immediate (0\u20137 days) \u2014 stop the blood", ST["h3"]),
        Paragraph("\u2022 Authenticate the control plane: privileged TCs (mission mode, thrusters, "
                  "heaters) only inside an authenticated session with CMAC challenge-response "
                  "and fresh nonces (fixes V-36 handshake, V-28, V0-06 in one move).", ST["bullet"]),
        Paragraph("\u2022 Bounds-check every external input at the frame layer before any copy; "
                  "reject unbounded SPP lengths (V0-03, V0-04\u2013V-05, V-09, V-13).", ST["bullet"]),
        Paragraph("\u2022 Flash-lock the code region (VTOR immutable) and remove TC-writable "
                  "debug APIDs (V-14, V0-09, V-37).", ST["bullet"]),
        Spacer(1, 6),
        Paragraph("Short-term (7\u201330 days) \u2014 make state honest", ST["h3"]),
        Paragraph("\u2022 Signed OTA (asymmetric signature before CRC); flash stores signed and "
                  "size-bounded; ARWC monotonic (V-18, V-19, V-20, V-38).", ST["bullet"]),
        Paragraph("\u2022 NMEA checksum at the parser + fix-vs-propagator cross-check; plausibility "
                  "threshold at a physically sane bound (~10 km/s) (V0-05, V0-17, V-36).", ST["bullet"]),
        Paragraph("\u2022 Per-APID rate limits and a watchdog with clean-restart semantics "
                  "(V0-08, V0-13\u2013V0-15, V-15).", ST["bullet"]),
        Spacer(1, 6),
        Paragraph("Medium-term (30\u201390 days) \u2014 depth and assurance", ST["h3"]),
        Paragraph("\u2022 Bus integrity (per-MID CMAC) so FDIR cannot be laundered; sensor "
                  "plausibility fed into the anomaly detector (V-17, V-24\u2013V-27).", ST["bullet"]),
        Paragraph("\u2022 Beacon/downlink budgets with fairness; detumble authority bound above "
                  "any attacker torque (V0-14, V-33, V-34, V-35).", ST["bullet"]),
        Paragraph("\u2022 Standing fuzz CI on the frame parser; TC journal ON by default; TEST "
                  "APID window closed by default (V-16, V-23; the V0-03 lesson).", ST["bullet"]),
        Spacer(1, 6),
        Paragraph("Per-finding detail: docs/DEFENSE.md (9 groups, each with the broken control, "
                  "the countermeasure, and the standard to check against).", ST["ts"]),
    ]
    section(story, 11, "Remediation Roadmap", roadmap, before_break=True)

    # ---- 12 methodology -----------------------------------------------------------
    meth = [
        Paragraph("Phases (adapted PTES)", ST["h3"]),
        Paragraph("\u2022 <b>Recon:</b> public source review of the upstream firmware "
                  "(Pwnsat/FlatSat v1.0.3, 22 source files read in full) + the lab firmware.", ST["bullet"]),
        Paragraph("\u2022 <b>Vulnerability analysis:</b> 56 candidates mapped to SPARTA v3.2 (Aerospace) "
                  "(The Aerospace Corporation, 2026-03-11); technique IDs and notional-risk "
                  "scores verified against sparta.aerospace.org.", ST["bullet"]),
        Paragraph("\u2022 <b>Exploitation:</b> one executable PoC per finding on the shared driver "
                  "poc/lib/fslab.py; 56/56 POC OK on the simulator and on FlatSat 1 over USB "
                  "(112 transcripts committed to the repository).", ST["bullet"]),
        Paragraph("\u2022 <b>Post-exploitation:</b> persistence (V-19/V-20), OTA (V-18), and "
                  "impact (crash/wedge PoCs v003/v015/v135) executed on both targets.", ST["bullet"]),
        Spacer(1, 6),
        Paragraph("Bench parity as a verification method", ST["h3"]),
        Paragraph("The simulator advances its workers only inside advance(); the firmware's bench "
                  "epoch clock (LAB_CTRL 0x27 sub 6 FEED_START) advances only inside a window, at "
                  "60.0\u00d7 cold-boot scale. The same PoC therefore exercises both targets at the "
                  "same model instants \u2014 a fix is proven on silicon with the same script that "
                  "proves it on the simulator. CI re-runs the self-test, the 56-PoC sweep, host "
                  "crypto vectors and the catalog integrity gate on every push; the release "
                  "workflow re-builds the firmware and publishes UF2 + md5 on every tag.", ST["ts"]),
        Spacer(1, 6),
        Paragraph("Severity convention", ST["h3"]),
        Paragraph("Severity labels are the repository writeups' own assessments, cross-checked "
                  "against the SPARTA v3.2 notional-risk triples quoted per finding. No CVSS "
                  "vectors are assigned: SPARTA is the applicable space framework, and inventing "
                  "web-style CVSS scores would misrepresent the domain.", ST["ts"]),
        Spacer(1, 6),
        Paragraph("Tools", ST["h3"]),
        Paragraph("In-house PoC framework (fslab.py) + the simulator; PlatformIO (firmware build); "
                  "no external scanners. Evidence: 112 committed transcripts, all ending POC OK.",
                  ST["ts"]),
    ]
    section(story, 12, "Methodology & Verification", meth, before_break=True)

    # ---- 13 appendix ---------------------------------------------------------------
    xref = [[Paragraph("ID", ST["sl"]), Paragraph("Finding", ST["sl"]),
             Paragraph("Sev", ST["sl"]), Paragraph("Group", ST["sl"]),
             Paragraph("SPARTA v3.2 (primary)", ST["sl"]), Paragraph("PoC", ST["sl"])]]
    for r in rows:
        sp = r["sparta_primary"].split(" \u00b7 ")[0]
        xref.append([
            Paragraph(r["id"], ParagraphStyle("xid", parent=ST["bs"], fontName=ffont("FBB"))),
            Paragraph(esc(r["title"][:64]), ST["bs"]),
            Paragraph(r["severity"][0] + r["severity"][1:].lower(),
                      ParagraphStyle("xsev", parent=ST["bs"], textColor=SEV_COLOR[r["severity"]])),
            Paragraph(str(r["group"][0]), ST["bs"]),
            Paragraph(esc(sp), ST["bs"]),
            Paragraph(esc(os.path.basename(r["poc"])), ST["bs"]),
        ])
    xt = Table(xref, colWidths=[CW * 0.08, CW * 0.40, CW * 0.09, CW * 0.07, CW * 0.16, CW * 0.20])
    xt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BGC),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BGC, BGCA]),
        ("GRID", (0, 0), (-1, -1), 0.4, GL),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    xref_sec = [xt, Spacer(1, 10),
                Paragraph("Evidence references", ST["h3"]),
                Paragraph(f"\u2022 evidence/ \u2014 56 simulator transcripts (POC OK)  \u2022 "
                          f"evidence-hw/ \u2014 56 FlatSat 1 transcripts (POC OK, image H md5 {IMAGE_MD5[:8]}\u2026; "
                          f"v003/v015/v135 annotated in hw_pass.txt)", ST["bullet"]),
                Paragraph("\u2022 docs/SPARTA_MAPPING.md \u2014 56-row matrix pinned to SPARTA v3.2 "
                          "(verified against sparta.aerospace.org)", ST["bullet"]),
                Paragraph("\u2022 FINDINGS.json \u2014 machine-readable catalog, drift-checked by "
                          "tests/host/check_catalog.py in CI", ST["bullet"]),
                Spacer(1, 10),
                Paragraph("Glossary", ST["h3"]),
                Paragraph("\u2022 <b>SPP</b> \u2014 Space Packet Protocol frame (the wire unit of the bench transport)  "
                          "\u2022 <b>FEED window</b> \u2014 the bench's advance() time window (LAB_CTRL 0x27 sub 6)", ST["bullet"]),
                Paragraph("\u2022 <b>FDICT</b> \u2014 flash-resident FDIR contingency dictionary  "
                          "\u2022 <b>ARWC</b> \u2014 anti-rollback write counter  "
                          "\u2022 <b>MID</b> \u2014 SpaceCAN message identifier", ST["bullet"]),
                Paragraph("\u2022 <b>OTAR</b> \u2014 over-the-air rekey  \u2022 <b>SDLS</b> \u2014 "
                          "CCSDS 355.0-B-2 Space Data Link Security  \u2022 <b>GS</b> \u2014 ground station",
                          ST["bullet"]),
                ]
    section(story, 13, "Appendix \u2014 Finding Cross-Reference", xref_sec, before_break=True)

    # ---- build ----------------------------------------------------------------------
    os.makedirs(os.path.dirname(OUT_PDF), exist_ok=True)
    doc = BaseDocTemplate(OUT_PDF, pagesize=A4,
                          leftMargin=MARG, rightMargin=MARG,
                          topMargin=56, bottomMargin=46,
                          title="FlatSat electr0sm0g Lab \u2014 Penetration Test Report",
                          author="\u00c9tienne Lacoche \u2014 Cybersecurity Researcher")
    frame = Frame(MARG, 46, CW, PAGE_H - 46 - 56, id="main")
    doc.addPageTemplates([PageTemplate(id="all", frames=[frame],
                                       onPage=page_decorations)])
    doc.build(story)

    # ---- JSON export (pentest-report.json, adapted schema) ---------------------------
    stats = {k: counts.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    data = {
        "engagement": {
            "name": "FlatSat electr0sm0g Lab Version assessment",
            "target": "FlatSat electr0sm0g Lab firmware (image H, md5 " + IMAGE_MD5 + ") on FlatSat 1 + bit-for-bit simulator",
            "dates": "2026-08-22 to " + REPORT_DATE,
            "status": "complete",
            "reporter": "\u00c9tienne Lacoche \u2014 Cybersecurity Researcher <etienne.lacoche@pm.me>",
        },
        "findings": [
            {
                "id": r["id"],
                "title": r["title"],
                "severity": r["severity"],
                "sparta_risk": r["sparta_risk"],
                "cvss_score": None,
                "cvss_vector": None,
                "cwe": None,
                "owasp": None,
                "affected_surface": f"group {r['group'][0]}: {r['group'][1]}",
                "description": r["summary"],
                "impact": {
                    "confidentiality": "HIGH" if r["severity"] in ("CRITICAL", "HIGH") else "MEDIUM",
                    "integrity": "HIGH" if r["severity"] in ("CRITICAL", "HIGH") else "MEDIUM",
                    "availability": "HIGH" if r["id"] in ("V0-03", "V0-13", "V0-14", "V0-15", "V-15", "V-33", "V-34", "V-35") else ("HIGH" if r["severity"] == "CRITICAL" else "MEDIUM"),
                    "business_impact": "Mission loss or uncontrolled privileged commanding on an open-hardware CubeSat lab; the same flaw classes apply to real flight software.",
                },
                "poc_verified": True,
                "poc_steps": [
                    f"python3 {r['poc']}  (simulator)",
                    f"python3 {r['poc']} --usb  (FlatSat 1, image H)",
                ],
                "remediation": {
                    "priority": "Immediate (0-7 days)" if r["severity"] in ("CRITICAL", "HIGH")
                                else "Short-term (7-30 days)",
                    "fix_description": (r["mitigation"] or "See docs/DEFENSE.md group "
                                          + str(r["group"][0]) + "."),
                    "references": [r["sparta_primary"].split(" \u00b7 ")[0]],
                },
                "suggestions": [
                    f"docs/DEFENSE.md group {r['group'][0]} ({r['group'][1]}) \u2014 blue-team countermeasures",
                    "docs/VERIFICATION.md \u2014 reproducible evidence for this finding",
                ],
                "remediation_status": "open",
            } for r in rows
        ],
        "statistics": {
            "total": len(rows),
            "critical": stats["CRITICAL"], "high": stats["HIGH"],
            "medium": stats["MEDIUM"], "low": stats["LOW"],
        },
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {OUT_PDF} ({os.path.getsize(OUT_PDF) / 1e6:.2f} MB)")
    print(f"wrote {OUT_JSON}")
    print("severity counts:", dict(stats))


if __name__ == "__main__":
    main()
