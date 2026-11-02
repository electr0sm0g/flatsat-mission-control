// SPDX-License-Identifier: GPL-2.0-or-later
//
// app.js -- FLATSAT ELECTR0SM0G LAB: in-browser mission control + dashboard.
//
// The Web Worker (worker.js) hosts Pyodide and runs the UNMODIFIED
// simulator + PoC code; it forwards ordered events (wire frames, state
// snapshots, transcript lines, verdicts, free-flight orbit_state). This file
// renders them at a controllable playback pace and proves provenance: every
// verdict compares the fresh transcript digest against the committed
// evidence digest baked into the DEMO blob at build time
// (tools/build_web_demo.py).
//
// Five views:
//   OVERVIEW — the A-to-Z explanation of what this project is (FlatSat
//              lineage, real vs simulated, KPIs, hero findings, SPARTA families, APID attack surface, V-36 killchain;
//   OPS      — live mission control (state tiles, SPP frame stream,
//              PoC console, verdict/parity bar);
//   INDEX    — the 56 writeups, step by step, with a live-proof pane;
//   REPORT   — the engagement report (verbatim pentest-report.json + PDF);
//   REPO     — byte-identical browser over the repository itself.
(() => {
"use strict";

const D = window.DEMO;
const $ = (id) => document.getElementById(id);

/* ------------------------------------------------------------- state */
const S = {
  worker: null,
  booted: false,
  engineReady: false,
  runLines: [],
  buf: [],
  frames: [],
  frameCount: 0,
  elided: 0,
  hold: { stream: false, cons: false, idx: false },
  lastFrameAt: 0,
  lastTms: 0,
  speed: 4,
  paused: false,
  running: false,
  condensed: false,
  curPoc: null,
  selected: -1,
  verdictInfo: null,
  sweep: { active: false, t0: 0, i: 0, n: 0 },
  tilePrev: {},
  view: "overview",
  idxOpen: false,
  idxFile: null,
  orbTimer: null,
  orbq: [],
  kc: { active: false, final: false,
        lit: [false, false, false, false, false],
        evi: [null, null, null, null, null] },
};
const IDX = { group: null, apid: null, q: "" };
try { const g0 = localStorage.getItem("fmc-idxg"); if (g0) IDX.group = g0; } catch (_) {}

/* ------------------------------------------------------------- helpers */
function pad(n, w) { return String(n).padStart(w, "0"); }
function fmtT(ms) {
  const s = Math.max(0, ms - 5000) / 1000;
  const m = Math.floor(s / 60);
  return `T+ ${pad(m, 2)}:${pad(Math.floor(s % 60), 2)}.${pad(Math.floor((s % 1) * 1000), 3)}`;
}
function hex16(hex, label) {
  // 16-byte hex rows with offsets
  let out = "";
  const b = hex.length / 2;
  for (let i = 0; i < b; i += 16) {
    const chunk = hex.slice(i * 2, (i + 16) * 2).match(/.{2}/g) || [];
    out += `<span class="off">${pad(i, 4)}</span>  ${chunk.join(" ")}\n`;
  }
  return out || "<span class='off'>(empty)</span>";
}
function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function modeName(m, armed) {
  const n = { 0: "SAFE", 1: "NOMINAL", 2: "PAYLOAD", 3: "PAYLOAD", 4: "IDLE" }[m] || "0x" + m.toString(16);
  return armed ? n + "·ARMED" : n;
}
function padName(p) { return ["OFF", "LEAK", "COVERT"][p] || ("0x" + p); }
function short(md5) { return md5 ? md5.slice(0, 8) + "…" + md5.slice(-4) : "—"; }
function sevWord(sev) { return (sev || "").split(/\s+/)[0] || ""; }
function sevClass(sev) {
  const w = (sev || "").toLowerCase();
  if (w.startsWith("crit")) return "crit";
  if (w.startsWith("high")) return "high";
  if (w.startsWith("med") || w.startsWith("mod")) return "med";
  if (w.startsWith("low")) return "low";
  if (w.startsWith("info")) return "low";
  return "";
}
function sevRail(sev) {
  const c = sevClass(sev);
  return c ? " sev-rail-" + c : "";
}

// family accent colors (one per SPARTA family, used on chips + cards)
const FAM_C = {
  REC: "#45e3ff", EX: "#ffb347", LM: "#b48cff", IA: "#ff8a5c",
  DE: "#ffd23f", PER: "#3affa0", EXF: "#ff4d8f",
};

/* ------------------------------------------------------ engine state */
/* Real milestones from the worker, eased between them: the bar never fakes a
   milestone, it only smooths the time between two known ones. On CDN failure
   the console degrades to read-only mode — every static view stays usable. */
const ENG = { cap: 6, pct: 0, state: "loading" };
const ENG_STEP_CAP = { 1: 45, 2: 82, 3: 93 };
function engPaint(offline) {
  const p = $("engine");
  if (!p) return;
  if (offline) { p.textContent = "READ-ONLY · CDN DOWN"; p.className = "pill eng warn"; p.title = "the pinned Pyodide CDN is unreachable — browse everything, RUN is disabled; python3 poc/<file> runs the same PoC locally"; return; }
  if (ENG.state === "ready") return;
  p.textContent = `ENGINE ${Math.round(ENG.pct)} %`;
}
function engTick() {
  if (ENG.state !== "loading") return;
  ENG.pct += (ENG.cap - ENG.pct) * 0.14;
  engPaint();
  const bar = $("boot-bar");
  if (bar) bar.firstElementChild.style.width = ENG.pct.toFixed(1) + "%";
}
setInterval(engTick, 220);
function onBootStep(ev) {
  ENG.cap = ENG_STEP_CAP[ev.step] || ENG.cap;
  bootLine("engine: " + (ev.label || "loading…"));
}
function onCdnDown() {
  ENG.state = "offline";
  const p = $("engine");
  engPaint(true);
  bootLine("PYODIDE CDN unreachable — read-only mode (everything except live runs remains available)", "bad");
  bootHide();
  $("selftest").textContent = "read-only · CDN down";
  $("selftest").className = "pill warn";
  engineReadOnly();
  for (const id of ["btn-run", "btn-sweep", "idx-run"]) {
    const b = $(id);
    if (b) { b.disabled = true; b.title = "disabled — python engine unavailable (CDN down)"; }
  }
}
function engineOffline() { return ENG.state === "offline"; }
function engineReadOnly() {
  const v = $("verdict");
  if (!v) return;
  v.className = "warn";
  v.innerHTML = `<span class="vtag">READ-ONLY</span><span class="vmsg">the pinned Pyodide CDN
    (all three mirrors — jsdelivr, unpkg, fastly — could not be reached: an ad blocker or DNS filter is a common cause.
    Every finding, writeup, doc, transcript and the report remain fully browsable; live runs
    are disabled. Locally: <code>python3 poc/&lt;file&gt;.py</code> produces the same transcript
    this page hashes against.
    <button id="cdn-retry">RETRY ENGINE</button></span>`;
}
function engineStuck() {
  const v = $("verdict");
  if (!v) return;
  v.className = "warn";
  v.innerHTML = `<span class="vtag">SLOW</span><span class="vmsg">the CPython/WASM download is
    taking a long time (≈13 MB from the Pyodide CDN) — a blocklist silently dropping it is a
    common cause. Runs are queued and will start automatically the moment it lands.
    <button id="cdn-retry">RETRY ENGINE</button></span>`;
}

/* ------------------------------------------------------ boot overlay */
// honest loader: every line is driven by a real runtime event, never a fake
// progress bar. Hidden once the free-flight telemetry has real points.
const BOOT = { el: null, log: null, hidden: false, failsafe: 0 };
function bootLine(msg, cls) {
  if (!BOOT.el || BOOT.hidden) return;
  const d = document.createElement("div");
  if (cls) d.className = cls;
  d.textContent = msg;
  BOOT.log.appendChild(d);
  BOOT.log.scrollTop = BOOT.log.scrollHeight;
}
function bootHide() {
  if (BOOT.hidden || !BOOT.el) return;
  BOOT.hidden = true;
  BOOT.el.classList.add("off");
  setTimeout(() => { if (BOOT.el) BOOT.el.style.display = "none"; }, 600);
}
function bootInit() {
  BOOT.el = $("boot");
  BOOT.log = $("boot-log");
  BOOT.failsafe = setTimeout(bootHide, 90_000);
  setTimeout(() => bootHide(), 1800);   // the engine keeps loading in the topbar pill
  bootLine(`runtime: Pyodide ${D.pyodide} · CPython/WASM (CDN pinned)`);
  bootLine("sources: flatsat_sim.py + fslab.py + 56 PoCs — verbatim, md5-pinned");
}
function bootAcquired() {
  bootLine("free-flight acquired — real FlatSatSim telemetry streaming (orbit telemetry live)", "ok");
  bootHide();
}

/* ------------------------------------------------------- KPI count-up */
function countUp(el, target, dur) {
  const m = /^(\d+)(?:\s*\/\s*(\d+))?$/.exec(target);
  if (!m || !el.animate) { el.textContent = target; return; }
  const a = +m[1], b = m[2] != null ? +m[2] : null;
  const t0 = performance.now();
  const step = (now) => {
    const f = Math.min(1, (now - t0) / dur);
    const e = 1 - Math.pow(1 - f, 3);
    el.textContent = b == null ? String(Math.round(a * e))
                               : `${Math.round(a * e)}/${b}`;
    if (f < 1) requestAnimationFrame(step);
    else el.textContent = target;
  };
  requestAnimationFrame(step);
}
function kpiCountUp() {
  countUp($("kpi-v1"), "56", 900);
  countUp($("kpi-v2"), "112/112", 1300);
  countUp($("kpi-v3"), "7", 700);
  countUp($("kpi-v4"), String(D.kpis.apids), 1100);
}

/* --------------------------------------------------- reveal on scroll */
let rvObs = null;
function revealAll(root) {
  if (!rvObs) {
    rvObs = new IntersectionObserver((ents) => {
      for (const e of ents) {
        if (e.isIntersecting) { e.target.classList.add("in"); rvObs.unobserve(e.target); }
      }
    }, { rootMargin: "0px 0px -5% 0px" });
  }
  root.querySelectorAll(".rv:not(.in)").forEach((el) => rvObs.observe(el));
}

/* ---------------------------------------------------- hash routing */
// #/overview · #/ops · #/index · #/index/<poc-file> — shareable deep links
function setHash(h) {
  if (location.hash !== h) location.hash = h;
}
function viewHash() {
  if (S.view === "index" && S.idxOpen && S.idxFile)
    return "#/index/" + S.idxFile;
  if (S.view === "repo" && REPO && REPO.cur) return "#/repo/" + REPO.cur.path;
  return "#/" + S.view;
}
function applyRoute() {
  const m = /^#\/(overview|ops|index|report|repo)(?:\/([\w.\-\/]+(?:\.py)?))?$/.exec(location.hash || "");
  if (!m) return false;
  const v = m[1], f = m[2];
  if (v === "index" && f) {
    if (pocMeta(f) && S.idxFile !== f) openIdxDetail(f);
    else setView("index");
  } else if (v === "index") {
    if (S.idxOpen) closeIdxDetail();
    else setView("index");
  } else if (v === "repo") {
    setView("repo");
    if (f) REPO_OPEN(f);
  } else {
    setView(v);
  }
  return true;
}


/* ------------------------------------------------------------- worker */
// Worker creation is wrapped so a blocked/hung CDN can be retried: the
// terminate + recreate cycle re-runs the worker script (and its
// importScripts of the Pyodide CDN) from scratch.
function onWorkerErr(e) {
  fatal(
    "worker error: " + (e.message || "unknown") +
    (e.lineno ? " @ " + (e.filename || "") + ":" + e.lineno : "")
  );
}
function onWorkerMsg(e) {
  const ev = e.data;
  if (ev.t === "fatal") { fatal(ev.e); return; }
  // free-flight orbit snapshots run in their own paced lane: a 3-orbit batch
  // streams 570 states, and at 30 ms each they would otherwise starve the
  // line/frame queue for ~17 s (RUN LIVE appearing to "do nothing").
  if (ev.t === "orbit_state" || ev.t === "orbit_done") {
    S.orbq.push(ev);
    if (S.orbq.length > 2400) S.orbq.splice(0, S.orbq.length - 2400);
    return;
  }
  S.buf.push(ev);
  if (S.buf.length > 30000) S.buf.splice(0, S.buf.length - 30000);
}

/* Single point where run state is toggled — also drives the thin
   progress bar at the top of the screen (body.is-running). */
function setRunning(v) {
  S.running = v;
  document.body.classList.toggle("is-running", !!v || S.sweep.active);
}
function bootWorker() {
  if (S.worker) { try { S.worker.terminate(); } catch (_) {} }
  S.worker = new Worker("worker.js");
  S.worker.onerror = onWorkerErr;
  S.worker.onmessage = onWorkerMsg;
  S.worker.postMessage({ cmd: "init", files: D.files });
  // watchdog: a blocklist that drops the CDN request leaves importScripts
  // hanging forever (no error, no cdndown) — surface a retry after 25 s
  clearTimeout(S.bootTimer);
  S.bootTimer = setTimeout(() => {
    if (!S.engineReady && ENG.state !== "offline") engineStuck();
  }, 25000);
}
bootWorker();
function retryEngine() {
  if (S.running || S.sweep.active) return;
  ENG.state = "booting";
  const ep = $("engine");
  if (ep) { ep.style.display = ""; engPaint(false); }
  const st = $("selftest");
  if (st) { st.textContent = "retrying engine load…"; st.className = "pill"; }
  for (const id of ["btn-run", "btn-sweep", "idx-run"]) {
    const b = $(id);
    if (b) { b.disabled = false; b.title = ""; }
  }
  engineStuck();
  bootWorker();
}
function runSelftest() { S.worker.postMessage({ cmd: "selftest" }); }

/* --------------------------------------------------------------- pacer */
const GAP = { frame: 90, line: 14, state: 0, verdict: 0, poc_start: 0,
              sweep_done: 0, selftest: 0, boot: 0, pymd5: 0,
              orbit_state: 30, orbit_done: 0 };
let nextAt = 0;
/* Time-sliced drain: at MAX a chatty PoC queues hundreds of frame/line
   events between two heartbeats; rendering the whole backlog in one
   synchronous task (hundreds of innerHTML + scrollTop layout flushes) was
   the visible "screen freezes then recovers". Cap each 30 ms tick at ~12 ms
   of render work — the backlog then drains across a few frames while the UI
   stays responsive; at 1x..16x the gap logic never hits the budget. */
setInterval(() => {
  if (S.paused) { flushScroll(); return; }
  const t0 = performance.now();
  const now = t0;
  let n = 0;
  while (S.buf.length && n < 4000) {
    const ev = S.buf[0];
    const gap = S.speed === "max" ? 0 : (GAP[ev.t] !== undefined ? GAP[ev.t] : 0) / S.speed;
    if (now < nextAt - 0.5) break;
    nextAt = now + gap;
    S.buf.shift();
    n += 1;
    handle(ev);
    if (performance.now() - t0 > 12) break;
  }
  flushScroll();
  tickLeds();
}, 30);

/* scrolled-to-bottom requests are deferred to one flush per tick: reading
   scrollHeight per event forces a synchronous layout each time */
const SCROLL = { stream: false, cons: false, idx: false };
function flushScroll() {
  if (SCROLL.stream && !S.hold.stream) { const s = $("stream"); s.scrollTop = s.scrollHeight; }
  if (SCROLL.cons && !S.hold.cons && $("autoscroll").checked) { const c = $("console"); c.scrollTop = c.scrollHeight; }
  if (SCROLL.idx && !S.hold.idx) { const c = $("idx-console"); c.scrollTop = c.scrollHeight; }
  SCROLL.stream = SCROLL.cons = SCROLL.idx = false;
}

/* ---- "reader mode": scrolling a live pane up holds the autoscroll where
   the reader is (nothing is dropped — lines keep appending underneath);
   a sticky pill counts what streamed past and one click resumes live ---- */
const HOLD_PANES = [["cons", "console"], ["stream", "stream"], ["idx", "idx-console"]];
const PILLS = {};
function pillGet(key, scroller) {
  let p = PILLS[key];
  if (!p || !p.isConnected) {
    p = document.createElement("div");
    p.className = "newmsg-host hidden";
    p.innerHTML = `<button type="button" title="jump to the newest line and resume autoscroll">` +
      `\u25bc <b>0</b> new lines \u2014 click to resume</button>`;
    p.querySelector("button").onclick = () => {
      scroller.scrollTop = scroller.scrollHeight;
      pillHide(key);
      if (key === "cons") $("autoscroll").checked = true;
    };
    PILLS[key] = p;
  }
  return p;
}
function pillHide(key) {
  const p = PILLS[key];
  if (p) { p.classList.add("hidden"); p.querySelector("b").textContent = "0"; }
}
function pillHold(key, scroller) {   // one more line streamed past a held reader
  const p = pillGet(key, scroller);
  scroller.appendChild(p);          // keep it pinned to the (growing) end
  const b = p.querySelector("b");
  b.textContent = String((parseInt(b.textContent, 10) || 0) + 1);
  p.classList.remove("hidden");
}
function pillReset(key) { S.hold[key] = false; pillHide(key); }
function bindHoldScrollers() {
  for (const [key, id] of HOLD_PANES) {
    const el = $(id);
    const grab = () => {                 // wheel-up / touch: reader intent, honoured before the next ticker flush
      if (S.hold[key]) return;
      S.hold[key] = true;
      const p = pillGet(key, el);
      el.appendChild(p);
      if (S.running || S.sweep.active) p.classList.remove("hidden");
    };
    el.addEventListener("wheel", (e) => { if (e.deltaY < 0) grab(); }, { passive: true });
    el.addEventListener("touchstart", grab, { passive: true });
    el.addEventListener("scroll", () => {
      const held = el.scrollHeight - el.scrollTop - el.clientHeight > 48;
      if (held === S.hold[key]) return;
      S.hold[key] = held;
      if (held) {
        const p = pillGet(key, el);
        el.appendChild(p);
        if (S.running || S.sweep.active) p.classList.remove("hidden");  // show live-hold at once
      } else pillHide(key);
    }, { passive: true });
  }
}

// dedicated telemetry lane for the free-flight snapshots (same 30 ms
// heartbeat, own queue; orbit_done is consumed after its batch so the
// telemetry lane never starves the line/frame queue)
setInterval(() => {
  if (S.paused) return;
  const t0 = performance.now();
  let n = S.speed === "max" ? 600 : S.speed >= 16 ? 8 : 1;
  while (n-- > 0 && S.orbq.length) {
    handle(S.orbq.shift());
    if (performance.now() - t0 > 8) break;
  }
}, 30);

function handle(ev) {
  switch (ev.t) {
    case "boot": onBoot(ev); break;
    case "selftest": onSelftest(ev); break;
    case "frame": onFrame(ev); break;
    case "state": onState(ev); break;
    case "boot_step": onBootStep(ev); break;
    case "cdndown": onCdnDown(); break;
    case "line": onLine(ev); break;
    case "poc_start": onPocStart(ev); break;
    case "verdict": onVerdict(ev); break;
    case "sweep_done": onSweepDone(ev); break;
    case "orbit_state": onOrbitState(ev); break;
    case "orbit_done": onOrbitDone(ev); break;
    case "emitfail":
      fatal("event delivery failure: " + ev.err + " — " + String(ev.s).slice(0, 80));
      break;
    default: break;
  }
}

function onBoot(ev) {
  S.booted = true;
  S.engineReady = true;
  clearTimeout(S.bootTimer);
  for (const id of ["btn-run", "btn-sweep", "idx-run"]) {
    const b = $(id);
    if (b) { b.disabled = false; b.title = ""; }
  }
  ENG.state = "ready"; ENG.pct = 100;
  const bar = $("boot-bar"); if (bar) bar.firstElementChild.style.width = "100%";
  const ep = $("engine"); if (ep) ep.style.display = "none";
  bootLine(`CPython ${ev.py} ready — sources mounted in MEMFS`, "ok");
  try { S.worker.postMessage({ cmd: "statekick" }); } catch (_) {}
  bootLine("running simulator self-test: FIPS-197 · SP800-38A/B · SDLS · OTAR");
  setLed("led-sim", "on");
  $("selftest").textContent = "running simulator self-test…";
  $("prov-text").textContent =
    `RUNNING UNMODIFIED · flatsat_sim.py md5 ${short(D.md5.sim)} · fslab.py md5 ` +
    `${short(D.md5.fslab)} · 56× poc/*.py (digest per card) · Pyodide ${D.pyodide} · ` +
    `CPython ${ev.py} (WASM) · target: SIMULATOR (bit-for-bit twin — hardware runs: evidence-hw/)`;
  runSelftest();
}

function onSelftest(ev) {
  const el = $("selftest");
  if (ev.out && ev.out.includes("SELFTEST OK")) {
    el.textContent = "SELFTEST OK · FIPS-197 · SP800";
    el.title = String(ev.out); // full self-test report as hover text
    el.className = "pill ok";
    bootLine("simulator self-test passed — crypto + CCSDS stack verified in WASM", "ok");
    kpiCountUp();
    startOrbit();
  } else {
    el.textContent = "SELFTEST FAILED";
    el.title = String(ev.out).slice(0, 200);
    el.className = "pill bad";
    setLed("led-sim", "bad");
    bootLine("simulator self-test FAILED", "bad");
    bootHide();
  }
  // engine is live now: start whatever the user clicked while it was booting
  if (S.pending) {
    const p = S.pending;
    S.pending = null;
    setTimeout(() => { p.kind === "sweep" ? startSweep() : runPoc(p.file, p.stayInIdx); }, 80);
  }
}

/* ------------------------------------------------------- views routing */
function setView(v) {
  S.view = v;
  document.querySelectorAll("#views-nav button").forEach((b) =>
    b.classList.toggle("on", b.dataset.view === v));
  document.querySelectorAll("#views > .view").forEach((s) =>
    s.classList.toggle("on", s.id === "view-" + v));
  setHash(viewHash());
  try { localStorage.setItem("fmc-view", v); } catch (_) {}
  if (v === "report") ensureReport();
  else if (v === "repo") ensureRepo();
}

/* -------------------------------------------------- telemetry pipeline
   Real model values only: free-flight orbit_state snapshots and PoC-run
   state snapshots feed the orbit scope, the telemetry point
   history below (also the CI contract), and nothing else — the overview
   shows the A-to-Z explanation instead of an animation. Nothing is
   interpolated, faked or decorative. */
const ORB = {
  pts: [],          // GPS sub-point track {lat, lon, ovr} — real fixes only
  ser: [],          // telemetry samples {t, pct, pw, tilt, dist, ecl, gate}
  cur: null,        // latest state (orbit_state shape)
  flashT: 0,        // wall-clock ms of the last real range jump (spoof)
  prevTs: 0,
  prevFix: -1,
};

/* schematic basemap constants were used by the ground-track canvas; the
   data pipeline (ORB.pts / ORB.ser) is kept: it feeds the topbar phase and
   the CI telemetry contract. */

function pushOrbSample(cur, tms) {
  if (cur.fix && cur.dist_m >= 0) {
    const prev = ORB.pts[ORB.pts.length - 1];
    if (!prev || Math.abs(cur.lat - prev.lat) + Math.abs(cur.lon - prev.lon) > 1e-7) {
      ORB.pts.push({ lat: cur.lat, lon: cur.lon, ovr: !!cur.ovr });
      if (ORB.pts.length > 400) ORB.pts.shift();
    }
    const now = performance.now();
    if (ORB.prevFix >= 0 && Math.abs(cur.dist_m - ORB.prevFix) > 2000 &&
        now - ORB.prevTs < 3000)
      ORB.flashT = now;
    ORB.prevFix = cur.dist_m;
    ORB.prevTs = now;
  }
  // sim-time axis, kept monotonic across run boundaries (sim resets)
  const s = (typeof tms === "number" && isFinite(tms)) ? tms / 1000 : null;
  const last = ORB.ser.length ? ORB.ser[ORB.ser.length - 1].t : null;
  let t;
  if (s === null) t = (last === null ? 0 : last) + 0.5;
  else if (last === null) t = s;
  else t = (s - last > 0 && s - last <= 5) ? s : last + 0.5;
  ORB.ser.push({
    t,
    pct: typeof cur.pct === "number" ? cur.pct : null,
    pw: typeof cur.power_w === "number" ? cur.power_w : null,
    tilt: typeof cur.tilt === "number" ? cur.tilt : null,
    dist: cur.dist_m >= 0 ? cur.dist_m : null,
    ecl: !!cur.eclipse,
    gate: !!cur.gate,
  });
  if (ORB.ser.length > 360) ORB.ser.shift();
}

function orbFeed(cur, tms) {
  if (tms) S.lastTms = tms;
  ORB.cur = cur;
  pushOrbSample(cur, tms);
  if (!BOOT.hidden) bootAcquired();
}

function onOrbitState(ev) {
  orbFeed(ev, ev.t_ms);
}
function onOrbitDone(ev) {
  if (!S.running && !S.sweep.active) {
    clearTimeout(S.orbTimer);
    S.orbTimer = setTimeout(startOrbit, 1200);
  }
}
function startOrbit() {
  if (!S.worker) return;
  S.worker.postMessage({ cmd: "orbit", orbits: 3 });
}
// live state snapshots from PoC runs feed the same telemetry pipeline
// (orbit scope + CI telemetry contract) during the run
function onOrbFromState(s, tms) {
  orbFeed({
    orbit_s: s.orbit_s, lat: s.gps.lat, lon: s.gps.lon,
    dist_m: s.gs.dist_m, fix: s.gps.fix && s.gs.dist_m >= 0, ovr: s.gps.ovr,
    gs_mode: s.gs.mode, gate: s.gs.gate,
    eclipse: s.mm.eclipse, pct: s.mm.pct, power_w: s.mm.power_w, tilt: s.mm.tilt,
  }, tms);
}
/* The explanatory panel (#ov-why) fills its headline numbers from the
   baked catalog — never re-typed constants. */
function initWhy() {
  const img = $("why-img");
  if (img) img.textContent = D.kpis.image_md5;
  const sev = {};
  const rf = (D.report && D.report.findings) || [];
  for (const f of rf) {
    const k = (f.severity || "").toUpperCase();
    if (k) sev[k] = (sev[k] || 0) + 1;
  }
  const sv = $("why-sev");
  if (sv) sv.innerHTML = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    .filter((s) => sev[s])
    .map((s) => `<span class="sevchip ${sevClass(s)}">${sev[s]} ${s}</span>`)
    .join(" ");
  const sb = $("why-sevbar");
  if (sb) sb.innerHTML = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    .filter((s) => sev[s])
    .map((s) => `<i class="${sevClass(s)}" style="flex:${sev[s]}" title="${s} — ${sev[s]} findings"></i>`)
    .join("");
  const fm = $("why-fams");
  if (fm) fm.textContent = Object.keys(D.group_counts).length;
  const ap = $("why-apids");
  if (ap) ap.textContent = D.kpis.apids;
  const go = (id, fn) => { const b = $(id); if (b) b.onclick = fn; };
  // THE FIVE VIEWS cards navigate for real
  document.querySelectorAll(".why-views .vcard[data-goto]").forEach((c) => {
    c.onclick = () => setView(c.dataset.goto);
  });
  go("why-v36", () => { setView("index"); openIdxDetail("v136_gps_spoof_chain.py"); });
  go("why-sweep", () => startSweep());
  go("why-threat", () => openRepoPath("docs/THREAT-MODEL.md"));
  go("why-report", () => setView("report"));
}


/* ------------------------------------------------- exhaustive frame decoder
   Every wire frame is described completely: the SPP primary header decoded
   bit by bit from the raw bytes, the link-security state as it really is on
   the bench, and the payload expanded field by field with the exact struct
   layouts of the committed simulator (flatsat_sim.py). For APIDs without a
   per-field firmware layout every byte is shown with its offset and ASCII —
   nothing is dropped. */
function pHex(h) {
  const a = new Uint8Array(Math.floor(h.length / 2));
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}
class BV {
  constructor(b) { this.b = b; }
  get n() { return this.b.length; }
  u8(i) { return i < this.n ? this.b[i] : NaN; }
  u16le(i) { return i + 1 < this.n ? this.b[i] | (this.b[i + 1] << 8) : NaN; }
  u16be(i) { return i + 1 < this.n ? (this.b[i] << 8) | this.b[i + 1] : NaN; }
  u32be(i) {
    if (i + 3 >= this.n) return NaN;
    return ((this.b[i] << 24) | (this.b[i + 1] << 16) |
            (this.b[i + 2] << 8) | this.b[i + 3]) >>> 0;
  }
  i16le(i) { const v = this.u16le(i); return v >= 0x8000 ? v - 0x10000 : v; }
  u32le(i) {
    if (i + 3 >= this.n) return NaN;
    return (this.b[i] | (this.b[i + 1] << 8) | (this.b[i + 2] << 16) |
            (this.b[i + 3] << 24)) >>> 0;
  }
  i32le(i) { const v = this.u32le(i); return v >= 0x80000000 ? v - 0x100000000 : v; }
  f32le(i) {
    if (i + 3 >= this.n) return NaN;
    return new DataView(this.b.buffer, this.b.byteOffset + i, 4).getFloat32(0, true);
  }
  hex(off, len) {
    return Array.from(this.b.subarray(off, Math.min(this.n, off + len)))
      .map((x) => pad(x, 2)).join(" ");
  }
  ascii(off, len) {
    let s = "";
    const e = Math.min(this.n, off + len);
    for (let i = off; i < e; i++) {
      const c = this.b[i];
      if (c === 0) break;
      s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : "·";
    }
    return s;
  }
}
const F = (k, v, cls, tip) =>
  `<span class="fdk"${tip ? ` title="${esc(tip)}"` : ""}>${k}</span>` +
  `<span class="fdv${cls ? " " + cls : ""}"${tip ? ` title="${esc(tip)}"` : ""}>${v}</span>`;
const fr = (...cells) => `<div class="fdrow">${cells.join("")}</div>`;
function num(x, fmt) { return Number.isFinite(x) ? fmt(x) : "?"; }
/* altitude in firmware units is centimetres — render it the way a human reads it */
function fmtAlt(cm) {
  return num(cm, (v) => {
    const m = v / 100;
    return Math.abs(m) >= 1000
      ? (m / 1000).toLocaleString("en-US", { maximumFractionDigits: 1 }) + " km"
      : m.toLocaleString("en-US", { maximumFractionDigits: 2 }) + " m";
  });
}
function hxv(x, w = 2) { return num(x, (v) => "0x" + v.toString(16).toUpperCase().padStart(w, "0")); }
function dec(x) { return num(x, (v) => v.toLocaleString("en-US")); }
function geo(x, scale, unit = "°") {
  return num(x, (v) => (v / scale).toFixed(7) + unit);
}
const MODE_N = { 0: "SAFE", 1: "NOMINAL", 2: "PAYLOAD·A", 3: "PAYLOAD·B", 4: "IDLE" };
const modeN = (v) => num(v, (x) => MODE_N[x] !== undefined ? `${MODE_N[x]} (${x})` : `0x${x}`);
const bs = (v, defs) => Number.isFinite(v)
  ? (defs.filter((d) => v & d[0]).map((d) => d[1]).join("·") || "0 — none")
  : "?";
const GS_BS = [[1, "GS-MODE"], [2, "GPS-USABLE"], [4, "IN-RANGE"], [8, "SESSION"], [0x10, "PENDING"], [0x20, "GATE-OPEN"]];
const GPS_BS = [[1, "UART"], [2, "CONN"], [4, "NMEA"], [8, "FIX"], [0x10, "READY"]];
const FLAG_BS = [[1, "BME280"], [2, "ACCEL"], [4, "GPS-UART"], [8, "GPS-FIX"], [0x10, "SECURE-LINK"], [0x20, "PAYLOAD-ARMED"], [0x40, "USB-DEBUG"]];
const FLAG2_BS = [[1, "ANOMALY"], [2, "FDIR-SAFE"], [4, "OTA-SLOT-B"], [8, "SDLS"], [0x10, "BROWNOUT"], [0x20, "PERSIST-COOKIE"]];
const DEFS_BS = [[1, "RADIO-CRC"], [2, "CLOAK"], [4, "FREQ-LOCK"], [8, "I2C-WHOAMI"], [0x10, "GPS-PLAUS"], [0x20, "TM-CTR"], [0x40, "TC-LOG"], [0x80, "ANOMALY-ENGINE"]];
const LAB_ST = [[1, "SECURE"], [2, "USB-DEBUG"], [4, "GS-MODE"], [8, "SESSION"], [0x10, "ARMED"]];
const LAB_F2 = [[1, "SDLS"], [2, "ARC-RELAXED"], [4, "DETUMBLE"], [8, "ECLIPSE"], [0x10, "BROWNOUT"]];
const SYMS = {
  0x10012340: "labFnDetumble", 0x10012440: "labFnLedRainbow",
  0x10012540: "labFnGsModeOff", 0x10012640: "labFnBeaconFlood",
  0x10012740: "labFnSecureLinkOff", 0x10012000: "labFnNoop",
  0x20002100: "gs_challenge", 0x20002200: "SA0_KEY / SA_TABLE",
  0x20002300: "arc_last", 0x20003000: "master_keys",
  0x20002000: "log_name", 0x20002800: "leak_pool",
  0xE000ED08: "SCB->VTOR", 0x4005802C: "WDT_SCRATCH", 0x40014000: "GPIO_BASE",
};
const symOf = (a) => SYMS[a >>> 0] ? ` — ${SYMS[a >>> 0]}` : "";
const yn = (v) => num(v, (x) => x ? "yes" : "no");
const okNo = (v) => num(v, (x) => x ? "OK" : "FAIL");

function frameWire(ev) {
  const wire = pHex(ev.wire || "");
  return { wire, off: ev.dir === "tm" && wire[0] === 0xAA ? 1 : 0 };
}
function framePayload(ev) {
  const { wire, off } = frameWire(ev);
  const total = (ev.len || 0) + 1;
  return wire.subarray(off + 6, off + 6 + total);
}
function hexGrid(b, label) {
  let out = "";
  for (let i = 0; i < b.length; i += 16) {
    const part = Array.from(b.subarray(i, i + 16));
    const hx = part.map((x) => pad(x, 2)).join(" ");
    const as = part.map((c) => (c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : "·")).join("");
    out += `<div class="fdhexl"><span class="fdoff">${pad(i, 4)}</span> ${hx.padEnd(47, " ")} <span class="fdasc">|${esc(as)}|</span></div>`;
  }
  return out ? `<div class="fdhexblk">${label ? `<div class="fdhexh">${label}</div>` : ""}${out}</div>` : "";
}

/* --- telecommand payload semantics (layouts from flatsat_sim._dispatch/_ext) */
const TC_D = {
  0x01: (b, ev) => [fr(F("cmd", "PING"),
    ev.sechdr ? F("secured-pilot", "replay counter " + b.hex(0, 4)) : F("mode", "baseline"))],
  0x02: () => [fr(F("cmd", "RESETC — command reboot", "warn"))],
  0x03: (b) => [fr(F("cmd", "SEND_FW — inventory/version request"), b.n ? F("payload", b.hex(0, b.n)) : F("payload", "(empty)"))],
  0x04: (b) => [fr(F("cmd", "SET_THRUSTER"), F("thruster", dec(b.u8(0))), F("power", `${dec(b.u8(1))}/255`))],
  0x05: (b) => [fr(F("cmd", "SET_BEACON_RATE"), F("period", `${dec(b.u8(0))} s`))],
  0x06: (b) => {
    const rows = [];
    if (b.n >= 2) rows.push(fr(F("cmd", "BROADCAST_MSG"), F("freq", `${dec(b.u16be(0))} MHz`),
      F("message", esc(b.ascii(2, b.n - 2)) || "(empty)")));
    else rows.push(fr(F("cmd", "BROADCAST_MSG"), F("payload", `${dec(b.n)} byte — msg_len = len−2 goes negative: firmware underflow path (V0-03)`, "warn")));
    return rows;
  },
  0x07: () => [fr(F("cmd", "FLASH_DUMP — 16 pages, crc8-verified", "warn"))],
  0x0B: (b) => [fr(F("cmd", "FLASH_READ"), F("magic", hxv(b.u8(0))),
    F("offset", dec(b.u16le(1))), F("len", dec(b.u8(3))),
    F("key", hxv(b.u16be(4), 4), b.u16be(4) === 0xC35A ? "ok" : "bad"))],
  0x0C: () => [fr(F("cmd", "GET_STATUS — no auth required by design", "warn"))],
  0x0D: (b) => [fr(F("cmd", "SET_MISSION_MODE"), F("mode", modeN(b.u8(0))))],
  0x0E: () => [fr(F("cmd", "GET_NAV"))],
  0x0F: () => [fr(F("cmd", "PWN_STATUS"))],
  0x10: (b) => [fr(F("cmd", "USB_DEBUG"), F("state", b.u8(0) ? "ON — telemetry forced cleartext" : "OFF", "warn"))],
  0x11: (b) => [fr(F("cmd", "GS_MODE"), F("request", b.u8(0) ? "ENABLE (arming needs range-gate)" : "DISABLE"))],
  0x12: (b) => {
    const p = b.u8(0);
    const rows = [fr(F("cmd", "GS_ACCESS"), F("phase", dec(p)))];
    if (p === 2) rows.push(fr(F("challenge-resp", b.hex(1, 4) + ` = 0x${(b.u32be(1) >>> 0).toString(16)}`, "warn"),
      F("rule", "resp = challenge ⊕ GS_XOR_KEY (static key)")));
    return rows;
  },
  0x13: () => [fr(F("cmd", "GS_STATUS — plain range/status query"))],
  0x14: (b) => [fr(F("cmd", "GPS_OVERRIDE — unvalidated NMEA analogue", "warn")),
    fr(F("lat", geo(b.i32le(0), 1e7)), F("lon", geo(b.i32le(4), 1e7)),
       F("alt", fmtAlt(b.i32le(8))), F("sats", dec(b.u8(12))))],
  0x15: (b) => [fr(F("cmd", "SDLS_CONFIG"), F("enable", yn(b.u8(0))),
    F("arc-bits", dec(b.u8(1))), F("window", dec(b.u8(2))))],
  0x16: (b) => {
    const sub = ["OTAR", "SA-SET", "SA-GET", "ARC-RESET"][b.u8(0)] || "sub " + b.u8(0);
    const rows = [fr(F("cmd", "SDLS_OTA"), F("sub", esc(sub)))];
    if (b.u8(0) === 0 && b.n >= 19) rows.push(fr(F("master-key", dec(b.u8(1))), F("sa", dec(b.u8(2))), F("key-cipher", b.hex(3, 16))));
    if (b.u8(0) === 1 && b.n >= 20) rows.push(fr(F("sa", dec(b.u8(1))), F("est/ast", `${dec(b.u8(2))}/${dec(b.u8(3))}`), F("key", b.hex(4, 16), "warn")));
    return rows;
  },
  0x17: (b) => [fr(F("cmd", "KEY_VERIFY — CTR encryption oracle (V-11)", "warn")),
    fr(F("kid", dec(b.u8(0))), F("counter", b.hex(1, 4)), F("block", b.hex(5, 16)))],
  0x18: (b) => [fr(F("cmd", "MEMCPY"), F("src", hxv(b.u32le(0), 8) + symOf(b.u32le(0))),
    F("dst", hxv(b.u32le(4), 8) + symOf(b.u32le(4))), F("len", dec(b.u16le(8))))],
  0x19: (b) => [fr(F("cmd", "MEM_READ"), F("addr", hxv(b.u32le(0), 8) + symOf(b.u32le(0)), "warn"),
    F("len", dec(b.u16le(4))))],
  0x1A: (b) => [fr(F("cmd", "SET_LOG_NAME"), F("name", esc(b.ascii(0, b.n)), "warn"))],
  0x1B: (b) => [fr(F("cmd", "SB_PUBLISH"), F("msg-id", hxv(b.u16be(0), 4)), F("body", b.hex(2, Math.min(32, b.n - 2))))],
  0x20: (b) => [fr(F("cmd", "TC_STATS"), F("op", b.u8(0) === 1 ? "RESET" : "READ"))],
  0x21: (b) => [fr(F("cmd", "PADDING_CONFIG"), F("pad-mode", ["OFF", "LEAK", "COVERT"][b.u8(0)] ?? hxv(b.u8(0))))],
  0x22: (b) => [fr(F("cmd", "COVERT_ENQ"), F("blob", `${dec(b.n)} B — ${b.hex(0, Math.min(32, b.n))}`))],
  0x24: (b) => [fr(F("cmd", "HEATER"), F("heater", dec(b.u8(0))), F("on", yn(b.u8(1))))],
  0x25: (b) => {
    const s = b.u8(0);
    const rows = [fr(F("cmd", "DEFENSES_CONFIG"), F("sub", dec(s)))];
    if (s === 0) rows.push(fr(F("def-flags", hxv(b.u8(1)), "warn"), F("bits", esc(bs(b.u8(1), DEFS_BS)))));
    if (s === 2) rows.push(fr(F("tclog-start", dec(b.u16be(1))), F("count", dec(b.u8(3)))));
    if (s === 4) rows.push(fr(F("sb-auth", yn(b.u8(1)))));
    return rows;
  },
  0x26: () => [fr(F("cmd", "LAB_STATUS — full 53-byte state blob request", "warn"))],
  0x27: (b) => [fr(F("cmd", "LAB_CTRL — bench backdoor (PER-0002)", "warn"), F("sub", hxv(b.u8(0))))],
  0x3FF: () => [fr(F("cmd", "IDLE_BEACON"))],
};
function tcGeneric(b) {
  if (!b.n) return [fr(F("payload", "(empty)"))];
  return [fr(F("sub-cmd", hxv(b.u8(0))), F("rest", b.hex(1, Math.min(48, b.n - 1)) || "—"))];
}

/* --- telemetry payload semantics (layouts from flatsat_sim._tm_* / _ext acks) */
const TM_D = {
  0x01: (b) => [fr(F("ack", esc(b.ascii(1, b.n - 1)) || "(no text)"), F("sc-id", hxv(b.u8(0))))],
  0x02: (b) => [fr(F("ack", "RESETC done"), F("boot-count", dec(b.u8(1))),
    F("persist-cookie", yn(b.u8(2))), F("marker", hxv(b.u8(3))))],
  0x03: () => [fr(F("ack", "SEND_FW inventory ack (v1.0.0)"))],
  0x06: (b) => [fr(F("echo", esc(b.ascii(0, b.n)), "ok"), F("len", dec(b.n) + " B"))],
  0x07: (b, ev) => [fr(F("flash-page", dec(b.u16le(1)), "warn"),
    F("offset", dec(b.u16le(3))), F("remaining", dec(b.u16le(5)) + " B"),
    F("crc8", hxv(b.u8(23))), F("seg-flag", hxv(ev.flags || 1)))],
  0x08: (b) => {
    const w = [];
    for (let i = 0; i < 8; i++) w.push(b.i16le(1 + i * 2) / 100);
    return [fr(F("sensor-words", "×100 (int16 as stored)"), F("values", w.join(" · "), "dim")),
      fr(F("thrusters", `[${dec(b.u8(17))}, ${dec(b.u8(18))}]`))];
  },
  0x09: (b) => [fr(F("error", esc(b.ascii(0, b.n)), "bad"))],
  0x0A: (b) => [fr(F("ack", "AES_CONFIG"), F("secure-link", b.u8(1) ? "ON" : "OFF", b.u8(1) ? "ok" : "warn"))],
  0x0B: (b) => {
    const ln = b.u8(3);
    return [fr(F("flash-read", `offset ${dec(b.u16le(1))} · len ${dec(ln)}`, "warn"),
      F("crc8", hxv(b.u8(4 + ln))), F("data", esc(b.ascii(4, ln))))];
  },
  0x0C: (b) => [
    fr(F("mode", modeN(b.u8(1))), F("flags", esc(bs(b.u8(2), FLAG_BS))),
       F("gps", esc(bs(b.u8(3), GPS_BS)))),
    fr(F("beacon", `${dec(b.u8(4))} s`), F("thrusters", `[${dec(b.u8(5))}, ${dec(b.u8(6))}]`),
       F("sats", dec(b.u8(7))), F("vcc", dec(b.u16le(8)) + " (raw)")),
    fr(F("last-freq", dec(b.u16le(10)) + " MHz"), F("uptime", dec(b.u32le(12)) + " s"),
       F("date", `2026-01-01 UTC ${dec(b.u8(18))}`), F("flags2", esc(bs(b.u8(23), FLAG2_BS))))],
  0x0D: (b) => [fr(F("mode", modeN(b.u8(1))), F("payload-armed", yn(b.u8(2))),
    F("flags", esc(bs(b.u8(3), FLAG_BS))))],
  0x0E: (b) => {
    if (b.n === 18) return [
      fr(F("ack", "GPS_OVERRIDE accepted — override now ACTIVE", "warn"),
         F("pad", hxv(b.u8(13))), F("def-flags", esc(bs(b.u8(14), DEFS_BS))), F("mode", modeN(b.u8(15)))),
      fr(F("lat", geo(b.i32le(1), 1e7), "warn"), F("lon", geo(b.i32le(5), 1e7), "warn"),
         F("alt", fmtAlt(b.i32le(9))), F("sats", dec(b.u8(12))))];
    return [
      fr(F("gps", esc(bs(b.u8(1), GPS_BS))), F("sats", dec(b.u8(2))),
         F("lat", geo(b.i32le(3), 1e7)), F("lon", geo(b.i32le(7), 1e7), "warn"),
         F("alt", fmtAlt(b.u32le(11)))),
      fr(F("date", `2026-01-01 UTC ${dec(b.u8(17))}`), F("motion", "shake ×100: " +
         [0, 1, 2, 3].map((i) => (b.i16le(21 + i * 2) / 100).toFixed(2)).join(" · ")))];
  },
  0x0F: (b) => [fr(F("mode", modeN(b.u8(1))), F("armed", yn(b.u8(2))),
    F("secure", yn(b.u8(3))), F("last-msg-len", dec(b.u8(8)) + " B", "warn"),
    F("vcc", dec(b.u16le(6))))],
  0x10: (b) => [fr(F("ack", "USB_DEBUG"), F("usb-debug", yn(b.u8(1))),
    F("secure", yn(b.u8(2)), b.u8(1) ? "warn" : ""))],
  0x11: (b) => [fr(F("gs-mode", yn(b.u8(2)), b.u8(2) ? "warn" : ""),
    F("req", dec(b.u8(1))), F("gs", esc(bs(b.u8(3), GS_BS))), F("gps", esc(bs(b.u8(4), GPS_BS)))),
    fr(F("session-left", dec(b.u16be(5)) + " s"), F("pending-left", dec(b.u16be(7)) + " s"))],
  0x12: (b) => {
    const auth = { 0: "challenge issued — waiting", 1: "AUTH OK — session open", 2: "AUTH FAIL", 3: "no pending challenge" };
    const a = b.u8(2);
    return [fr(F("phase", dec(b.u8(1))),
      F("auth", esc(auth[a] !== undefined ? auth[a] : `code ${a}`), a === 1 ? "ok" : "warn")),
      fr(F("challenge", `0x${(b.u32be(5) >>> 0).toString(16).toUpperCase()}`, "warn",
           "32-bit challenge; the firmware expects response = challenge ⊕ GS_XOR_KEY, a static constant readable straight out of the image — so a passive radio recording lets anyone answer the handshake offline (V-36)"),
         F("gs", esc(bs(b.u8(3), GS_BS))), F("session-left", dec(b.u16be(9)) + " s"))];
  },
  0x13: (b) => {
    const d = b.u16le(3);
    return [fr(F("dist", d === 0xFFFF ? "no fix" : dec(d) + " m", d !== 0xFFFF && d <= 35000 ? "ok" : "bad"),
      F("gate", bs(b.u8(1), GS_BS).includes("GATE-OPEN") ? "OPEN" : "CLOSED",
        bs(b.u8(1), GS_BS).includes("GATE-OPEN") ? "ok" : "warn")),
      fr(F("gs-flags", esc(bs(b.u8(1), GS_BS))), F("gps", esc(bs(b.u8(2), GPS_BS))),
         F("session", dec(b.u16le(5)) + " s")),
      fr(F("challenge", `0x${(b.u32le(7) >>> 0).toString(16).toUpperCase()}`, "warn",
           "32-bit challenge; the firmware expects response = challenge ⊕ GS_XOR_KEY, a static constant readable straight out of the image — so a passive radio recording lets anyone answer the handshake offline (V-36)"),
         F("pending", dec(b.u16le(11)) + " s"), F("radius", dec(b.u16le(19)) + " m (GS_RADIUS_M)", "",
           "range-gate radius: inside this circle GS_MODE arming and privileged telecommands are accepted; APIDs 0x10/0x12 and the USB backdoors bypass the gate (PER-0002)")),
      fr(F("gs-x", geo(b.i32le(13), 1e7)), F("gs-y", geo(b.i32le(17), 1e7)))];
  },
  0x15: (b) => [fr(F("ack", "SDLS_CONFIG"), F("sdls", yn(b.u8(2))),
    F("arc-bits", dec(b.u8(3))), F("window", dec(b.u8(4))))],
  0x16: (b) => {
    const sub = ["OTAR", "SA-SET", "SA-GET", "ARC-RESET"][b.u8(1)] || "sub " + b.u8(1);
    const rows = [fr(F("ack", esc(sub)), F("ok", okNo(b.u8(2))))];
    if (b.u8(1) === 2) rows.push(fr(F("sa", dec(b.u8(3))), F("est/ast", `${dec(b.u8(4))}/${dec(b.u8(5))}`),
      F("key", b.hex(6, 16), "warn"), F("null-keys", dec(b.u8(22)) + " master keys still zeroed", "warn")));
    return rows;
  },
  0x17: (b) => [fr(F("oracle", "KEY_VERIFY output", "warn"), F("kid", dec(b.u8(1))),
    F("cipher→plain", b.hex(2, 16)))],
  0x18: (b) => [fr(F("ack", "MEMCPY"), F("ok", okNo(b.u8(1))),
    F("src", hxv(b.u32le(2), 8) + symOf(b.u32le(2)), "warn"),
    F("dst", hxv(b.u32le(6), 8) + symOf(b.u32le(6)), "warn"), F("len", dec(b.u16le(10))))],
  0x19: (b) => [fr(F("mem-read", hxv(b.u32le(1), 8) + symOf(b.u32le(1)), "warn"),
    F("len", dec(b.u16le(5)))),
    fr(F("data", b.hex(7, Math.min(32, b.n - 7))))],
  0x1A: (b) => [fr(F("ack", "SET_LOG_NAME"), F("usb", yn(b.u8(1))), F("secure", yn(b.u8(2))),
    F("gs-mode", yn(b.u8(3))), F("pad", hxv(b.u8(4))))],
  0x1B: (b) => [fr(F("ack", "SB_PUBLISH"), F("msg", hxv(b.u16be(2), 4)),
    F("ok", okNo(b.u8(4))), F("sensor-mask", hxv(b.u8(5))), F("vcc-frozen", yn(b.u8(6))))],
  0x20: (b) => [fr(F("mode", b.u8(1) === 1 ? "RESET" : "READ"), F("samples", dec(b.u8(2)))),
    fr(F("rssi-avg", dec(b.i16le(3)) + " dBm"), F("snr-avg", (b.i16le(5) / 10).toFixed(1) + " dB"),
       F("frame-err", dec(b.i16le(7)))),
    fr(F("rssi-min", dec(b.i16le(9)) + " dBm"), F("rssi-max", dec(b.i16le(11)) + " dBm"),
       F("last-apid", hxv(b.u16be(14))), F("crc-def", yn(b.u8(13))))],
  0x21: (b) => [fr(F("pad-mode", ["OFF", "LEAK", "COVERT"][b.u8(1)] ?? hxv(b.u8(1)), b.u8(1) ? "warn" : ""),
    F("covert-qlen", dec(b.u16be(2)) + " B"), F("cloak", yn(b.u8(4))))],
  0x22: (b) => [fr(F("enq-ok", okNo(b.u8(1))), F("covert-qlen", dec(b.u16be(2)) + " B"),
    F("pad", hxv(b.u8(4))))],
  0x24: (b) => [fr(F("heater", dec(b.u8(1))), F("on", yn(b.u8(2))),
    F("batt", dec(b.u16le(3)) + " %"), F("bus", (b.u16le(5) / 100).toFixed(2) + " V"),
    F("power", (b.u16le(7) / 100).toFixed(2) + " W"))],
  0x25: (b) => {
    const s = b.u8(1);
    if (s === 0 || s === 3) return [fr(F("ack", `DEFENSES ${s === 3 ? "FACTORY-RESET" : "SET"}`),
      F("def-flags", hxv(b.u8(2)), "warn"), F("bits", esc(bs(b.u8(2), DEFS_BS))))];
    if (s === 1) return [fr(F("ack", "DEFENSES READ"), F("def-flags", hxv(b.u8(2))),
      F("bits", esc(bs(b.u8(2), DEFS_BS))), F("tclog", dec(b.u8(3)) + " entries"),
      F("evicted", dec(b.u16be(4)) + " TCs lost", "warn"))];
    if (s === 2) {
      const rows = [fr(F("ack", "TCLOG DUMP"), F("total", dec(b.u8(2))),
        F("returned", dec(b.u8(3)) + " entries", "warn"))];
      let o = 4, n = 0;
      while (o + 9 <= b.n && n < 6) {
        const e = new BV(b.b.subarray(o));
        const pl = e.u8(8);
        rows.push(fr(F(`tc[${n}]`, `${dec(e.u32le(0))} ms`), F("apid", hxv(e.u16be(4))),
          F("seq", dec(e.u16be(6))), F("payload", e.hex(9, pl))));
        o += 9 + (Number.isFinite(pl) ? pl : 0); n += 1;
      }
      return rows;
    }
    if (s === 4) return [fr(F("ack", "SB_AUTH"), F("enabled", yn(b.u8(2))))];
    return [fr(F("ack", "DEFENSES sub " + dec(s)))];
  },
  0x26: (b) => [
    fr(F("state", esc(bs(b.u8(2), LAB_ST))), F("mode", modeN(b.u8(3))),
       F("pad", hxv(b.u8(4))), F("def-flags", esc(bs(b.u8(5), DEFS_BS)), "warn")),
    fr(F("gps-reject", dec(b.u16le(6)) + " overrides refused", "warn"),
       F("sats", dec(b.u8(8))), F("fix", yn(b.u8(9))), F("boot-count", dec(b.u32le(10)))),
    fr(F("sim-clock", dec(b.u32le(14)) + " ms"),
       F("challenge", `0x${(b.u32le(18) >>> 0).toString(16).toUpperCase()}`, "warn"),
       F("bus", num(b.f32le(22), (v) => v.toFixed(2) + " V"))),
    fr(F("ota-hash", b.hex(26, 8)), F("pending-boot", yn(b.u8(34))),
       F("tc-stats", dec(b.u8(35)) + " samples"), F("arc-last", dec(b.u32le(36)))),
    fr(F("f2", esc(bs(b.u8(40), LAB_F2))), F("batt", dec(b.u8(41)) + " %"),
       F("power", num(b.f32le(42), (v) => v.toFixed(2) + " W")),
       F("tilt", num(b.f32le(46), (v) => v.toFixed(3) + " rad/s")))],
  0x3FF: (b) => [fr(F("beacon", esc(b.ascii(0, b.n))))],
};
function tmGeneric(b) {
  if (!b.n) return [fr(F("payload", "(empty)"))];
  return [fr(F("payload", `${dec(b.n)} B — no per-field layout defined in firmware for this APID`),
    F("byte0", hxv(b.u8(0))))];
}

function decodeFrame(ev) {
  if (ev.bad) return fr(F("frame", "malformed — raw bytes only", "bad"), F("raw", esc((ev.wire || "").slice(0, 120))));
  const { wire, off } = frameWire(ev);
  if (wire.length < off + 6) return fr(F("frame", "truncated header", "bad"));
  const ident = (wire[off] << 8) | wire[off + 1];
  const seqc = (wire[off + 2] << 8) | wire[off + 3];
  const ln = (wire[off + 4] << 8) | wire[off + 5];
  const ver = (ident >> 13) & 7, type = (ident >> 12) & 1;
  const sec = (ident >> 11) & 1, apid = ident & 0x7ff;
  const seg = (seqc >> 14) & 3, count = seqc & 0x3fff;
  const name = ev.apid_name || "";
  const rows = [
    fr(F("SPP", `V${ver} · ${type ? "TC" : "TM"} · sec-hdr ${sec}`, "",
      "CCSDS Space Packet Protocol primary header, decoded from the first 6 wire bytes: version, packet type (0=telemetry, 1=command), secure-header flag"),
       F("APID", `0x${pad(apid, 2)}${name ? " " + esc(name) : ""}`, "warn",
      "Application Process Identifier — the CCSDS address of the firmware handler this packet is routed to"),
       F("SEG", `0b${pad(seg, 2)} (fw: 1=full 2=first 3=last)`, "",
      "Segmentation flag; this firmware treats only 1 as a complete packet (V-34 truncation finding exercises this)"),
       F("count", dec(count), "",
      "14-bit sequence counter — never validated on uplink: the replay hole (V0-07); on the wire it is also the AES-CTR nonce for telemetry when DEF_TM_CTR is on"),
       F("len-field", `${dec(ln)} → data ${dec(ln + 1)} B`, "",
      "CCSDS length field = data octets − 1; the unpacker copies one byte too many (V0-16 off-by-one)"))];
  if (ev.dir === "tc" && ev.via) rows.push(fr(F("path", esc(ev.via), "",
    "radio = over the air through the LoRa link; usb = bench cable. LAB_STATUS/LAB_CTRL answer on usb regardless of the range gate — the bench backdoor (PER-0002)"),
    ev.via === "usb" ? F("note", "bench transport — LAB_STATUS/LAB_CTRL bypass the GS gate (PER-0002)")
                     : F("note", "radio path — SDLS pre-processing applies")));
  if (ev.dir === "tm" && wire[0] === 0xAA) rows.push(fr(F("framing", "0xAA USB prefix (bench TTY), stripped for the SPP view", "",
    "the bench serial transport prefixes every emitted frame with 0xAA so the reader can resynchronise; it is transport framing, not part of the CCSDS packet")));
  if (ev.wrapped) {
    rows.push(fr(F("link-crypto",
      ev.dir === "tc"
        ? "payload AES-128 wrapped under LINK_KEY — key readable from the image (V0-02)"
        : (ev.pmode === "ctr"
          ? "payload AES-CTR under SA-0 session key, counter = packet count (DEF_TM_CTR)"
          : "payload AES-128-ECB wrapped under LINK_KEY (secure-link TM policy)"), "warn")));
  } else {
    rows.push(fr(F("link-crypto", ev.dir === "tc"
      ? "cleartext uplink — secure-link OFF on this path (V0-10)"
      : "cleartext downlink (link off, USB debug leak, or forced-clear ack)", "dim")));
  }
  const pay = new BV(ev.wrapped && ev.plain ? pHex(ev.plain) : framePayload(ev));
  const sem = ev.dir === "tc"
    ? (TC_D[apid] ? TC_D[apid](pay, ev) : (apid >= 0xF0 && apid <= 0xFF
        ? [fr(F("cmd", "TESTMODE — flips fdir_safe (needs testmode)"))] : tcGeneric(pay)))
    : (TM_D[apid] ? TM_D[apid](pay, ev) : tmGeneric(pay));
  const grids =
    hexGrid(wire, ev.dir === "tm" && wire[0] === 0xAA ? "WIRE — 0xAA + SPP as emitted" : "WIRE — SPP as emitted") +
    (ev.wrapped && ev.plain ? hexGrid(pHex(ev.plain), "DECRYPTED PAYLOAD") : "");
  return rows.join("") + sem.join("") + grids;
}

/* ------------------------------------------------------------ frame view */
const FRAMES_MAX_DOM = 700;
function onFrame(ev) {
  S.frames.push(ev);
  if (S.frames.length > 5000) S.frames.splice(0, S.frames.length - 5000);
  S.frameCount += 1;
  if (ev.t_ms) S.lastTms = ev.t_ms;
  if (S.condensed) return;
  if ((ev.dir === "tc" && !$("flt-tc").checked) || (ev.dir === "tm" && !$("flt-tm").checked)) return;
  const row = document.createElement("div");
  row.className = `fr ${ev.dir}` + (ev.apid === 0x09 ? " err" : "");
  row.dataset.fno = ev.fno;
  const enc = ev.wrapped ? `<span class="fe aes">AES</span>` : `<span class="fe clear">CLR</span>`;
  const hhead = (ev.wire || "").slice(0, 28);
  row.innerHTML =
    `<span class="ft">${fmtT(ev.t_ms || 0)}</span>` +
    `<span class="fd">${ev.dir === "tc" ? "▲TC" : "▼TM"}</span>` +
    `<span class="fa">0x${pad(ev.apid, 2) || "??"}<span class="nm">${esc(ev.apid_name || "")}</span></span>` +
    `<span class="fs">fl:${pad(ev.flags || 0, 2)} seq:${pad(ev.seq || 0, 4)}</span>` +
    `<span class="fl">L=${ev.len || 0}</span>` + enc +
    `<span class="fh">${esc(hhead)}</span>`;
  row.onclick = () => selectFrame(ev.fno);
  const item = document.createElement("div");
  item.className = "fitem";
  item.appendChild(row);
  const dec = document.createElement("div");
  dec.className = "fdec";
  dec.innerHTML = decodeFrame(ev);
  dec.onclick = () => selectFrame(ev.fno);
  item.appendChild(dec);
  item.setAttribute("role", "button");
  item.tabIndex = 0;
  item.setAttribute("aria-label", `frame ${ev.fno} ${ev.dir === "tc" ? "uplink" : "downlink"} apid 0x${(ev.apid ?? 0).toString(16).padStart(2, "0")} ${ev.len ?? 0} bytes${ev.err ? " error" : ""} — activate to decode`);
  item.onclick = () => selectFrame(ev.fno);   /* the whole card is a button: tap anywhere */
  item.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); row.click(); } };
  const stream = $("stream");
  const elide = stream.querySelector(".elide");
  if (elide) elide.remove();
  while (stream.children.length - (stream.firstElementChild && stream.firstElementChild.classList.contains("elide") ? 1 : 0) >= FRAMES_MAX_DOM) {
    const first = stream.querySelector(".fitem");
    if (!first) break;
    first.remove();
    S.elided += 1;
    let el = stream.querySelector(".elide");
    if (!el) {
      el = document.createElement("div");
      el.className = "elide";
      stream.prepend(el);
    }
    el.textContent = `— ${S.elided} earlier frames elided —`;
  }
  if (S.speed <= 16) item.classList.add("nf");
  stream.appendChild(item);
  if (S.hold.stream) pillHold("stream", stream); else SCROLL.stream = true;
  S.lastFrameAt = performance.now();
  updateFrameCount();
}

function updateFrameCount() {
  const buf = S.buf.length;
  $("framecount").textContent =
    `${S.frameCount} frames` + (S.elided ? ` (+${S.elided} elided)` : "") +
    (buf > 60 ? ` · sim ahead ${buf}` : "");
}

function selectFrame(fno) {
  const ev = S.frames.find((f) => f.fno === fno);
  if (!ev) return;
  S.selected = fno;
  document.querySelectorAll(".fr.sel").forEach((n) => n.classList.remove("sel"));
  const node = document.querySelector(`.fr[data-fno="${fno}"]`);
  if (node) node.classList.add("sel");
  const ins = $("inspector");
  const bits = bitDiagram(ev);
  let extra = "";
  if (ev.wrapped && ev.plain) {
    extra +=
      `<div class="hexblock"><span class="off">DECRYPTED PAYLOAD — ${ev.dir === "tc"
        ? "attacker decrypts the uplink (AES-128-ECB, hardcoded image key)"
        : "ECB unwrap under the link key (secure-link TM policy)"}\n` +
      hex16(ev.plain, "plain") + `</div>` +
      (ev.dir === "tc"
        ? `<div class="note">V0-02: key PWNsatLabKey1234 is readable from the firmware image — the uplink is never actually secret.</div>`
        : `<div class="note ok">TM was wrapped by the spacecraft; shown as it left the device (0xAA-prefixed USB framing stripped for the SPP view).</div>`);
  } else if (!ev.wrapped && !ev.bad) {
    extra += ev.dir === "tc"
      ? `<div class="note">Cleartext telecommand — secure-link is OFF on this path (V0-10 makes that switchable over the air).</div>`
      : `<div class="note ok">Forced-cleartext TM (v2 extension family).</div>`;
  }
  ins.innerHTML =
    `<div class="ihead"><b>FRAME #${ev.fno}</b> ` +
    `${ev.dir === "tc" ? "UPLINK" : "DOWNLINK"} · 0x${pad(ev.apid, 2)} ${esc(ev.apid_name || "")} ` +
    `· via=${ev.via || "—"} · ${fmtT(ev.t_ms || 0)} · L=${ev.len || 0}</div>` +
    (bits || "") +
    `<div class="hexblock"><span class="off">WIRE (raw, as tapped on ${ev.dir === "tc" ? "uplink" : "downlink + 0xAA framing"})\n` +
    hex16(ev.wire || "", "wire") + `</div>` + extra;
  ins.classList.add("open");
}

function bitCells(value, bits, hiRanges) {
  // bits: number of cells (top bit index bits-1 .. 0), row-reverse so MSB is leftmost
  let out = "";
  for (let b = 0; b < bits; b++) {
    const bit = (value >> b) & 1;
    const hit = hiRanges.find(([lo, hi]) => b >= lo && b <= hi);
    out += `<span class="cell${hit ? " " + hit[2] : ""}">${bit}</span>`;
  }
  return out;
}
function bitDiagram(ev) {
  if (ev.bad) return "";
  const ident = ((ev.ptype & 1) << 12) | ((ev.sechdr & 1) << 11) | (ev.apid & 0x7FF);
  const seqc = ((ev.flags & 3) << 14) | (ev.seq & 0x3FFF);
  const lenf = ev.len > 0 ? (ev.len - 1) & 0xFFFF : 0;
  return (
    `<div class="bits">` +
    `<div class="bitrow"><span class="lbl">IDENT (u16)</span><div class="cells">${bitCells(ident, 13, [[10, 10, "hi"], [11, 11, "hi2"], [12, 12, "hi2"]])}</div></div>` +
    `<div class="bitnames"><span style="width:165px">APID 10:0</span><span style="width:16px;text-align:center">SEC</span><span style="width:16px;text-align:center">P</span></div>` +
    `<div class="bitrow"><span class="lbl">SEQ/FLAGS (u16)</span><div class="cells">${bitCells(seqc, 16, [[13, 13, "hi"], [14, 15, "hi2"]])}</div></div>` +
    `<div class="bitnames"><span style="width:214px">SEQ 13:0</span><span style="width:32px;text-align:center">FLAGS 15:14</span></div>` +
    `<div class="bitrow"><span class="lbl">LENGTH (u16)</span><div class="cells">${bitCells(lenf, 16, [[0, 15, "hi"]])}</div></div>` +
    `<div class="bitnames"><span style="width:246px">payload_len − 1 (off-by-one kept, v116)</span></div>` +
    `</div>`
  );
}

/* ------------------------------------------------------------ state view */
function tile(id, label, htmlFn) {
  const el = document.createElement("div");
  el.className = "tile";
  el.id = "tile-" + id;
  el.innerHTML = `<div class="tl">${label}</div><div class="tbody"></div>`;
  $("tiles").appendChild(el);
  const render = (s) => {
    const html = s ? htmlFn(s) : `<div class="rows"><div class="r"><span>—</span></div></div>`;
    if (S.tilePrev[id] !== html) {
      S.tilePrev[id] = html;
      const body = el.querySelector(".tbody");
      body.innerHTML = html;
      // ultra-sober attention: an accent appears only where attention is
      // warranted — nominal tiles stay visually silent
      const bad = /st-CRASHED|class="bad"/.test(html);
      el.classList.toggle("acc-bad", bad);
      el.classList.toggle("acc-warn", !bad && /st-HANGED|class="warn"|⚠/.test(html));
      // twin keyframe names: switching between them restarts the animation
      // without the classic void-offsetWidth forced synchronous layout
      const flip = !el.classList.contains("flash-a");
      el.classList.toggle("flash-a", flip);
      el.classList.toggle("flash-b", !flip);
    }
  };
  return render;
}
const T = {};
function big(v, cls) { return `<div class="big ${cls || ""}">${v}</div>`; }
function r(k, v, cls) { return `<div class="r"><span>${k}</span><b class="${cls || ""}">${v}</b></div>`; }

function buildTiles() {
  T.craft = tile("craft", "CRAFT STATE", (s) =>
    big(`<span class="st-${s.state}">${s.state}</span><span class="u">${modeName(s.mode, s.payload_armed)}</span>`) +
    `<div class="rows">` +
    r("BOOT", s.boot_count) +
    r("TM CTR", pad(s.tm_counter, 4)) +
    r("TC CTR", pad(s.tc_counter, 4)) +
    `</div>`);
  T.secure = tile("secure", "SECURE LINK", (s) =>
    big(s.secure ? "AES ON" : "AES OFF", s.secure ? "" : "st-CRASHED") +
    `<div class="rows">` +
    r("KEY", "PWNsatLabKey1234 <span class='u'>(V0-02)</span>") +
    r("USB DEBUG", s.usb_debug ? "ON" : "off", s.usb_debug ? "warn" : "off") +
    r("PERSIST COOKIE", s.persist_cookie ? "YES" : "no", s.persist_cookie ? "warn" : "off") +
    `</div>`);
  T.gps = tile("gps", "GPS / PNT", (s) => {
    const g = s.gps;
    const st = g.kill ? "KILLED" : g.ovr ? "SPOOFED" : g.fix ? "FIX" : "NO FIX";
    const cls = g.kill ? "st-CRASHED" : g.ovr ? "st-HANGED" : g.fix ? "st-RUN" : "st-HANGED";
    return big(st, cls) +
      `<div class="rows">` +
      r("LAT", g.lat.toFixed(5) + "°") +
      r("LON", g.lon.toFixed(5) + "°") +
      r("ALT", (g.alt_cm / 100).toFixed(0) + " m") +
      r("SVS", g.sats) +
      r("REJECT", g.reject, g.reject ? "bad" : "off") +
      `</div>`;
  });
  T.gs = tile("gs", "GS GATE", (s) => {
    const g = s.gs;
    let st, cls;
    if (!g.mode) { st = "MODE OFF"; cls = "st-RUN"; }
    else if (g.gate) { st = "OPEN"; cls = "st-RUN"; }
    else { st = "LOCKED"; cls = "st-CRASHED"; }
    return big(st, cls) +
      `<div class="rows">` +
      r("SESSION", g.session ? `T−${g.session_ttl_s}s` : "—", g.session ? "on" : "off") +
      r("PENDING", g.pending ? `T−${g.pending_ttl_s}s` : "—", g.pending ? "warn" : "off") +
      r("DIST", g.dist_m >= 0 ? g.dist_m.toFixed(0) + " m" : "—") +
      r("CHALLENGE", g.challenge ? "0x" + g.challenge.toString(16).padStart(8, "0") : "—") +
      `</div>`;
  });
  T.sdls = tile("sdls", "SDLS", (s) => {
    const d = s.sdls;
    return big(d.enabled ? "ENABLED" : "OFF", d.enabled ? "" : "st-HANGED") +
      `<div class="rows">` +
      r("ARC", `${d.arc_bits} b` + (d.relaxed ? " RELAXED" : "")) +
      r("WINDOW", d.arc_win) +
      r("ARC LAST", d.arc_last) +
      r("CLEAR SAs", `${d.null_sas}/64`, d.null_sas > 0 ? "warn" : "off") +
      `</div>`;
  });
  T.fdir = tile("fdir", "FDIR", (s) => {
    const f = s.fdir;
    const el = $("tile-fdir");
    if (el) el.classList.toggle("badline", !!f.safe);
    return big(f.safe ? `SAFE · ${f.cause || "?"}` : "ARMED", f.safe ? "st-CRASHED" : "st-RUN") +
      `<div class="rows">` +
      r("TRIGGERS", f.triggers, f.triggers ? "warn" : "off") +
      r("TILT", s.mm.tilt.toFixed(2) + " rad/s", s.mm.tilt > 5 ? "bad" : "") +
      `</div><div class="meter"><i class="${s.mm.tilt > 5 ? "bad" : ""}" style="width:${Math.min(100, s.mm.tilt * 10).toFixed(1)}%"></i><span class="mark" style="left:50%"></span></div>`;
  });
  T.bus = tile("bus", "BUS & POWER", (s) => {
    const m = s.mm;
    return big(m.bus_v.toFixed(2) + " <span class='u'>V</span>") +
      `<div class="meter"><i class="${m.brownout ? "bad" : ""}" style="width:${Math.max(0, Math.min(100, m.pct)).toFixed(1)}%"></i></div>` +
      `<div class="rows">` +
      r("BATT", m.pct.toFixed(1) + " %", m.pct < 20 ? "bad" : "") +
      r("POWER", m.power_w.toFixed(2) + " W") +
      r("ECLIPSE", s.eclipse ? "YES" : "no", s.eclipse ? "warn" : "off") +
      r("THRUST", `${m.t_thr[0]} / ${m.t_thr[1]}`) +
      r("BROWNOUT", m.brownout ? "YES" : "no", m.brownout ? "bad" : "off") +
      `</div>`;
  });
  T.flash = tile("flash", "FLASH / OTA", (s) => {
    const f = s.flash;
    return big(`SLOT ${f.active_slot ? "B" : "A"}` + (f.pending_boot ? " <span class='u st-HANGED'>PENDING</span>" : "")) +
      `<div class="rows">` +
      r("BOOT TRY", `${f.boot_try} · booted ${f.booted_slot || "—"}`) +
      r("ARWC", f.arwc + (f.arwc_enforce ? "·ENF" : "")) +
      r("SCHED", f.sched_n + (f.sched_n ? " ⚠" : "")) +
      r("TCLOG", f.tclog_n + (f.tclog_enabled ? "" : " (off)")) +
      r("FDICT", f.fdict_locked ? "LOCKED" : "open", f.fdict_locked ? "warn" : "off") +
      `</div>`;
  });
  T.sc = tile("sc", "SPACECAN", (s) => {
    const c = s.sc;
    return big(c.congested ? "CONGESTED" : "NOMINAL", c.congested ? "st-HANGED" : "st-RUN") +
      `<div class="rows">` +
      r("MOTOR", c.nodes.MOTOR ? `e${c.nodes.MOTOR.err}${c.nodes.MOTOR.off ? " OFF" : ""}` : "—") +
      r("BATTERY", c.nodes.BATTERY ? `e${c.nodes.BATTERY.err}${c.nodes.BATTERY.off ? " OFF" : ""}` : "—") +
      r("SENSOR", c.nodes.SENSOR ? `e${c.nodes.SENSOR.err}${c.nodes.SENSOR.off ? " OFF" : ""}` : "—") +
      r("CHARGE", c.charge + " %") +
      `</div>`;
  });
  T.covert = tile("covert", "COVERT CH.", (s) => {
    const c = s.covert;
    return big(padName(c.pad_mode)) +
      `<div class="rows">` +
      r("QUEUE", `${c.q_len}/1024`) +
      r("VCC", c.vcc + (c.vcc_frozen ? " FROZEN" : ""), c.vcc_frozen ? "warn" : "") +
      r("LEAK POS", c.leak_pos) +
      `</div>`;
  });
  T.tclink = tile("tclink", "TC LINK", (s) => {
    const t = s.tcs;
    return big(pad(t.n, 2) + " <span class='u'>TC</span>") +
      `<div class="rows">` +
      r("LAST RSSI", t.rssi !== null && t.rssi !== undefined ? t.rssi + " dBm" : "—") +
      r("LAST SNR", t.snr !== null && t.snr !== undefined ? t.snr.toFixed(1) + " dB" : "—") +
      r("LAST APID", t.last_apid ? "0x" + t.last_apid.toString(16).padStart(2, "0") : "—") +
      `</div>`;
  });
  T.anom = tile("anom", "ANOMALY", (s) => {
    const a = s.anom;
    return big(a.alarm ? "ALARM" : "CLEAR", a.alarm ? "st-CRASHED" : "st-RUN") +
      `<div class="rows">` +
      r("Z", a.z) +
      r("LAST CH", a.last_ch) +
      r("TC SEEN", a.tc_seen) +
      `</div>`;
  });
  T.counters = tile("counters", "COUNTERS / DEF", (s) =>
    big("0x" + s.def_flags.toString(16).padStart(2, "0")) +
    `<div class="rows">` +
    r("VTOR", "0x" + s.vtor.toString(16).padStart(8, "0")) +
    r("SB AUTH", s.sb.auth ? "ON" : "off") +
    r("SENS MASK", "0x" + s.sb.sensor_mask.toString(16).padStart(2, "0")) +
    `</div>`);
}
function onState(ev) {
  const s = ev.s;
  if (!s) return;
  if (ev.t_ms) S.lastTms = ev.t_ms;
  for (const k in T) T[k](s);
  setLed("led-key", s.secure ? "on" : "warn");
  setLed("led-state", s.state === "RUN" ? "on" : s.state === "CRASHED" ? "bad" : "warn");
  onOrbFromState(s, ev.t_ms);
}

/* ------------------------------------------------------------- console */
function lineClass(t, ev) {
  let cls = ev.ev ? "ev" : "";
  if (/^={10,}/.test(t)) cls = "banner";
  else if (/^>/.test(t) === false && t.includes("--> TC")) cls = "tc";
  else if (t.includes("<-- TM")) cls = "tm";
  else if (/^\s*POC OK/.test(t) || t === "POC OK") cls = "ok";
  else if (/POC FAILED|CHECK FAILED|POC ERROR|Error/.test(t)) cls = "bad";
  return cls;
}
function onLine(ev) {
  if (ev.ev && !S.sweep.active) S.runLines.push(ev.text || "");
  const t = ev.text;
  if (!S.condensed) {
    const c = $("console");
    const node = document.createElement("div");
    node.className = "ln " + lineClass(t, ev);
    node.textContent = t;
    if (S.speed <= 16) node.classList.add("nf");
    c.appendChild(node);
    while (c.children.length > 3000) c.firstChild.remove();
    if (S.hold.cons) pillHold("cons", c); else SCROLL.cons = true;
  }
  // index live-proof pane (same run, same source events)
  if (S.idxOpen && !S.sweep.active && S.idxFile === S.curPoc) {
    const c = $("idx-console");
    const node = document.createElement("div");
    node.className = "ln " + lineClass(t, ev);
    node.textContent = t;
    if (S.speed <= 16) node.classList.add("nf");
    c.appendChild(node);
    while (c.children.length > 3000) c.firstChild.remove();
    if (S.hold.idx) pillHold("idx", c); else SCROLL.idx = true;
  }
  // killchain: light stages as the committed evidence anchors appear
  if (ev.ev) kcAnchor(t);
}

/* ------------------------------------------------------------- verdict */
function pocMeta(file) { return D.pocs.find((p) => p.file === file); }

function verdictContent(ev, meta) {
  // Compact status bar: tag + finding id + terse stats + hash verdict, one line.
  // The full explanation rides on the bar's tooltip (set by onVerdict).
  const id = meta ? meta.id : ev.poc;
  const title = meta ? `${meta.id} · ${meta.title}` : ev.poc;
  const evPath = (meta && meta.ev_path) || "evidence/" + ev.poc.replace(".py", ".txt");
  if (ev.ok && ev.match) {
    return { cls: "ok", html:
      `<span class="vtag">POC OK</span>` +
      `<span class="vmsg">${esc(id)} · ${ev.nlines} lines · ${ev.frames} frames · ${ev.wall_s} s · ` +
      `md5 <span class="hash">${short(ev.md5)}</span> == committed ✓</span>` +
      `<button id="vdiff" title="side-by-side: this browser run vs the committed transcript">COMPARE ⤢</button>`,
      tip: `POC OK — ${title}\n` +
        `The transcript produced in this browser hashes (normalised md5 ${short(ev.md5)}) byte-identical to the committed simulator transcript ${evPath}.\n` +
        `The same unmodified PoC also passed on the physical FlatSat 1 board (bench parity).\n` +
        `COMPARE shows the two transcripts side by side.` };
  }
  if (ev.ok && !ev.match) {
    return { cls: "bad", html:
      `<span class="vtag">DIVERGENT</span>` +
      `<span class="vmsg">${esc(id)} · passed but md5 <span class="hash">${short(ev.md5)}</span> ≠ committed <span class="hash">${short(ev.md5_exp)}</span></span>`,
      tip: `${title}\n` +
        `The PoC passed, but this run's transcript hash differs from the committed one (non-deterministic run?).` };
  }
  return { cls: "bad", html:
    `<span class="vtag">POC FAILED</span>` +
    `<span class="vmsg">${esc(id)} · exit ${ev.code} — see console above</span>`,
    tip: `${title}\nThe PoC exited with code ${ev.code}; the console above holds the failing transcript.` };
}

function onVerdict(ev) {
  const v = $("verdict");
  const meta = pocMeta(ev.poc);
  S.verdictInfo = { poc: ev.poc, ok: ev.ok, match: ev.match };
  const c = verdictContent(ev, meta);
  v.className = c.cls;
  v.dataset.poc = ev.poc;
  v.innerHTML = c.html;
  v.title = c.tip || "";
  const card = document.querySelector(`.card[data-poc="${ev.poc}"]`);
  if (card && ev.ok && ev.match) card.classList.add("done");
  const ic = document.querySelector(`.idxcard[data-poc="${ev.poc}"]`);
  if (ic && ev.ok && ev.match) ic.classList.add("done");
  if (S.sweep.active) {
    const cell = document.querySelector(`.scell[data-poc="${ev.poc}"]`);
    if (cell) {
      cell.classList.remove("run");
      cell.classList.add(ev.ok && ev.match ? "ok" : "bad");
      if (ev.ok && ev.match) cell.querySelector(".st").textContent =
        `${ev.nlines} ln · ${ev.frames} fr · ${ev.wall_s}s ✓`;
      else cell.querySelector(".st").textContent = ev.ok ? "hash mismatch ✗" : "failed ✗";
    }
  }
  if (ev.poc === "v136_gps_spoof_chain.py" && !S.sweep.active) {
    S.kc.active = false;
    S.kc.final = ev.ok && ev.match;
    renderKc();
  }
  if (S.idxOpen && S.idxFile === ev.poc) {
    const iv = $("idx-verdict");
    iv.className = "verdictbox " + c.cls;
    iv.innerHTML = c.html;
    iv.title = c.tip || "";
  }
  if (!S.sweep.active) setRunning(false);
  updateFrameCount();
}

function fatal(e) {
  const v = $("verdict");
  v.className = "bad";
  v.title = "";
  v.innerHTML = `<span class="vtag">FAULT</span><span class="vmsg">${esc(e)}</span>`;
  $("selftest").textContent = "worker fault — see verdict";
  $("selftest").className = "pill bad";
  // never leave the UI locked after a fault: RUN/SWEEP must stay usable
  S.pending = null;
  if (S.running) setRunning(false);
  if (S.sweep && S.sweep.active) S.sweep.active = false;
  bootLine("FATAL — " + String(e).slice(0, 120), "bad");
  bootHide();
}

/* --------------------------------------------------------------- sweep */
function startSweep() {
  if (engineOffline()) { engineReadOnly(); return; }
  if (!S.engineReady) { S.pending = { kind: "sweep" }; engineQueued("the 56-PoC sweep"); return; }
  if (S.sweep.active) { $("sweep").classList.remove("hidden"); return; }
  S.sweep = { active: true, t0: Date.now(), i: 0, n: D.pocs.length };
  S.condensed = true;
  setRunning(true);
  S.kc.active = false;
  S.kc.final = false;
  renderKc();
  const grid = $("sweep-grid");
  grid.innerHTML = "";
  for (const p of D.pocs) {
    const c = document.createElement("div");
    c.className = "scell";
    c.dataset.poc = p.file;
    c.title = p.id + " — " + p.title + " · open in INDEX";
    c.onclick = () => { $("sweep").classList.add("hidden"); setView("index"); openIdxDetail(p.file); };
    c.innerHTML = `<span class="sid">${p.id}</span><span class="st">${p.title.slice(0, 26)}…</span>`;
    grid.appendChild(c);
  }
  $("sweep").classList.remove("hidden");
  $("sweep-count").textContent = `0 / ${S.sweep.n}`;
  $("sweep-fill").style.width = "0%";
  $("sweep-final").textContent = "";
  $("sweep-final").className = "";
  S.worker.postMessage({
    cmd: "sweep",
    poc: D.pocs.map((p) => p.file),
    expect: Object.fromEntries(D.pocs.map((p) => [p.file, p.ev_md5])),
  });
}
function onPocStart(ev) {
  S.runLines = [];
  if (S.sweep.active) {
    S.sweep.i = ev.i;
    $("sweep-count").textContent = `${ev.i} / ${ev.n}`;
    if ($("sweep").classList.contains("hidden"))
      $("btn-sweep").textContent = `SWEEP ${ev.i}/${ev.n} ▸`;
    const cell = document.querySelector(`.scell[data-poc="${ev.poc}"]`);
    if (cell) cell.classList.add("run");
  }
  if (ev.poc === "v136_gps_spoof_chain.py" && !S.sweep.active) {
    S.kc = { active: true, final: false,
             lit: [false, false, false, false, false],
             evi: [null, null, null, null, null] };
    renderKc();
  }
}
function onSweepDone(ev) {
  const el = $("sweep-final");
  const n = S.sweep.n || ev.n || 0;
  if (ev.ok === n && ev.bad.length === 0) {
    el.textContent = `SWEEP COMPLETE — ${ev.ok}/${n} POC OK · all transcripts hash-verified vs committed evidence · ${ev.wall_s} s`;
    el.className = "ok";
  } else {
    el.textContent = `SWEEP DONE — ${ev.ok}/${n} OK · failed: ${ev.bad.join(", ") || "hash mismatches"}`;
    el.className = "bad";
  }
  $("sweep-count").textContent = `${ev.ok} / ${n} OK`;
  $("sweep-fill").style.width = "100%";
  S.sweep.active = false;
  setRunning(false);
  $("btn-sweep").textContent = `SWEEP ${n}/${n}`;
  $("sweep-time").textContent = (Date.now() - S.sweep.t0) / 1000 + " s wall";
}

/* ------------------------------------------------------------- catalog */
const GROUP_DESC = {
  REC: "Reconnaissance & eavesdropping",
  EX: "Execution (ST0004)",
  LM: "Lateral Movement (ST0007)",
  IA: "Initial Access (ST0003)",
  DE: "Defense Evasion (ST0006)",
  PER: "Persistence (ST0005)",
  EXF: "Exfiltration (ST0008)",
  IMP: "Impact",
};
function buildCatalog() {
  const body = $("catalog-body");
  const groups = {};
  for (const p of D.pocs) {
    (groups[p.group] = groups[p.group] || []).push(p);
  }
  const order = Object.keys(groups).sort();
  const heroDiv = document.createElement("div");
  heroDiv.className = "catgroup";
  const heroes = D.pocs.filter((p) => p.hero);
  heroDiv.innerHTML = `<h3>HERO PICKS <span class="gdesc">the five that tell the story</span></h3>`;
  const hc = document.createElement("div");
  hc.className = "catcards";
  heroes.forEach((p) => hc.appendChild(card(p)));
  heroDiv.appendChild(hc);
  body.appendChild(heroDiv);
  for (const g of order) {
    const div = document.createElement("div");
    div.className = "catgroup";
    div.innerHTML = `<h3>${g} <span class="gdesc">${GROUP_DESC[g] || ""} · ${groups[g].length}</span></h3>`;
    const cs = document.createElement("div");
    cs.className = "catcards";
    groups[g].slice().sort((a, b) => a.id.localeCompare(b.id)).forEach((p) => cs.appendChild(card(p)));
    div.appendChild(cs);
    body.appendChild(div);
  }
}
function card(p) {
  const c = document.createElement("div");
  c.className = "card" + (p.hero ? " hero" : "");
  c.dataset.poc = p.file;
  c.innerHTML =
    `<span class="cid">${p.id}</span>` +
    `<span><span class="ct">${esc(p.title)}</span>` +
    `<div class="cm">${esc(p.sparta)} · ${p.file} · ev ${short(p.ev_md5)}</div></span>`;
  c.onclick = () => { $("catalog").classList.add("hidden"); runPoc(p.file); };
  return c;
}

/* ----------------------------------------------------------- killchain */
function kcStageEl(i, st) {
  const d = document.createElement("div");
  d.className = "kc-stage";
  d.dataset.kc = i;
  d.innerHTML =
    `<span class="kc-n">STEP ${i + 1}</span>` +
    `<span class="kc-t">${H(st.title)}</span>` +
    `<span class="kc-d">${H(st.desc)}</span>` +
    `<span class="kc-e"></span>`;
  return d;
}
function renderKc() {
  document.querySelectorAll(".kc-stage[data-kc]").forEach((el) => {
    const i = +el.dataset.kc;
    el.classList.toggle("live", S.kc.lit[i] && S.kc.active);
    el.classList.toggle("done", S.kc.lit[i] && !S.kc.active);
    const e = el.querySelector(".kc-e");
    if (e) e.textContent = S.kc.evi[i] ? "✦ " + S.kc.evi[i] : "";
  });
  const anyLit = S.kc.lit.some(Boolean);
  const allLit = S.kc.lit.every(Boolean);
  for (const wrap of [$("ov-kc-stages"), $("idx-stages")]) {
    if (!wrap) continue;
    wrap.classList.toggle("chaining", S.kc.active && anyLit);
    wrap.classList.toggle("chain-done", !S.kc.active && allLit && S.kc.final);
  }
  const foot = $("ov-kc-foot");
  if (foot) {
    if (!S.kc.active && allLit && S.kc.final) {
      foot.textContent = "CHAIN COMPLETE — 5/5 evidence-anchored stages reproduced " +
        "live; fresh transcript hashes to the committed evidence";
      foot.classList.add("done");
    } else if (S.kc.active) {
      foot.textContent = "chain executing — " + S.kc.lit.filter(Boolean).length +
        "/5 committed evidence anchors matched so far…";
      foot.classList.remove("done");
    } else {
      foot.textContent = "stages light up live as the committed evidence anchors " +
        "appear in the v136 transcript";
      foot.classList.remove("done");
    }
  }
}
function kcAnchor(t) {
  if (!S.kc.active) return;
  D.killchain.forEach((st, i) => {
    if (!S.kc.lit[i] && t.includes(st.anchor)) {
      S.kc.lit[i] = true;
      S.kc.evi[i] = t.replace(/^\[\s*[\d.]+\]\s*/, "");
      renderKc();
    }
  });
}

/* ------------------------------------------------------------- overview */
function buildOverview() {
  const K = D.kpis;
  $("kpi-v4").textContent = K.apids;
  $("kpi-v5").textContent = K.image_md5.slice(0, 8) + "…";
  $("kpi-s5").textContent =
    "UF2 · " + K.image_size.toLocaleString("en-US") + " B · md5 " +
    K.image_md5.slice(0, 12) + "… (image H)";

  // hero findings
  const hg = $("ov-heroes-grid");
  D.heroes.forEach((h) => {
    const el = document.createElement("div");
    el.className = "hero-card" + sevRail(h.severity);
    el.innerHTML =
      `<span class="hc-id">${h.id} <span class="sevchip ${sevClass(h.severity)}">${esc(sevWord(h.severity))}</span></span>` +
      `<span class="hc-title">${esc(h.title)}</span>` +
      `<span class="hc-note">${esc(h.note)}</span>` +
      `<span class="hc-actions"><button data-act="read">READ</button>` +
      `<button data-act="run" class="primary">RUN ▸</button></span>`;
    el.querySelector('[data-act="read"]').onclick = (e) => {
      e.stopPropagation(); openIdxDetail(h.file);
    };
    el.querySelector('[data-act="run"]').onclick = (e) => {
      e.stopPropagation(); runPoc(h.file);
    };
    hg.appendChild(el);
  });

  // SPARTA families
  const fg = $("ov-families-grid");
  for (const g of Object.keys(D.group_counts).sort()) {
    const famPocs = D.pocs.filter((p) => p.group === g);
    let best = null;
    for (const p of famPocs) if (p.risk && (!best || p.risk.a > best.a)) best = p.risk;
    const el = document.createElement("div");
    el.className = "fam-card";
    el.title = `SPARTA v3.2 family ${g} (Space Attack Research and Tactic Analysis, The Aerospace Corporation) — ${D.groups[g] || GROUP_DESC[g] || g} · ${famPocs.length} findings — click to open the index filtered on this family`;
    const c = FAM_C[g] || "var(--dim)";
    el.innerHTML =
      `<span class="fc-code" style="color:${c};text-shadow:0 0 12px ${c}55">${g}</span>` +
      `<span><span class="fc-label">${esc(D.groups[g] || g)}</span>` +
      `<span class="fc-risk">${best ? `max notional risk ${best.a}|${best.b}|${best.c}${best.ref ? " (" + esc(best.ref) + ")" : ""}` : "no notional risk triple published"}</span></span>` +
      `<span class="fc-count">${famPocs.length}<small>FINDINGS</small></span>`;
    el.onclick = () => openIndexFiltered({ group: g });
    fg.appendChild(el);
  }

  // APID attack surface
  const ag = $("ov-apid-grid");
  const maxN = Math.max(1, ...D.apid_surface.map((a) => a.tc + a.tm));
  D.apid_surface.slice()
    .sort((a, b) => (b.tc + b.tm) - (a.tc + a.tm) || a.apid - b.apid)
    .forEach((a) => {
      const el = document.createElement("div");
      el.className = "apid-cell" + (a.tc + a.tm >= maxN * 0.5 ? " hot" : "");
      el.style.setProperty("--h", ((a.tc + a.tm) / maxN).toFixed(3));
      el.title = "findings: " + a.pocs.join(", ");
      el.innerHTML =
        `<span class="ac-hex">0x${a.apid.toString(16).toUpperCase()}</span>` +
        `<span class="ac-name">${esc(a.name || "—")}</span>` +
        `<span class="ac-io"><b class="tc">▲${a.tc}</b> TC · <b class="tm">▼${a.tm}</b> TM</span>`;
      el.onclick = () => openIndexFiltered({ apid: a.apid });
      ag.appendChild(el);
    });

  // killchain pipeline
  const ks = $("ov-kc-stages");
  D.killchain.forEach((st, i) => ks.appendChild(kcStageEl(i, st)));
  renderKc();
}

/* ------------------------------------------------------------- controls */
function engineQueued(what) {
  const v = $("verdict");
  v.className = "warn";
  v.innerHTML = `<span class="vtag" style="color:#1a1205;background:var(--warn)">BOOTING</span>` +
    `<span class="vmsg dim">CPython/WASM engine still loading (${what} queued) — it will start on its ` +
    `own the moment the engine is ready. Watch the engine pill up top for progress.</span>`;
}
function runPoc(file, stayInIdx) {
  if (engineOffline()) { engineReadOnly(); return; }
  if (!S.engineReady) { S.pending = { kind: "run", file, stayInIdx }; engineQueued("this PoC run"); return; }
  try { const b = $("idx-run"); if (b) b.classList.remove("coach"); } catch (_) {}
  if (S.running || S.sweep.active) return;
  const meta = pocMeta(file);
  if (!meta) return;
  S.curPoc = file;
  setRunning(true);
  S.condensed = false;
  S.frames = [];
  S.frameCount = 0;
  S.elided = 0;
  S.selected = -1;
  $("stream").innerHTML = "";
  $("console").innerHTML = "";
  pillReset("stream"); pillReset("cons");
  $("inspector").classList.remove("open");
  $("inspector").innerHTML = "";
  const v = $("verdict");
  v.className = "";
  v.innerHTML = `<span class="vtag" style="color:var(--up);background:#0d2531">RUN</span>` +
    `<span class="vmsg dim">${esc(meta.id)} · ${esc(meta.title)} — executing unmodified PoC under CPython/WASM…</span>`;
  if (S.idxOpen && S.idxFile === file) {
    $("idx-console").innerHTML = "";
    pillReset("idx");
    const iv = $("idx-verdict");
    iv.className = "verdictbox";
    iv.innerHTML = `<span class="dim">RUN — ${esc(meta.id)} executing under CPython/WASM…</span>`;
  }
  if (file === "v136_gps_spoof_chain.py") {
    S.kc = { active: true, final: false,
             lit: [false, false, false, false, false],
             evi: [null, null, null, null, null] };
    renderKc();
  }
  const sel = $("pocsel");
  sel.value = file;
  S.worker.postMessage({ cmd: "run", poc: file, expect: meta.ev_md5 });
  if (!stayInIdx) setView("ops");
  updateFrameCount();
}

function tickLeds() {
  setLed("led-link", performance.now() - S.lastFrameAt < 2000 ? "on" : "off");
}
function setLed(id, cls) {
  const el = $(id);
  if (!el) return;
  const prev = el.className;
  const next = "led " + cls;
  if (prev !== next) el.className = next;
}

/* ----------------------------------------------------------- index view */
function idxMatches(p) {
  if (IDX.group && p.group !== IDX.group) return false;
  if (IDX.apid != null && !(D.poc_apids[p.file] || []).includes(IDX.apid)) return false;
  if (IDX.q) {
    const hay = (p.id + " " + p.title + " " + p.sparta + " " +
                 (p.summary || "") + " " + p.file).toLowerCase();
    if (!hay.includes(IDX.q)) return false;
  }
  return true;
}
function idxCard(p) {
  const c = document.createElement("div");
  c.className = "idxcard" + sevRail(p.severity);
  c.dataset.poc = p.file;
  c.tabIndex = 0;
  c.innerHTML =
    `<span class="ic-id">${p.id}</span>` +
    `<span>` +
    `<span class="ic-title">${esc(p.title)}</span>` +
    `<div class="ic-sum">${esc(p.summary || "")}</div>` +
    `<div class="ic-meta"><span class="sevchip ${sevClass(p.severity)}" title="${esc(p.severity)} — severity as rated in the finding writeup">${esc(sevWord(p.severity))}</span>` +
    `<span>${esc(p.sparta.split("·")[0].trim())}</span><span>ev ${short(p.ev_md5)}</span></div>` +
    `</span>` +
    `<span class="ic-actions"><button data-act="read">READ</button>` +
    `<button data-act="run" class="primary">RUN</button></span>`;
  c.onclick = () => openIdxDetail(p.file);
  c.querySelector('[data-act="read"]').onclick = (e) => {
    e.stopPropagation(); openIdxDetail(p.file);
  };
  c.querySelector('[data-act="run"]').onclick = (e) => {
    e.stopPropagation();
    openIdxDetail(p.file);
    runPoc(p.file, true);
  };
  return c;
}
function buildIndexCards() {
  const wrap = $("idx-cards");
  wrap.innerHTML = "";
  const list = D.pocs.filter(idxMatches);
  for (const p of list) wrap.appendChild(idxCard(p));
  if (!buildIndexCards.built) {
    buildIndexCards.built = true;
    wrap.querySelectorAll(".idxcard").forEach((el) => el.classList.add("rv"));
    revealAll(wrap);
  }
  const cnt = $("idx-count");
  if (cnt) cnt.textContent = `${list.length} / ${D.pocs.length}`;
}
function buildChips() {
  const wrap = $("idx-chips");
  wrap.innerHTML = "";
  const mk = (label, g) => {
    const c = document.createElement("button");
    c.className = "chip" + (IDX.group === g ? " on" : "");
    const n = g ? (D.group_counts[g] || 0) : D.pocs.length;
    const dot = g
      ? `<i style="display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:5px;vertical-align:1px;background:${FAM_C[g] || "var(--dim)"}"></i>`
      : "";
    c.innerHTML = `${dot}${label}<span class="cn">${n}</span>`;
    if (g) c.title = `SPARTA v3.2 family ${g} — ${GROUP_DESC[g] || ""} · ${n} findings — click to filter`;
    else c.title = "all 56 findings";
    c.onclick = () => {
      IDX.group = g;
      try { localStorage.setItem("fmc-idxg", g || ""); } catch (_) {}
      IDX.apid = null;
      buildChips();
      buildIndexCards();
    };
    wrap.appendChild(c);
  };
  mk("ALL", null);
  for (const g of Object.keys(D.group_counts).sort()) mk(g, g);
  if (IDX.apid != null) {
    const c = document.createElement("button");
    c.className = "chip on";
    c.textContent = "APID 0x" + IDX.apid.toString(16).toUpperCase() + " ✕";
    c.onclick = () => {
      IDX.apid = null;
      buildChips();
      buildIndexCards();
    };
    wrap.appendChild(c);
  }
  const cnt = document.createElement("span");
  cnt.id = "idx-count";
  wrap.appendChild(cnt);
  buildIndexCards();
}
function openIndexFiltered(f) {
  closeIdxDetail();
  IDX.group = f.group || null;
  IDX.apid = f.apid != null ? f.apid : null;
  IDX.q = "";
  $("idx-search").value = "";
  buildChips();
  setView("index");
}

/* ------------------------------------------------ markdown renderer */
let tocHeads = [];
function mdInline(s) {
  // s is HTML-escaped; returns inline HTML
  const codes = [];
  let out = s;
  out = out.replace(/`([^`]+)`/g, (m, c) => {
    codes.push(c);
    return "\u0000" + (codes.length - 1) + "\u0000";
  });
  out = out.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
  out = out.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, "$1<i>$2</i>");
  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g,
    (m, t, u) => `<span class="mdl" title="${u}">${t}</span>`);
  out = out.replace(/\u0000(\d+)\u0000/g, (m, i) => `<code>${codes[+i]}</code>`);
  return out;
}
function H(t) { return mdInline(esc(t)); }

/* -------------------------------------------------- mermaid (offline-first)
   Vendored mermaid 11 (MIT) is baked into the bundle as D.mermaid_src and
   evaluated ONLY when a diagram is first shown — no boot cost, no CDN, works
   offline. A failed parse or eval keeps the raw source block: the document
   never breaks because of a diagram. */
const MMD = { ready: null, seq: 0 };
function mmdLoad() {
  if (MMD.ready) return MMD.ready;
  MMD.ready = new Promise((res, rej) => {
    if (window.mermaid) { res(window.mermaid); return; }
    // inline scripts evaluate synchronously on appendChild and their load
    // event is unreliable — evaluate, then take the global it just defined
    try {
      const s = document.createElement("script");
      s.textContent = D.mermaid_src;
      document.head.appendChild(s);
      if (!window.mermaid) throw new Error("mermaid global missing");
      {
        window.mermaid.initialize({
          startOnLoad: false, securityLevel: "strict",
          theme: "base", fontFamily: "Inter, system-ui, sans-serif",
          themeVariables: {
            background: "#0b1120", primaryColor: "#12203a",
            primaryBorderColor: "#4cc9f0", primaryTextColor: "#dbe6f5",
            secondaryColor: "#1a2540", tertiaryColor: "#0f1830",
            lineColor: "#7d93b0", edgeLabelBackground: "#0b1120",
            clusterBkg: "rgba(76,201,240,.05)", clusterBorder: "rgba(76,201,240,.35)",
            actorBkg: "#12203a", actorBorder: "#4cc9f0", actorTextColor: "#dbe6f5",
            actorLineColor: "#7d93b0", signalColor: "#a8bdd8",
            signalTextColor: "#dbe6f5", labelBoxBkgColor: "#12203a",
            labelBoxBorderColor: "#4cc9f0", labelTextColor: "#dbe6f5",
            noteBkgColor: "#16233c", noteTextColor: "#dbe6f5",
            noteBorderColor: "#4a5f80", activationBkgColor: "#1a2540",
            sequenceNumberColor: "#0b1120",
          },
        });
        res(window.mermaid);
      }
    } catch (e) { MMD.ready = null; rej(e); }
  });
  return MMD.ready;
}
async function mmdRenderAll(root) {
  const blocks = Array.prototype.slice.call(root.querySelectorAll("div.mmd"));
  if (!blocks.length) return;
  let m;
  try { m = await mmdLoad(); }
  catch (e) { blocks.forEach((x) => x.classList.add("mmd-fail")); return; }
  for (const blk of blocks) {
    if (!blk.isConnected) continue;
    blk.classList.add("mmd-run");
    try {
      const srcEl = blk.querySelector("code");
      const { svg } = await m.render(
        "fmc-mmd-" + (++MMD.seq), (srcEl ? srcEl.textContent : blk.dataset.code) || "");
      const wrap = document.createElement("div");
      wrap.className = "mmd-svg";
      wrap.innerHTML = svg;
      const sv = wrap.querySelector("svg");
      if (sv) { sv.removeAttribute("height"); sv.style.maxWidth = "100%"; sv.style.height = "auto"; }
      blk.replaceWith(wrap);
    } catch (e) {
      blk.classList.remove("mmd-run");
      blk.classList.add("mmd-fail");
    }
  }
}

function mdRender(md) {
  tocHeads = [];
  let hcount = 0;
  let html = "";
  let para = [], list = null, quote = [], table = [], code = null, codeLang = "";
  const flushPara = () => {
    if (para.length) { html += `<p>${H(para.join(" "))}</p>`; para = []; }
  };
  const flushList = () => {
    if (list) {
      html += `<${list.t}>` +
        list.items.map((x) => `<li>${H(x)}</li>`).join("") + `</${list.t}>`;
      list = null;
    }
  };
  const flushQuote = () => {
    if (quote.length) { html += `<blockquote>${H(quote.join(" "))}</blockquote>`; quote = []; }
  };
  const flushTable = () => {
    if (!table.length) return;
    const rows = table.filter((row, i) =>
      !(i === 1 && /^[\s|:-]+$/.test(row)));
    if (rows.length) {
      let t = "<table>";
      rows.forEach((row, ri) => {
        const cells = row.replace(/^\|/, "").replace(/\|$/, "")
          .split("|").map((c) => c.trim());
        const tag = ri === 0 ? "th" : "td";
        t += "<tr>" + cells.map((c) => `<${tag}>${H(c)}</${tag}>`).join("") + "</tr>";
      });
      html += t + "</table>";
    }
    table = [];
  };
  for (const raw of md.replace(/\r\n/g, "\n").split("\n")) {
    if (code !== null) {
      if (raw.trimStart().startsWith("```")) {
        if (codeLang === "mermaid") {
          const src = esc(code.join("\n"));
          html += `<div class="mmd" data-code="${src}">` +
            `<pre class="mmd-src"><code>${src}</code></pre></div>`;
        } else {
          html += `<div class="codewrap"><pre><code>${esc(code.join("\n"))}</code></pre>` +
            (codeLang ? `<span class="clang">${esc(codeLang)}</span>` : "") + `</div>`;
        }
        code = null;
      } else {
        code.push(raw);
      }
      continue;
    }
    if (raw.trimStart().startsWith("```")) {
      flushPara(); flushList(); flushQuote(); flushTable();
      code = [];
      codeLang = raw.trim().slice(3).trim().split(/\s+/)[0] || "";
      continue;
    }
    if (!raw.trim()) {
      flushPara(); flushList(); flushQuote(); flushTable();
      continue;
    }
    const hm = raw.match(/^(#{1,4})\s+(.*)$/);
    if (hm) {
      flushPara(); flushList(); flushQuote(); flushTable();
      const lvl = hm[1].length;
      const txt = hm[2].trim();
      const id = "md-h-" + (++hcount);
      if (lvl === 2) tocHeads.push({ id, txt });
      html += `<h${lvl} id="${id}">${H(txt)}</h${lvl}>`;
      continue;
    }
    if (/^\s{0,3}(-{3,}|\*{3,})\s*$/.test(raw)) {
      flushPara(); flushList(); flushQuote(); flushTable();
      html += "<hr>";
      continue;
    }
    const qm = raw.match(/^\s{0,3}>\s?(.*)$/);
    if (qm) { flushPara(); flushList(); flushTable(); quote.push(qm[1]); continue; }
    if (raw.trimStart().startsWith("|")) {
      flushPara(); flushList(); flushQuote();
      table.push(raw.trim());
      continue;
    }
    const lm = raw.match(/^\s*([-*]|\d+[.)])\s+(.*)$/);
    if (lm) {
      flushPara(); flushTable(); flushQuote();
      const t = /^\d/.test(lm[1]) ? "ol" : "ul";
      if (!list || list.t !== t) { flushList(); list = { t, items: [] }; }
      list.items.push(lm[2]);
      continue;
    }
    para.push(raw.trim());
  }
  flushPara(); flushList(); flushQuote(); flushTable();
  if (code !== null)
    html += `<div class="codewrap"><pre><code>${esc(code.join("\n"))}</code></pre>` +
      (codeLang ? `<span class="clang">${esc(codeLang)}</span>` : "") + `</div>`;
  return `<div class="md">${html}</div>`;
}
function buildToc() {
  const nav = $("idx-toc");
  nav.innerHTML = "";
  tocAnchors = [];
  for (const hh of tocHeads) {
    const a = document.createElement("a");
    a.href = "#" + hh.id;
    a.textContent = hh.txt;
    a.title = hh.txt;
    a.onclick = (e) => {
      e.preventDefault();
      const el = document.getElementById(hh.id);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    };
    nav.appendChild(a);
    tocAnchors.push({ a, el: document.getElementById(hh.id) });
  }
  tocSpy();
}
// scrollspy: highlight the TOC entry for the section in view
let tocAnchors = [];
let tocSpyPending = false;
function tocSpy() {
  const doc = $("idx-doc");
  if (!doc || !tocAnchors.length) return;
  const dr = doc.getBoundingClientRect();
  const top = doc.scrollTop + 48;
  let act = -1;
  tocAnchors.forEach((t, i) => {
    if (!t.el) t.el = document.getElementById(t.a.hash.slice(1));
    if (t.el && t.el.getBoundingClientRect().top - dr.top + doc.scrollTop <= top)
      act = i;
  });
  tocAnchors.forEach((t, i) => t.a.classList.toggle("act", i === act));
}

/* ------------------------------------------------ index detail split */
function openIdxDetail(file) {
  try {
    const rec = (JSON.parse(localStorage.getItem("fmc-rec") || "[]")).filter((x) => x !== file);
    rec.unshift(file);
    localStorage.setItem("fmc-rec", JSON.stringify(rec.slice(0, 3)));
  } catch (_) {}
  const p = pocMeta(file);
  if (!p) return;
  S.idxOpen = true;
  S.idxFile = file;
  $("idx-catalog-view").classList.add("hidden");
  $("idx-detail").classList.remove("hidden");
  S.lastCard = document.activeElement instanceof Element ? document.activeElement.closest(".idxcard") : null;
  $("idx-back").focus({ preventScroll: true });
  $("idx-detail-id").textContent = p.id;
  $("idx-detail-title").textContent = p.title;
  const sev = $("idx-detail-sev");
  sev.textContent = sevWord(p.severity);
  sev.title = p.severity || "";
  sev.className = "sevchip " + sevClass(p.severity);
  $("idx-detail-meta").textContent =
    `${p.sparta} · ${p.file} · ev ${short(p.ev_md5)}`;
  $("idx-doc").innerHTML = mdRender(D.writeups[file] || "(writeup missing)");
  mmdRenderAll($("idx-doc"));
  glHint($("idx-doc"));
  try {
    if (!localStorage.getItem("fmc-coached")) {
      const rb = $("idx-run");
      rb.classList.add("coach");
      setTimeout(() => rb.classList.remove("coach"), 7000);
      localStorage.setItem("fmc-coached", "1");
    }
  } catch (_) {}
  const sh = $("idx-share");
  if (sh) { sh.textContent = "SHARE ⧉"; sh.disabled = false; }
  buildToc();
  $("idx-doc").scrollTop = 0;
  const st = $("idx-stages");
  if (file === "v136_gps_spoof_chain.py") {
    st.classList.remove("hidden");
    st.innerHTML = "";
    D.killchain.forEach((s, i) => st.appendChild(kcStageEl(i, s)));
    renderKc();
  } else {
    st.classList.add("hidden");
    st.innerHTML = "";
  }
  $("idx-console").innerHTML = "";
  pillReset("idx");
  const v = $("idx-verdict");
  v.className = "verdictbox";
  v.innerHTML = `<span class="dim">standby — RUN LIVE to execute ${p.id} here</span>`;
  v.title = "A POC OK verdict means this browser run reproduces the committed simulator transcript byte-for-byte (normalised md5) — the same unmodified PoC also passed on the real FlatSat 1 board.";
  $("idx-live-foot").innerHTML =
    "provenance: fresh transcript md5 vs committed evidence/" +
    p.file.replace(/\.py$/, ".txt");
  setView("index");
}
function closeIdxDetail() {
  S.idxOpen = false;
  S.idxFile = null;
  $("idx-detail").classList.add("hidden");
  $("idx-catalog-view").classList.remove("hidden");
  if (S.lastCard && document.contains(S.lastCard)) S.lastCard.focus({ preventScroll: true });
  S.lastCard = null;
  setHash("#/index");
}

/* ------------------------------------------------- glossary + guided help
   Pedagogic layer: every acronym used on this console gets a plain-language
   definition, and one overlay explains how to read each view. Pure display —
   no engine state involved. */
const GLOSSARY = [
  ["AES-128", "Symmetric 128-bit block cipher. Both the legacy secure-link wrap and the SDLS session crypto here are AES-128; the link key is hardcoded in the firmware image, which is why the link is trust-but-verify, not trust.", "V0-02 · V-11"],
  ["APID", "Application Process Identifier — the 11-bit CCSDS address in every packet header, selecting the firmware handler. The 42-APID attack surface is mapped on the OVERVIEW panel.", "V0-01"],
  ["ARC", "Anti-Replay Counter — 16-bit volatile counter with a forward-only window (delta 1..+5) inside the SDLS security map; zeroed by RESETC and wraps at 65536, both of which reopen replays.", "V-07 · V-38"],
  ["bench / USB", "The physical debug cable between laptop and satellite (transcript frames are logged via=usb or via=radio). LAB_STATUS and LAB_CTRL answer over this transport even with the radio gate closed — the intentional bench backdoor.", "PER-0002"],
  ["CCSDS", "Consultative Committee for Space Data Systems — the body behind the packet and security standards this craft follows (SPP, SDLS).", ""],
  ["challenge / response", "GS_AUTH handshake: the craft issues a 32-bit challenge derived deterministically from telemetry (the RP2040 carries no qualified RNG), the ground answers challenge ⊕ GS_XOR_KEY. The XOR key is static and present in the image, so anyone who heard one exchange can answer forever.", "V0-06 · V-36"],
  ["CMAC", "Cipher-based Message Authentication Code — AES-based authenticity checksum used by the SDLS secured pilot channel.", ""],
  ["CTR mode", "AES counter mode — the block cipher used as a stream cipher, applied to telemetry when the DEF_TM_CTR defense is on (counter = packet count). Reusing a counter under the same key leaks; V-11 weaponises exactly that as an encryption oracle.", "V-11"],
  ["ECB mode", "Electronic Codebook — each 16-byte block encrypted independently (the legacy link wrap). Malleable: flipping a ciphertext bit flips the same plaintext bit, deterministically.", "V0-11"],
  ["evidence / transcript", "The exact console output a PoC produces. Committed twice per finding: evidence/ (simulator) and evidence-hw/ (real board) — 112 transcripts.", ""],
  ["FDIR", "Fault Detection, Isolation and Recovery — the craft's autonomous safety engine; its contingency dictionary is reprogrammable from the radio without authorisation.", "V-20"],
  ["FIPS-197 / SP800-38A/B", "The AES specification and its block-operation modes — the published test vectors the WASM boot self-test replays — the same ones the Python twin self-tests (the firmware side is gated by a host syntax check, not by test vect tests.", ""],
  ["GS / ground station", "The Earth station at 36.1699°, −115.1398°; the orbit model runs a 95-second period (eclipse / battery / tilt); the demo craft holds its beacon position, so the range window stays open.", ""],
  ["GS gate", "The 35 km range gate (GS_RADIUS_M) around the GS: GS arming and privileged telecommands are gated to this circle (0x10/0x12 and the USB backdoors bypass it) — the lock that the V-36 GPS spoof picks.", "V-36"],
  ["GS_XOR_KEY", "Static 32-bit constant (0xC0DEFACE) behind the ground-station handshake, present in the firmware image.", "V0-06"],
  ["hash md5 / parity", "One-way 128-bit fingerprint of bytes. A verdict 'POC OK · hash match' means the transcript produced in this browser has the same md5 as the committed simulator transcript — and the same unmodified PoC code additionally ran green on the physical board (bench parity, separate transcripts in evidence-hw/).", ""],
  ["LINK_KEY", "The AES-128 key of the secure link, hardcoded in the image ('PWNsatLabKey1234' on v0).", "V0-02"],
  ["LoRa", "Long Range low-power radio — the physical layer here (two SX1262 transceivers on the real board). Anyone with a receiver hears the uplink: the radio is a broadcast medium.", ""],
  ["MAC (auth)", "Message Authentication Code — cryptographic checksum proving integrity and origin; its absence is half of this catalog.", ""],
  ["NMEA", "The marine-born text GPS protocol (NMEA 0183, 1980s era); its parser takes an unvalidated position override — the door to every spoof here.", "V0-05 · V-36"],
  ["OTA / OTAR", "Over-The-Air Rekeying — the SDLS procedure to hand new keys to the craft remotely; here every master key is null and OTAR checks only the key index — any console can rekey the craft.", "V-10"],
  ["PoC", "Proof of Concept — a small script demonstrating a finding end-to-end on the wire. The 56 run in this browser exactly as committed, unmodified.", ""],
  ["Pyodide / WASM", "CPython compiled to WebAssembly: a real Python 3.12 interpreter inside your browser tab. Nothing is mocked — the demo imports the same simulator and PoC sources the CI runs.", ""],
  ["replay attack", "Resending a captured valid packet. With no timestamp or nonce the craft obeys again (V0-07); rolling the ARC back accepts a stale secured command (V-07).", "V0-07 · V-07"],
  ["SA / security association", "SDLS pairing of key + parameters (SA-0…SA-63 — 64 slots). OTAR-SET writes into the SA slot — and accepts null keys with no authorisation.", "V-10"],
  ["SDLS", "Space Data Link Security — the CCSDS standard for authenticated, encrypted space links, implemented here with several deliberate flaws.", ""],
  ["sec-hdr", "CCSDS secondary-header flag; on this craft a set flag on a PING marks a 'secured pilot' packet carrying the MAC.", ""],
  ["SPARTA", "Space Attack Research and Tactic Analysis — The Aerospace Corporation's space-cyber threat matrix (sparta.aerospace.org); every finding here is mapped to it. Families are the matrix tactics: REC Reconnaissance · EX Execution · IA Initial Access · DE Defense Evasion · PER Persistence · LM Lateral Movement · EXF Exfiltration (RD and IMP exist too; 7 of 9 appear in this catalog).", ""],
  ["SPP", "Space Packet Protocol — the CCSDS format: 6-byte primary header + data. Every frame in the OPS stream is decoded header-bit-by-header-bit from the raw wire bytes.", ""],
  ["TC / TM", "TeleCommand (uplink, ▲ amber) versus Telemetry (downlink, ▼ cyan).", ""],
  ["VTOR", "ARM Cortex-M register holding the interrupt vector-table base address; redirect it and every interrupt jumps into attacker code — a one-TC privilege escalation.", "V-14"],
];
function buildOverlays() {
  $("glossary-body").innerHTML = "<dl style='margin:0'>" + GLOSSARY.map(([k, d, ref]) =>
    `<div class="gl-term"><dt>${esc(k)}</dt><dd>${esc(d)}${ref ? `<span class="gl-ref">→ ${esc(ref)}</span>` : ""}</dd></div>`).join("") + "</dl>";
  $("help-body").innerHTML = `
    <div class="help-sec"><h3>WHAT THIS IS</h3><p>
      The complete attack lab of the FlatSat electr0sm0g Lab Version: 56 vulnerabilities, each proven by a PoC
      that is <b>byte-for-byte unmodified</b> — the same Python that drove the real RP2040 board runs
      here on CPython/WASM. A run passes only when its fresh transcript hashes (md5) to the committed
      evidence: <b>bench parity, in your browser</b>.</p></div>
    <div class="help-sec"><h3>THE FIVE VIEWS</h3>
      <p><b>OVERVIEW</b> — the A-to-Z explanation of what this project is: its FlatSat lineage (what
      the upstream platform is, what carries over, how this firmware flashes onto that same board),
      what is real and what is simulated, then the campaign at a glance: KPIs, the 42-APID attack
      surface, the 7 SPARTA tactics exercised here (of the matrix's 9), and the V-36 killchain that lights up live during a run.</p>
      <p><b>OPS</b> — mission control: the toolbar picks the target PoC and starts the run (RUN,
      full 56/56 SWEEP, playback speed); left, the spacecraft's internal state read from the live
      model; middle, every wire frame with a complete field-by-field decode; bottom, the PoC's own
      console and the parity verdict.</p>
      <p><b>INDEX</b> — the 56 findings as teach-up: Summary → Root cause → Attack mechanism →
      step-by-step walkthrough → Impact → Mitigations. RUN LIVE executes any of them here.</p>
      <p><b>REPORT</b> — the engagement report exactly as committed (impact, remediation, status per
      finding, severity filters) plus the full __PDF_PAGES__-page PDF in-page.</p>
      <p><b>REPO</b> — every interesting committed file, byte-identical with its md5 in the header:
      design docs, the 114 committed evidence transcripts (56 simulator + 56 hardware + 2 host checks), the firmware sources, the runnable Python.</p></div>
    <div class="help-sec"><h3>READING THE FRAME STREAM</h3>
      <div class="leg-row"><span class="leg-k" style="color:var(--dn)">▲ TC</span> uplink — a command sent to the craft</div>
      <div class="leg-row"><span class="leg-k" style="color:var(--up)">▼ TM</span> downlink — telemetry the craft emitted</div>
      <div class="leg-row"><span class="leg-k">AES / CLR</span> payload wrapped under the link key / cleartext on the wire</div>
      <div class="leg-row"><span class="leg-k">fdec block</span> the full decode: SPP header bits, security path, every payload field, hex + ASCII grids</div>
      <div class="leg-row"><span class="leg-k">⚠ amber</span> field involved in a named finding (the chip cites it)</div></div>
    <div class="help-sec"><h3>LIVE</h3><div class="help-keys">
      <kbd>▶</kbd><span>this console is the live lab: <a href="https://xenographic.org" target="_blank" rel="noopener">https://xenographic.org</a> — bookmark it, no install; source &amp; firmware download are linked in REPORT</span>
    </div></div>
    <div class="help-sec"><h3>KEYBOARD</h3><div class="help-keys">
      <kbd>1 / 2 / 3</kbd><span>switch OVERVIEW / OPS / INDEX</span>
      <kbd>4 / 5</kbd><span>open REPORT (engagement report) / REPO (docs, evidence, firmware, sources)</span>
      <kbd>R</kbd><span>run the PoC selected in the OPS toolbar</span>
      <kbd>/</kbd><span>jump to the index search box</span>
      <kbd>G</kbd><span>open / close this glossary</span>
      <kbd>?</kbd><span>open / close this help</span>
      <kbd>Esc</kbd><span>close the top-most overlay or detail pane</span>
    </div></div>`;
  const show = (id) => $(id).classList.remove("hidden");
  const hide = (id) => $(id).classList.add("hidden");
  $("btn-glossary").onclick = () => show("glossary");
  $("btn-help").onclick = () => show("helpov");
  document.querySelectorAll(".ov-close").forEach((b) =>
    b.onclick = () => hide(b.dataset.close));
  document.querySelectorAll(".overlay").forEach((ov) =>
    ov.addEventListener("click", (e) => { if (e.target === ov) ov.classList.add("hidden"); }));
  $("ov-start-go").onclick = () => { setView("index"); openIdxDetail("v136_gps_spoof_chain.py"); };
  $("ov-start-x").onclick = () => {
    $("ov-start").classList.add("hidden");
    try { localStorage.setItem("fmc-start-dismissed", "1"); } catch (_) {}
  };
  try { if (localStorage.getItem("fmc-start-dismissed")) $("ov-start").classList.add("hidden"); } catch (_) {}
}
/* ------------------------------------------------- command palette (Ctrl+K) */
const CMDK = { sel: 0, rows: [] };
let CMDK_ALL = null;
function cmdkCatalog() {
  if (CMDK_ALL) return CMDK_ALL;
  const it = [
    { g: "VIEWS", k: "1", label: "OVERVIEW — verified briefing & headline numbers", act: () => setView("overview") },
    { g: "VIEWS", k: "2", label: "OPS — live mission control, decoded frame by frame", act: () => setView("ops") },
    { g: "VIEWS", k: "3", label: "INDEX — the 56 findings, readable and runnable", act: () => setView("index") },
    { g: "VIEWS", k: "4", label: "REPORT — the engagement report as committed", act: () => setView("report") },
    { g: "VIEWS", k: "5", label: "REPO — browse the repository itself", act: () => setView("repo") },
    { g: "ACTIONS", k: "⚡", label: "Run the full sweep — 56 PoCs, one session", act: () => startSweep() },
    { g: "ACTIONS", k: "?", label: "Help — how to read this console", act: () => $("helpov").classList.remove("hidden") },
    { g: "ACTIONS", k: "g", label: "Glossary — every acronym in plain language", act: () => $("glossary").classList.remove("hidden") },
  ];
  try {
    for (const r of (JSON.parse(localStorage.getItem("fmc-rec") || "[]")).slice(0, 3)) {
      const p = D.pocs.find((x) => x.file === r);
      if (p) it.push({ g: "RECENT", k: p.id, label: p.title, act: () => { setView("index"); openIdxDetail(p.file); } });
    }
  } catch (_) {}
  for (const p of D.pocs)
    it.push({ g: "FINDINGS", k: p.id, label: p.title, act: () => { setView("index"); openIdxDetail(p.file); } });
  return (CMDK_ALL = it);
}
function cmdkRender(q) {
  const list = $("cmdk-list");
  q = (q || "").trim().toLowerCase();
  const hits = cmdkCatalog().filter((i) =>
    !q || i.label.toLowerCase().includes(q) || i.k.toLowerCase().includes(q));
  const cap = { VIEWS: 99, ACTIONS: 99, FINDINGS: 22 };
  const used = {};
  CMDK.rows = [];
  let html = "", group = null;
  for (const it of hits) {
    used[it.g] = (used[it.g] || 0) + 1;
    if (used[it.g] > cap[it.g]) continue;
    if (it.g !== group) { html += `<div class="ck-grp">${it.g}</div>`; group = it.g; }
    html += `<div class="ck-item" data-i="${CMDK.rows.length}"><kbd>${esc(it.k)}</kbd><span>${esc(it.label)}</span><em>↵</em></div>`;
    CMDK.rows.push(it);
  }
  list.innerHTML = html || `<div class="ck-none">no match — try “gps”, “replay”, “sweep”…</div>`;
  CMDK.sel = 0;
  cmdkPaint();
  list.querySelectorAll(".ck-item").forEach((el) => {
    el.onmouseenter = () => { CMDK.sel = +el.dataset.i; cmdkPaint(); };
    el.onclick = () => cmdkRun();
  });
}
function cmdkPaint() {
  const list = $("cmdk-list");
  list.querySelectorAll(".ck-item").forEach((el) =>
    el.classList.toggle("sel", +el.dataset.i === CMDK.sel));
  const cur = list.querySelector(".ck-item.sel");
  if (cur) cur.scrollIntoView({ block: "nearest" });
}
function cmdkRun() {
  const it = CMDK.rows[CMDK.sel];
  cmdkShow(false);
  if (it) it.act();
}
function cmdkShow(v) {
  const ov = $("cmdk");
  if (v) {
    $("cmdk-input").value = "";
    cmdkRender("");
    ov.classList.remove("hidden");
    CMDK.open = true;
    $("cmdk-input").focus();
  } else {
    ov.classList.add("hidden");
    CMDK.open = false;
  }
}
$("btn-cmdk").onclick = () => cmdkShow(true);
$("cmdk").onclick = (e) => { if (e.target === $("cmdk")) cmdkShow(false); };
$("cmdk-input").oninput = (e) => cmdkRender(e.target.value);
$("cmdk-input").onkeydown = (e) => {
  if (e.key === "ArrowDown") { e.preventDefault(); CMDK.sel = Math.min(CMDK.sel + 1, CMDK.rows.length - 1); cmdkPaint(); }
  else if (e.key === "ArrowUp") { e.preventDefault(); CMDK.sel = Math.max(CMDK.sel - 1, 0); cmdkPaint(); }
  else if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); cmdkRun(); }
  else if (e.key === "Escape") { e.stopPropagation(); cmdkShow(false); }
  else if (e.key === "Tab") { e.preventDefault(); CMDK.sel = Math.min(CMDK.sel + 1, CMDK.rows.length - 1); cmdkPaint(); }
};
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    cmdkShow($("cmdk").classList.contains("hidden"));
  }
}, true);

/* ------------------------------------------------- transcript comparison */
const TS_RE_JS = /^\[\s*\d+\.\d{3}\] (.*)$/;
function normLines(lines) {
  const out = [];
  for (const pl of lines.join("\n").split("\n")) {
    const m = TS_RE_JS.exec(pl);
    out.push(m ? m[1] : pl);
  }
  return out;
}
function openDiff(poc) {
  const meta = pocMeta(poc);
  const evPath = (meta && meta.ev_path) || "evidence/" + poc.replace(".py", ".txt");
  const pool = (D.repo || []).concat(D.files || []);
  const evFile = pool.find((f) => f.path === evPath) ||
    pool.find((f) => f.path.endsWith("/" + evPath));
  const left = normLines(S.runLines);
  // committed files keep raw wall-clock prefixes; normalize identically to the
  // hashing rule so the comparison shows what the md5 equality actually means
  const right = evFile ? normLines([evFile.text]) : [];
  const n = Math.max(left.length, right.length);
  let diff = 0, rows = "";
  for (let i = 0; i < n; i++) {
    const l = i < left.length ? left[i] : "";
    const r = i < right.length ? right[i] : "";
    const eq = l === r;
    if (!eq) diff++;
    rows += `<div class="dl ${eq ? "eq" : "ne"}"><span class="dn">${i + 1}</span>` +
      `<span class="dc l">${esc(l) || "&nbsp;"}</span><span class="dc r">${esc(r) || "&nbsp;"}</span></div>`;
  }
  const st = diff === 0
    ? `<b class="ok">byte-identical</b> · ${n} lines · 0 divergences`
    : `<b class="sp">${diff} / ${n} lines diverge</b> (normalisation: wall-clock prefixes)`;
  $("diff-sub").innerHTML = ` — live browser run vs <code>${evPath}</code> · ${st}`;
  $("diff-cols").innerHTML =
    `<div class="dheads"><span></span><span class="dcol-h">LIVE RUN — this browser (normalised)</span>` +
    `<span class="dcol-h r">COMMITTED — simulator transcript (bench parity: evidence-hw/)</span></div>` + rows;
  $("diff").classList.remove("hidden");
}
document.addEventListener("click", (e) => {
  if (e.target && e.target.id === "vdiff" && S.verdictInfo) openDiff(S.verdictInfo.poc);
  if (e.target && e.target.id === "cdn-retry") retryEngine();
});
$("diff-close").onclick = () => $("diff").classList.add("hidden");
$("diff").onclick = (e) => { if (e.target === $("diff")) $("diff").classList.add("hidden"); };

/* share: copy a deep link to the open finding (route already exists) */
$("idx-share").onclick = () => {
  const btn = $("idx-share");
  const url = location.origin + location.pathname + "#/index/" + S.idxFile;
  const done = () => { btn.textContent = "COPIED ✓"; setTimeout(() => { btn.textContent = "SHARE ⧉"; }, 1600); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(done, () => fallback());
  } else fallback();
  function fallback() {
    const ta = document.createElement("textarea");
    ta.value = url; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch (_) { btn.textContent = url.slice(0, 24) + "…"; }
    ta.remove();
  }
};

/* stream quick filters: visibility-only (independent of the TC/TM render gates) */
const SF = { errIdx: 0 };
function sfSet(mode) {
  const s = $("stream");
  ["fltq-tc", "fltq-tm", "fltq-err"].forEach((c) => s.classList.remove(c));
  if (mode === "tc") s.classList.add("fltq-tc");
  else if (mode === "tm") s.classList.add("fltq-tm");
  else if (mode === "err") s.classList.add("fltq-err");
  [["sf-all", "all"], ["sf-tc", "tc"], ["sf-tm", "tm"], ["sf-err", "err"]]
    .forEach(([id, m]) => $(id).classList.toggle("on", m === mode));
}
function nextErr() {
  const rows = Array.prototype.slice.call(document.querySelectorAll("#stream .fr.err"));
  if (!rows.length) return;
  const el = rows[SF.errIdx++ % rows.length];
  el.scrollIntoView({ block: "center", behavior: "smooth" });
  el.classList.add("jumped");
  setTimeout(() => el.classList.remove("jumped"), 1200);
  if (!el.parentElement.querySelector(".fdec.open")) el.click();
}
$("sf-all").onclick = () => sfSet("all");
$("sf-tc").onclick = () => sfSet("tc");
$("sf-tm").onclick = () => sfSet("tm");
$("sf-err").onclick = () => sfSet("err");
$("sf-next").onclick = () => nextErr();

/* glossary: first occurrence of each term gets a hover definition in place */
function glHint(root) {
  if (!root) return;
  try {
    const terms = GLOSSARY.map((g) => g[0])
      .sort((x, y) => y.length - x.length)
      .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    const re = new RegExp("\\b(" + terms.join("|") + ")\\b");
    const used = new Set();
    const marks = [];
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (w.nextNode()) {
      const n = w.currentNode;
      if (!re.test(n.nodeValue)) continue;
      const p = n.parentElement;
      if (!p || /CODE|KBD|BUTTON|A|SCRIPT/.test(p.tagName) || p.classList.contains("gl-hint")) continue;
      if (p.closest("svg")) continue;   // never annotate inside a rendered diagram
      marks.push(n);
    }
    for (const n of marks) {
      const m = re.exec(n.nodeValue);
      const term = m[1];
      if (used.has(term)) continue;
      used.add(term);
      const g = GLOSSARY.find((x) => x[0] === term);
      const def = g ? g[1] : "";
      const span = document.createElement("span");
      span.className = "gl-hint";
      span.tabIndex = 0;
      span.dataset.tip = def.length > 210 ? def.slice(0, 207) + "…" : def;
      span.textContent = term;
      const frag = document.createDocumentFragment();
      const before = n.nodeValue.slice(0, m.index);
      const after = n.nodeValue.slice(m.index + term.length);
      if (before) frag.appendChild(document.createTextNode(before));
      frag.appendChild(span);
      if (after) frag.appendChild(document.createTextNode(after));
      n.parentNode.replaceChild(frag, n);
    }
  } catch (_) { /* tooltips are progressive enhancement */ }
}

function overlayOpen() {
  const ids = ["glossary", "helpov", "catalog", "sweep", "diff"];
  for (const id of ids)
    if (!$(id).classList.contains("hidden")) return id;
  return null;
}

/* ------------------------------------------------------------- bindings */
function bindUI() {
  $("btn-run").onclick = () => runPoc($("pocsel").value);
  $("btn-sweep").onclick = startSweep;
  $("btn-pause").onclick = () => {
    S.paused = !S.paused;
    $("btn-pause").textContent = S.paused ? "▶" : "⏸";
    $("btn-pause").classList.toggle("on", S.paused);
  };
  $("btn-catalog").onclick = () => $("catalog").classList.remove("hidden");
  $("catalog-close").onclick = () => $("catalog").classList.add("hidden");
  $("sweep-close").onclick = () => $("sweep").classList.add("hidden");
  buildOverlays();
  $("autoscroll").onchange = () => { if ($("autoscroll").checked) { $("console").scrollTop = $("console").scrollHeight; pillHide("cons"); } };
  bindHoldScrollers();
  try {
    const sp0 = localStorage.getItem("fmc-speed");
    if (sp0) {
      const b0 = document.querySelector(`#speed button[data-sp="${sp0}"]`);
      if (b0) { b0.click(); }
    }
  } catch (_) {}
  document.querySelectorAll("#speed button").forEach((b) => {
    b.onclick = () => {
      S.speed = b.dataset.sp === "max" ? "max" : parseInt(b.dataset.sp, 10);
      document.querySelectorAll("#speed button").forEach((x) => x.classList.toggle("on", x === b));
      try { localStorage.setItem("fmc-speed", b.dataset.sp); } catch (_) {}
    };
  });
  // view tabs
  document.querySelectorAll("#views-nav button[data-view]").forEach((b) => {
    b.onclick = () => setView(b.dataset.view);
  });
  // overview killchain CTA
  $("btn-chain").onclick = () => {
    openIdxDetail("v136_gps_spoof_chain.py");
    runPoc("v136_gps_spoof_chain.py", true);
  };
  // index controls
  $("idx-back").onclick = () => closeIdxDetail();
{ // swipe left → back to the catalog (native-feeling mobile navigation)
  let x0 = 0, y0 = 0, t0 = 0;
  const dd = $("idx-detail");
  dd.addEventListener("touchstart", (e) => {
    const t = e.touches[0]; x0 = t && e.touches.length === 1 ? t.clientX : 0; y0 = t ? t.clientY : 0; t0 = Date.now();
  }, { passive: true });
  dd.addEventListener("touchend", (e) => {
    if (!x0 || !S.idxOpen) { x0 = 0; return; }
    const t = e.changedTouches[0], dx = t.clientX - x0, dy = t.clientY - y0;
    x0 = 0;
    if (e.target.closest("table, .mmd-svg, pre, [style*=overflow]")) return;
    if (dx < -70 && Math.abs(dy) < 45 && Date.now() - t0 < 600) closeIdxDetail();
  }, { passive: true });
}
  $("idx-run").onclick = () => { if (S.idxFile) runPoc(S.idxFile, true); };
  $("idx-src").onclick = () => {
    if (S.idxFile) openRepoPath("poc/" + S.idxFile);
  };
  $("idx-ev").onclick = () => {
    if (S.idxFile)
      openRepoPath("evidence/" + S.idxFile.replace(/\.py$/, "") + ".txt");
  };
  $("idx-search").oninput = (e) => {
    IDX.q = e.target.value.trim().toLowerCase();
    buildIndexCards();
  };
  // PoC selector grouped by SPARTA family
  const sel = $("pocsel");
  const groups = {};
  for (const p of D.pocs) (groups[p.group] = groups[p.group] || []).push(p);
  for (const g of Object.keys(groups).sort()) {
    const og = document.createElement("optgroup");
    og.label = `${g} — ${GROUP_DESC[g] || ""}`;
    groups[g].slice().sort((a, b) => a.id.localeCompare(b.id)).forEach((p) => {
      const o = document.createElement("option");
      o.value = p.file;
      o.textContent = `${p.id} · ${p.title.slice(0, 52)}${p.hero ? " ★" : ""}`;
      og.appendChild(o);
    });
    sel.appendChild(og);
  }
  sel.value = D.pocs.find((p) => p.hero)?.file || D.pocs[0].file;

  // TOC scrollspy (doc pane scrolls → highlight the visible section)
  $("idx-doc").addEventListener("scroll", () => {
    if (tocSpyPending) return;
    tocSpyPending = true;
    requestAnimationFrame(() => { tocSpyPending = false; tocSpy(); });
  });

  // deep links: #/overview · #/ops · #/index · #/index/<poc-file>
  window.addEventListener("hashchange", () => { applyRoute(); });

  // keyboard: "/" focuses the index search, Esc closes overlays
  document.addEventListener("keydown", (e) => {
    const tag = (document.activeElement || {}).tagName;
    const typing = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
    if (e.key === "/" && !typing) {
      e.preventDefault();
      if (S.idxOpen) closeIdxDetail();
      setView("index");
      $("idx-search").focus();
    } else if (e.key === "Escape") {
      const ov = overlayOpen();
      if (ov === "sweep" && S.sweep.active) $("sweep").classList.add("hidden");
      else if (ov) $("" + ov).classList.add("hidden");
      else if (S.idxOpen) closeIdxDetail();
    } else if (!typing && !overlayOpen()) {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        const cs = Array.prototype.slice.call(document.querySelectorAll(".idxcard"));
        if (S.view === "index" && !S.idxOpen && cs.length) {
          e.preventDefault();
          const i = cs.indexOf(document.activeElement);
          const j = i < 0 ? 0 : Math.max(0, Math.min(cs.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)));
          cs[j].focus();
        }
      } else if (e.key === "Enter" && (document.activeElement || {}).classList
                 && document.activeElement.classList.contains("idxcard")) {
        document.activeElement.click();
      } else if (e.key === "n") { nextErr(); }
      else if (e.key === "1") setView("overview");
      else if (e.key === "2") setView("ops");
      else if (e.key === "3") setView("index");
      else if (e.key === "4") setView("report");
      else if (e.key === "5") setView("repo");
      else if (e.key === "r" && !S.running && !S.sweep.active && S.booted) {
        const ae = document.activeElement || {};
        const card = ae.classList && ae.classList.contains("idxcard") ? ae : null;
        runPoc(card ? card.dataset.poc : $("pocsel").value);
      }
      else if (e.key === "g") $("glossary").classList.toggle("hidden");
      else if (e.key === "?") $("helpov").classList.toggle("hidden");
    }
  });
}

/* ============================================================ REPORT view
   The engagement report rendered verbatim from the embedded
   reports/pentest-report.json — every finding with impact, PoC steps,
   remediation, and one-click jumps to the live PoC, writeup, source and
   committed bench evidence. */
const RPT = { sev: null, q: "" };
function ensureReport() {
  if (ensureReport.done || !D || !D.report) return;
  ensureReport.done = true;
  const R = D.report, eng = R.engagement, st = R.statistics;
  const pdf = "data:application/pdf;base64," + D.pdf_b64;
  const w = $("report-wrap");
  const chip = (n, sev, cls) =>
    `<button class="rpt-sev ${cls}" data-sev="${sev}" title="filter by ${sev}">${n} ${sev}</button>`;
  w.innerHTML =
    `<div id="rpt-head" class="panel">
      <div class="colhead">ENGAGEMENT REPORT
        <span class="dim">— verbatim reports/pentest-report.json</span></div>
      <div class="eyebrow">engagement · ${esc(eng.dates)} · sparta v3.2 · ${D.report.findings.length} findings</div>
      <h1>${esc(eng.name)}</h1>
      <div class="rpt-eng">
        <div><span class="dim">target</span>&nbsp; ${esc(eng.target)}</div>
        <div><span class="dim">dates</span>&nbsp; ${esc(eng.dates)}
             &nbsp;·&nbsp; <span class="dim">status</span> ${esc(eng.status)}</div>
        <div><span class="dim">reporter</span>&nbsp; ${esc(eng.reporter)}</div>
      </div>
      <div id="rpt-stats">
        <span class="rpt-stat big"><b>${st.total}</b> findings</span>
        ${chip(st.critical, "CRITICAL", "crit")}
        ${chip(st.high, "HIGH", "high")}
        ${chip(st.medium, "MEDIUM", "med")}
        ${chip(st.low, "LOW", "low")}
        <span class="rpt-stat ok"><b>112 / 112</b> PoC runs verified — simulator
          + FlatSat 1 hardware</span>
        <span id="rpt-dl">
          <a id="rpt-pdf" href="${pdf}" download="FlatSat-Electr0sm0g-Lab-Pentest-Report.pdf"
             title="the full report as committed: reports/FlatSat-Electr0sm0g-Lab-Pentest-Report.pdf">⬇ FULL REPORT (PDF)</a>
          <a id="rpt-rel" href="https://github.com/electr0sm0g/flatsat-mission-control/releases/tag/v1.0.0"
             target="_blank" rel="noopener"
             title="GitHub release v1.0.0: flashable firmware.uf2 + md5sum.txt built by CI from this exact tag (final bench image H, md5 bfc145c9…, recorded in hw_pass.txt)">GitHub release v1.0.0 ↗</a>
        </span>
      </div>
      <div id="rpt-bar">${[["crit", st.critical], ["high", st.high], ["med", st.medium], ["low", st.low]]
        .map(([c, n]) => `<i class="${c}" style="flex:${n}"></i>`).join("")}</div>
    </div>
    <div id="rpt-controls">
      <input id="rpt-q" type="text" aria-label="filter the 56 findings" autocomplete="off" spellcheck="false"
        placeholder="filter findings — id, title, surface, description…">
      <span id="rpt-count" class="dim"></span>
    </div>
    <div id="rpt-list"></div>`;
  const filt = () => {
    const list = $("rpt-list");
    list.innerHTML = "";
    let n = 0;
    for (const f of R.findings) {
      if (RPT.sev && f.severity !== RPT.sev) continue;
      if (RPT.q) {
        const hay = (f.id + " " + f.title + " " + (f.affected_surface || "") +
          " " + (f.cwe || "") + " " + (f.description || "")).toLowerCase();
        if (!hay.includes(RPT.q)) continue;
      }
      list.appendChild(rptFinding(f));
      n++;
    }
    $("rpt-count").textContent = n + " / " + R.findings.length + " findings";
  };
  w.querySelectorAll(".rpt-sev").forEach((b) => {
    b.onclick = () => {
      RPT.sev = b.dataset.sev === RPT.sev ? null : b.dataset.sev;
      w.querySelectorAll(".rpt-sev").forEach((x) =>
        x.classList.toggle("on", !!RPT.sev && x === b));
      filt();
    };
  });
  $("rpt-q").oninput = (e) => {
    RPT.q = e.target.value.trim().toLowerCase();
    filt();
  };
  filt();
}
function rptFinding(f) {
  const d = document.createElement("div");
  d.className = "rpt-f " + sevClass(f.severity);
  d.dataset.sev = f.severity;
  const p = (D.pocs || []).find((x) => x.id === f.id);
  const imp = f.impact || {};
  const impCell = (k, v) => v
    ? `<div class="rpt-imp"><span class="dim">${esc(k.replace(/_/g, " "))}</span>` +
      `<span class="sevchip ${sevClass(v)}">${esc(sevWord(v))}</span></div>` : "";
  const li = (a) => (a || []).map((s) => `<li>${esc(s)}</li>`).join("");
  const rem = f.remediation || {};
  d.innerHTML =
    `<div class="rpt-f-head">
      <span class="ic-id">${esc(f.id)}</span>
      <span class="sevchip ${sevClass(f.severity)}">${esc(sevWord(f.severity))}</span>
      <span class="rpt-f-title">${esc(f.title)}</span>
      <span class="rpt-status ${f.remediation_status === "open" ? "open" : ""}">${esc(f.remediation_status || "")}</span>
     </div>
     <div class="rpt-f-meta dim">${[f.sparta_risk, f.affected_surface, f.cwe, f.owasp].filter(x => x && x !== "—").map(esc).join(" · ")}` +
      (f.cvss_score ? ` · CVSS ${esc(String(f.cvss_score))}` : "") +
      (f.poc_verified ? ` · <span class="rpt-ok">PoC verified on simulator AND hardware</span>` : "") +
     `</div>
     <p class="rpt-desc">${esc(f.description || "")}</p>
     <div class="rpt-cols">
       <div><h4>IMPACT</h4>
         ${["confidentiality", "integrity", "availability", "business_impact"]
           .map((k) => impCell(k, imp[k])).join("")}</div>
       <div><h4>PROOF OF CONCEPT</h4>
         <ol class="rpt-ol">${li(f.poc_steps)}</ol>
         ${p ? `<div class="rpt-actions">
           <button data-act="run" class="primary">RUN POC ▸</button>
           <button data-act="writeup">WRITEUP</button>
           <button data-act="src">SOURCE</button>
           <button data-act="ev">EVIDENCE</button></div>` : ""}</div>
       <div><h4>REMEDIATION <span class="dim">${esc(rem.priority || "")}</span></h4>
         <p class="rpt-desc">${esc(rem.fix_description || "")}</p>
         ${f.suggestions && f.suggestions.length ? `<h4>SEE ALSO</h4><ul class="rpt-ol">${li(f.suggestions)}</ul>` : ""}</div>
     </div>`;
  if (p) {
    d.querySelector('[data-act="run"]').onclick =
      () => { setView("index"); openIdxDetail(p.file); runPoc(p.file, true); };
    d.querySelector('[data-act="writeup"]').onclick =
      () => { setView("index"); openIdxDetail(p.file); };
    d.querySelector('[data-act="src"]').onclick =
      () => openRepoPath("poc/" + p.file);
    d.querySelector('[data-act="ev"]').onclick =
      () => openRepoPath("evidence/" + p.file.replace(/\.py$/, "") + ".txt");
  }
  return d;
}

/* =============================================================== REPO view
   Byte-identical browser over the repository itself: the 12 docs, the 114
   committed evidence transcripts, the vulnerable-by-design firmware
   sources, the runnable Python (simulator / fslab / harness / 56 PoCs —
   the exact bytes the worker executes), FINDINGS.json, README, the talk
   and the PDF report. Each file shows the committed md5. */
const REPO = { list: [], sec: {}, cur: null };
function repoRunnables() {
  const out = [];
  for (const f of D.files || []) {
    const path = f.path.replace(/^\/repo\//, "");
    const base = path.split("/").pop();
    let md5 = "";
    if (base === "flatsat_sim.py") md5 = D.md5.sim;
    else if (base === "fslab.py") md5 = D.md5.fslab;
    else if (base === "harness.py") md5 = D.md5.harness;
    else {
      const p = (D.pocs || []).find((x) => x.file === base);
      if (p) md5 = p.src_md5;
    }
    out.push({ sec: "RUNNABLE CODE", path, name: base, kind: "code",
               size: f.content.length, md5, text: f.content });
  }
  return out;
}
function ensureRepo() {
  if (ensureRepo.done || !D || !D.repo) return;
  ensureRepo.done = true;
  const pdfEntry = { sec: "REPORTS", kind: "pdf",
    path: "reports/FlatSat-Electr0sm0g-Lab-Pentest-Report.pdf",
    name: "FlatSat-Electr0sm0g-Lab-Pentest-Report.pdf",
    size: Math.round(D.pdf_b64.length * 3 / 4), md5: "" };
  REPO.list = D.repo.concat(repoRunnables(), [pdfEntry]);
  const order = ["GUIDE", "DOCUMENTATION", "EVIDENCE", "FIRMWARE",
                 "RUNNABLE CODE", "REPORTS"];
  const tree = $("repo-tree");
  tree.innerHTML = "";
  for (const sec of order) {
    const files = REPO.list.filter((f) => f.sec === sec);
    if (!files.length) continue;
    const head = document.createElement("button");
    head.className = "repo-sec";
    head.innerHTML = `<i class="chev">▾</i>${esc(sec)} <span class="rc">${files.length}</span>`;
    const box = document.createElement("div");
    box.className = "repo-files";
    for (const f of files) {
      const b = document.createElement("button");
      b.className = "repo-f";
      b.dataset.path = f.path;
      b.title = f.path + " — " + f.size.toLocaleString("en-US") + " bytes" +
        (f.md5 ? " · md5 " + f.md5 : "");
      b.innerHTML = `<span class="rf-name">${esc(f.name)}</span>` +
        `<span class="rf-size">${f.size > 1023 ? Math.round(f.size / 1024) + "K" : f.size + "B"}</span>`;
      b.onclick = () => { setView("repo"); openRepoFile(f); };
      box.appendChild(b);
    }
    if (sec === "EVIDENCE" || sec === "FIRMWARE" || sec === "RUNNABLE CODE")
      box.classList.add("collapsed");
    head.onclick = () => box.classList.toggle("collapsed");
    REPO.sec[sec] = { head, box };
    tree.appendChild(head);
    tree.appendChild(box);
  }
  $("repo-search").oninput = (e) => {
    const q = e.target.value.trim().toLowerCase();
    for (const sec in REPO.sec) {
      const box = REPO.sec[sec].box;
      let hits = 0;
      box.querySelectorAll(".repo-f").forEach((b) => {
        const hit = !q || b.dataset.path.toLowerCase().includes(q);
        b.style.display = hit ? "" : "none";
        if (hit) hits++;
      });
      if (q) box.classList.toggle("collapsed", hits === 0);
    }
  };
  openRepoFile(REPO.list.find((f) => f.path === "docs/THREAT-MODEL.md") ||
               REPO.list[0]);
}
function openRepoPath(path) {
  ensureRepo();
  if (!ensureRepo.done) return;
  const f = REPO.list.find((x) => x.path === path);
  if (f) { setView("repo"); openRepoFile(f); }
}
function REPO_OPEN(path) { openRepoPath(path); }
function openRepoFile(f) {
  // hash-driven re-entry guard: same file, hash already points at it
  if (REPO.cur === f && location.hash === "#/repo/" + f.path) return;
  REPO.cur = f;
  document.querySelectorAll(".repo-f.on").forEach((b) => b.classList.remove("on"));
  const btn = document.querySelector('.repo-f[data-path="' + f.path + '"]');
  if (btn) {
    btn.classList.add("on");
    if (btn.parentElement.classList.contains("collapsed"))
      btn.parentElement.classList.remove("collapsed");
  }
  setHash("#/repo/" + f.path);
  $("repo-path").textContent = f.path;
  const nlines = f.text ? f.text.split("\n").length : 0;
  $("repo-info").textContent =
    f.size.toLocaleString("en-US") + " bytes" +
    (nlines ? " · " + nlines.toLocaleString("en-US") + " lines" : "") +
    (f.md5 ? " · md5 " + f.md5 : "");
  const dl = $("repo-download");
  dl.href = f.kind === "pdf"
    ? "data:application/pdf;base64," + D.pdf_b64
    : "data:text/plain;charset=utf-8," + encodeURIComponent(f.text || "");
  dl.download = f.name;
  dl.classList.remove("hidden");
  const body = $("repo-body");
  body.innerHTML = "";
  if (f.kind === "md") {
    const art = document.createElement("article");
    art.className = "repo-md";
    art.innerHTML = mdRender(f.text);
    body.appendChild(art);
    mmdRenderAll(art);
  } else if (f.kind === "json") {
    let pretty = f.text;
    try { pretty = JSON.stringify(JSON.parse(f.text), null, 2); } catch (e) {}
    body.appendChild(repoPre(pretty));
  } else if (f.kind === "html") {
    const fr = document.createElement("iframe");
    fr.className = "repo-html";
    fr.setAttribute("sandbox", "allow-scripts");
    fr.srcdoc = f.text;
    body.appendChild(fr);
  } else if (f.kind === "pdf") {
    const em = document.createElement("embed");
    em.src = "data:application/pdf;base64," + D.pdf_b64;
    em.type = "application/pdf";
    body.appendChild(em);
  } else {
    body.appendChild(repoPre(f.text || ""));
  }
  body.scrollTop = 0;
}
function repoPre(text) {
  const pre = document.createElement("pre");
  pre.className = "repo-pre";
  const lines = text.split("\n");
  let html = "";
  for (let i = 0; i < lines.length; i++)
    html += `<span class="rl"><i>${i + 1}</i>${esc(lines[i]) || " "}</span>`;
  pre.innerHTML = html;
  return pre;
}

/* ------------------------------------------------------------------ init */
window.__run = (file) => runPoc(file);
window.__STATE = () => ({
  booted: S.booted, frames: S.frameCount, running: S.running,
  verdict: S.verdictInfo, buf: S.buf.length,
  view: S.view,
  orb: {
    pts: ORB.pts.length,
    cur: ORB.cur ? {
      dist_m: ORB.cur.dist_m,
      eclipse: ORB.cur.eclipse,
      phase: +Math.min(1, ORB.cur.orbit_s / D.orbit_period).toFixed(3),
    } : null,
  },
  kc: S.kc.lit.filter(Boolean).length,
  idxCards: document.querySelectorAll("#idx-cards .idxcard").length,
  idxOpen: S.idxOpen,
});
buildTiles();
buildCatalog();
buildOverview();
buildChips();
initWhy();
bindUI();
bootInit();
// reveal-on-scroll for the showcase surfaces (ops console stays raw)
document.querySelectorAll("#view-overview .panel, #idx-intro")
  .forEach((el) => el.classList.add("rv"));
revealAll(document.getElementById("view-overview"));
revealAll(document.getElementById("view-index"));
if (!applyRoute()) {
  let v0 = "overview";
  try { const s = localStorage.getItem("fmc-view"); if (s) v0 = s; } catch (_) {}
  setView(v0);
}
bootWorker();
})();
