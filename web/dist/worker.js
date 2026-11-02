// SPDX-License-Identifier: GPL-2.0-or-later
//
// worker.js -- Pyodide host for the flatsat-electr0sm0g lab browser demo.
//
// Runs in a Web Worker so the main thread (UI) stays responsive while the
// UNMODIFIED simulator + PoC code executes in CPython/WASM. Events emitted
// by web/harness.py (wire frames, state snapshots, transcript lines,
// verdicts) are forwarded to the page as messages in order.
//
// Pyodide is pinned (no floating CDN): v0.27.4. Three equivalent origins are
// tried in order with a per-origin timeout — hardened browsers (Mullvad,
// Brave, Pi-hole/DNS filters) sometimes block or black-hole one hostname
// while another serves the exact same bytes.
"use strict";

const PYODIDE_CDNS = [
  "https://cdn.jsdelivr.net/pyodide/v0.27.4/full/",
  "https://unpkg.com/pyodide@0.27.4/",
  "https://fastly.jsdelivr.net/pyodide/v0.27.4/full/",
];
let CDN_BASE = null; // set by boot() to the first origin that answered

// fetch + eval instead of importScripts: gives an abortable timeout so a
// sinkholed (never-answering) CDN cannot hang the worker forever.
async function tryCdn(base, ms) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(base + "pyodide.js", { signal: ctl.signal, mode: "cors" });
    if (!r.ok) return false;
    (0, eval)(await r.text()); // UMD: defines self.loadPyodide, like importScripts
    return typeof self.loadPyodide === "function";
  } catch (e) {
    return false;
  } finally {
    clearTimeout(t);
  }
}

// CDN_OK is decided during boot (the first init message), not at eval time.
let CDN_OK = true;

let py = null;

// harness.py pushes events through this global (json string).
self.__emit = function (s) {
  let ev;
  try { ev = JSON.parse(s); }
  catch (e) {
    self.postMessage({ t: "emitfail", err: String(e), s: String(s).slice(0, 160) });
    return;
  }
  self.postMessage(ev);
};

// The boot is a long await. Commands that arrive while it runs MUST be
// serialised behind it — clicking RUN during boot used to reach a null
// `py`, raise, and leave the UI with a stuck FAULT verdict.
let readyP = null;

self.onmessage = async function (e) {
  const m = e.data;
  if (m.cmd === "init") {
    if (!CDN_OK || readyP) return;
    readyP = (async () => {
      self.postMessage({ t: "boot_step", step: 1, label: "fetching python runtime" });
      for (const base of PYODIDE_CDNS) {
        if (await tryCdn(base, 12000)) { CDN_BASE = base; break; }
      }
      if (!CDN_BASE) {
        CDN_OK = false;
        self.postMessage({ t: "cdndown", e: "no pyodide CDN answered" });
        return;
      }
      py = await loadPyodide({ indexURL: CDN_BASE });
      self.postMessage({ t: "boot_step", step: 2, label: "CPython up — mounting sources" });
      for (const f of m.files) {
        const dir = f.path.slice(0, f.path.lastIndexOf("/"));
        if (dir) py.FS.mkdirTree(dir);
        py.FS.writeFile(f.path, f.content);
      }
      py.runPython(
        "import builtins, js, sys; " +
        "builtins.__worker_emit = js.__emit; " +
        'sys.path.insert(0, "/repo/web"); ' +
        'import harness; harness.install()'
      );
      self.postMessage({ t: "boot_step", step: 3, label: "harness ready" });
      self.postMessage({
        t: "boot",
        py: py.runPython("import sys; sys.version.split()[0]"),
      });
    })();
    // report a boot failure once; later commands drop quietly (banner already shown)
    readyP.catch((err) =>
      self.postMessage({ t: "fatal", e: "engine boot: " + String((err && err.message) || err) }));
    return;
  }
  if (!CDN_OK || !readyP) return; // engine unavailable, or init was never sent
  try {
    await readyP; // everything below runs strictly after boot completed
    if (!py) return; // boot ended without an engine (cdndown) — banner already shown
    if (m.cmd === "selftest") {
      const out = py.runPython("import harness; harness.do_selftest()");
      self.postMessage({ t: "selftest", out: String(out) });
    } else if (m.cmd === "run") {
      py.runPython(
        "import harness; harness.run_poc(" +
        JSON.stringify(m.poc) + ", " + JSON.stringify(m.expect || "") + ")"
      );
    } else if (m.cmd === "sweep") {
      py.runPython(
        "import harness; harness.run_sweep(" +
        JSON.stringify(m.poc) + ", " + JSON.stringify(m.expect || {}) + ")"
      );
    } else if (m.cmd === "statekick") {
      // one real state snapshot for the OPS tiles (idle craft is real too)
      py.runPython("import harness; harness.idle_state()");
    } else if (m.cmd === "orbit") {
      // free-flight for the overview range scope (real FlatSatSim, frames off)
      py.runPython(
        "import harness; harness.run_orbit(" +
        JSON.stringify(m.orbits || 3) + ")"
      );
    }
  } catch (err) {
    self.postMessage({ t: "fatal", e: String((err && err.message) || err) });
  }
};
