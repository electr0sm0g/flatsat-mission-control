// SPDX-License-Identifier: GPL-2.0-or-later
//
// web_demo_test.mjs -- headless-Chromium verification of the in-browser demo.
//
// Serves web/dist (started by the CI job), boots the page, and asserts the
// claims of the demo itself:
//   1. the real simulator boots under Pyodide (CPython/WASM) and its
//      self-test (FIPS-197 / SP800-38A/B / SDLS / OTAR) passes;
//   2. the unmodified PoCs v101 (V-01) and v136 (V-36) execute and the UI
//      verdict reports POC OK with the transcript md5 matching the
//      committed evidence digest (the parity proof);
//   3. the live frame stream and the state tiles actually render, every
//      frame carrying an exhaustive decode block, with the pedagogic
//      overlays (glossary, help, start-here) built.
//
// Usage: node web_demo_test.mjs [url]     (default http://127.0.0.1:8931/)
import { chromium } from "playwright";

const url = process.argv[2] || "http://127.0.0.1:8931/";
const log = (...a) => console.log("[webdemo]", ...a);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });

await page.goto(url, { waitUntil: "load", timeout: 60_000 });
log("page loaded — waiting for Pyodide boot + simulator self-test…");
await page.waitForFunction(
  () => window.__STATE && window.__STATE().booted,
  null,
  { timeout: 240_000, polling: 1_000 }
);
await page.waitForSelector("#selftest.ok", { timeout: 120_000 });
log("boot OK — simulator self-test OK (FIPS-197 / SP800-38A/B / SDLS / OTAR)");

async function runAndAssert(file) {
  const t0 = Date.now();
  await page.evaluate((f) => window.__run(f), file);
  await page.waitForFunction(
    (f) => {
      const v = window.__STATE().verdict;
      return v && v.poc === f;
    },
    file,
    { timeout: 300_000, polling: 500 }
  );
  // regression guard: the run must START promptly — an event-lane starvation
  // (e.g. orbit snapshots flooding the queue) used to delay first output ~17 s
  const waited = Date.now() - t0;
  if (waited > 30_000) throw new Error(`${file}: verdict only after ${waited} ms — event starvation?`);
  const v = await page.evaluate(() => window.__STATE().verdict);
  if (!v.ok || !v.match) {
    throw new Error(`${file}: verdict ok=${v.ok} match=${v.match}`);
  }
  const frames = await page.evaluate(() => window.__STATE().frames);
  if (frames < 10) throw new Error(`${file}: frame stream empty (${frames})`);
  log(`${file} — POC OK, transcript hash verified, ${frames} frames rendered`);
}

await runAndAssert("v101_send_fw_inventory.py");
await runAndAssert("v136_gps_spoof_chain.py");

const tileLen = await page.evaluate(() =>
  document.getElementById("tiles").innerHTML.length);
if (tileLen < 2_000) throw new Error(`state tiles not populated (${tileLen})`);

const vt = await page.textContent("#verdict");
if (!vt.includes("POC OK") || !vt.includes("committed")) {
  throw new Error("verdict bar missing parity claim: " + vt);
}

// dashboard: 3-view SPA — index holds the 56 writeups, the orbit range
// scope received real free-flight points, the killchain pipeline lit its
// 5 evidence-anchored stages during the v136 run.
const st = await page.evaluate(() => window.__STATE());
if (st.view !== "ops") throw new Error("view did not switch to ops on __run: " + st.view);
if (st.idxCards !== 56) throw new Error(`index cards: ${st.idxCards} != 56`);
if (st.orb.pts < 10) throw new Error(`orbit scope free-flight points: ${st.orb.pts}`);
if (st.kc !== 5) throw new Error(`killchain stages lit: ${st.kc}/5`);
// the overview explanation panel (FlatSat lineage + A-to-Z "what this project
// is") is a contract: blocks, depth, and the honest upstream/integration marks
const why = await page.evaluate(() => {
  const el = document.getElementById("ov-why");
  if (!el) return { blocks: 0, words: 0 };
  const q = (s) => el.querySelectorAll(s).length;
  return {
    blocks: q(".wblock"),
    words: (el.textContent || "").split(/\s+/).filter(Boolean).length,
    next: !!document.getElementById("why-v36"),
    ext: [...el.querySelectorAll("a.ext")].filter(
      (a) => a.href === "https://github.com/Pwnsat/FlatSat").length,
    mapRows: q(".why-map tr") - 1,
    steps: q(".why-steps .step"),
    flow: q("#why-flow .fstep"),
    views: q(".why-views .vcard"),
  };
});
if (why.blocks < 8 || why.words < 500 || !why.next || why.ext < 3 ||
    why.mapRows < 4 || why.steps !== 3 || why.flow !== 5 || why.views !== 5)
  throw new Error(`overview explanation thin: ${JSON.stringify(why)}`);
log(`dashboard OK — view=${st.view} · index 56/56 · telemetry pts=${st.orb.pts} · killchain 5/5 · why ${why.blocks} blocks/${why.words} words · flatsat lineage: ${why.ext} upstream links, ${why.mapRows}-row mapping, ${why.steps} flash steps, ${why.flow}-stage chain`);

// v3 pedagogy/depth contract: every frame in the stream carries an exhaustive
// decode block, and the glossary / help / start-here aids are built.
const ped = await page.evaluate(() => ({
  fdec: document.querySelectorAll("#stream .fitem .fdec").length,
  terms: document.querySelectorAll("#glossary .gl-term").length,
  help: !!document.getElementById("help-body") &&
        document.getElementById("help-body").textContent.length > 500,
  start: !!document.getElementById("ov-start"),
}));
if (ped.fdec < 10) throw new Error(`exhaustive decode blocks missing (${ped.fdec})`);
if (ped.terms < 25) throw new Error(`glossary too thin (${ped.terms} terms)`);
if (!ped.help) throw new Error("help overlay content missing");
if (!ped.start) throw new Error("start-here strip missing");
log(`pedagogy OK — ${ped.fdec} decoded frames · glossary ${ped.terms} terms · help · start-here`);

// ---- v3 intel surfaces: REPORT (engagement report) + REPO (source browser)
await page.click('#views-nav button[data-view="report"]');
await page.waitForFunction(() =>
  document.querySelectorAll("#rpt-list .rpt-f").length >= 56, null,
  { timeout: 30_000, polling: 200 });
const rpt = await page.evaluate(() => ({
  cards: document.querySelectorAll("#rpt-list .rpt-f").length,
  pdf: !!document.querySelector("#rpt-pdf[href^='data:application/pdf']"),
  rel: !!document.querySelector("#rpt-rel[href='https://github.com/electr0sm0g/flatsat-mission-control/releases/tag/v1.0.0']"),
  eng: (document.getElementById("rpt-head")?.textContent || "").includes("electr0sm0g"),
}));
if (rpt.cards < 56 || !rpt.pdf || !rpt.rel || !rpt.eng)
  throw new Error(`report view incomplete: ${JSON.stringify(rpt)}`);
await page.click('#views-nav button[data-view="repo"]');
await page.waitForFunction(() =>
  document.querySelectorAll("#repo-tree .repo-f").length >= 150, null,
  { timeout: 30_000, polling: 200 });
const repo = await page.evaluate(() => {
  const all = [...document.querySelectorAll(".repo-f")];
  return {
    files: all.length,
    ev: all.some((b) => b.dataset.path.startsWith("evidence/")),
    fw: all.some((b) => b.dataset.path.startsWith("firmware/")),
    doc: all.some((b) => b.dataset.path === "docs/THREAT-MODEL.md"),
    run: all.some((b) => b.dataset.path === "simulator/flatsat_sim.py"),
    body: (document.getElementById("repo-body").textContent || "").length,
  };
});
if (!repo.ev || !repo.fw || !repo.doc || !repo.run || repo.body < 500)
  throw new Error(`repo view incomplete: ${JSON.stringify(repo)}`);
// mermaid fences must become real rendered SVG (offline vendor engine),
// not raw code: default repo file is docs/THREAT-MODEL.md (1 graph diagram),
// README.md carries a flowchart + a sequence diagram (2 diagrams).
await page.waitForFunction(() =>
  document.querySelectorAll("#repo-body .mmd-svg svg").length >= 1 ||
  document.querySelectorAll("#repo-body .mmd-fail").length >= 1, null,
  { timeout: 90_000, polling: 300 });
const mmd1 = await page.evaluate(() => ({
  svgs: document.querySelectorAll("#repo-body .mmd-svg svg").length,
  shapes: document.querySelectorAll("#repo-body .mmd-svg svg .node").length,
  failed: document.querySelectorAll("#repo-body .mmd-fail").length,
}));
if (!mmd1.svgs || !mmd1.shapes || mmd1.failed)
  throw new Error(`mermaid render failed (threat model): ${JSON.stringify(mmd1)}`);
await page.evaluate(() => {
  const btn = document.querySelector('.repo-f[data-path="README.md"]');
  if (btn) btn.parentElement.classList.remove("collapsed");
});
await page.click('.repo-f[data-path="README.md"]');
// engine may already be warm: the two blocks can convert to svg between two
// polls — wait for the end state (svg count or fallback), not the transition.
await page.waitForFunction(() =>
  document.querySelectorAll("#repo-body .mmd-svg svg").length >= 2 ||
  document.querySelectorAll("#repo-body .mmd-fail").length >= 1, null,
  { timeout: 60_000, polling: 300 });
const mmd2 = await page.evaluate(() => ({
  svgs: document.querySelectorAll("#repo-body .mmd-svg svg").length,
  nodes: document.querySelectorAll("#repo-body .mmd-svg svg .node").length,
  seq: document.querySelectorAll("#repo-body .mmd-svg svg .actor, #repo-body .mmd-svg svg text.messageText").length,
  failed: document.querySelectorAll("#repo-body .mmd-fail").length,
}));
if (mmd2.svgs < 2 || !mmd2.nodes || !mmd2.seq || mmd2.failed)
  throw new Error(`mermaid render failed (README flowchart+sequence): ${JSON.stringify(mmd2)}`);
log(`mermaid OK — threat model + README rendered offline (${mmd1.shapes + mmd2.nodes} shapes, sequence actors ${mmd2.seq})`);
// deep-link: index detail -> committed bench evidence in REPO
await page.click('#views-nav button[data-view="index"]');
await page.waitForTimeout(400);
await page.click('.idxcard[data-poc="v136_gps_spoof_chain.py"]');
await page.waitForTimeout(400);
// the per-PoC attack diagram must render inside the finding detail too:
// V-36 carries a 5-stage sequenceDiagram (killchain)
await page.waitForFunction(() =>
  document.querySelectorAll("#idx-doc .mmd-svg svg .actor").length >= 4 ||
  document.querySelectorAll("#idx-doc .mmd-fail").length >= 1, null,
  { timeout: 60_000, polling: 300 });
const diag = await page.evaluate(() => ({
  actors: document.querySelectorAll("#idx-doc .mmd-svg svg .actor").length,
  failed: document.querySelectorAll("#idx-doc .mmd-fail").length,
}));
if (!diag.actors || diag.failed)
  throw new Error(`V-36 attack diagram did not render: ${JSON.stringify(diag)}`);
await page.click("#idx-ev");
await page.waitForFunction(() =>
  (document.getElementById("repo-path").textContent || "")
    .includes("evidence/v136_gps_spoof_chain.txt"), null,
  { timeout: 15_000, polling: 200 });
const evShown = await page.evaluate(() =>
  (document.getElementById("repo-body").textContent || "").includes("POC OK"));
if (!evShown) throw new Error("evidence transcript did not render in REPO");
log(`intel OK — report ${rpt.cards} findings · repo ${repo.files} files ` +
    `(docs/evidence/firmware/runnable) · evidence deep-link`);

await page.screenshot({ path: "web-demo-verify.png", fullPage: true });
log("screenshot: web-demo-verify.png");

if (errors.length) log("console/page errors:", errors.join(" | "));
log("WEB DEMO VERIFY: PASS");
await browser.close();
