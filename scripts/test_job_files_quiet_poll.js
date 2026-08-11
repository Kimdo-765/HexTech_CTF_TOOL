#!/usr/bin/env node
/**
 * The job file browser must not show its own polling.
 *
 * WHAT WAS WRONG, REPORTED BY THE OPERATOR 2026-08-11.
 * The job detail HTML is rebuilt on every poll. The browser was rebuilt with
 * it — a fresh `Loading…` placeholder, then a wholesale `innerHTML` rewrite of
 * the listing a moment later. On an idle directory that is a blink every
 * couple of seconds, and on a directory being read it also threw away the
 * scroll position and cancelled hover. The listing was correct and unreadable.
 *
 * THE CONTRACT UNDER TEST. A poll that changes nothing must touch no DOM at
 * all; the only proof of that is NODE IDENTITY, so this suite holds references
 * across polls and asserts the same objects come back. `Loading…` is reachable
 * only from a paint with nothing to show. A file that genuinely appears
 * mid-run is inserted at its sorted position and marked `jf-new` so CSS can
 * fade it in — the ordering matters because the API guarantees directories
 * before files, and appending would break that the moment a directory appears.
 *
 * WHAT THIS CANNOT PROVE. Whether the result LOOKS smooth. jsdom has no
 * renderer; the animation itself is a CSS keyframe asserted only as a class
 * here. That has to be looked at.
 *
 * Run:  node scripts/test_job_files_quiet_poll.js [--mutate NAME]
 */
const fs = require("fs");
const path = require("path");

let JSDOM;
try {
  ({ JSDOM } = require("jsdom"));
} catch (e) {
  console.log("SKIP: jsdom not installed");
  process.exit(0);
}

const MUTATIONS = [
  "none",
  "loading-on-poll",     // the placeholder is written unconditionally again
  "rebuild-list",        // the listing is rewritten wholesale instead of patched
  "append-new",          // new rows are appended rather than placed in order
  "no-shape-check",      // a file->directory flip is patched instead of replaced
  "animate-first-paint", // every row animates, so opening shimmers
  "wipe-on-poll-error",  // a dropped poll erases a good listing
  "stale-poll-merges",   // a response for the directory being left is applied
];
const _mi = process.argv.indexOf("--mutate");
const MUTATE = _mi > -1 ? process.argv[_mi + 1] : "none";
if (!MUTATIONS.includes(MUTATE)) {
  console.error(`unknown mutation ${MUTATE}; one of ${MUTATIONS.join(", ")}`);
  process.exit(2);
}

const ROOT = path.resolve(__dirname, "..");
let appjs = fs.readFileSync(path.join(ROOT, "web-ui/app.js"), "utf8");

let PASS = 0, FAIL = 0;
function check(label, got, want) {
  const a = JSON.stringify(got), b = JSON.stringify(want);
  if (a === b) { PASS++; } else {
    FAIL++;
    console.log(`FAIL  ${label}\n        got  = ${a}\n        want = ${b}`);
  }
}

// ---------------------------------------------------------------- mutations
if (MUTATE === "loading-on-poll") {
  appjs = appjs.replace(
    "  const firstPaint = !list.querySelector(\".jf-row, .jf-empty\");\n" +
    "  if (firstPaint) list.innerHTML",
    "  const firstPaint = !list.querySelector(\".jf-row, .jf-empty\");\n" +
    "  if (true) list.innerHTML");
} else if (MUTATE === "animate-first-paint") {
  appjs = appjs.replace("      if (!opts.firstPaint) {", "      if (true) {");
} else if (MUTATE === "no-shape-check") {
  appjs = appjs.replace(
    "if (row && row.dataset.shape !== _jfShape(e)) {", "if (row && false) {");
} else if (MUTATE === "stale-poll-merges") {
  appjs = appjs.replace("  if (_jobFilesPath.get(id) !== path) return;\n", "");
} else if (MUTATE === "wipe-on-poll-error") {
  appjs = appjs.replace("    if (firstPaint) {\n      list.innerHTML = `<span style=",
                        "    if (true) {\n      list.innerHTML = `<span style=");
}

// The host runs Node 12, which cannot parse optional chaining. Slice the
// browser out and strip it — the same approach the other UI suites take.
const es5 = (src) => src.replace(/\?\.\(/g, "(").replace(/\?\.\[/g, "[").replace(/\?\./g, ".");
// Start at the state declaration so `_fmtFileSize` and `_jobFilesCrumbs` come
// with it. Slicing from `_jfRowInner` left them behind and the browser threw on
// its first call — a harness that can only run part of the unit proves nothing
// about the unit.
const _from = appjs.indexOf("const _jobFilesPath = new Map();");
const _to = appjs.indexOf("/** Called after the job detail re-renders.");
if (_from < 0 || _to < 0 || _to <= _from) {
  console.error("anchors not found — the browser block moved; fix the slice");
  process.exit(2);
}
let SRC = es5(appjs.slice(_from, _to));

if (MUTATE === "rebuild-list") {
  // The pre-fix behaviour: throw the listing away and rebuild it.
  SRC = SRC.replace(
    "  const have = new Map();",
    "  list.innerHTML = \"\";\n  const have = new Map();");
} else if (MUTATE === "append-new") {
  SRC = SRC.replace(
    "    const next = cursor ? cursor.nextElementSibling : list.firstElementChild;\n" +
    "    if (next !== row) list.insertBefore(row, next);",
    "    if (row.parentNode !== list) list.appendChild(row);");
}

// ------------------------------------------------------------------- fixture
const dom = new JSDOM(`<!doctype html><body>
  <div id="detail">
    <div class="job-files" data-job="abc123abc123">
      <div class="job-files-bar">
        <span class="job-files-crumbs"></span>
        <button type="button" class="btn btn-sm job-files-refresh">Refresh</button>
      </div>
      <div class="job-files-list"></div>
    </div>
  </div></body>`, { runScripts: "outside-only" });
const win = dom.window;
const doc = win.document;
const JOB = "abc123abc123";

// Entries exactly as the API returns them: directories first, then files.
const E = (name, over) => Object.assign(
  { name, path: name, is_dir: false, is_link: false, size: 10 }, over || {});
const BASE = [
  E("src", { is_dir: true, size: null }),
  E("work", { is_dir: true, size: null }),
  E("meta.json", { size: 120 }),
  E("solver.sage.stdout", { size: 791 }),
];

let NEXT = { entries: BASE, truncated: false, cap: 2000 };
let FAIL_NEXT = false;
const OVERRIDE = {};        // path -> payload, for tests that use two directories
let HOLD = null;            // a path whose response is withheld until released
let RELEASE = null;

win.API = "/api";
win.escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
// Path-aware and holdable. An immediately-resolving stub cannot reproduce an
// out-of-order response at all: both loads would read whatever the payload
// variable held by the time `.json()` ran, so a stale-response test written
// against it passes with the defence removed. Snapshot at request time, and
// let one request be parked.
win.fetch = (url) => {
  if (FAIL_NEXT) return Promise.reject(new Error("network down"));
  const m = /path=([^&]*)/.exec(String(url));
  const p = decodeURIComponent(m ? m[1] : "");
  const payload = Object.prototype.hasOwnProperty.call(OVERRIDE, p) ? OVERRIDE[p] : NEXT;
  const body = { ok: true, json: () => Promise.resolve(payload) };
  if (HOLD === p) return new Promise((r) => { RELEASE = () => r(body); });
  return Promise.resolve(body);
};

// Declarations made inside `window.eval` do not land on the window in jsdom 19,
// so the entry point is handed out explicitly rather than fished off the global.
win.eval(`${SRC}\nwindow.loadJobFiles = loadJobFiles;`);
const load = (p) => win.loadJobFiles(JOB, p === undefined ? "" : p);

const list = doc.querySelector(".job-files-list");
const rows = () => Array.from(list.querySelectorAll(":scope > .jf-row"));
const keys = () => rows().map((r) => r.dataset.key);
const byKey = (k) => list.querySelector(`.jf-row[data-key="${k}"]`);
const html = () => list.innerHTML;

// jsdom resolves the stub promises on the microtask queue; two ticks is enough
// for fetch -> json -> reconcile.
const settle = () => new Promise((r) => setImmediate(() => setImmediate(r)));

(async () => {
  // ------------------------------------------------- ① the first paint
  const p0 = load("");
  check("a paint with nothing to show says so", /Loading…/.test(html()), true);
  await p0; await settle();

  check("the listing renders", keys(),
        ["src", "work", "meta.json", "solver.sage.stdout"]);
  check("...and the placeholder is gone", /Loading…/.test(html()), false);
  check("a first paint does not animate — opening must not shimmer",
        rows().filter((r) => r.classList.contains("jf-new")).length, 0);

  // ------------------------------------- ② a poll that changes nothing
  const before = rows();
  await load(""); await settle();
  check("an unchanged poll never shows Loading", /Loading…/.test(html()), false);
  check("...and reuses the very same nodes — the only proof of no churn",
        rows().every((r, i) => r === before[i]), true);
  check("...changing nothing about them",
        rows().length === before.length, true);

  // ------------------------------------------------ ③ a file appears
  NEXT = { entries: BASE.concat([E("solver.sage.stderr", { size: 0 })]),
           truncated: false, cap: 2000 };
  await load(""); await settle();
  check("the new file is listed", keys().includes("solver.sage.stderr"), true);
  check("...marked so CSS can fade it in",
        byKey("solver.sage.stderr").classList.contains("jf-new"), true);
  check("...while every pre-existing row is untouched",
        before.every((r) => r.parentNode === list && !r.classList.contains("jf-new")),
        true);

  // A directory arriving mid-run must land BEFORE the files, not at the end.
  NEXT = { entries: [E("newdir", { is_dir: true, size: null })].concat(NEXT.entries),
           truncated: false, cap: 2000 };
  await load(""); await settle();
  check("a directory arriving mid-run keeps dirs-before-files order",
        keys(), ["newdir", "src", "work", "meta.json",
                 "solver.sage.stdout", "solver.sage.stderr"]);

  // ------------------------------------ ④ a growing file is patched, not rebuilt
  const growing = byKey("solver.sage.stdout");
  NEXT = {
    entries: NEXT.entries.map((e) => (e.path === "solver.sage.stdout"
      ? E("solver.sage.stdout", { size: 4096 }) : e)),
    truncated: false, cap: 2000,
  };
  await load(""); await settle();
  check("a growing file keeps its node", byKey("solver.sage.stdout") === growing, true);
  check("...with only the size text updated",
        growing.querySelector(".jf-size").textContent, "4 KB");
  check("...and is not re-animated", growing.classList.contains("jf-new"), false);

  // -------------------------------- ⑤ a name whose SHAPE changed is replaced
  const wasFile = byKey("meta.json");
  NEXT = {
    entries: NEXT.entries.map((e) => (e.path === "meta.json"
      ? E("meta.json", { is_dir: true, size: null }) : e)),
    truncated: false, cap: 2000,
  };
  await load(""); await settle();
  check("a file replaced by a directory of the same name is rebuilt",
        byKey("meta.json") !== wasFile, true);
  check("...and renders as a directory",
        /📁/.test(byKey("meta.json").innerHTML), true);

  // ----------------------------------------------- ⑥ a deletion is applied
  NEXT = { entries: NEXT.entries.filter((e) => e.path !== "newdir"),
           truncated: false, cap: 2000 };
  await load(""); await settle();
  check("a vanished entry is removed", keys().includes("newdir"), false);

  // ------------------------- ⑦ the unkeyed siblings are not churned either
  NEXT = { entries: NEXT.entries, truncated: true, cap: 2000 };
  await load(""); await settle();
  const trunc = list.querySelector(".jf-trunc");
  check("the truncation notice is shown", !!trunc, true);
  check("...last, after every row", trunc === list.lastElementChild, true);
  await load(""); await settle();
  check("...and survives an unchanged poll as the same node",
        list.querySelector(".jf-trunc") === trunc, true);

  // ------------------------------- ⑧ a dropped poll must not erase the view
  const kept = keys();
  FAIL_NEXT = true;
  await load(""); await settle();
  check("a failed background poll leaves the listing alone", keys(), kept);
  check("...and does not report an error over a good listing",
        /network down/.test(html()), false);

  // A paint with nothing to preserve DOES report it.
  list.innerHTML = "";
  await load(""); await settle();
  check("a failed FIRST paint reports the error", /network down/.test(html()), true);
  FAIL_NEXT = false;

  // ---------------------------------------------- ⑨ empty directory handling
  NEXT = { entries: [], truncated: false, cap: 2000 };
  list.innerHTML = "";
  await load(""); await settle();
  const empty = list.querySelector(".jf-empty");
  check("an empty directory says so", !!empty, true);
  await load(""); await settle();
  check("...and the notice is not churned on a poll",
        list.querySelector(".jf-empty") === empty, true);
  check("...and an empty directory does not re-trigger Loading",
        /Loading…/.test(html()), false);

  // ------------------- ⑩ a stale in-flight poll must not merge into a new dir
  // Rewriting the list made this self-correcting: the next poll overwrote the
  // mess. A reconciler MERGES, so a response for the directory being left would
  // blend two directories into one listing under the wrong crumb trail.
  NEXT = { entries: BASE, truncated: false, cap: 2000 };
  OVERRIDE["work"] = { entries: [E("nested.txt", { size: 3 })],
                       truncated: false, cap: 2000 };
  list.innerHTML = "";
  await load(""); await settle();
  check("(setup) the root is listed", keys().length, 4);

  HOLD = "";                        // park a poll for the directory being LEFT
  const stale = load("");
  await settle();
  HOLD = null;
  await load("work");               // the operator clicks into work/
  await settle();
  check("(setup) the new directory is shown", keys(), ["nested.txt"]);

  RELEASE();                        // the parked root response lands late
  await stale; await settle();
  check("a poll for the directory being LEFT does not merge into the new one",
        keys(), ["nested.txt"]);
  check("...and the crumb trail still describes what is on screen",
        /data-path="work"/.test(doc.querySelector(".job-files-crumbs").innerHTML), true);

  console.log(`== summary: ${PASS} passed, ${FAIL} failed; mutation=${MUTATE} ==`);
  process.exit(FAIL ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
