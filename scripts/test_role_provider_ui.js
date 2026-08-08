#!/usr/bin/env node
/**
 * The hybrid setting has to be reachable from the UI, and it is ONE map.
 *
 * Four selects that each POST their own key would create a settings shape the
 * server does not have, and a role cleared in the UI would linger server-side
 * because the generic save loop turns "" into `null` (clear THIS key) rather
 * than removing an entry from a map. So the contract under test is: the four
 * controls are assembled into `agent_role_providers`, sent whole every time,
 * and never leak as `role_provider_*` keys.
 *
 * jsdom proves the wiring and the payload. It cannot prove colour or layout —
 * those are not asserted here.
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

const ROOT = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(ROOT, "web-ui/index.html"), "utf8");
const appjs = fs.readFileSync(path.join(ROOT, "web-ui/app.js"), "utf8");

let PASS = 0, FAIL = 0;
function check(label, got, want) {
  const a = JSON.stringify(got), b = JSON.stringify(want);
  if (a === b) { PASS++; console.log("PASS  " + label); }
  else { FAIL++; console.log(`FAIL  ${label}\n        got  = ${a}\n        want = ${b}`); }
}

const ROLES = ["judge", "reviewer", "report", "monitor"];

// ---------------------------------------------------------------------------
// 1. The controls exist, with exactly the roles and targets the server accepts.
// ---------------------------------------------------------------------------
const dom = new JSDOM(html);
const doc = dom.window.document;

check("one select per overridable role",
  ROLES.map((r) => !!doc.querySelector(`[name=role_provider_${r}]`)),
  ROLES.map(() => true));

for (const r of ROLES) {
  const opts = Array.from(doc.querySelectorAll(`[name=role_provider_${r}] option`))
    .map((o) => o.value);
  check(`${r}: options are follow / claude / gpt`, opts, ["", "claude", "gpt"]);
}

// Grok is a whole-job backend; offering it here would let an operator pick a
// route the server silently drops.
check("grok is not offered as a role target",
  ROLES.some((r) => Array.from(doc.querySelectorAll(`[name=role_provider_${r}] option`))
    .some((o) => o.value === "grok")),
  false);

check("a role the server cannot override is not offered",
  !!doc.querySelector("[name=role_provider_main]"), false);

// ---------------------------------------------------------------------------
// 2. The save assembles ONE map, and clearing a role really clears it.
// ---------------------------------------------------------------------------
// Exercise the real source rather than a restatement of it: pull the two
// blocks out of app.js and run them over a jsdom form.
function evalIn(win, code) {
  return win.eval(code);
}

const dom2 = new JSDOM(html, { runScripts: "outside-only" });
const win = dom2.window;
const form = win.document.getElementById("settings-form");

// The constants and the assembly are pulled from app.js rather than restated,
// so a change to production that this test does not follow shows up as a
// failure instead of quietly passing against a stale copy.
//
// `es5` only strips optional chaining: the host still runs Node 12, which
// cannot parse it. Every element these expressions reach exists in the
// fixture, so the stripped form behaves identically — and the container's
// Node 20 runs the same file unmodified.
const es5 = (src) => src.replace(/\?\.\(/g, "(").replace(/\?\.\[/g, "[").replace(/\?\./g, ".");
const constBlock = es5(appjs.slice(
  appjs.indexOf("const ROLE_OVERRIDABLE ="),
  appjs.indexOf("function renderRoleProviderStatus")));
// Anchored from the submit handler, not from the first `const routes = {}` in
// the file — `currentTopology` also declares one, and slicing from there
// silently captured a malformed chunk. An ambiguous anchor is the same trap the
// mutation batteries kept hitting.
const _saveAt = appjs.indexOf('document.getElementById("settings-form").addEventListener("submit"');
const assembly = es5(appjs.slice(
  appjs.indexOf("  const routes = {};", _saveAt),
  appjs.indexOf("payload.agent_role_providers = routes;", _saveAt)
    + "payload.agent_role_providers = routes;".length));
const loadSrc = es5(appjs.slice(appjs.indexOf("  const roleRoutes ="),
  appjs.indexOf("renderRoleProviderStatus(f);")));
check("the assembly block was found in app.js", assembly.length > 40, true);
check("...and the load block too", loadSrc.length > 40, true);

// One eval, so the constants and the two functions share a scope — `const`
// declared in its own eval is not visible to a later one.
// ONE eval: `const` declared in its own eval is invisible to a later one, and
// constBlock already carries TOPOLOGIES / currentTopology / applyTopology
// (it runs up to renderRoleProviderStatus), so slicing them again would just
// shadow them in a scope that cannot see the constants.
win.eval(constBlock + `
  window.setProviderUI = function () {};
  window.renderProviderAuthUI = function () {};
  window.renderRoleProviderStatus = function () {};
  window._assemble = function (e) { const payload = {}; ${assembly} return payload; };
  window._load = function (f, s) { ${loadSrc} };
  window._topo = function (f) { return currentTopology(f); };
  window._apply = function (f, n) { return applyTopology(f, n); };
`);

// nothing selected -> empty map, NOT four nulls and NOT absent
check("no routing selected sends an empty map",
  win._assemble({ target: form }).agent_role_providers, {});

form.querySelector("[name=role_provider_judge]").value = "claude";
form.querySelector("[name=role_provider_reviewer]").value = "claude";
check("selected roles are assembled into one map",
  win._assemble({ target: form }).agent_role_providers,
  { judge: "claude", reviewer: "claude" });

form.querySelector("[name=role_provider_reviewer]").value = "";
check("clearing a role removes it from the map, rather than sending null",
  win._assemble({ target: form }).agent_role_providers, { judge: "claude" });

// ---------------------------------------------------------------------------
// 3. The selects must NOT leak as individual settings keys.
// ---------------------------------------------------------------------------
const saveSrc = appjs.slice(appjs.indexOf('document.getElementById("settings-form").addEventListener("submit"'));
check("the generic loop skips role_provider_* keys",
  saveSrc.includes('k.startsWith("role_provider_")'), true);
check("...before the payload is built from FormData",
  saveSrc.indexOf('k.startsWith("role_provider_")') < saveSrc.indexOf("payload.agent_role_providers"),
  true);

// ---------------------------------------------------------------------------
// 4. Loading round-trips, and an unknown target degrades to "follow".
// ---------------------------------------------------------------------------
win._load(form, { agent_role_providers: { judge: "gpt", monitor: "claude" } });
check("stored routes populate the selects",
  ROLES.map((r) => form.querySelector(`[name=role_provider_${r}]`).value),
  ["gpt", "", "", "claude"]);

// NOTE: this holds via the DOM, not via the `ROLE_TARGETS.includes` guard in
// loadSettings — assigning a value with no matching <option> leaves a select
// at "". Verified by mutation: deleting that guard does NOT fail this check.
// It is kept as a contract on what the operator SEES (a route the server would
// drop must not render as if it were active), and the guard stays because it
// would become load-bearing the moment this control stops being a <select>.
win._load(form, { agent_role_providers: { judge: "grok", reviewer: "nope" } });
check("a target the server would drop renders as follow, not as itself",
  ROLES.map((r) => form.querySelector(`[name=role_provider_${r}]`).value),
  ["", "", "", ""]);

// The load-side guard is not what protects the PAYLOAD — this is. Assemble
// after loading a droppable target and the map must stay empty.
check("...and never reaches the payload either",
  win._assemble({ target: form }).agent_role_providers, {});

win._load(form, {});
check("no stored map leaves every role following the job provider",
  ROLES.map((r) => form.querySelector(`[name=role_provider_${r}]`).value),
  ["", "", "", ""]);


// ---------------------------------------------------------------------------
// 5. The topology preset FILLS the form and is never itself a setting.
// ---------------------------------------------------------------------------
check("the topology block travels with the constants",
  constBlock.includes("const TOPOLOGIES = {") && constBlock.includes("function applyTopology"),
  true);

function formState(f) {
  return [
    (f.querySelector("[name=agent_provider]:checked") || {}).value || "",
    ...ROLES.map((r) => f.querySelector(`[name=role_provider_${r}]`).value),
  ];
}

win._apply(form, "hybrid");
check("hybrid puts the job on Codex and routes judge + reviewer to Claude",
  formState(form), ["gpt", "claude", "claude", "", ""]);
check("...and the assembled payload matches",
  win._assemble({ target: form }).agent_role_providers,
  { judge: "claude", reviewer: "claude" });

win._apply(form, "codex");
check("all-Codex clears every route", formState(form), ["gpt", "", "", "", ""]);
check("...so the payload map is empty, not stale",
  win._assemble({ target: form }).agent_role_providers, {});

win._apply(form, "claude");
check("all-Claude switches the job provider too",
  formState(form), ["claude", "", "", "", ""]);

// Round-trip: the select must report back what the controls actually say, so
// an operator who hand-edits one role sees it stop claiming a named topology.
win._apply(form, "hybrid");
check("a matching form reads back as hybrid", win._topo(form), "hybrid");
form.querySelector("[name=role_provider_report]").value = "claude";
check("...and as custom the moment it stops matching", win._topo(form), "custom");
win._apply(form, "codex");
check("an all-Codex form reads back as codex", win._topo(form), "codex");

check("the preset never reaches the settings payload",
  saveSrc.includes('k === "topology_preset"'), true);
check("...and is not a settings key the server knows",
  fs.readFileSync(path.join(ROOT, "modules/settings_io.py"), "utf8")
    .includes("topology_preset"),
  false);


// ---------------------------------------------------------------------------
// 6. The Timeline must not claim a routed-away role runs on the job's backend.
//    Source-level, because the render path needs a live job to exercise: the
//    contract is that the API resolves per role and the card carries it.
// ---------------------------------------------------------------------------
const jobsRoute = fs.readFileSync(path.join(ROOT, "api/routes/jobs.py"), "utf8");
const runEvents = fs.readFileSync(path.join(ROOT, "modules/gpt_run_events.py"), "utf8");

check("the timeline resolves the provider per role",
  /provider_for_role\(job_id, role\)/.test(jobsRoute), true);
check("...and takes that provider's model, not the GPT preset's",
  /role_model_for\(role, where, None\)/.test(jobsRoute), true);
check("...only substituting when the role is routed away",
  /fallbacks\[role\] if where == "gpt"/.test(jobsRoute), true);
check("the provider reaches the card",
  /"provider": configured_providers\.get\(role, ""\)/.test(runEvents), true);
check("...and summarize_agents accepts it",
  /configured_providers: dict\[str, str\] \| None = None/.test(runEvents), true);
check("the card renders a badge for a routed role",
  /agent\.provider && agent\.provider !== "gpt"/.test(appjs), true);


// ---------------------------------------------------------------------------
// 7. The agent cards stay put; only the event list scrolls.
//    jsdom does no layout, so this pins the two things that CAN be wrong
//    without looking wrong: which element is the scroll container, and whether
//    the poll's scroll-preservation still points at it. Getting the second
//    wrong silently yanks the view to the bottom every 2 seconds.
// ---------------------------------------------------------------------------
// Comments stripped FIRST. The rule below explains itself with the words
// "min-height:0", and the assertion that the declaration exists was matching
// that prose — passing whether or not the declaration was there. A check that
// a comment can satisfy is not a check.
// style.css had NO cache-buster at all, so a browser could keep an old copy
// through a deploy and the change would look like it never shipped — which is
// how the fixed-header layout first appeared not to work.
const indexHtml = fs.readFileSync(path.join(ROOT, "web-ui/index.html"), "utf8");
check("style.css is cache-busted like app.js",
  /href="\/static\/style\.css\?v=/.test(indexHtml), true);
// The buster is DERIVED from the assets it busts, and this recomputes it.
// A hand-typed version string goes stale silently: it was not bumped with the
// scaffold-badge change, so browsers kept an app.js without the badge while
// the API already returned the field — the third time in this branch that a
// shipped UI change looked like it never shipped. Now editing app.js or
// style.css without regenerating the tag fails here, and the failure prints
// the value to use.
const crypto = require("crypto");
const _assetHash = "a" + crypto.createHash("sha256")
  .update(fs.readFileSync(path.join(ROOT, "web-ui/app.js")))
  .update(fs.readFileSync(path.join(ROOT, "web-ui/style.css")))
  .digest("hex").slice(0, 8);
check(`the buster is derived from the assets (expected ?v=${_assetHash})`,
  new RegExp("\\?v=" + _assetHash).test(indexHtml), true);
check("...and both busters move together",
  (indexHtml.match(/\?v=([0-9a-z-]+)/g) || []).length >= 2
  && new Set(indexHtml.match(/\?v=([0-9a-z-]+)/g)).size === 1, true);

const css = fs.readFileSync(path.join(ROOT, "web-ui/style.css"), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "");
// Just the `.gpt-timeline-feed {…}` block. Slicing to the next selector swept
// in the child rules that follow it — including the event list's own
// `overflow-y: auto`, which made the "feed is not a scroller" check read the
// opposite of what it asks.
// Anchored at a LINE START: `.run-log-window .gpt-timeline-feed { display:none }`
// appears earlier and matched first, so the slice examined a one-line
// visibility rule and every assertion below read the wrong block. Third time
// an ambiguous anchor has bitten in this branch.
const _feedAt = css.indexOf("\n.gpt-timeline-feed {") + 1;
const feedRule = css.slice(_feedAt, css.indexOf("}", _feedAt) + 1);

check("the feed is a fixed box, not a scroller",
  /overflow:\s*hidden/.test(feedRule) && !/overflow-y:\s*auto/.test(feedRule), true);
check("...laid out as a column so the list can take the remaining height",
  /flex-direction:\s*column/.test(feedRule), true);
// The view-toggle rule is (0,3,0) and beats the plain `.gpt-timeline-feed`
// rule, so a `display: block` there defeats the whole layout regardless of
// what the block below says. This is what actually shipped broken.
check("the rule that reveals the timeline does not force display:block",
  /data-view="timeline"\] \.gpt-timeline-feed \{ display: flex; \}/.test(css), true);
check("the agent grid does not shrink",
  /\.gpt-timeline-feed > \.gpt-agent-grid \{[^}]*flex:\s*0 0 auto/.test(css), true);
check("the event list is the scroller",
  /\.gpt-timeline-feed > \.gpt-event-list \{[^}]*overflow-y:\s*auto/.test(css), true);
check("...and can actually shrink (the min-height:0 flex trap)",
  /\.gpt-timeline-feed > \.gpt-event-list \{[^}]*min-height:\s*0/.test(css), true);

const preserve = (appjs.match(/detail\.querySelector\("\.gpt-timeline-feed[^"]*"\)/g) || []);
check("scroll preservation captures and restores the same element", preserve.length, 2);
check("...and that element is the event list, not the feed",
  preserve.every((m) => m.includes(".gpt-event-list")), true);

console.log(`\n${PASS + FAIL} checks, ${FAIL} failed`);
process.exit(FAIL ? 1 : 0);
