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
const assembly = es5(appjs.slice(
  appjs.indexOf("  const routes = {};"),
  appjs.indexOf("payload.agent_role_providers = routes;") + "payload.agent_role_providers = routes;".length));
const loadSrc = es5(appjs.slice(appjs.indexOf("  const roleRoutes ="),
  appjs.indexOf("renderRoleProviderStatus(f);")));
check("the assembly block was found in app.js", assembly.length > 40, true);
check("...and the load block too", loadSrc.length > 40, true);

// One eval, so the constants and the two functions share a scope — `const`
// declared in its own eval is not visible to a later one.
win.eval(constBlock + `
  window._assemble = function (e) { const payload = {}; ${assembly} return payload; };
  window._load = function (f, s) { ${loadSrc} };
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

console.log(`\n${PASS + FAIL} checks, ${FAIL} failed`);
process.exit(FAIL ? 1 : 0);
