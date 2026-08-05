// Regression suite for the agent-event age readout (the ⚡ pill).
//
// The host's node is too old for this repo's app.js (optional chaining), so run
// it in a container that has node 20:
//
//   docker cp web-ui/app.js  <worker>:/tmp/app.js
//   docker cp scripts/test_agent_liveness_ui.js <worker>:/tmp/t.js
//   docker exec <worker> node --check /tmp/app.js && docker exec <worker> node /tmp/t.js
//
// WHY THIS EXISTS
// A liveness chip lived here before and was removed in bc55640. It read the
// same field this pill reads — meta.last_agent_event_at — and classified it:
// green "active" at <=30s, amber "silent" beyond. Measured over 3303 agent
// events on job e601cd358ad6, the gap distribution has a median of 0s but a
// max of 16 min, and time-weighted the chip showed amber on a perfectly
// healthy job 75.3% of the time. Re-confirmed live on job 729c62380722 while
// healthy: a single 484s (8m04s) gap between agent events.
//
// So the pill states the age and classifies NOTHING. The operator reads
// liveness from the counter resetting, not from a colour. These checks exist
// to stop the classification creeping back, and to stop the other historical
// failure — substituting started_at/updated_at when the field is absent, which
// measures "time since the job started" and fires on every job (43d896f).
//
// The two tick functions are sliced out of the real app.js and executed, so
// this tests shipped code rather than a copy. The render block lives inside a
// 400-line function and cannot be sliced; it is covered by source invariants,
// each written so it FAILS if the guard it protects is removed.

const fs = require("fs");

let bad = 0, ran = 0;
const t = (label, cond, got) => {
  ran++;
  console.log((cond ? "PASS  " : "FAIL  ") + label + (cond ? "" : `  | got=${JSON.stringify(got)}`));
  if (!cond) bad++;
};

// ---------------------------------------------------------------- load
function findApp() {
  for (const p of ["/tmp/app.js", "web-ui/app.js", "../web-ui/app.js"]) {
    if (fs.existsSync(p)) return fs.readFileSync(p, "utf8");
  }
  console.log("FATAL  app.js not found");
  process.exit(2);
}
const SRC = findApp();

/** Slice `function NAME(...) { ... }` out of the source by brace matching. */
function sliceFn(name) {
  const start = SRC.indexOf(`function ${name}(`);
  if (start === -1) return null;
  let i = SRC.indexOf("{", start), depth = 0;
  for (; i < SRC.length; i++) {
    if (SRC[i] === "{") depth++;
    else if (SRC[i] === "}" && --depth === 0) return SRC.slice(start, i + 1);
  }
  return null;
}

const fmtSrc = sliceFn("_fmtAgentAge");
const tickSrc = sliceFn("_tickLivePill");
t("_fmtAgentAge is present in app.js", !!fmtSrc);
t("_tickLivePill is present in app.js", !!tickSrc);
if (!fmtSrc || !tickSrc) { console.log(`\n${ran} checks, ${bad} failed`); process.exit(1); }

// ------------------------------------------------------------ fake DOM
// Minimal stand-in: enough for the agent-pill branch and the stop condition.
// The elapsed-pill branch is exercised only to prove it still runs unharmed.
let _pills = [];
let _cleared = false;
const document = {
  querySelectorAll: (sel) =>
    sel.includes(".agent-pill") ? _pills.filter((p) => p._agent)
      : _pills.filter((p) => p._timing),
  querySelector: (sel) => {
    const wantAgent = sel.includes(".agent-pill");
    const wantTiming = sel.includes(".timing-pill.live");
    const hit = _pills.find((p) => (wantAgent && p._agent) || (wantTiming && p._timing));
    return hit || null;
  },
};
let livePillTimer = 1;
const clearInterval = () => { _cleared = true; livePillTimer = null; };

const mkAgentPill = (iso) => ({
  _agent: true, dataset: { agentAt: iso }, textContent: "(stale)",
  title: "unchanged", querySelector: () => null,
});

const sandbox = { document, clearInterval, livePillTimer };
const run = new Function("document", "clearInterval", "livePillTimer",
  `${fmtSrc}\n${tickSrc}\nreturn {_fmtAgentAge, _tickLivePill};`);
const api = run(sandbox.document, clearInterval, livePillTimer);

// ------------------------------------------------------------ format
console.log("\n--- the readout must make a RESET visible ----------------");
t("seconds render bare", api._fmtAgentAge(0) === "0s" && api._fmtAgentAge(42) === "42s",
  [api._fmtAgentAge(0), api._fmtAgentAge(42)]);
t("REGRESSION: seconds stay visible past a minute — a reset must not be hidden "
  + "for up to 60s",
  api._fmtAgentAge(484) === "8m 4s", api._fmtAgentAge(484));
t("hours degrade to h/m", api._fmtAgentAge(7325) === "2h 2m", api._fmtAgentAge(7325));
t("never negative", api._fmtAgentAge(0) === "0s");

// -------------------------------------------------------------- tick
console.log("\n--- the tick updates the age in place --------------------");
const iso = new Date(Date.now() - 12_000).toISOString();
const pill = mkAgentPill(iso);
_pills = [pill];
_cleared = false;
api._tickLivePill();
t("the age is written into the pill", /^⚡ 1[123]s$/.test(pill.textContent), pill.textContent);
t("REGRESSION: the tooltip survives the tick — it carries the 'long gaps are "
  + "normal' explanation", pill.title === "unchanged", pill.title);
t("the timer is NOT cleared while an agent pill is on screen", !_cleared);

const old = mkAgentPill(new Date(Date.now() - 484_000).toISOString());
_pills = [old];
api._tickLivePill();
t("an 8-minute gap renders as a plain number, with no state added",
  old.textContent === "⚡ 8m 4s" || old.textContent === "⚡ 8m 3s", old.textContent);

console.log("\n--- the timer stops only when nothing live remains --------");
_pills = []; _cleared = false;
api._tickLivePill();
t("no pills at all -> timer cleared", _cleared);

_pills = [mkAgentPill(iso)]; _cleared = false;
api._tickLivePill();
t("REGRESSION: an agent pill with no elapsed pill keeps the timer alive — a "
  + "frozen counter reads exactly like a wedged agent", !_cleared);

// -------------------------------------------------- source invariants
console.log("\n--- classification must not creep back -------------------");
const block = SRC.slice(SRC.indexOf("let agentPill ="), SRC.indexOf("agentPill = \"\"") + 4000);
const render = SRC.slice(SRC.indexOf("let agentPill ="),
  SRC.indexOf("</span>`;", SRC.indexOf("let agentPill =")) + 9);

t("the pill is rendered from last_agent_event_at",
  render.includes("job.last_agent_event_at"));
t("REGRESSION: it is gated on the field EXISTING",
  /job\.status === "running" && job\.last_agent_event_at/.test(render), render.slice(0, 160));
t("REGRESSION: no fallback to started_at / updated_at — that chain measures "
  + "time-since-job-start and fires on every job",
  !render.includes("started_at") && !render.includes("updated_at"));
t("exactly one class, with no state variants",
  (render.match(/class="agent-pill[^"]*"/g) || []).length === 1
  && !/agent-pill (warn|dead|silent|active|stale)/.test(render),
  (render.match(/class="agent-pill[^"]*"/g) || []));
t("the tooltip tells the operator a climbing number is normal",
  render.includes("silent for minutes") || render.includes("15-40 min"), render.slice(-400));
t("the pill is actually placed in the panel", SRC.includes("${timingPill}${agentPill}"));

const CSS = (() => {
  for (const p of ["/tmp/style.css", "web-ui/style.css", "../web-ui/style.css"]) {
    if (fs.existsSync(p)) return fs.readFileSync(p, "utf8");
  }
  return null;
})();
if (CSS === null) {
  console.log("SKIP  style.css not found next to this test");
} else {
  const rule = CSS.slice(CSS.indexOf(".agent-pill {"), CSS.indexOf("}", CSS.indexOf(".agent-pill {")) + 1);
  t(".agent-pill is styled", rule.startsWith(".agent-pill {"), rule.slice(0, 40));
  t("REGRESSION: it uses the muted/neutral tokens, not a warning colour — its "
    + "predecessor was amber 75.3% of a healthy run",
    rule.includes("var(--fg-muted)") && !/yellow|red|orange|amber/i.test(rule), rule);
  t("...and does not pulse or otherwise demand attention",
    !rule.includes("animation"), rule);
  t("no state-variant rules exist for it",
    !/\.agent-pill\.(warn|dead|silent|active|stale)/.test(CSS));
}

console.log(`\n${ran} checks, ${bad} failed`);
process.exit(bad ? 1 : 0);
