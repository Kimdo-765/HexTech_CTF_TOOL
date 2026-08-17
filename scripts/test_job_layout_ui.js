// Regression suite for the job detail layout.
//
// Run in a container with node 20 (the host's node predates optional chaining):
//
//   docker cp web-ui/app.js    <worker>:/tmp/app.js
//   docker cp web-ui/style.css <worker>:/tmp/style.css
//   docker cp scripts/test_job_layout_ui.js <worker>:/tmp/t.js
//   docker exec <worker> node /tmp/t.js
//
// WHAT CHANGED
// The job modal is min(1600px, 96vw) wide and was rendering one column into
// it. Two consequences: prose and log lines ran the full 1600px, and the run
// log — the thing you watch while a job runs — started below the fold on every
// job, under the description, flags, findings and result.
//
// Now: facts as chips, actions full-width, then two columns — outcome (flags,
// candidates, error, description, findings, result) on the left and activity
// (live SDK feed, run log) on the right. One column again under 1150px.
//
// The risky part is not the CSS, it is that the template is one 60-line
// backtick string whose blocks are interpolated by name. Dropping or
// double-nesting one `</div>` yields markup that still parses as JavaScript and
// only looks wrong in a browser. So the template is EXECUTED here with each
// block stubbed, and the resulting document order is asserted.

const fs = require("fs");

let bad = 0, ran = 0;
const t = (label, cond, got) => {
  ran++;
  console.log((cond ? "PASS  " : "FAIL  ") + label + (cond ? "" : `  | got=${JSON.stringify(got)}`));
  if (!cond) bad++;
};
const read = (names) => {
  for (const p of names) if (fs.existsSync(p)) return fs.readFileSync(p, "utf8");
  return null;
};
const SRC = read(["/tmp/app.js", "web-ui/app.js", "../web-ui/app.js"]);
const CSS = read(["/tmp/style.css", "web-ui/style.css", "../web-ui/style.css"]);
if (!SRC || !CSS) { console.log("FATAL  web-ui sources not found"); process.exit(2); }

// ------------------------------------------------- render the real template
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const i = SRC.indexOf("detail.innerHTML = `");
const j = SRC.indexOf("\n  `;", i);
t("the detail template is locatable", i !== -1 && j > i);
if (i === -1 || j < 0) { console.log(`\n${ran} checks, ${bad} failed`); process.exit(1); }
const tpl = SRC.slice(i + "detail.innerHTML = ".length, j + 4);

const stub = (n) => `<div class="STUB-${n}"></div>`;
const job = {
  id: "abc123", status: "running", module: "crypto", filename: "chal.zip",
  target_url: "host:1234", stage: "analyze", cost_usd: 1.25, job_timeout: 9999,
  agent_provider: "claude", agent_provider_label: "Claude (Agent SDK)",
  model: "claude-opus-5", started_at: new Date().toISOString(),
};
const env = {
  job, id: job.id, escapeHtml,
  _metaChip: (k, v) => `<span class="job-meta-chip"><b>${escapeHtml(k)}</b>${escapeHtml(String(v))}</span>`,
  _tgts: [], targetExtra: "", timingPill: '<span class="timing-pill live"></span>',
  agentPill: '<span class="agent-pill"></span>', timeoutBlock: "",
  runBlock: stub("run"), descBlock: stub("desc"), candBlock: stub("cand"),
  errorBlock: stub("error"), flagBlock: stub("flag"),
  // The operator's ok/wrong banner. Present for flag_ready and for a finished
  // job whose flag can still be ruled wrong.
  verdictBlock: stub("verdict"),
  logFindingsBlock: stub("findings"), resultBlock: stub("result"),
  monitorView: false, monitorLang: "ko", runlogTz: "utc", log: "l1\nl2",
  monitorFeedHTML: "", tokensPill: '<span class="tokens-pill"></span>',
  isGptJob: false, activityView: "log", gptTimelineTools: false,
  gptTimelineHTML: '<div class="STUB-gpt-timeline"></div>',
  _logSearch: {}, _localTzName: () => "KST", colorizeRunLog: (l) => l,
};
let html = "";
try {
  html = new Function(...Object.keys(env), `return ${tpl}`)(...Object.values(env));
} catch (e) {
  t("the template evaluates", false, String(e).slice(0, 160));
  console.log(`\n${ran} checks, ${bad} failed`); process.exit(1);
}
t("the template evaluates", html.length > 0);
const at = (needle) => html.indexOf(needle);

const gptHtml = new Function(...Object.keys(env), `return ${tpl}`)(
  ...Object.values({
    ...env,
    job: {...job, agent_provider: "gpt", agent_provider_label: "OpenAI Codex"},
    isGptJob: true,
    activityView: "timeline",
  }),
);
t("Claude keeps the legacy log tabs", html.includes('data-action="view-log"')
  && !html.includes('data-action="view-gpt-timeline"'));
t("GPT gets its isolated Timeline tab", gptHtml.includes('data-action="view-gpt-timeline"')
  && gptHtml.includes('class="gpt-timeline-feed"'));
t("GPT has no narrator Monitor UI", !gptHtml.includes('data-action="view-gpt-monitor"')
  && !gptHtml.includes('class="monitor-feed"')
  && !gptHtml.includes('data-action="monitor-lang"'));
t("Claude keeps its existing Monitor UI", html.includes('data-action="view-monitor"')
  && html.includes('class="monitor-feed"')
  && html.includes('data-action="monitor-lang"'));

// -------------------------------------------------------------- structure
console.log("\n--- the two columns, and what is in them -----------------");
t("a job-grid exists", at('class="job-grid"') !== -1);
t("an outcome column exists", at('class="job-col-outcome"') !== -1);
t("an activity column exists", at('class="job-col-activity"') !== -1);
for (const k of ["flag", "cand", "error", "desc", "findings", "result"]) {
  t(`  ${k} is in the OUTCOME column`,
    at(`STUB-${k}`) > at('class="job-col-outcome"') && at(`STUB-${k}`) < at('class="job-col-activity"'),
    at(`STUB-${k}`));
}
t("the run log is in the ACTIVITY column",
  at("run-log-window") > at('class="job-col-activity"'));
t("the live SDK feed is too", at('class="sdk-live"') > at('class="job-col-activity"'));
t("REGRESSION: actions sit ABOVE the split, so they do not move when the "
  + "layout collapses to one column", at("STUB-run") < at('class="job-grid"'));

console.log("\n--- markup must actually close ---------------------------");
const count = (re) => (html.match(re) || []).length;
t("every <div> is closed", count(/<div\b/g) === count(/<\/div>/g),
  [count(/<div\b/g), count(/<\/div>/g)]);
t("every <span> is closed", count(/<span\b/g) === count(/<\/span>/g),
  [count(/<span\b/g), count(/<\/span>/g)]);
t("the columns are siblings, not nested",
  at('class="job-col-activity"') > at('class="job-col-outcome"')
  && html.slice(at('class="job-col-outcome"'), at('class="job-col-activity"')).includes("</div>"));

console.log("\n--- the nodes other code binds to must survive -----------");
// renderJob's own scroll-restore and the poll path query these by class /
// attribute after every re-render. A layout change that renames or drops one
// of them fails silently: querySelector returns null and the branch is skipped.
for (const sel of ['class="run-log"', 'class="monitor-feed"', 'class="sdk-live-feed"',
                   'class="run-log-window"', 'data-action="toggle-tz"',
                   'data-action="view-monitor"', 'class="run-log-search"']) {
  t(`  ${sel} still rendered`, at(sel) !== -1);
}

console.log("\n--- facts as chips ---------------------------------------");
t("chips are rendered", count(/job-meta-chip/g) >= 6, count(/job-meta-chip/g));
t("REGRESSION: the old one-line `·`-joined meta is gone",
  !/module: \$\{job\.module\} ·/.test(SRC) && !html.includes("module: crypto ·"),
  html.slice(at('class="job-meta"'), at('class="job-meta"') + 120));
t("every value still present: module", html.includes("crypto"));
t("...target", html.includes("host:1234"));
t("...model", html.includes("claude-opus-5"));
t("...cost, at 4dp", html.includes("$1.2500"), html.match(/\$[\d.]+/));
t("an absent optional field renders NO chip rather than an empty one",
  !new Function(...Object.keys(env), `return ${tpl}`)(
    ...Object.values({...env, job: {...job, model: null, cost_usd: null}}))
    .includes("<b>model </b>"));

console.log("\n--- CSS --------------------------------------------------");
t(".job-grid is a grid", /\.job-grid \{[^}]*display: grid/.test(CSS));
t("REGRESSION: it collapses to one column on a narrow window",
  /@media \(max-width: 1150px\) \{\s*\.job-grid \{ grid-template-columns: 1fr; \}/.test(CSS),
  (CSS.match(/@media \(max-width: 1150px\)[\s\S]{0,90}/) || [])[0]);
t("columns may shrink (min-width:0), or a long log line widens the grid",
  /\.job-col-outcome, \.job-col-activity \{ min-width: 0; \}/.test(CSS));
t("REGRESSION: the activity column sticks only in TWO-column mode — sticky in "
  + "one column would pin the log over the content below it",
  /@media \(min-width: 1151px\)[\s\S]{0,200}position: sticky/.test(CSS));
t("chips are styled", CSS.includes(".job-meta-chip {"));

console.log(`\n${ran} checks, ${bad} failed`);
process.exit(bad ? 1 : 0);
