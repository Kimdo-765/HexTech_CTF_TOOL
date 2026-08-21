// Regression suite for the Dashboard panel.
//
// Run in a container with node 20 (the host's node is too old for this repo's
// app.js — it uses optional chaining):
//
//   docker cp web-ui/app.js      <worker>:/tmp/app.js
//   docker cp web-ui/index.html  <worker>:/tmp/index.html
//   docker cp web-ui/style.css   <worker>:/tmp/style.css
//   docker cp scripts/test_dashboard_ui.js <worker>:/tmp/t.js
//   docker exec <worker> node /tmp/t.js
//
// WHAT MOVED
// The jobs list used to be a permanent second column of `main`, beside
// whichever module panel was open. It now lives in the Dashboard panel. The
// toolbar ids and #jobs-list are deliberately UNCHANGED so selectJob,
// deleteJob, refreshJobs and the flag alarm keep binding to the same nodes —
// this was a move, not a rewrite. The checks below pin that down, because the
// failure mode of getting it wrong is silent: `document.getElementById(...)`
// returns null at load time and the listener is simply never attached.
//
// `main` also had to drop from `1fr 1fr` to `1fr`; with the second child gone
// every panel would otherwise render into the left half of the window.

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
const HTML = read(["/tmp/index.html", "web-ui/index.html", "../web-ui/index.html"]);
const CSS = read(["/tmp/style.css", "web-ui/style.css", "../web-ui/style.css"]);
if (!SRC || !HTML || !CSS) { console.log("FATAL  web-ui sources not found"); process.exit(2); }

// Pull the real ring/format helpers out of app.js and run them.
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
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const ringSrc = sliceFn("_dashRing"), bytesSrc = sliceFn("_dashBytes");
t("_dashRing is present", !!ringSrc);
t("_dashBytes is present", !!bytesSrc);
if (!ringSrc || !bytesSrc) { console.log(`\n${ran} checks, ${bad} failed`); process.exit(1); }
const api = new Function("escapeHtml",
  `${bytesSrc}\n${ringSrc}\nreturn {_dashRing, _dashBytes};`)(escapeHtml);

// ------------------------------------------------------------------ format
console.log("\n--- byte formatting --------------------------------------");
t("GiB above a gigabyte", api._dashBytes(2 * 1073741824) === "2.0 GiB", api._dashBytes(2147483648));
t("MiB in between", api._dashBytes(373587968) === "356 MiB", api._dashBytes(373587968));
t("REGRESSION: zero is a NUMBER here, not fmtBytes's \"unlimited\" — that "
  + "string answers a different question (what is the cap)",
  api._dashBytes(0) === "0 KiB", api._dashBytes(0));
t("a missing value degrades to ?", api._dashBytes(null) === "?", api._dashBytes(null));

// -------------------------------------------------------------------- ring
console.log("\n--- the ring must encode the number it claims -------------");
const arc = (html) => {
  const m = html.match(/stroke-dasharray="([\d.]+) ([\d.]+)"/);
  return m ? Number(m[1]) / Number(m[2]) : null;
};
t("0% draws no arc", Math.abs(arc(api._dashRing(0, "x", "")) - 0) < 1e-6);
t("50% draws half the circumference",
  Math.abs(arc(api._dashRing(50, "x", "")) - 0.5) < 1e-3, arc(api._dashRing(50, "x", "")));
t("100% closes the ring",
  Math.abs(arc(api._dashRing(100, "x", "")) - 1) < 1e-3, arc(api._dashRing(100, "x", "")));
t("the percentage is also printed as text",
  api._dashRing(37, "x", "").includes(">37%<"), api._dashRing(37, "x", ""));

console.log("\n--- unmeasurable is not the same as zero -----------------");
const unknown = api._dashRing(null, "x", "");
t("REGRESSION: a null reading renders '—', not 0%",
  unknown.includes(">—<") && !unknown.includes(">0%<"), unknown.slice(-260));
t("...and gets no severity class",
  !/dash-ring (warn|high)/.test(unknown), unknown.slice(0, 60));

console.log("\n--- severity is earned, not decorative -------------------");
t("a normal container is plain", !/dash-ring (warn|high)/.test(api._dashRing(40, "x", "")));
t("75% warns", /dash-ring warn/.test(api._dashRing(75, "x", "")));
t("90% is high", /dash-ring high/.test(api._dashRing(90, "x", "")));
t("out-of-range input is clamped, never drawn past full",
  Math.abs(arc(api._dashRing(140, "x", "")) - 1) < 1e-3, arc(api._dashRing(140, "x", "")));
t("a hostile label cannot inject markup",
  !api._dashRing(10, '<img src=x onerror=alert(1)>', "").includes("<img"),
  api._dashRing(10, '<img src=x onerror=alert(1)>', "").slice(0, 200));

// ------------------------------------------------------------------ markup
console.log("\n--- the move must not orphan any listener ----------------");
t("a Dashboard tab exists", /data-tab="dashboard"/.test(HTML));
t("...positioned before Containers",
  HTML.indexOf('data-tab="dashboard"') < HTML.indexOf('data-tab="containers"'));
t("its panel exists with the id the tab switcher derives",
  /id="panel-dashboard"/.test(HTML));
t("REGRESSION: the standalone <section id=\"jobs\"> is gone",
  !/<section id="jobs">/.test(HTML));
const dash = HTML.slice(HTML.indexOf('id="panel-dashboard"'),
  HTML.indexOf('id="panel-containers"'));
for (const id of ["jobs-list", "refresh-jobs", "bulk-filter", "bulk-delete"]) {
  t(`  #${id} still exists, inside the dashboard panel`,
    dash.includes(`id="${id}"`), dash.includes(`id="${id}"`));
  t(`  ...and app.js still binds it`, SRC.includes(`"${id}"`) || SRC.includes(`#${id}`));
}
t("the ring mount points exist",
  dash.includes('id="dash-host-ring"') && dash.includes('id="dash-container-rings"'));

console.log("\n--- layout ------------------------------------------------");
const mainRule = CSS.slice(CSS.indexOf("main { padding"), CSS.indexOf("}", CSS.indexOf("main { padding")) + 1);
t("REGRESSION: main is ONE column now that #jobs is not its second child",
  /grid-template-columns:\s*1fr\s*;/.test(mainRule), mainRule);
t(".dash-ring is styled", CSS.includes(".dash-ring {"));
// The usage/cap pair is 15-17 chars ("152 MiB / 2.0 GiB"). A fixed 5.5rem tile
// fitted the short ones and split the long ones after the slash, so the cap's
// number and its unit landed on different lines. nowrap is the guarantee; the
// width floor only keeps the tiles even.
t("REGRESSION: the usage/cap pair cannot wrap mid-value",
  /\.dash-ring \.dash-sub\s*\{[^}]*white-space:\s*nowrap/.test(CSS),
  CSS.slice(CSS.indexOf(".dash-ring .dash-sub"), CSS.indexOf(".dash-ring .dash-sub") + 90));
t("  ...the container tiles have a floor AND can still grow past it",
  /\.dash-rings \.dash-ring\s*\{[^}]*width:\s*auto[^}]*min-width:\s*7rem/.test(CSS),
  CSS.slice(CSS.indexOf(".dash-rings .dash-ring"), CSS.indexOf(".dash-rings .dash-ring") + 70));
t("  ...a long container label still truncates instead of widening the tile",
  /\.dash-ring-label \{[^}]*max-width:\s*7rem[^}]*text-overflow:\s*ellipsis/.test(CSS));
// #dash-host-ring is a .dash-ring with a 92px svg and no value line. The floor
// above is deliberately scoped away from it; an unscoped `.dash-ring { min-width }`
// would push the Host RAM donut off its caption, which no CSS regex would catch.
t("  ...and the host ring keeps its own width",
  /\.dash-ring \{[^}]*width:\s*5\.5rem/.test(CSS),
  CSS.slice(CSS.indexOf(".dash-ring {"), CSS.indexOf(".dash-ring {") + 110));

console.log("\n--- wiring ------------------------------------------------");
t("the dashboard tab loads the rings",
  /data-tab="dashboard"[\s\S]{0,200}loadDashboard\(\)/.test(SRC));
t("loadDashboard reads host_mem from the API", SRC.includes("data.host_mem"));
t("REGRESSION: it asks for sizes=false — the disk walk is the slow half and "
  + "the rings only need memory", SRC.includes("containers?sizes=false"));
t("only RUNNING containers get a ring (a stopped one reports no memory_stats)",
  /state === "running"/.test(SRC));
t("the poll stops when the panel is not active",
  /panel-dashboard[\s\S]{0,120}_stopDashPoll\(\)/.test(SRC));
t("REGRESSION: freshly rendered job rows restart the 1s tick, or the "
  + "dashboard's own counters freeze between polls",
  /status === "running"\)\) _ensureLivePillTimer\(\)/.test(SRC));
t("row pills reuse the shared age formatter", /rowPills[\s\S]{0,600}_fmtAgentAge\(/.test(SRC));
t("REGRESSION: the row's agent pill has no started_at fallback either",
  /if \(job\.last_agent_event_at\) \{/.test(SRC));

// ------------------------------------------------------- retry/target gates
// The job-card affordances (Retry / Change target / Stop) are computed in a
// block inside renderJob(). This oracle used to live in test_flag_ready.py and
// read the FIRST `const hasTarget` line out of app.js — which is the job-CREATE
// form's variable (app.js ~865), not the render gate 2600 lines below it. So
// three separate mutants passed against it: dropping forensic from retry,
// adding forensic to change-target, and removing flag_ready from the retry
// statuses. Run the real block.
console.log("\n--- the card offers exactly the affordances the module earns ---");

function sliceBlock(startNeedle, endNeedle) {
  const start = SRC.indexOf(startNeedle);
  if (start === -1) return null;
  const end = SRC.indexOf(endNeedle, start);
  if (end === -1) return null;
  return SRC.slice(start, end);
}

const blockSrc = sliceBlock('let runBlock = "";', "// The operator's true/false-positive call");
t("the render-affordance block was located", !!blockSrc);
if (blockSrc) {
  // Only `job` and `escapeHtml` cross into the block; everything else it needs
  // it declares. Returning the gate booleans AND the rendered html lets the
  // checks below assert both the decision and the button it produced.
  // Compile and call are both wrapped: a rename or a syntax slip must arrive as
  // a NAMED failure with the summary still printed, not as an exception that
  // kills the run. A crash and a pass look identical to anyone reading exit
  // codes, and this file's job is to fail by name.
  let renderGates = null;
  try {
    renderGates = new Function(
      "job", "escapeHtml",
      `${blockSrc}\n return {runBlock,` +
      `  canRetry: typeof canRetry === "undefined" ? undefined : canRetry,` +
      `  canContinue: typeof canContinue === "undefined" ? undefined : canContinue,` +
      `  hasTarget: typeof hasTarget === "undefined" ? undefined : hasTarget,` +
      `  showRetry: typeof showRetry === "undefined" ? undefined : showRetry,` +
      `  showChangeTarget: typeof showChangeTarget === "undefined" ? undefined : showChangeTarget,` +
      `  showStop: typeof showStop === "undefined" ? undefined : showStop,` +
      `  showStopResume: typeof showStopResume === "undefined" ? undefined : showStopResume,` +
      `  isExploitableModule: typeof isExploitableModule === "undefined" ? undefined : isExploitableModule};`
    );
  } catch (e) {
    t("the render block compiles", false, String(e));
  }
  const gateErrors = [];
  const gatesFor = (module, status) => {
    if (!renderGates) return { runBlock: "" };
    try {
      return renderGates({ module, status, id: "abc123abc123" }, escapeHtml);
    } catch (e) {
      gateErrors.push(`${module}/${status}: ${e}`);
      return { runBlock: "" };
    }
  };
  const hasAction = (html, action) =>
    new RegExp(`data-action="${action}"`).test(html);

  // forensic finished: the backend rebuilds it (canRetry) AND, as of the
  // all-modules target round, it accepts a target. This assertion used to read
  // "forensic is NOT offered change-target — it takes none"; that was true when
  // the module had no target field at all. It has one now, `_resubmit` carries
  // target_url into the child meta, and the orchestrator reads it back — so a
  // change-target here reaches a real consumer and the button is correct.
  let g = gatesFor("forensic", "finished");
  t("forensic is retryable", g.canRetry === true, g.canRetry);
  t("REGRESSION: a finished forensic job offers Retry",
    g.showRetry === true && hasAction(g.runBlock, "retry"), g.runBlock);
  t("forensic now takes a target, so change-target is offered and lands somewhere",
    g.hasTarget === true && g.showChangeTarget === true
      && hasAction(g.runBlock, "change-target"), g.runBlock);

  // Retryable and continuable are different questions, and the card asked only
  // the first one. /retry rebuilds a forensic job from its image and works;
  // /continue would have to fork a provider session, and forensic's
  // orchestrator builds none — the server answers 400. The card used to draw
  // the button anyway, because continueHtml was gated on showRetry.
  t("forensic advertises BOTH retry buttons",
    hasAction(g.runBlock, "retry") && hasAction(g.runBlock, "retry-manual"),
    g.runBlock);
  // Asserted on what is RENDERED, not on a variable's name. The earlier version
  // read g.canContinue, which made a harmless rename of the declaration AND its
  // use — same behaviour, different spelling — come out red. A check that fails
  // on a rename it should not care about is measuring the wrong thing, which is
  // the same defect as one that passes on a rename it should catch.
  t("REGRESSION: forensic does NOT advertise a Continue the server refuses",
    !hasAction(g.runBlock, "continue"), g.runBlock);

  // The control: a module that really can be continued still offers it, so the
  // check above is about forensic and not about Continue disappearing.
  const gp = gatesFor("pwn", "no_flag");
  t("  ...while pwn still offers Continue",
    hasAction(gp.runBlock, "continue"), gp.runBlock);

  // Cross-file parity. The card's canContinue and the server's
  // _CONTINUABLE_MODULES are two written-out lists, and written-out lists drift
  // — that is the whole history of this file. Neither may be derived from
  // canRetry (that defaulted new modules to allowed), so the invariant lives
  // here instead.
  // ---------------------------------------------------------------------
  // Capability parity, judged the only way that cannot be faked.
  //
  // Five rounds of this check were regex over source text, and each round a
  // mutant walked past it: a hardcoded candidate list, then a missing list,
  // then a declaration split across lines. Every fix was a better regex. The
  // method was the defect — a comment or a string literal can wear the shape
  // of a declaration, and no amount of pattern care changes that.
  //
  // The backend list now comes from Python's own parser, so only real code
  // counts. The UI side is not read at all: it is EXERCISED, and what the card
  // renders is the answer. How the declaration is spelled, or across how many
  // lines, stops being a question anyone has to ask.
  // ---------------------------------------------------------------------
  const { execFileSync } = require("child_process");
  const retryPath = ["api/routes/retry.py", "../api/routes/retry.py"]
    .find((f) => fs.existsSync(f));
  t("the server's retry module is on disk", !!retryPath, retryPath);

  const AST_PROBE = `
import ast, json, sys
tree = ast.parse(open(sys.argv[1]).read())
want = {"_RETRYABLE_MODULES", "_CONTINUABLE_MODULES"}
out = {}
for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id in want:
                vals = None
                if isinstance(node.value, (ast.Tuple, ast.List)):
                    vals = [e.value for e in node.value.elts
                            if isinstance(e, ast.Constant)]
                out.setdefault(tgt.id, []).append(vals)
print(json.dumps(out))
`;
  let SERVER = {};
  try {
    SERVER = JSON.parse(
      execFileSync("python3", ["-c", AST_PROBE, retryPath], { encoding: "utf8" })
    );
  } catch (e) {
    t("the backend capability lists parse", false, String(e));
  }
  for (const name of ["_RETRYABLE_MODULES", "_CONTINUABLE_MODULES"]) {
    const got = SERVER[name] || [];
    t(`${name} is assigned exactly once, as a literal`,
      got.length === 1 && Array.isArray(got[0]), got);
  }
  const serverRetry = ((SERVER._RETRYABLE_MODULES || [[]])[0] || []).slice().sort();
  const serverCont = ((SERVER._CONTINUABLE_MODULES || [[]])[0] || []).slice().sort();

  // Candidates only need to be a superset — they decide what gets EXERCISED,
  // not what is contractual. Harvesting every quoted name in the render block
  // means a module added anywhere in it is tried, decoy or not; a decoy simply
  // renders nothing and drops out.
  const NEGATIVE = ["misc", "hybrid", "live-fire"];
  const candidates = Array.from(new Set([
    ...serverRetry, ...serverCont, ...NEGATIVE,
    ...((blockSrc.match(/"([a-z0-9-]+)"/g) || [])
      .map((x) => x.replace(/"/g, ""))
      .filter((x) => /^[a-z][a-z0-9-]*$/.test(x))),
  ]));

  const setEq = (a, b) =>
    JSON.stringify(a.slice().sort()) === JSON.stringify(b.slice().sort());
  const renders = (m, st, action) => hasAction(gatesFor(m, st).runBlock, action);

  const TERMINAL = ["failed", "no_flag", "finished", "stopped", "flag_ready"];
  const LIVE = ["queued", "running"];

  for (const st of TERMINAL) {
    const r = candidates.filter((m) => renders(m, st, "retry"));
    const c = candidates.filter((m) => renders(m, st, "continue"));
    t(`REGRESSION: [${st}] rendered Retry set equals _RETRYABLE_MODULES`,
      setEq(r, serverRetry), { rendered: r.sort(), server: serverRetry });
    t(`REGRESSION: [${st}] rendered Continue set equals _CONTINUABLE_MODULES`,
      setEq(c, serverCont), { rendered: c.sort(), server: serverCont });
  }
  for (const st of LIVE) {
    const r = candidates.filter((m) => renders(m, st, "retry"));
    const c = candidates.filter((m) => renders(m, st, "continue"));
    t(`REGRESSION: [${st}] renders neither Retry nor Continue`,
      r.length === 0 && c.length === 0, { retry: r, continue: c });
  }
  t("no module/status combination threw while rendering", gateErrors, []);

  // Parity: every module the backend will rebuild is offered Retry by the card.
  // This is the check the old 200-char source slice was trying to make.
  // Discovered, not hardcoded: a six-name literal here would go stale the day
  // the server list changes, and stale-but-green is the failure this file keeps
  // producing.
  for (const m of serverRetry) {
    t(`  card offers Retry for ${m} (matches the backend _RETRYABLE_MODULES)`,
      gatesFor(m, "no_flag").showRetry === true, m);
  }
}

console.log(`\n${ran} checks, ${bad} failed`);
process.exit(bad ? 1 : 0);
