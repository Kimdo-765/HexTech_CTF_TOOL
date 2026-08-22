// Regression suite for the Dashboard panel.
//
// HOW TO RUN
//
//   node scripts/test_dashboard_ui.js
//
// The suite itself avoids the syntax the host's old node cannot parse, and it
// never evaluates app.js whole — it slices the pieces it needs — so it runs on
// the host directly. It REQUIRES jsdom, which decides whether a rendered button
// matches the selectors app.js binds on. jsdom 19 resolves from the system path
// (/usr/share/nodejs/jsdom), independent of cwd, so running from a copied tree
// or a /tmp archive works. Without it the suite exits 2 with FATAL rather than
// printing a green skip: "skipped" is not an answer to "is this control wired
// up?", and this file exists to answer exactly that.
//
// To run it inside the worker container instead, the tree must be copied and
// that image must also provide jsdom:
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
// A hard requirement, deliberately NOT the `try { require } catch { SKIP }`
// shape used by test_role_provider_ui.js and test_job_files_quiet_poll.js.
// This file's whole job is to say whether a control is really wired up, and a
// suite that answers "skipped" to that question while printing green is the
// exact failure mode the last four rounds were about. Resolved from the system
// path (/usr/share/nodejs/jsdom), so it works from a /tmp archive too.
let JSDOM;
try {
  ({ JSDOM } = require("jsdom"));
} catch (e) {
  console.log(`FATAL  jsdom is required and could not be loaded: ${e.message}`);
  process.exit(2);
}

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
  // ---------------------------------------------------------------------
  // Is this control really wired up? Asked by EXECUTION, not by spelling.
  // ---------------------------------------------------------------------
  // Four attempts answered it by reading source text, each wrong in a new way:
  //
  //   substring       any mention counted, including one inside a comment
  //   + real <button> fixed that, then demanded `retry-btn` for EVERY action —
  //                   but change-target binds on `.change-target-btn`, stop on
  //                   `.stop-job-btn`, and three gpt actions on no class at all
  //   + derived map   read the selectors out of app.js with a hand-written
  //                   lexer, which then rejected spellings that RUN the same (a
  //                   division after a string, a d escape, a template) and,
  //                   worse, reduced a CSS selector to a list of dotted names —
  //                   so `[class~="retry-btn"]` yielded an EMPTY requirement and
  //                   a genuinely unbound button passed
  //
  // One mistake wearing four hats: source spelling standing in for behaviour.
  // Both stand-ins are gone.
  //
  //   WHICH selectors — from RUNNING the binding block against a recording
  //   `detail`. The engine resolves escapes, templates and arithmetic, so the
  //   strings collected are whatever the code actually passes. And only a query
  //   whose result is handed to addEventListener counts: a lookup that merely
  //   sets a title or scrolls something into view binds nothing and must not
  //   constrain the render.
  //
  //   DOES IT MATCH — asked of jsdom's selector engine, the same CSS a browser
  //   runs. `[class~=]`, `:not()` and selector lists are its problem now. A
  //   button inside an HTML comment does not match either, so the hand-rolled
  //   comment strip is gone as well: one less barrier of ours to keep alive.
  const sliceDiag = [];
  const runDiag = [];

  // The block's END is a needle. Its START is FOUND BY RUNNING, not asserted.
  //
  // Anchoring the start on a needle made the answer depend on where a
  // declaration sits: hoist `const cls = "retry-btn"` one line above the first
  // binding and the selector it builds is byte-identical at runtime, but the
  // slice cannot see the constant and the suite went red on a refactor that
  // changed nothing. That is a source-layout contract wearing a behaviour
  // contract's clothes — the same disease as reading selectors out of the text.
  //
  // So the start is widened backwards one line at a time and the WIDEST window
  // that both parses and runs is the one used. Nothing is hand-written into
  // scope; a declaration the block needs is included because including it makes
  // the block run, and a window that does not run is not used. If no window
  // runs, the failure carries the identifier's name.
  const BIND_START = "  const retryBtn = detail.querySelector(";
  const BIND_END = "  const runBtn = detail.querySelector(";
  const WIDEN_MAX = 25;      // lines the start may move back
  const nStart = SRC.split(BIND_START).length - 1;
  const nEnd = SRC.split(BIND_END).length - 1;

  const CLICK_SELECTORS = [];   // queries whose result got a click listener
  // Diagnostic-only, by design: no mutant changes colour if this list is
  // dropped. P1/P2 green and P9 red already pin the listener criterion in both
  // directions; this is here so a failure message can say what the block queried
  // WITHOUT binding, which is the first thing a reader wants to know.
  const OTHER_QUERIES = [];
  let widenedBy = null;
  const attempts = [];

  const tryWindow = (src) => {
    const seen = [];
    const record = (sel) => {
      const node = { selector: sel, bound: false, dataset: {} };
      seen.push(node);
      return {
        dataset: node.dataset,
        addEventListener(type) { if (type === "click") node.bound = true; },
      };
    };
    const detailStub = {
      querySelector: (sel) => record(sel),
      // Modelled, not answered with []. Nothing in the block binds through a
      // loop today, so no mutant reaches this arm — but an empty answer would
      // make `for (const b of detail.querySelectorAll(sel)) b.addEventListener`
      // vanish from the recording with NO diagnostic, and the suite would go
      // quietly narrower instead of red.
      querySelectorAll: (sel) => [record(sel)],
    };
    try {
      // `new Function`, NOT window.eval — jsdom 19 drops listeners registered
      // through window.eval, reproduced on a three-line DOM with no app code at
      // all (recorded at scripts/test_container_processes.py:418).
      new Function("detail", src)(detailStub);
      return { ok: true, seen };
    } catch (e) {
      return { ok: false, error: `${e.constructor.name}: ${e.message}` };
    }
  };

  if (nStart !== 1 || nEnd !== 1) {
    sliceDiag.push({ startNeedleCount: nStart, endNeedleCount: nEnd });
  } else {
    const endIdx = SRC.indexOf(BIND_END);
    const starts = [SRC.indexOf(BIND_START)];
    for (let k = 0; k < WIDEN_MAX; k++) {
      const here = starts[starts.length - 1];
      if (here <= 0) break;
      const prev = SRC.lastIndexOf("\n", here - 2);
      if (prev < 0) break;
      starts.push(prev + 1);
    }
    // The END stays a needle, and that is a measurement, not a preference: of
    // the next 300 line boundaries below it, exactly ONE produces a window that
    // even executes, and that one cuts `const runBtn = detail.querySelector(...)`
    // off from the addEventListener below it — recording a query as unbound
    // when the product really does bind it. Everything wider is either
    // unbalanced or reaches a module-level variable (`_sdkLiveHidden`) the
    // window cannot see. Widening forward buys nothing and pays in a half-truth.
    //
    // What that leaves: a binding BELOW this needle is outside the window, so
    // if its action ever renders the sweep calls it unwired. That is a red
    // saying "look here", not a silent pass — the same maintenance-red as a
    // renamed start needle. Today the two sets coincide exactly: the card
    // renders seven actions and the window binds those same seven, checked by
    // running, not by asserting.
    // NARROWEST first, not widest. Widest-first would silently prefer a bigger
    // window that happened to parse and run, pulling in queries the block does
    // not make and marking things wired that its own bindings never touch —
    // extra bound selectors only ever make MORE look wired, which is the
    // false-green direction. Taking the smallest window that runs means a line
    // is included because the block cannot run without it, and not one line
    // more. The widening stops the moment it succeeds.
    for (let k = 0; k < starts.length; k++) {
      const res = tryWindow(SRC.slice(starts[k], endIdx));
      if (res.ok) {
        widenedBy = k;
        for (const n of res.seen) (n.bound ? CLICK_SELECTORS : OTHER_QUERIES).push(n.selector);
        break;
      }
      attempts.push({ widenLines: k, error: res.error });
    }
    if (widenedBy === null) {
      // Every window failed. The narrowest attempt's error is the one that
      // names what the block itself needed; report it rather than reading the
      // silence as "nothing is bound".
      runDiag.push(attempts[attempts.length - 1].error);
    }
  }

  const panel = new JSDOM('<!doctype html><body><div id="job-detail"></div></body>')
    .window.document.getElementById("job-detail");
  const selErrors = [];

  // The rendered block is parsed as HTML and queried with the selectors the app
  // binds on. `<button>` is still required: the card's contract is that these
  // affordances are buttons, and a listener attached to a <span> would work in a
  // browser but is not what this file is pinning.
  // "Is this action wired up AND carried by a button." The tag half used to be
  // policed here, which only ever saw the four actions hasAction happens to be
  // called with — Stop and Stop-resume could become <span>s unseen. Both halves
  // are now swept over EVERY rendered action at the end of this block; this
  // helper keeps the conjunction so the parity assertions read the same.
  const hasAction = (html, action) => {
    panel.innerHTML = String(html || "");
    for (const sel of CLICK_SELECTORS) {
      let hits;
      try {
        hits = panel.querySelectorAll(sel);
      } catch (e) {
        selErrors.push([sel, e.message]);
        continue;
      }
      for (const el of Array.from(hits)) {
        if (el.tagName === "BUTTON" && el.getAttribute("data-action") === action) {
          return true;
        }
      }
    }
    return false;
  };

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

# Every WRITE to these names is counted — Assign, AnnAssign and AugAssign alike.
# Counting only Assign let a later "+=" reshape a list after the fact without
# the probe noticing there were two writes.
#
# The value is read with literal_eval, all or nothing. Filtering elements to the
# ones that happen to be constants was the defect: a conditional, a starred
# unpack or a call would be dropped SILENTLY and the survivors passed off as the
# whole list. If it is not a plain tuple of strings, this reports null and the
# exactly-once assertion turns red rather than comparing against a guess.
tree = ast.parse(open(sys.argv[1]).read())
want = {"_RETRYABLE_MODULES", "_CONTINUABLE_MODULES"}
out = {}


def record(name, value_node):
    try:
        val = ast.literal_eval(value_node)
    except Exception:
        val = None
    ok = (
        isinstance(val, tuple)                       # immutable literal only
        and all(isinstance(x, str) for x in val)
    )
    out.setdefault(name, []).append(list(val) if ok else None)


for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id in want:
                record(tgt.id, node.value)
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        tgt = node.target
        if isinstance(tgt, ast.Name) and tgt.id in want:
            record(tgt.id, node.value if node.value is not None else ast.Constant(None))
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
  // The candidate set decides what gets EXERCISED, so it has to be a superset
  // of anything the block could branch on. Harvesting only double-quoted atoms
  // meant a module named with single quotes or a template literal was never
  // tried at all — the check had nothing to say about it. Every quoting style
  // is harvested now, and the canonical module universe is added outright so a
  // module the block never mentions is still probed.
  const UNIVERSE = ["web", "pwn", "crypto", "rev", "web3", "forensic",
                    "misc", "hybrid", "live-fire"];
  const atoms = (src) => {
    const out = [];
    for (const re of [/"([a-z0-9-]+)"/g, /'([a-z0-9-]+)'/g, /`([a-z0-9-]+)`/g]) {
      let m;
      while ((m = re.exec(src)) !== null) out.push(m[1]);
    }
    return out.filter((x) => /^[a-z][a-z0-9-]*$/.test(x));
  };
  const candidates = Array.from(new Set([
    ...serverRetry, ...serverCont, ...UNIVERSE, ...atoms(blockSrc),
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
  // `.length === 0`, not the array. An array — empty or not — is truthy, so the
  // previous form passed unconditionally: it was a check that could not fail,
  // cited as a safeguard two turns before this was noticed.
  t("no module/status combination threw while rendering",
    gateErrors.length === 0, gateErrors);

  // Parity: every module the backend will rebuild is offered Retry by the card.
  // This is the check the old 200-char source slice was trying to make.
  // Discovered, not hardcoded: a six-name literal here would go stale the day
  // the server list changes, and stale-but-green is the failure this file keeps
  // producing.
  for (const m of serverRetry) {
    t(`  card offers Retry for ${m} (matches the backend _RETRYABLE_MODULES)`,
      gatesFor(m, "no_flag").showRetry === true, m);
  }

  // These run LAST and report on the machinery every hasAction call above used.
  // They exist so that "nothing matched" can never be spent as a free pass on a
  // `!hasAction(...)` assertion: each way the machinery can come up empty has a
  // name here instead.
  t("app.js's button-binding block was located by both of its ends",
    sliceDiag.length === 0, { sliceDiag, widenedBy, attempts });
  t("  ...and running it bound listeners without throwing",
    runDiag.length === 0, runDiag);
  t("  ...and every selector it binds on evaluates as CSS",
    selErrors.length === 0, selErrors);
  // A COUNT is not coverage. `CLICK_SELECTORS.length >= 7` was satisfied while
  // Stop's selector had been swapped for a duplicate of Retry's — seven
  // bindings, six distinct, Stop bound to nothing, and the suite green. And the
  // tag check only saw actions someone had thought to call hasAction with.
  //
  // So both questions are asked of EVERY action the card actually renders,
  // found by enumerating the DOM rather than by naming them here.
  const unwiredActions = [];
  const nonButtonActions = [];
  const sweptActions = new Set();
  for (const m of candidates) {
    for (const st of [...TERMINAL, ...LIVE]) {
      let block;
      try {
        block = gatesFor(m, st).runBlock;
      } catch (e) {
        continue;   // gateErrors above already reports a throw by name
      }
      panel.innerHTML = String(block || "");
      for (const el of Array.from(panel.querySelectorAll("[data-action]"))) {
        const action = el.getAttribute("data-action");
        sweptActions.add(action);
        const wired = CLICK_SELECTORS.some((sel) => {
          try { return el.matches(sel); } catch (e) { return false; }
        });
        const where = { module: m, status: st, action, tag: el.tagName };
        if (!wired) unwiredActions.push(where);
        if (el.tagName !== "BUTTON") nonButtonActions.push(where);
      }
    }
  }
  t("every action the card renders is wired to a real click listener",
    unwiredActions.length === 0, unwiredActions);
  t("every action the card renders is carried by a <button>",
    nonButtonActions.length === 0, nonButtonActions);
  // Non-vacuity for the sweep: with nothing rendered both lists are empty and
  // the two checks above pass by having nothing to look at.
  t("  ...and the sweep actually had actions to look at",
    sweptActions.size >= 5, [...sweptActions].sort());

  // Non-vacuity for the MATCHING, stated without naming a class. Take a block
  // app.js really renders and read its actions out of the DOM rather than from a
  // list here. Each one must count as rendered; the same markup with its classes
  // stripped must not (that is the unbound case F16 was about, and the case the
  // `[class~=]` spelling silently readmitted); and the same markup inside an
  // HTML comment must not.
  //
  // "with its classes stripped must not count" holds because every binding in
  // this block requires a class. If app.js ever binds an action with a bare
  // `[data-action=...]`, this turns red — deliberately, so that the change is
  // looked at rather than absorbed.
  const probeHtml = String(gatesFor("forensic", "finished").runBlock || "");
  panel.innerHTML = probeHtml;
  const renderedActions = Array.from(panel.querySelectorAll("button[data-action]"))
    .map((b) => b.getAttribute("data-action"));
  // Classes are stripped through the DOM, not with a regex. `\sclass="[^"]*"`
  // is blind to class='...' — the same quote-blindness this round is removing
  // from the matcher, reappearing in the check that is supposed to police it.
  for (const el of Array.from(panel.querySelectorAll("*"))) el.removeAttribute("class");
  const noClasses = panel.innerHTML;
  const inComment = `<!-- ${probeHtml} -->`;
  const probes = renderedActions.map((a) => ({
    action: a,
    rendered: hasAction(probeHtml, a),
    classesStripped: hasAction(noClasses, a),
    insideComment: hasAction(inComment, a),
  }));
  t("a rendered button counts; the same markup unclassed or commented out does not",
    renderedActions.length >= 2
      && probes.every((x) => x.rendered === true
        && x.classesStripped === false && x.insideComment === false),
    probes);
}

console.log(`\n${ran} checks, ${bad} failed`);
process.exit(bad ? 1 : 0);
