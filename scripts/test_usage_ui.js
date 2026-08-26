#!/usr/bin/env node
/** Regression: incomplete dollar accounting must never render as budget room. */
const fs = require("fs");
const path = require("path");

let JSDOM;
try { ({ JSDOM } = require("jsdom")); }
catch (e) { console.log("SKIP: jsdom not installed"); process.exit(0); }

const ROOT = path.resolve(__dirname, "..");
const src = fs.readFileSync(path.join(ROOT, "web-ui/app.js"), "utf8");
const start = src.indexOf("function renderUsage(u)");
const end = src.indexOf("\nasync function deleteJob", start);
if (start < 0 || end < 0) throw new Error("renderUsage slice not found");

const dom = new JSDOM(`<!doctype html><body>
  <span id="usage-pill" class="usage-pill usage-pill--warn"></span>
  <span id="ratelimit-chip"></span>
  <span id="grok-ratelimit-chip"></span>
  <span id="codex-ratelimit-chip"></span>
</body>`, { runScripts: "outside-only" });
dom.window.eval(`${src.slice(start, end)}\nwindow.renderUsage = renderUsage;`);

let pass = 0, fail = 0;
function check(name, condition, detail = "") {
  if (condition) { pass++; console.log(`PASS  ${name}`); }
  else { fail++; console.log(`FAIL  ${name}${detail ? `: ${detail}` : ""}`); }
}

const pill = dom.window.document.getElementById("usage-pill");
dom.window.renderUsage({
  spent_usd: 5.96,
  spent_usd_complete: false,
  terminal_unpriced_estimate_usd: 18.4224,
  in_flight_estimate_usd: 0,
  budget_usd: 40,
  remaining_usd: null,
  pct_used: null,
});
check("incomplete spend is labelled unmeasurable", pill.textContent === "spend unmeasurable", pill.textContent);
check("known subtotal remains inspectable", pill.title.includes("$5.9600"), pill.title);
check("token estimate remains separate", pill.title.includes("~18.4224 USD"), pill.title);
check("incomplete subtotal gets no safe-looking warning color",
  !pill.classList.contains("usage-pill--warn") && !pill.classList.contains("usage-pill--over"));

dom.window.renderUsage({
  spent_usd: 8,
  spent_usd_complete: true,
  in_flight_estimate_usd: 0,
  budget_usd: 10,
  remaining_usd: 2,
  pct_used: 80,
});
check("complete spend still renders used over budget", pill.textContent === "$8.00 / $10 (80%)", pill.textContent);
check("complete 80 percent still warns", pill.classList.contains("usage-pill--warn"));

console.log(`\n${pass + fail} checks, ${fail} failed`);
process.exit(fail ? 1 : 0);
