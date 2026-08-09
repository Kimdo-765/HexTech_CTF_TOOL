#!/usr/bin/env node
// LF-5 browser contract. Pure-source extraction keeps this runnable on the
// host's old Node without jsdom while still executing the production renderer.

const fs = require("fs");
const path = require("path");

const mutation = process.argv[2] || "none";
const root = path.resolve(__dirname, "..");
let src = fs.readFileSync(path.join(root, "web-ui/app.js"), "utf8");
const html = fs.readFileSync(path.join(root, "web-ui/index.html"), "utf8");
const main = fs.readFileSync(path.join(root, "api/main.py"), "utf8");

let passed = 0, failed = 0;
function check(label, got, want = true) {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    passed++; console.log("PASS  " + label);
  } else {
    failed++; console.log(`FAIL  ${label}\n      got  = ${JSON.stringify(got)}\n      want = ${JSON.stringify(want)}`);
  }
}

function sliceFn(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start === -1) return null;
  let i = source.indexOf("{", start), depth = 0;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}" && --depth === 0) return source.slice(start, i + 1);
  }
  return null;
}

if (mutation === "ready-state") {
  src = src.replace("job.ready_to_deploy === true", "job.ready_to_deploy === false");
} else if (mutation === "unverified-state") {
  src = src.replace(
    "else if (job.ready_to_deploy === false)",
    "else if (job.ready_to_deploy === true)",
  );
} else if (mutation === "evidence-tier") {
  src = src.replace(
    "const tiers = Array.isArray(job.evidence_tiers)",
    "const tiers = false && Array.isArray(job.evidence_tiers)",
  );
} else if (mutation === "artifact-download") {
  src = src.replace(
    'href="${API}/jobs/${encodeURIComponent(jobId)}/file/report.md"',
    'href="${API}/jobs/${encodeURIComponent(jobId)}/file/patched.zip"',
  );
}

const rendererSource = sliceFn(src, "liveFireOutcomeHtml");
check("live-fire result renderer exists", !!rendererSource);
if (!rendererSource) process.exit(1);
const escapeHtml = (value) => String(value).replace(/[&<>\"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[char]);
const render = new Function(
  "API", "escapeHtml", `${rendererSource}\nreturn liveFireOutcomeHtml;`,
)("/api", escapeHtml);

const ready = render({
  module: "live-fire", status: "finished", ready_to_deploy: true,
  evidence_tiers: ["B"],
}, "job one");
check("ready_to_deploy=true renders READY", ready.includes("<strong>READY</strong>"));
check("READY shows evidence tier B", ready.includes("tier B"));
check("READY is not labelled UNVERIFIED", ready.includes("<strong>UNVERIFIED</strong>"), false);

const unverified = render({
  module: "live-fire", status: "finished", ready_to_deploy: false,
  evidence_tiers: ["A"],
}, "job two");
check("ready_to_deploy=false renders UNVERIFIED", unverified.includes("<strong>UNVERIFIED</strong>"));
check("UNVERIFIED shows evidence tier A", unverified.includes("tier A"));
check("UNVERIFIED never inherits READY", unverified.includes("<strong>READY</strong>"), false);
check("UNVERIFIED explicitly warns against deployment", unverified.includes("do not treat as deployable"));

for (const artifact of ["patched.zip", "report.md", "verification.json"]) {
  check(`${artifact} has its own download URL`,
    unverified.includes(`/file/${artifact}`) && unverified.includes(`⬇ ${artifact}`));
}
check("job ids are URL encoded in downloads", unverified.includes("job%20two"));
check("non-live-fire jobs get no live-fire panel", render({module: "web"}, "x"), "");

const pending = render({
  module: "live-fire", status: "running", ready_to_deploy: null,
  evidence_tiers: [],
}, "pending");
check("an in-flight job says PENDING, not UNVERIFIED", pending.includes("<strong>PENDING</strong>"));
check("downloads wait for a finished job", pending.includes("patched.zip"), false);

const formStart = html.indexOf('id="live-fire-form"');
const form = html.slice(formStart, html.indexOf("</form>", formStart));
for (const field of ["file", "verification", "description", "model", "effort", "job_timeout"]) {
  check(`live-fire form sends ${field}`, form.includes(`name="${field}"`));
}
check("live-fire submit uses its dedicated API route",
  /live-fire-form[\s\S]{0,180}\/modules\/live-fire\/analyze/.test(src));
check("API app registers only a dedicated live-fire prefix",
  main.includes('prefix="/api/modules/live-fire"'));
check("no fixed 480/120 deadline is present in the live-fire form",
  !/\b(?:480|120)\b/.test(form));

// Shared-panel regression: adding live-fire must not remove or rename the
// existing module forms/listeners.
for (const moduleName of ["web", "pwn", "forensic", "misc", "crypto", "rev", "web3"]) {
  check(`existing ${moduleName} form remains`, html.includes(`id="${moduleName}-form"`));
  check(`existing ${moduleName} submit listener remains`, src.includes(`getElementById("${moduleName}-form")`));
}

console.log(`\n== summary: ${passed} passed, ${failed} failed; mutation=${mutation} ==`);
process.exit(failed ? 1 : 0);
