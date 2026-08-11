#!/usr/bin/env node
// S3 hybrid parent detail renderer. Executes the production renderer directly
// without jsdom, matching the host-compatible pattern used by LF-5.

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const src = fs.readFileSync(path.join(root, "web-ui/app.js"), "utf8");
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

const rendererSource = sliceFn(src, "hybridStageEvidenceHtml");
check("hybrid stage evidence renderer exists", !!rendererSource);
if (!rendererSource) process.exit(1);

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[char]);
const render = new Function(
  "escapeHtml", `${rendererSource}\nreturn hybridStageEvidenceHtml;`,
)(escapeHtml);

const html = render({
  module: "hybrid",
  hybrid: {
    stages: [
      {stage: 0, module: "rev", child_job_id: "aaa111aaa111", status: "finished", cost_usd: 1.25},
      {stage: 1, module: "pwn", child_job_id: "bbb222bbb222", status: "running", cost_usd: 2.5},
    ],
    stage_flag_evidence: [
      {
        stage: 0, module: "rev", child_job_id: "aaa111aaa111",
        value: "DH{weak}", provenance: {tier: "narrative", field: "flags"},
        disposition: "unverified",
      },
      {
        stage: 1, module: "pwn", child_job_id: "bbb222bbb222",
        value: "<script>alert(1)</script>",
        provenance: {tier: "marker", field: "flags"}, disposition: "confirmed",
      },
    ],
  },
});

check("parent detail opens the hybrid evidence panel", html.includes('class="hybrid-stage-evidence" open'));
check("stage order is rendered", html.indexOf("aaa111aaa111") < html.indexOf("bbb222bbb222"));
check("stage modules are rendered", html.includes("rev") && html.includes("pwn"));
check("stage statuses are rendered", html.includes("finished") && html.includes("running"));
check("stage costs are rendered once each", html.includes("$1.2500") && html.includes("$2.5000"));
check("provenance tier and source are rendered", html.includes("narrative / flags") && html.includes("marker / flags"));
check("both dispositions are rendered", html.includes("unverified") && html.includes("confirmed"));
check("evidence values are HTML escaped", html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
check("raw evidence HTML cannot execute", html.includes("<script>alert(1)</script>"), false);
check("non-hybrid jobs render no hybrid panel", render({module: "pwn"}), "");

const empty = render({module: "hybrid", hybrid: {stages: [], stage_flag_evidence: []}});
check("empty parent states the missing stage records", empty.includes("No stages recorded."));
check("empty parent states the missing evidence records", empty.includes("No flag evidence recorded yet."));

const retryMatch = src.match(/const isExploitableModule = \[([^\]]+)\]\.includes\(job\.module\);/);
const retryModules = retryMatch ? retryMatch[1].match(/"[^"]+"/g).map((v) => JSON.parse(v)) : [];
check("hybrid parent is not a scalar retry module", retryModules.includes("hybrid"), false);

console.log(`\n== summary: ${passed} passed, ${failed} failed ==`);
process.exit(failed ? 1 : 0);
