// Regression suite for the flag pill's provenance marker.
//
// The host's node is too old for this repo's app.js (optional chaining), so run
// it inside a container that has node 20:
//
//   docker cp web-ui/app.js  <worker>:/tmp/app.js
//   docker cp scripts/test_flag_provenance_ui.js <worker>:/tmp/t.js
//   docker exec <worker> node --check /tmp/app.js && docker exec <worker> node /tmp/t.js
//
// THE INCIDENT — job 0c04e636633c
// meta.flags held "DH{ + 36 chars of [a-z0-9_] + }", which is the solver's own
// diagnostic banner, swept out of its stdout by a bare regex. The solver had
// printed ZERO `FLAG_CANDIDATE:` markers and its last line read "no flag found".
// In the job list that pill was byte-identical to one covering a real capture:
// `flag_trusted_tier` is a BOOL, and it was true for both "the solver declared
// this string" and "a flag-shaped string turned up in its output".
//
// `meta.flag_provenance` (marker | runner_regex | narrative) names the tier.
// This asserts the pill renders the distinction. It promotes and drops nothing
// — flag curation stays MANUAL, via the UI.
//
// The logic below is a copy of the expression in web-ui/app.js; keep the two in
// step. `assertMatchesApp()` fails if app.js no longer contains it.

const fs = require("fs");

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function pill(job) {
  const provNote = job.flag_sweep_suppressed
    ? "\n\n⚑ The runner's own output DID contain this string — and the same output declares it found nothing. Dropped from the trusted tier; whatever promoted this flag was something else."
    : ({
        runner_regex: "\n\n⚑ SWEPT, not declared — the solver printed no `FLAG_CANDIDATE:` marker, so nothing asserts this IS the flag; only that it is flag-shaped.",
        narrative: "\n\n⚑ From the agent's report.md / findings.json only — the runner's own stdout/stderr does not contain it.",
      }[job.flag_provenance] || "");
  return (job.flags && job.flags.length)
    ? `<span class="flag-pill" title="${escapeHtml(job.flags.join('\n') + provNote)}">🚩 ${job.flags.length}${provNote ? "⚑" : ""}</span>` : "";
}

let bad = 0, ran = 0;
const t = (label, cond, got) => {
  ran++;
  console.log((cond ? "PASS  " : "FAIL  ") + label + (cond ? "" : `  | got=${JSON.stringify(got)}`));
  if (!cond) bad++;
};

const F = ["DH{real}"];

console.log("--- weak provenance must not look like a capture ----------");
t("an explicit FLAG_CANDIDATE marker gets NO warning mark",
  !pill({ flags: F, flag_provenance: "marker" }).includes("⚑"));
t("REGRESSION: a bare sweep hit IS marked",
  pill({ flags: F, flag_provenance: "runner_regex" }).includes("🚩 1⚑"),
  pill({ flags: F, flag_provenance: "runner_regex" }));
t("agent prose IS marked",
  pill({ flags: F, flag_provenance: "narrative" }).includes("🚩 1⚑"));
t("the tooltip says WHY, not just that something is off",
  pill({ flags: F, flag_provenance: "runner_regex" }).includes("no `FLAG_CANDIDATE:` marker"));

console.log("\n--- a suppressed sweep must not be reported as 'never printed' ---");
// The scanner drops a flag-shaped string when the SAME runner output declares
// failure. If report.md then carries the same string, the tier is honestly
// "narrative" — whose note says the runner's output does not contain it. It
// does. This asserts the suppression fact wins.
const supp = pill({ flags: F, flag_provenance: "narrative", flag_sweep_suppressed: true });
t("REGRESSION: the false 'runner's output does not contain it' is NOT shown",
  !supp.includes("does not contain it"), supp);
t("...the runner-did-print-it fact is shown instead",
  supp.includes("DID contain this string"));
t("...and it is still marked", supp.includes("🚩 1⚑"));
t("suppression also overrides the runner_regex note",
  !pill({ flags: F, flag_provenance: "runner_regex", flag_sweep_suppressed: true })
    .includes("SWEPT, not declared"));

console.log("\n--- it must not break what already works -----------------");
t("a job finished BEFORE this field existed renders unmarked",
  !pill({ flags: F }).includes("⚑"));
t("an unrecognised provenance value renders unmarked, not broken",
  !pill({ flags: F, flag_provenance: "something_new" }).includes("⚑"));
t("no flags -> no pill at all",
  pill({ flags: [], flag_provenance: "runner_regex" }) === "");
t("the flag itself is still in the tooltip",
  pill({ flags: F, flag_provenance: "runner_regex" }).includes("DH{real}"));
t("a quote inside a flag cannot break out of the title attribute",
  !pill({ flags: ['DH{a"b}'], flag_provenance: "marker" })
    .replace(/&quot;/g, "").split('title="')[1].split('"')[0].includes('"'));

console.log("\n--- the copy above still matches app.js ------------------");
function assertMatchesApp() {
  for (const p of ["/tmp/app.js", "web-ui/app.js", "../web-ui/app.js"]) {
    if (!fs.existsSync(p)) continue;
    const src = fs.readFileSync(p, "utf8");
    t("app.js still keys the pill on flag_provenance",
      src.includes("job.flag_provenance"));
    t("app.js still appends the marker inside the pill",
      src.includes('${provNote ? "⚑" : ""}'));
    return true;
  }
  console.log("SKIP  app.js not found next to this test");
  return false;
}
assertMatchesApp();

console.log(`\n${ran} checks, ${bad} failed`);
process.exit(bad ? 1 : 0);
