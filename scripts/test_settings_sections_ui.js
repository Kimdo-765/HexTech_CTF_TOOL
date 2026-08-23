#!/usr/bin/env node
/**
 * Settings is a clicked-into list of sections, and the reorganisation must not
 * cost the operator a single setting.
 *
 * The failure modes this exists for are all SILENT — they ship green through
 * every other oracle in scripts/:
 *   - a control that leaves <form id="settings-form"> stops being saved AND
 *     null-derefs loadSettings() half-way, so the form silently half-populates;
 *   - a control the operator never opened is sent as `null` (= clear the
 *     override) if a pane is ever built/filled lazily instead of hidden;
 *   - a constraint-invalid control inside a HIDDEN pane aborts submission
 *     before any listener runs: Save becomes a no-op with nothing on screen;
 *   - a nav <button> without type="button" is a submit button;
 *   - a sub-pane classed .panel is stripped by the top-level tab switcher,
 *     which renders Settings blank.
 *
 * Every check below is run against the real index.html / app.js.
 *
 *   node scripts/test_settings_sections_ui.js
 */
const fs = require("fs");
const path = require("path");

let JSDOM;
try { ({ JSDOM } = require("jsdom")); }
catch (e) { console.log("SKIP: jsdom not installed"); process.exit(0); }

const ROOT = path.resolve(__dirname, "..");
const HTML = fs.readFileSync(path.join(ROOT, "web-ui/index.html"), "utf8");
const SRC = fs.readFileSync(path.join(ROOT, "web-ui/app.js"), "utf8");

let PASS = 0, FAIL = 0;
function t(label, cond, detail) {
  if (cond) { PASS++; console.log("PASS  " + label); }
  else { FAIL++; console.log(`FAIL  ${label}${detail !== undefined ? "\n        " + detail : ""}`); }
}

// Node 12 on the host cannot parse optional chaining; the sliced production
// code is only ever reached through elements that exist in this fixture.
const es5 = (s) => s.replace(/\?\.\(/g, "(").replace(/\?\.\[/g, "[").replace(/\?\./g, ".");

const dom = new JSDOM(HTML, { runScripts: "outside-only" });
const win = dom.window;
const doc = win.document;
const form = doc.getElementById("settings-form");
const panelSettings = doc.getElementById("panel-settings");

// The complete set of settings the form is responsible for. Spelled out so
// that losing one during a re-nesting is a named failure, not a silent gap.
const NAMES = ["agent_provider", "topology_preset", "role_provider_judge",
  "role_provider_reviewer", "role_provider_report", "role_provider_monitor",
  "anthropic_api_key", "claude_model", "claude_effort", "claude_model_custom",
  "xai_api_key", "grok_model", "grok_effort", "grok_model_custom",
  "gpt_runtime", "openai_api_key", "gpt_model", "gpt_effort", "gpt_model_custom",
  "auth_token", "job_ttl_days", "job_timeout_seconds", "worker_concurrency",
  "worker_slot_mem", "dynamic_worker_mem", "budget_usd", "callback_url",
  "judge_mode", "enable_exploit_library_hint"];

// --- 1. nothing left the form, and nothing left a section -------------------
console.log("\n--- every control is still in the form, in exactly one section ---");
const inForm = new Set(Array.from(form.querySelectorAll("[name]"), (e) => e.name));
for (const n of NAMES) {
  t(`  ${n} is inside #settings-form`, inForm.has(n));
}
t("no settings control escaped into the panel but outside the form",
  Array.from(panelSettings.querySelectorAll("[name]")).every((e) => form.contains(e)),
  Array.from(panelSettings.querySelectorAll("[name]"))
    .filter((e) => !form.contains(e)).map((e) => e.name).join(","));
const panes = Array.from(panelSettings.querySelectorAll("[data-settings-pane]"));
t("the panel is split into sections", panes.length >= 2, panes.length);
t("every named control sits inside a section",
  Array.from(form.querySelectorAll("[name]"))
    .every((e) => e.closest("[data-settings-pane]")),
  Array.from(form.querySelectorAll("[name]"))
    .filter((e) => !e.closest("[data-settings-pane]")).map((e) => e.name).join(","));
t("no section nests inside another",
  panes.every((p) => !p.parentElement.closest("[data-settings-pane]")));

// --- 2. the menu ------------------------------------------------------------
console.log("\n--- the menu is a list of real buttons, correctly wired ----------");
const nav = doc.getElementById("settings-nav");
t("a settings nav exists", !!nav);
const items = nav ? Array.from(nav.querySelectorAll("[data-settings-target]")) : [];
t("it has one item per section", items.length === new Set(panes.map((p) => p.dataset.settingsPane)).size,
  `${items.length} items / ${new Set(panes.map((p) => p.dataset.settingsPane)).size} sections`);
t("every item points at a section that exists",
  items.every((b) => panes.some((p) => p.dataset.settingsPane === b.dataset.settingsTarget)));
t("every section is reachable from the menu",
  panes.every((p) => items.some((b) => b.dataset.settingsTarget === p.dataset.settingsPane)));
// A <button> in a form with no type is a SUBMIT button: every menu click would
// save. The only typeless button in this form is Save itself.
t("every menu item is type=button (a typeless one submits the form)",
  items.every((b) => b.getAttribute("type") === "button"),
  items.filter((b) => b.getAttribute("type") !== "button").map((b) => b.textContent.trim()).join(","));
t("menu items are NOT .tab (the top-level switcher would hijack them)",
  items.every((b) => !b.classList.contains("tab")));
t("sections are NOT .panel (the top-level switcher strips their .active)",
  panes.every((p) => !p.classList.contains("panel")));
t("each item's aria-controls resolves to a real element",
  items.every((b) => !b.getAttribute("aria-controls") || !!doc.getElementById(b.getAttribute("aria-controls"))));
t("exactly one section is active in the shipped markup (broken JS => a section, not a blank page)",
  panes.filter((p) => p.className.split(/\s+/).some((c) => /pane--on|--active/.test(c))).length === 1);

// --- 3. the top-level tab switcher must not blank Settings ------------------
console.log("\n--- the real top-level switcher, run over the real markup -------");
const switcher = SRC.slice(SRC.indexOf('document.querySelectorAll(".tab").forEach'),
  SRC.indexOf('document.getElementById(`panel-${t.dataset.tab}`).classList.add("active");')
  + 'document.getElementById(`panel-${t.dataset.tab}`).classList.add("active");\n  });\n});'.length);
t("the switcher block was found in app.js", switcher.length > 80, switcher.length);
win.eval(es5(switcher));
const before = panes.find((p) => p.className.includes("--on"));
doc.querySelector('.tab[data-tab="pwn"]').click();
doc.querySelector('.tab[data-tab="settings"]').click();
t("the active section survives a round-trip through another top-level tab",
  !!before && before.className.includes("--on"));

// --- 4. hidden sections still save ------------------------------------------
console.log("\n--- one Save covers every section -------------------------------");
const style = doc.createElement("style");
style.textContent = "[data-settings-pane]{display:none}[data-settings-pane].settings-pane--on{display:block}";
doc.head.appendChild(style);
// The model/effort catalogs are filled by fillModelSelects() at runtime; an
// empty <select> contributes nothing to FormData, so give each one an option
// first — the question here is containment, not catalog population.
form.querySelectorAll("select").forEach((sel) => {
  if (!sel.options.length) sel.appendChild(new win.Option("x", "x"));
});
const fd = new win.FormData(form);
const keys = new Set(Array.from(fd.keys()));
// Two names FormData legitimately drops, and both are already handled:
// `worker_concurrency` is deliberately `disabled` (read-only live slot count),
// and an unchecked checkbox is absent by spec — which is exactly why the save
// handler reads the two checkboxes off the form instead of off FormData.
const CHECKBOXES = ["dynamic_worker_mem", "enable_exploit_library_hint"];
const expect = NAMES.filter((n) => n !== "worker_concurrency" && !CHECKBOXES.includes(n));
t("every setting is still submitted while its section is hidden",
  expect.every((n) => keys.has(n)), expect.filter((n) => !keys.has(n)).join(","));
t("the two checkboxes are still read off the form, not off FormData",
  CHECKBOXES.every((n) => new RegExp(`\\[name=${n}\\]"\\)\\.checked`).test(SRC)
    && !!form.querySelector(`[name=${n}]`)));
t("...and no section is disabled (a <fieldset disabled> drops everything inside it)",
  !panelSettings.querySelector("fieldset[disabled], [data-settings-pane][disabled]"));

// --- 4b. layout conventions jsdom cannot see -------------------------------
// jsdom does not lay anything out, so nothing above can notice a control that
// renders in the wrong PLACE. Both checks below come from a shipped bug: the
// dynamic_worker_mem checkbox was written with class="row", which matches no
// rule in style.css, so it inherited `label { flex-direction: column }` and
// drifted into the middle of the page, detached from its own text.
console.log("\n--- layout conventions (a DOM test cannot see position; assert the convention instead) ---");
const CSS_SRC = fs.readFileSync(path.join(ROOT, "web-ui/style.css"), "utf8");

const boxes = Array.from(form.querySelectorAll('input[type="checkbox"]'));
t("every settings checkbox sits in a label.checkbox (the row convention; " +
  "a plain label is a COLUMN and separates the box from its text)",
  boxes.length > 0 && boxes.every((b) => {
    const l = b.closest("label");
    return l && l.classList.contains("checkbox");
  }),
  boxes.filter((b) => {
    const l = b.closest("label");
    return !(l && l.classList.contains("checkbox"));
  }).map((b) => b.name).join(","));

// A class token that appears in NO stylesheet rule and in NO script is dead: it
// looks like styling to whoever wrote it and does nothing at all.
const dead = [];
for (const el of Array.from(panelSettings.querySelectorAll("[class]"))) {
  for (const c of Array.from(el.classList)) {
    if (CSS_SRC.includes("." + c)) continue;
    if (SRC.includes('"' + c + '"') || SRC.includes("'" + c + "'")) continue;
    if (!dead.includes(c)) dead.push(c);
  }
}
t("no class in the Settings panel is styled by nothing and scripted by nothing",
  dead.length === 0, dead.join(","));

// --- 5. Save must not become a silent no-op ---------------------------------
console.log("\n--- an invalid field in a hidden section still reaches the handler ---");
t("the form is novalidate", form.hasAttribute("novalidate"));
const cb = form.querySelector("[name=callback_url]");
cb.value = "not a url";
t("...and the field is genuinely invalid", !cb.checkValidity());
let ran = false;
form.addEventListener("submit", (e) => { ran = true; e.preventDefault(); });
form.querySelector('button[type="submit"]').click();
t("clicking Save still fires submit", ran);
const saveSrc = SRC.slice(SRC.indexOf('document.getElementById("settings-form").addEventListener("submit"'));
const gate = saveSrc.slice(0, saveSrc.indexOf("const fd = new FormData"));
t("the handler validates in JS instead", /willValidate/.test(gate) && /checkValidity\(\)/.test(gate), gate.length);
t("...and reveals the offending field's section before focusing it",
  /showSettingsPane\(/.test(gate) && gate.indexOf("showSettingsPane(") < gate.indexOf(".focus()"));

// --- 6. the production pane switcher itself ---------------------------------
console.log("\n--- showSettingsPane(), sliced out of app.js and run -------------");
const fnSrc = SRC.slice(SRC.indexOf("function _settingsPanes()"),
  SRC.indexOf("// The ONLY partial refresh"));
t("showSettingsPane was found in app.js", /function showSettingsPane/.test(fnSrc), fnSrc.length);
if (!/function showSettingsPane/.test(fnSrc)) {
  // Degrade to a named failure rather than a ReferenceError stack: an absent
  // switcher is a result, not broken tooling.
  console.log(`\n${PASS + FAIL} checks, ${FAIL} failed (section switcher absent — rest skipped)`);
  process.exit(1);
}
win.eval(`
  window.loadTunnelStatus = function () { window._tunnelRefreshed = true; };
  window.refreshWorkerMemLive = function () { window._memRefreshed = true; };
  ${es5(fnSrc)}
  window.showSettingsPane = showSettingsPane;
`);
const on = () => panes.filter((p) => p.classList.contains("settings-pane--on"))
  .map((p) => p.dataset.settingsPane);
win.showSettingsPane("ops");
t("clicking a section shows exactly that one", JSON.stringify(on()) === '["ops"]', on().join(","));
t("...and refreshes the live worker-memory readout it contains", win._memRefreshed === true);
const footer = doc.getElementById("settings-footer");
t("Save is visible on a section that has form fields", footer && footer.hidden === false);
win.showSettingsPane("presets");
t("Save is HIDDEN on the presets section, which the form does not save",
  footer && footer.hidden === true);
win._tunnelRefreshed = false;
win.showSettingsPane("access");
t("entering the tunnel section re-polls the tunnel", win._tunnelRefreshed === true);
t("the tunnel section shows both of its parts", on().length === 2 && on().every((n) => n === "access"),
  on().join(","));
win.showSettingsPane("no-such-section");
t("an unknown/stale section name falls back to the first, never to a blank page",
  on().length >= 1, on().join(","));

// --- 7. the tunnel poll gate followed the tunnel into a section -------------
console.log("\n--- the 5s tunnel poll is gated on the tunnel being on screen ----");
const tunnelGate = SRC.slice(SRC.indexOf("async function loadTunnelStatus"),
  SRC.indexOf("document.getElementById(\"tunnel-activate\")"));
t("the poll gate names the tunnel block, not just the settings panel",
  /tunnel-block/.test(tunnelGate) && /panel-settings/.test(tunnelGate));

console.log(`\n${PASS + FAIL} checks, ${FAIL} failed`);
process.exit(FAIL ? 1 : 0);
