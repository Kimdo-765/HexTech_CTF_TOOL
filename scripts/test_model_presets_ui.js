#!/usr/bin/env node
/* Offline contract checks for provider-scoped preset UI wiring. */
"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(root, "web-ui", "index.html"), "utf8");
const js = fs.readFileSync(path.join(root, "web-ui", "app.js"), "utf8");
const css = fs.readFileSync(path.join(root, "web-ui", "style.css"), "utf8");

let passed = 0;
let failed = 0;
function check(label, condition) {
  console.log(`${condition ? "PASS" : "FAIL"}  ${label}`);
  condition ? passed++ : failed++;
}

for (const provider of ["claude", "grok", "gpt"]) {
  check(`${provider} preset tab exists`, html.includes(`data-preset-provider="${provider}"`));
}
check("provider stores are initialized independently", /providers:\s*emptyPresetProviders\(\)/.test(js));
check("provider tab selects its own bucket", /PRESET_STORE\.providers\[PRESET_PROVIDER\]/.test(js));
check("Claude catalog is selectable", /models:\s*CLAUDE_MODELS/.test(js));
check("Grok catalog is selectable", /models:\s*GROK_MODELS/.test(js));
check("GPT catalog is selectable", /models:\s*GPT_MODELS/.test(js));
check("save sends version-2 provider store", /JSON\.stringify\(\{ version: 2, providers: PRESET_STORE\.providers \}\)/.test(js));
check("v2 UI refuses save through a stale v1 API", /PRESET_API_VERSION < 2/.test(js));
check("job provider change opens matching preset tab", /setPresetProvider\(p\)/.test(js));
check("active preset label names provider", html.includes('id="preset-provider-label"'));
check("selected provider tab is styled", /\.preset-provider-tabs button\.active/.test(css));

console.log(`\n${passed} checks, ${failed} failed`);
process.exit(failed ? 1 : 0);
