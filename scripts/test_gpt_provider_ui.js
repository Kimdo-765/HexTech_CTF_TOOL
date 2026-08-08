#!/usr/bin/env node
/* Offline contract checks for the GPT provider's Settings/UI wiring. */
"use strict";

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(root, "web-ui", "index.html"), "utf8");
const js = fs.readFileSync(path.join(root, "web-ui", "app.js"), "utf8");
const css = fs.readFileSync(path.join(root, "web-ui", "style.css"), "utf8");
const settings = fs.readFileSync(path.join(root, "modules", "settings_io.py"), "utf8");
const workerReq = fs.readFileSync(path.join(root, "worker", "requirements.txt"), "utf8");
const apiReq = fs.readFileSync(path.join(root, "api", "requirements.txt"), "utf8");
const compose = fs.readFileSync(path.join(root, "docker-compose.yml"), "utf8");
const workerDocker = fs.readFileSync(path.join(root, "worker", "Dockerfile"), "utf8");
const apiDocker = fs.readFileSync(path.join(root, "api", "Dockerfile"), "utf8");
const jobsRoute = fs.readFileSync(path.join(root, "api", "routes", "jobs.py"), "utf8");
const codexRateLimit = fs.readFileSync(path.join(root, "modules", "codex_rate_limit.py"), "utf8");
const codexHomeInit = fs.readFileSync(path.join(root, "scripts", "init-codex-runtime-home.sh"), "utf8");
const startScript = fs.readFileSync(path.join(root, "start.sh"), "utf8");
const restartScript = fs.readFileSync(path.join(root, "restart.sh"), "utf8");
const gptEvents = fs.readFileSync(path.join(root, "modules", "gpt_run_events.py"), "utf8");
const codexAdapter = fs.readFileSync(path.join(root, "modules", "codex_cli.py"), "utf8");
const monitor = fs.readFileSync(path.join(root, "modules", "_monitor.py"), "utf8");

let pass = 0;
let fail = 0;
function check(name, ok) {
  if (ok) {
    pass += 1;
    console.log(`PASS  ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL  ${name}`);
  }
}

check("GPT provider radio exists", /name="agent_provider" value="gpt"/.test(html));
check("GPT Settings block exists", /id="settings-gpt-block"/.test(html));
check("OpenAI key field exists", /name="openai_api_key"/.test(html));
check("Codex OAuth runtime field exists", /name="gpt_runtime"/.test(html));
check("Codex OAuth is the first/default runtime", /value="codex">Codex CLI/.test(html));
check("Codex OAuth status exists", /id="codex-oauth-status"/.test(html));
check("Codex quota chip exists", /id="codex-ratelimit-chip"/.test(html));
check("GPT provider card has auth badge", /id="gpt-provider-auth"/.test(html));
check("Claude and Grok cards have auth badges", /id="claude-provider-auth"/.test(html) && /id="grok-provider-auth"/.test(html));
check("GPT model field exists", /name="gpt_model"/.test(html));
check("GPT effort field exists", /name="gpt_effort"/.test(html));
check("Codex minimal effort is offered", /GPT_EFFORTS\s*=\s*\[[^\]]*"minimal"/.test(js));
check("GPT model catalog includes Sol", /"gpt-5\.6-sol"/.test(js));
check("GPT model catalog includes Terra", /"gpt-5\.6-terra"/.test(js));
check("GPT model catalog includes Luna", /"gpt-5\.6-luna"/.test(js));
check("provider normalization accepts GPT", /\["claude", "grok", "gpt"\]\.includes/.test(js));
check("GPT block receives provider-active", /gptBlock\.classList\.toggle\("provider-active", p === "gpt"\)/.test(js));
check("saved GPT model is loaded", /_setModelField\(f, "gpt_model"/.test(js));
check("custom GPT model overrides select", /fd\.set\("gpt_model", gptCustom\)/.test(js));
check("blank OpenAI key preserves secret", /k === "openai_api_key"/.test(js));
check("OpenAI key status supports env", /openai_api_key_env_set/.test(js));
check("Codex OAuth status uses settings view", /codex_oauth_detected/.test(js));
check("GPT card reports ChatGPT OAuth readiness", /✓ ChatGPT OAuth ready/.test(js));
check("provider selection preserves live auth status", /renderProviderAuthUI\(t\.value, \{unsaved: true\}\)/.test(js));
check("Codex quota payload is rendered", /u\.codex_rate_limit/.test(js));
check("Codex quota is labeled as remaining", /Codex.*_rlRemainingLabel\(cr\)/.test(js));
check("stale Codex quota is visible without hover", /codexUsageIcon = cr\.stale \? "⚠" : "⏳"/.test(js)
  && /_rlStaleSuffix\(cr\)/.test(js)
  && /cr\.stale \|\| cr\.status === "allowed_warning"/.test(js));
check("auth badges have ready styling", /provider-auth-badge\.auth-ready/.test(css));
check("saved GPT runtime is loaded", /gptRuntimeSel\.value = gptRuntime/.test(js));
check("presets use provider-scoped GPT models", /provider === "gpt"\) return \{ models: GPT_MODELS/.test(js));
check("GPT presets hide only the unused monitor role", /provider === "gpt" \? roles\.filter\(\(role\) => role !== "monitor"\) : roles/.test(js));
check("three provider cards fit the grid", /repeat\(3, minmax\(0, 1fr\)\)/.test(css));
check("settings schema exposes OpenAI key", /\("openai_api_key", "OPENAI_API_KEY"/.test(settings));
check("settings defaults to Codex OAuth", /\("gpt_runtime", "GPT_RUNTIME", str, "codex"\)/.test(settings));
check("settings schema exposes GPT model", /\("gpt_model", "GPT_MODEL"/.test(settings));
check("worker image installs OpenAI SDK", /^openai>=/m.test(workerReq));
check("api image installs OpenAI SDK", /^openai>=/m.test(apiReq));
check("worker image installs Codex CLI", /@openai\/codex@/.test(workerDocker));
check("api image installs Codex CLI", /@openai\/codex@/.test(apiDocker));
check("compose mounts host Codex auth", /HOST_CODEX_HOME[^\n]*:\/root\/\.codex/.test(compose));
check("compose fallback avoids live TUI home", /HOST_CODEX_HOME:-\.\/data\/codex-home/.test(compose));
check("launch scripts select isolated Codex home", /HOST_CODEX_HOME:-\$HOME\/\.codex-hextech/.test(startScript) && /HOST_CODEX_HOME:-\$REAL_HOME\/\.codex-hextech/.test(restartScript));
check("launch scripts reject the live TUI Codex home", /HOST_CODEX_HOME.*CODEX_LOGIN_HOME[\s\S]{0,220}\bdie\b/.test(startScript)
  && /HOST_CODEX_HOME.*CODEX_LOGIN_HOME[\s\S]{0,300}exit 2/.test(restartScript));
check("Codex bootstrap copies OAuth only", /SOURCE_HOME\/auth\.json/.test(codexHomeInit) && !/cp[^\n]*config\.toml/.test(codexHomeInit));
check("usage API exposes Codex quota", /"codex_rate_limit": read_codex_rate_limit\(\)/.test(jobsRoute));
check("Codex quota uses CLI app-server", /account\/rateLimits\/read/.test(codexRateLimit));
check("Codex quota removes API-key overrides", /env\.pop\("OPENAI_API_KEY"/.test(codexRateLimit));
check("GPT jobs default to structured Timeline", /gpt_log_view"\) \|\| "timeline"/.test(js));
check("GPT activity offers only Timeline and Raw log", !/view-gpt-monitor/.test(js)
  && /\["timeline", "log"\]\.includes\(value\)/.test(js));
check("GPT UI never fetches Monitor", /if \(!isGptJob\) \{\s*try \{\s*const mr = await fetch\(`\$\{API\}\/jobs\/\$\{id\}\/monitor/.test(js));
check("GPT Timeline has a dedicated API", /\/{job_id}\/gpt-timeline/.test(jobsRoute));
check("GPT Timeline is provider gated", /agent_provider[\s\S]{0,120}!= "gpt"/.test(jobsRoute));
check("GPT Monitor endpoint is disabled", /provider == "gpt"[\s\S]{0,100}"enabled": False/.test(jobsRoute));
check("GPT Timeline omits the removed monitor role", /role != "monitor" and fallbacks\.get\(role\)/.test(jobsRoute));
check("GPT monitor tasks are provider gated", /def _monitor_enabled_for_job/.test(monitor)
  && /return provider != "gpt"/.test(monitor)
  && /not _monitor_enabled_for_job\(job_id\)/.test(monitor));
check("GPT Timeline can hide ordinary tools", /data-show-tools/.test(js) && /gpt-tool-event/.test(css));
check("GPT Timeline renders role model cards", /gpt-agent-grid/.test(js) && /gpt-agent-card/.test(css));
check("legacy GPT logs have a read-only projection", /derive_gpt_events_from_run_log/.test(gptEvents));
check("Codex adapter emits structured GPT events", /emit_gpt_event/.test(codexAdapter));
check("Claude and Grok logging are not imported by GPT events", !/from modules\.(?:grok|_common)|claude_agent_sdk/.test(gptEvents));

console.log(`\n${pass} checks, ${fail} failed`);
process.exit(fail ? 1 : 0);
