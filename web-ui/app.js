const API = "/api";

// Catalog of Claude models offered in every Analyze form. Add new
// snapshot/alias names here to expose them. Empty value = "use the
// global Settings model".
const CLAUDE_MODELS = [
  // Aliases (Anthropic recommends pinning to dated snapshots in
  // production). Sorted by family (Opus → Sonnet → Haiku) then by
  // version (newest first). 1M-context variants follow their
  // alias immediately so the dropdown groups the same model's
  // 200K / 1M choices together.
  //
  // The SDK accepts the `[1m]` suffix; claude-code auto-enables
  // the long-context beta. Verified 2026-05-24 under the worker's
  // current authenticated plan: Opus 4.7[1m] and Opus 4.1[1m] both
  // work. Opus 4.8[1m] added 2026-05-29 — confirmed available on
  // the current plan (the Claude Code session driving this tool runs
  // on claude-opus-4-8[1m]).
  // Sonnet/Haiku [1m] respond with "Usage credits are required for
  // long context requests" — billing-tier limited and intentionally
  // not listed here.
  //
  // Claude 5 family — newest. Fable 5 base + [1m] verified 2026-07-02
  // (FABLE_OK / FABLE1M_OK); Sonnet 5 base + [1m] verified 2026-07-19
  // (SONNET5_OK / SONNET51M_OK) — both trivial-prompt round-trips on the
  // worker's authenticated plan. Unlike Sonnet 4.x, whose [1m] is credit-
  // gated ("Usage credits are required for long context requests"), Sonnet
  // 5[1m] and Fable 5[1m] are NOT credit-gated here.
  // Opus 5 base + [1m] added 2026-07-24, same way — verified by trivial
  // round-trip IN THE WORKER (OPUS5_OK / OPUS51M_OK) on the authenticated
  // plan, so it is the new flagship Opus and leads the list. (Still no
  // Haiku 5.) NOTE: this only ADDS choices — the global default stays
  // whatever Settings says; nothing here changes a running job's model.
  "claude-opus-5",
  "claude-opus-5[1m]",
  "claude-fable-5",
  "claude-fable-5[1m]",
  "claude-sonnet-5",
  "claude-sonnet-5[1m]",
  "claude-opus-4-8",
  "claude-opus-4-8[1m]",
  "claude-opus-4-7",
  "claude-opus-4-7[1m]",
  "claude-opus-4-6",
  "claude-opus-4-6[1m]",
  "claude-opus-4-1",
  "claude-opus-4-1[1m]",
  "claude-opus-4",
  "claude-sonnet-4-6",
  "claude-sonnet-4-5",
  "claude-sonnet-4",
  "claude-haiku-4-5",
  "claude-haiku-4",
  // Dated snapshots (most stable for reproducible runs). Same sort
  // order — Opus / Sonnet / Haiku, newest first.
  "claude-opus-4-7-20251205",
  "claude-opus-4-1-20250805",
  "claude-sonnet-4-6-20251119",
  "claude-sonnet-4-5-20250929",
  "claude-sonnet-4-20250514",
  "claude-haiku-4-5-20251001",
  "claude-3-7-sonnet-latest",
  "claude-3-5-sonnet-20241022",
  "claude-3-5-haiku-20241022",
];

// Reasoning effort levels accepted by ClaudeAgentOptions(effort=...).
// SDK translates these to a `--effort <value>` CLI arg; empty = SDK
// default (model-dependent). Higher effort means longer per-turn
// thinking budget and (typically) higher per-call cost — pick "max"
// for high-stakes synthesis turns and "low" for cheap probes.
const CLAUDE_EFFORTS = ["low", "medium", "high", "xhigh", "max"];

// Grok Build / xAI model ids offered in Settings (and per-job dropdowns
// when agent_provider=grok). `grok-build` is the coding-agent default.
const GROK_MODELS = [
  "grok-build",
  "grok-4.5",
  "grok-4",
  "grok-3",
  "grok-3-mini",
  "grok-code-fast-1",
];

// Grok CLI effort ladder (union with Claude's so per-job dropdowns stay
// one list). Empty = CLI/model default.
const GROK_EFFORTS = ["none", "minimal", "low", "medium", "high", "xhigh", "max"];

// Active provider from last Settings load — drives per-job model lists.
let activeAgentProvider = "claude";

function fillModelSelects(provider) {
  const p = provider || activeAgentProvider || "claude";
  const models = p === "grok" ? GROK_MODELS : CLAUDE_MODELS;
  // Per-job selects: empty = "default from Settings"
  document.querySelectorAll('[data-role="model-select"]').forEach((sel) => {
    const prev = sel.value;
    sel.innerHTML = "";
    sel.appendChild(new Option("(default — Settings value)", ""));
    for (const m of models) sel.appendChild(new Option(m, m));
    if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
  });
  // Global Claude Settings select (always Claude catalog).
  document.querySelectorAll('[data-role="model-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use env / default)", ""));
    for (const m of CLAUDE_MODELS) sel.appendChild(new Option(m, m));
  });
  // Global Grok Settings select.
  document.querySelectorAll('[data-role="grok-model-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use env / default)", ""));
    for (const m of GROK_MODELS) sel.appendChild(new Option(m, m));
  });
}

function fillEffortSelects(provider) {
  const p = provider || activeAgentProvider || "claude";
  const efforts = p === "grok" ? GROK_EFFORTS : CLAUDE_EFFORTS;
  // Per-job: empty = Settings value (falls through to SDK default if
  // Settings is also empty). Same UX as fillModelSelects.
  document.querySelectorAll('[data-role="effort-select"]').forEach((sel) => {
    const prev = sel.value;
    sel.innerHTML = "";
    sel.appendChild(new Option("(default — Settings value)", ""));
    for (const e of efforts) sel.appendChild(new Option(e, e));
    if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
  });
  document.querySelectorAll('[data-role="effort-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use SDK default)", ""));
    for (const e of CLAUDE_EFFORTS) sel.appendChild(new Option(e, e));
  });
  document.querySelectorAll('[data-role="grok-effort-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use CLI default)", ""));
    for (const e of GROK_EFFORTS) sel.appendChild(new Option(e, e));
  });
}

function setProviderUI(provider) {
  const p = provider === "grok" ? "grok" : "claude";
  activeAgentProvider = p;
  const radio = document.querySelector(
    `#settings-form input[name=agent_provider][value="${p}"]`
  );
  if (radio) radio.checked = true;
  const claudeBlock = document.getElementById("settings-claude-block");
  const grokBlock = document.getElementById("settings-grok-block");
  if (claudeBlock) claudeBlock.classList.toggle("provider-active", p === "claude");
  if (grokBlock) grokBlock.classList.toggle("provider-active", p === "grok");
  fillModelSelects(p);
  fillEffortSelects(p);
}

let selectedJob = null;
let pollTimer = null;

// Per-job token snapshots used to render Δ in the tokens pill so the
// run-log footer shows live "↓X k tokens" deltas the way Claude
// Code's status line does. Keyed by job id; reset whenever the job
// changes or its turn count regresses (= retry/resume forked it).
const _prevTokens = {};

// In-flight reviewer/retry streams, keyed by the job the retry was
// launched FROM. streamRetry() runs a POST fetch + ReadableStream with NO
// AbortController, so navigating to another job (which rebuilds
// #job-detail.innerHTML and destroys the ephemeral retry-panel) does NOT
// kill the stream — it keeps running server-side. Without a place to hold
// the "reviewer in progress" state OUTSIDE the DOM, re-entering the job
// rebuilds the detail from server data alone and the panel is gone. This
// map holds each stream's state so renderReviewerPanel() can repaint it
// after any detail re-render. Entry shape:
//   { flow, flowEmoji, flowVerb, isManual, stageText, text, firstToken,
//     status: "running"|"done"|"error", kind, newJobId }
// Known limit: in-page only — a full page reload (F5) loses it, and the
// POST stream can't be re-attached after reload anyway. The reported bug
// is SPA navigation (leave the job window, come back), which this covers.
const activeReviewers = new Map();

// Live SSE stream state. We keep the 2-second poller as a fallback so
// the panel still works when the server-side stream is unavailable
// (older worker image, redis hiccup, browser without EventSource).
// When a live stream connects, the poller's interval is widened so the
// stream is the primary signal and the poller is only there to refresh
// derived fields the stream doesn't carry (file links, full result_data).
let liveStream = null;
let liveStreamJobId = null;
let liveStreamConnected = false;
let _metaRefreshTimer = null;

// ── Flag alarm: bottom-right toast + beep on a NEW [FLAG?] candidate or
// a NEW promoted 🚩 flag, for ANY job (works even with no detail panel
// open, via the global poller added at startup). _flagSeen tracks the
// VALUES already alarmed per job; the FIRST poll seeds the baseline
// silently so we never alarm for jobs already flagged when the page loads.
//
// Values, not counts. The count version alarmed on `nCands > prev.cands`,
// which produced BOTH of the symptoms the operator reported:
//   * DUPLICATES — refreshJobs() has no in-flight guard and is driven by two
//     timers plus ~10 call sites, so two fetches can land out of order. The
//     older response lowers the stored count, and the next poll re-detects
//     the same transition and re-toasts the SAME flag. A set only ever grows,
//     so a stale response is now a subset that adds nothing.
//   * MISSED — the old code toasted `fc[fc.length - 1]` once per pass and
//     used `else if`, so if a poll brought two candidates only the last one
//     alarmed, and if it brought a flag AND a candidate the candidate was
//     swallowed. Both were then recorded as seen, so they never fired later.
//     Now every fresh value alarms, and flags and candidates are independent.
// (The comment on _showFlagToast already claimed "per-candidate dedup in
// _detectFlagTransitions" — this is that dedup finally existing.)
const _flagSeen = {};            // jobId -> { flags: Set<string>, cands: Set<string> }
let _flagAlarmReady = false;     // becomes true after the baseline pass
let _flagAudioCtx = null;        // lazy WebAudio context for the beep

function _scheduleMetaRefresh(id) {
  if (_metaRefreshTimer) return;
  _metaRefreshTimer = setTimeout(() => {
    _metaRefreshTimer = null;
    if (selectedJob === id) renderJob(id);
  }, 350);
}

// User preference: hide/show the live SDK panel. Persisted so the
// choice survives page reloads. Defaults to "show".
let _sdkLiveHidden = (() => {
  try { return localStorage.getItem("sdk_live_hidden") === "1"; }
  catch (_) { return false; }
})();

// Log-tail style live feed: one row per SDK event, single fixed-height
// pane, no card chrome, no animations. The earlier card-based design
// caused reflow + typing animation that read as visual chaos.
const _SDK_MAX_LINES = 60;
const _SDK_BODY_PREVIEW_CHARS = 240;

function _renderSdkEvent(id, payload) {
  const panel = document.querySelector(
    `.sdk-live[data-job-id="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`,
  );
  if (!panel) return;
  panel.hidden = false;
  if (_sdkLiveHidden) panel.classList.add("collapsed");
  const feed = panel.querySelector(".sdk-live-feed");
  if (!feed) return;

  const kind = payload.kind || "";
  const tag = payload.tag || "main";

  let label, body, kindClass;
  if (kind === "text") {
    label = "AGENT"; kindClass = "sdk-text"; body = payload.text || "";
  } else if (kind === "thinking") {
    label = "THINK"; kindClass = "sdk-think"; body = payload.thinking || "";
  } else if (kind === "tool_use") {
    label = `TOOL ${payload.name || "?"}`;
    kindClass = "sdk-tool";
    try {
      body = typeof payload.input === "string"
        ? payload.input
        : JSON.stringify(payload.input);
    } catch (_) { body = String(payload.input || ""); }
  } else if (kind === "tool_result") {
    label = payload.is_error ? "RESULT(err)" : "RESULT";
    kindClass = payload.is_error ? "sdk-error" : "sdk-result";
    body = payload.preview || "";
  } else {
    label = kind.toUpperCase(); kindClass = "sdk-misc";
    try { body = JSON.stringify(payload); } catch (_) { body = String(payload); }
  }

  // Collapse whitespace + truncate so each event is exactly one row.
  // The full body still lands in the run-log below; this pane is for
  // an at-a-glance live view, not the full transcript.
  const preview = (body || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, _SDK_BODY_PREVIEW_CHARS);

  const wasAtBottom =
    feed.scrollTop + feed.clientHeight >= feed.scrollHeight - 8;

  const line = document.createElement("div");
  line.className = `sdk-line ${kindClass}`;
  line.innerHTML =
    `<span class="sdk-line-tag">[${escapeHtml(tag)}]</span> ` +
    `<span class="sdk-line-label">${escapeHtml(label)}</span>: ` +
    `<span class="sdk-line-body">${escapeHtml(preview)}</span>`;
  feed.appendChild(line);

  while (feed.children.length > _SDK_MAX_LINES) {
    feed.removeChild(feed.firstChild);
  }
  if (wasAtBottom) feed.scrollTop = feed.scrollHeight;
}

function _appendLiveLogLine(id, payload) {
  // Backfill events are redundant — renderJob's /log fetch already
  // populated the pre. Streaming starts strictly after backfill_done.
  if (payload.backfill) return;
  // A filter is active: the <pre> shows only matching lines, so don't append
  // unfiltered live lines. The 2s poll re-fetches + re-applies the filter.
  if ((_logSearch[id] || "").trim()) return;
  const pre = document.querySelector(
    `pre.run-log[data-job-id="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`,
  );
  if (!pre) return;
  const wasAtBottom =
    pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 12;
  const tsPrefix = payload.ts ? `[${payload.ts}] ` : "";
  const raw = tsPrefix + (payload.line || "") + "\n";
  // Use colorizeRunLog so the appended line picks up the same styling
  // as polled renders (agent tags get colored, paths underlined, etc.).
  let colored = raw;
  try {
    colored = colorizeRunLog(raw, null);
  } catch (_) {
    colored = escapeHtml(raw);
  }
  pre.insertAdjacentHTML("beforeend", colored);
  // Cap to last ~600KB so an unbounded live tail doesn't slow the DOM.
  if (pre.textContent.length > 700_000) {
    // Slice from the textContent baseline, then re-colorize once.
    const tail = pre.textContent.slice(-500_000);
    try {
      pre.innerHTML = colorizeRunLog(tail, null);
    } catch (_) {
      pre.textContent = tail;
    }
  }
  if (wasAtBottom) pre.scrollTop = pre.scrollHeight;
}

function _openLiveStream(id) {
  _closeLiveStream();
  if (typeof EventSource === "undefined") return;
  let es;
  try {
    es = new EventSource(`${API}/jobs/${id}/stream`);
  } catch (_) {
    return;
  }
  liveStream = es;
  liveStreamJobId = id;
  liveStreamConnected = false;

  es.addEventListener("log", (e) => {
    if (liveStreamJobId !== id) return;
    try {
      _appendLiveLogLine(id, JSON.parse(e.data));
    } catch (_) {}
  });
  es.addEventListener("meta", (e) => {
    if (liveStreamJobId !== id) return;
    // Only structural changes (status / flag / lifecycle) need a full
    // detail.innerHTML rebuild. Token / turn / compaction deltas would
    // otherwise re-render every ~350ms during an active agent turn and
    // visibly drift the user's scroll position. The slow poller still
    // refreshes the tokens-pill every 8s, which is good enough.
    try {
      const payload = JSON.parse(e.data);
      // A status change OR a freshly-spotted flag candidate ([FLAG?])
      // warrants a detail rebuild so the operator sees it at once.
      if (payload && (payload.status_update || payload.flag_candidates)) {
        _scheduleMetaRefresh(id);
      }
    } catch (_) {}
  });
  es.addEventListener("sdk", (e) => {
    if (liveStreamJobId !== id) return;
    try {
      _renderSdkEvent(id, JSON.parse(e.data));
    } catch (_) {}
  });
  es.addEventListener("monitor", (e) => {
    if (liveStreamJobId !== id) return;
    try {
      _appendMonitorEntry(id, JSON.parse(e.data));
    } catch (_) {}
  });
  es.addEventListener("backfill_done", () => {
    liveStreamConnected = true;
    // Now that the live stream is providing events, widen the poll
    // interval so we don't fight the stream with full re-renders.
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = setInterval(async () => {
        const job = await renderJob(id);
        if (job && ["finished", "failed", "no_flag"].includes(job.status)) {
          clearInterval(pollTimer);
          pollTimer = null;
          await refreshJobs();
          await refreshStats();
        }
      }, 8000);
    }
  });
  es.addEventListener("done", () => {
    _closeLiveStream();
    // Final structural refresh so result-block file links + cost
    // pill update one last time.
    renderJob(id, { force: true });
    refreshJobs();
    refreshStats();
  });
  es.onerror = () => {
    // EventSource auto-reconnects unless we explicitly close. If the
    // browser flags the stream as permanently closed, surrender and
    // let the (still-running) 2s poller carry the panel forward.
    if (!liveStream) return;
    if (liveStream.readyState === EventSource.CLOSED) {
      liveStream = null;
      liveStreamJobId = null;
      liveStreamConnected = false;
    }
  };
}

function _closeLiveStream() {
  if (liveStream) {
    try { liveStream.close(); } catch (_) {}
  }
  liveStream = null;
  liveStreamJobId = null;
  liveStreamConnected = false;
  if (_metaRefreshTimer) {
    clearTimeout(_metaRefreshTimer);
    _metaRefreshTimer = null;
  }
}

// Run-log timestamp display mode. Logs are written in UTC by the
// orchestrator (`[HH:MM:SS]`). Default is UTC so behavior is
// unchanged for users who haven't opted in. The toggle button in
// the run-log titlebar flips this and triggers a re-render.
let runlogTz = (() => {
  try { return localStorage.getItem("runlog_tz") || "utc"; }
  catch (_) { return "utc"; }
})();
function _setRunlogTz(tz) {
  if (tz !== "utc" && tz !== "local") tz = "utc";
  runlogTz = tz;
  try { localStorage.setItem("runlog_tz", tz); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}
function _localTzName() {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "local"; }
  catch (_) { return "local"; }
}

// --- MONITOR view: curated, LLM-narrated signal feed over run.log --------
// A per-job monitor task (api-side) filters run.log to meaningful signals and
// narrates each batch in every configured language; entries stream over the
// SSE `monitor` channel and back-fill from /api/jobs/<id>/monitor. The run-log
// window has a Run-log|Monitor view toggle + a language <select>. Both prefs
// persist like runlogTz.
let monitorView = (() => {
  try { return localStorage.getItem("monitor_view") === "1"; }
  catch (_) { return false; }
})();
let monitorLang = (() => {
  try { return localStorage.getItem("monitor_lang") || "ko"; }
  catch (_) { return "ko"; }
})();
function _setMonitorView(on) {
  monitorView = !!on;
  try { localStorage.setItem("monitor_view", monitorView ? "1" : "0"); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}
function _setMonitorLang(lang) {
  monitorLang = lang || "ko";
  try { localStorage.setItem("monitor_lang", monitorLang); } catch (_) {}
  if (selectedJob) renderJob(selectedJob, { force: true });
}

const _MON_SEV_ICON = { good: "🟢", info: "●", warn: "▲", err: "■" };

function _fmtMonTime(iso) {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    if (runlogTz === "local") return d.toLocaleTimeString([], { hour12: false });
    return d.toISOString().slice(11, 19);  // UTC HH:MM:SS
  } catch (_) { return ""; }
}

function _monText(entry, lang) {
  const t = entry && entry.text;
  if (!t) return "";
  if (typeof t === "string") return t;
  return t[lang] || t.en || t.ko
    || Object.values(t).find((v) => typeof v === "string" && v) || "";
}

function _monRowHtml(entry, lang) {
  const sev = entry.sev || "info";
  const kind = entry.kind || "";
  const time = _fmtMonTime(entry.ts);
  const text = _monText(entry, lang);
  const raw = Array.isArray(entry.raw) ? entry.raw.join("\n") : "";
  return `<div class="mon-row mon-${escapeHtml(sev)}" title="${escapeHtml(raw)}">`
    + `<span class="mon-ico">${_MON_SEV_ICON[sev] || "●"}</span>`
    + `<span class="mon-time">${escapeHtml(time)}</span>`
    + `<span class="mon-kind mon-kind-${escapeHtml(kind)}">${escapeHtml(kind)}</span>`
    + `<span class="mon-text">${escapeHtml(text)}</span>`
    + `</div>`;
}

function renderMonitorEntries(entries, lang) {
  if (!entries || !entries.length) {
    return `<div class="mon-empty">아직 모니터 해설이 없습니다 · no monitor commentary yet</div>`;
  }
  return entries.map((e) => _monRowHtml(e, lang)).join("");
}

function _appendMonitorEntry(id, payload) {
  // Backfilled entries already arrived via renderJob's /monitor fetch.
  if (payload && payload.backfill) return;
  const feed = document.querySelector(
    `.monitor-feed[data-job-id="${(window.CSS && CSS.escape) ? CSS.escape(id) : id}"]`,
  );
  if (!feed) return;
  const empty = feed.querySelector(".mon-empty");
  if (empty) empty.remove();
  const wasAtBottom =
    feed.scrollTop + feed.clientHeight >= feed.scrollHeight - 12;
  feed.insertAdjacentHTML("beforeend", _monRowHtml(payload, monitorLang));
  while (feed.children.length > 800) feed.removeChild(feed.firstChild);
  if (wasAtBottom) feed.scrollTop = feed.scrollHeight;
}
// Lightweight 1-second tick that updates ONLY the timing pill's
// textContent on running jobs. Independent of pollTimer (which
// re-renders the whole detail panel and is paused on selection /
// open forms), so the elapsed counter stays smooth.
let livePillTimer = null;
// Age of the agent's last SDK event, in the same visual family as the elapsed
// pill. Seconds are kept visible past the minute mark on purpose: the whole
// point of this readout is watching it reset, and "8m" alone hides the reset
// for up to a minute.
function _fmtAgentAge(sec) {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

function _tickLivePill() {
  // Same 1s tick drives the agent-event age. It is a separate element from the
  // elapsed pill because they answer different questions — how long the job has
  // run, versus how long since the agent last said anything — and because the
  // elapsed pill must keep ticking on a job whose agent has not started yet.
  document.querySelectorAll(".agent-pill[data-agent-at]").forEach((pill) => {
    const iso = pill.dataset.agentAt;
    if (!iso) return;
    const sec = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    pill.textContent = `⚡ ${_fmtAgentAge(sec)}`;
  });
  document.querySelectorAll(".timing-pill.live").forEach((pill) => {
    const startedIso = pill.dataset.startedAt;
    if (!startedIso) return;
    const sec = Math.max(0, Math.round((Date.now() - new Date(startedIso).getTime()) / 1000));
    const fmt = sec < 60 ? `${sec}s`
      : sec < 3600 ? `${Math.floor(sec/60)}m ${sec%60}s`
      : `${Math.floor(sec/3600)}h ${Math.floor((sec%3600)/60)}m`;
    // Only replace the text node holding the time; keep the inner
    // "running" tag span untouched.
    const tagEl = pill.querySelector(".timing-tag");
    if (!tagEl) return;
    pill.firstChild && (pill.firstChild.nodeValue = `⏱ ${fmt} `);
  });
  // Stop only when NEITHER live readout is on screen. Keying this on the
  // elapsed pill alone would be right today (a running job always has
  // started_at, so it is a superset) but silently wrong the moment that stops
  // holding — and the failure is invisible: a frozen counter reads exactly like
  // a wedged agent, which is the one thing this readout must never fake.
  if (!document.querySelector(".timing-pill.live, .agent-pill[data-agent-at]")) {
    clearInterval(livePillTimer);
    livePillTimer = null;
  }
}
function _ensureLivePillTimer() {
  if (livePillTimer) return;
  livePillTimer = setInterval(_tickLivePill, 1000);
}

document.querySelectorAll(".tab").forEach((t) => {
  t.addEventListener("click", () => {
    if (t.disabled) return;
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    document.getElementById(`panel-${t.dataset.tab}`).classList.add("active");
  });
});

// Directive folded into the description when "Capture remote flag" is ticked.
// Leads with the literal phrase so it's grep-able, then spells out the bar the
// operator wants. NOTE this is a USER-TURN hint (description → build_user_prompt
// → client.query), so it COUNTERS but does not override the system-prompt line
// (CTF_PREAMBLE: "...or producing a working exploit is the explicit goal") that
// otherwise lets a locally-validated / banner-only exploit read as goal-complete.
// It's a strong operator directive, NOT a hard success gate — the orchestrator's
// flag-scan + success decision (_common.py scan_job_for_flags / auto-run gate)
// is separate and unchanged by this checkbox.
const CAPTURE_REMOTE_FLAG_DIRECTIVE =
  "capture remote flag — this job is ONLY successful if your exploit/solver " +
  "captures the REAL flag from the remote target and prints it on its own line " +
  "as `FLAG_CANDIDATE: <flag>`. Local-only validation, a planted test flag, or a " +
  "banner-only smoke check do NOT count as success; keep iterating (reconnect/retry) " +
  "until the genuine remote flag is captured.";

async function submitJob(form, endpoint) {
  const fd = new FormData(form);
  // Multi-target rows (the +/× list) → join non-empty values with newlines into
  // the canonical field (target_url for web, target for pwn/crypto) so the
  // backend's parse_targets() splits them. The row inputs are intentionally
  // unnamed, so they never reach FormData on their own.
  const tlist = form.querySelector(".target-list");
  if (tlist && tlist.dataset.field) {
    const vals = Array.from(tlist.querySelectorAll(".target-input"))
      .map((i) => i.value.trim())
      .filter(Boolean);
    fd.set(tlist.dataset.field, vals.join("\n"));
  }
  for (const cb of form.querySelectorAll('input[type="checkbox"]')) {
    // Nameless checkboxes (e.g. the capture-remote-flag toggle) are UI-only and
    // must not leak into FormData as a blank-named field — they're handled below.
    if (!cb.name) continue;
    fd.set(cb.name, cb.checked ? "true" : "false");
  }
  // "Capture remote flag" toggle → fold the directive into the description so the
  // agent prompt (which otherwise accepts a "working exploit" as goal-complete)
  // gets an explicit remote-capture success bar. The checkbox itself carries no
  // `name`, so it never reaches the backend as a form field.
  //
  // GATE on an actual target: only fold the "capture from the REMOTE target"
  // mandate in when the job HAS a remote target. `tlist.dataset.field` is the
  // canonical target field (target_url for web, target for pwn/crypto/rev),
  // already populated from the row inputs above, so `fd.get()` is authoritative
  // here. An empty value means a genuinely offline job (e.g. a rev crackme with
  // only a binary) where "capture the REAL flag from the remote target" is
  // unsatisfiable by construction — folding it in there just makes the agent
  // chase a nonexistent remote (this misdirected offline rev job 0d0c3de3fbfb).
  // Any filled target row makes this non-empty, so TARGETED jobs are unchanged.
  const crf = form.querySelector(".capture-remote-flag-cb");
  const tfield = tlist && tlist.dataset.field;
  const hasTarget = tfield ? (fd.get(tfield) || "").trim() !== "" : false;
  if (crf && crf.checked && hasTarget) {
    const cur = (fd.get("description") || "").trim();
    if (!cur.toLowerCase().includes("capture remote flag")) {
      fd.set("description", cur
        ? `${cur}\n\n${CAPTURE_REMOTE_FLAG_DIRECTIVE}`
        : CAPTURE_REMOTE_FLAG_DIRECTIVE);
    }
  } else if (crf && crf.checked && !hasTarget) {
    // Operator ticked the box but gave no target — surface it (dev console)
    // rather than silently folding an unsatisfiable remote mandate into an
    // offline job.
    console.warn(
      "🚩 Capture remote flag ticked but no remote target provided — " +
        "mandate not applied (offline job).",
    );
  }
  // "Flag format" → stored in meta for the scanner (authoritative matcher),
  // AND folded into the description so the agent emits FLAG_CANDIDATE in the
  // right format and uses LOCAL{...} for local-test flags.
  const ff = (fd.get("flag_format") || "").trim();
  if (ff) {
    const cur = (fd.get("description") || "").trim();
    const directive =
      `FLAG FORMAT — the real flag for this challenge has the form \`${ff}\`. ` +
      "Emit `FLAG_CANDIDATE: <flag>` ONLY for a flag of this exact format; for any " +
      "local/test flag you plant, use a different format like `LOCAL{...}` so it is " +
      "never mistaken for the real capture.";
    if (!cur.includes("FLAG FORMAT")) {
      fd.set("description", cur ? `${cur}\n\n${directive}` : directive);
    }
  }
  // Drop empty optional fields so backend uses its default.
  const to = fd.get("job_timeout");
  if (to === "" || to == null) fd.delete("job_timeout");
  const model = fd.get("model");
  if (model === "" || model == null) fd.delete("model");
  const effort = fd.get("effort");
  if (effort === "" || effort == null) fd.delete("effort");
  if (ff === "") fd.delete("flag_format");

  const res = await fetch(`${API}${endpoint}`, { method: "POST", body: fd });
  if (!res.ok) {
    alert(`error: ${res.status} ${await res.text()}`);
    return;
  }
  const data = await res.json();
  await refreshJobs();
  selectJob(data.job_id);
}

// ---- Multi-target rows (+ / × buttons) -----------------------------------
// Web/Pwn/Crypto target fields are a dynamic list. "+ add target" appends a
// row; "×" removes one (always keeping ≥1). submitJob() joins the row values
// into the canonical field. Listeners are delegated so dynamically-added rows
// work without re-binding.
function makeTargetRow(placeholder) {
  const row = document.createElement("div");
  row.className = "target-row";
  const inp = document.createElement("input");
  inp.type = "text";
  inp.className = "target-input";
  inp.placeholder = placeholder || "";
  const rm = document.createElement("button");
  rm.type = "button";
  rm.className = "target-remove";
  rm.tabIndex = -1;
  rm.title = "Remove this target";
  rm.textContent = "×";
  row.append(inp, rm);
  return row;
}

document.addEventListener("click", (e) => {
  const addBtn = e.target.closest(".target-add");
  if (addBtn) {
    const list = addBtn.closest(".target-list");
    const rows = list.querySelector(".target-rows");
    const row = makeTargetRow(list.dataset.placeholder || "");
    rows.appendChild(row);
    row.querySelector(".target-input").focus();
    return;
  }
  const rmBtn = e.target.closest(".target-remove");
  if (rmBtn) {
    const rows = rmBtn.closest(".target-rows");
    if (rows.querySelectorAll(".target-row").length > 1) {
      rmBtn.closest(".target-row").remove();
    } else {
      // Last remaining row: clear instead of removing so one input always stays.
      const inp = rmBtn.closest(".target-row").querySelector(".target-input");
      if (inp) inp.value = "";
    }
  }
});

// The native "Reset" button clears values but leaves added rows behind — prune
// each target list back to a single empty row after the reset runs.
document.addEventListener("reset", (e) => {
  const lists = e.target.querySelectorAll
    ? e.target.querySelectorAll(".target-list") : [];
  if (!lists.length) return;
  setTimeout(() => {
    lists.forEach((list) => {
      const rows = list.querySelector(".target-rows");
      rows.querySelectorAll(".target-row").forEach((r, i) => { if (i > 0) r.remove(); });
      const first = rows.querySelector(".target-input");
      if (first) first.value = "";
    });
  }, 0);
});

// Build a multi-target row list for the retry / continue / resume forms — same
// markup + classes as the main submit forms, so the global +/× delegated
// listeners and CSS apply automatically. `prefill` (optional, newline/comma
// separated) seeds rows; blank → one empty row.
function targetListHtml(placeholder, prefill) {
  const vals = (prefill || "").split(/[\r\n,]+/).map((s) => s.trim()).filter(Boolean);
  if (!vals.length) vals.push("");
  const ph = escapeHtml(placeholder || "");
  const rows = vals.map((v) => `
        <div class="target-row">
          <input type="text" class="target-input" placeholder="${ph}" value="${escapeHtml(v)}" />
          <button type="button" class="target-remove" tabindex="-1" title="Remove this target">×</button>
        </div>`).join("");
  return `<div class="target-list" data-placeholder="${ph}">
        <div class="target-rows">${rows}</div>
        <button type="button" class="target-add" title="Add another target">+ add target</button>
      </div>`;
}

// Collect a form's non-empty target rows into a newline-joined string. The
// backend (_read_retry_body → _resolve_targets → parse_targets) splits it:
// "" = keep prior target, "(none)" = clear, several lines = multi-target.
function gatherTargets(formEl) {
  const list = formEl.querySelector(".target-list");
  if (!list) return "";
  return Array.from(list.querySelectorAll(".target-input"))
    .map((i) => i.value.trim())
    .filter(Boolean)
    .join("\n");
}

// Reviewer-mode retry/resume with an optional MULTI-target override (was a
// single-line window.prompt). No manual hint — the auto-reviewer generates it;
// this just lets the operator point the retry/resume at one or more new targets
// via the +/× list. opts: {formKey, submitLabel, streamOpts}.
function openReviewerRetryForm(jobId, anchorBtn, opts) {
  opts = opts || {};
  const key = opts.formKey || "retry";
  const existing = document.getElementById(`reviewer-${key}-form-` + jobId);
  if (existing) { existing.querySelector(".target-input")?.focus(); return; }
  const form = document.createElement("div");
  form.className = "retry-manual-form";
  form.id = `reviewer-${key}-form-` + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Target (override; blank = keep prior, "(none)" = clear · <b>+ add target</b> for several)</label>
    ${targetListHtml("e.g. http://newhost:8080  ·  ctf.example.com:31337")}
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit">${opts.submitLabel || "↻ Retry (reviewer)"}</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Auto-reviewer writes the hint · optional new target(s)</small>
    </div>
  `;
  anchorBtn.parentElement.insertAdjacentElement("afterend", form);
  const submit = form.querySelector(".retry-manual-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  form.querySelector(".target-input")?.focus();
  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", () => {
    const freshCb = document.getElementById(`fresh-ctx-${jobId}`);
    const target = gatherTargets(form);
    form.remove();
    streamRetry(jobId, anchorBtn, null, {
      ...(opts.streamOpts || {}),
      target,
      fresh: !!(freshCb && freshCb.checked),
    });
  });
}

document.getElementById("web-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/web/analyze");
});
document.getElementById("pwn-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/pwn/analyze");
});
document.getElementById("forensic-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/forensic/collect");
});
document.getElementById("misc-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/misc/analyze");
});
document.getElementById("crypto-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/crypto/analyze");
});
document.getElementById("rev-form").addEventListener("submit", (e) => {
  e.preventDefault(); submitJob(e.target, "/modules/rev/analyze");
});

function _setModelField(f, name, customName, catalog, value) {
  const modelSel = f.querySelector(`[name=${name}]`);
  const modelCustom = f.querySelector(`[name=${customName}]`);
  if (!modelSel) return;
  const cur = value || "";
  if (catalog.includes(cur)) {
    modelSel.value = cur;
    if (modelCustom) modelCustom.value = "";
  } else {
    modelSel.value = "";
    if (modelCustom) modelCustom.value = cur;
  }
}

async function loadSettings() {
  const res = await fetch(`${API}/settings`);
  if (!res.ok) return;
  const s = await res.json();
  const f = document.getElementById("settings-form");

  // Provider first so model/effort catalogs match the selection.
  const provider = (s.agent_provider === "grok") ? "grok" : "claude";
  setProviderUI(provider);

  _setModelField(f, "claude_model", "claude_model_custom", CLAUDE_MODELS, s.claude_model);
  _setModelField(f, "grok_model", "grok_model_custom", GROK_MODELS, s.grok_model);

  // Claude effort (mirrors model: empty = SDK default; otherwise one
  // of low/medium/high/xhigh/max). Stored under `claude_effort` in the
  // settings blob; per-job submissions inherit it when their own
  // effort dropdown is left blank.
  const effortSel = f.querySelector("[name=claude_effort]");
  if (effortSel) {
    const curEffort = s.claude_effort || "";
    effortSel.value = CLAUDE_EFFORTS.includes(curEffort) ? curEffort : "";
  }
  const grokEffortSel = f.querySelector("[name=grok_effort]");
  if (grokEffortSel) {
    const curG = s.grok_effort || "";
    grokEffortSel.value = GROK_EFFORTS.includes(curG) ? curG : "";
  }

  f.querySelector("[name=job_ttl_days]").value =
    s.job_ttl_days != null ? s.job_ttl_days : "";
  f.querySelector("[name=job_timeout_seconds]").value =
    s.job_timeout_seconds != null ? s.job_timeout_seconds : "";
  // Show the LIVE slot count, not the stored `worker_concurrency`. That
  // setting is inert under the slot split (runner.py forces 1 process per slot
  // container) and /data/settings.json still holds its pre-split value, so
  // rendering it would tell the operator "3 parallel jobs" while two slots are
  // running. Fall back to the stored value only when the live count is
  // unavailable — i.e. a pre-split deployment, where it is still the truth.
  const liveSlots = s.worker_mem_live && s.worker_mem_live.available
    ? s.worker_mem_live.slot_count : null;
  f.querySelector("[name=worker_concurrency]").value =
    liveSlots != null ? liveSlots
      : (s.worker_concurrency != null ? s.worker_concurrency : "");
  const memInput = f.querySelector("[name=worker_slot_mem]");
  if (memInput) memInput.value = s.worker_slot_mem != null ? s.worker_slot_mem : "";
  renderWorkerMemLive(s.worker_mem_live);
  const budgetInput = f.querySelector("[name=budget_usd]");
  if (budgetInput) budgetInput.value = s.budget_usd ? s.budget_usd : "";
  f.querySelector("[name=callback_url]").value = s.callback_url || "";
  // enable_judge default-True; only un-check when explicitly stored false
  f.querySelector("[name=enable_judge]").checked = s.enable_judge !== false;
  // enable_exploit_library_hint default-False
  f.querySelector("[name=enable_exploit_library_hint]").checked = !!s.enable_exploit_library_hint;

  document.getElementById("key-status").textContent = s.anthropic_api_key_set
    ? `set (${s.anthropic_api_key_masked}) — leave blank to keep, type new to replace`
    : (s.anthropic_api_key_env_set ? "using ANTHROPIC_API_KEY from env" : "not set");
  document.getElementById("oauth-status").textContent = s.claude_oauth_detected
    ? "✓ Claude Code OAuth detected — works without API key"
    : "✗ no OAuth credentials — run `claude login` on the host";
  document.getElementById("oauth-status").classList.toggle("oauth-ok", !!s.claude_oauth_detected);

  const xaiStatus = document.getElementById("xai-key-status");
  if (xaiStatus) {
    xaiStatus.textContent = s.xai_api_key_set
      ? `set (${s.xai_api_key_masked}) — leave blank to keep, type new to replace`
      : (s.xai_api_key_env_set ? "using XAI_API_KEY from env" : "not set");
  }
  const grokAuth = document.getElementById("grok-auth-status");
  if (grokAuth) {
    grokAuth.textContent = s.grok_auth_detected
      ? "✓ Grok auth.json detected — works without API key"
      : "✗ no Grok auth file — run `grok login` on the host (mount ~/.grok) or set XAI_API_KEY";
    grokAuth.style.color = s.grok_auth_detected ? "var(--green)" : "var(--fg-muted)";
  }

  const provStatus = document.getElementById("provider-status");
  if (provStatus) {
    if (provider === "grok") {
      const authOk = s.xai_api_key_set || s.xai_api_key_env_set || s.grok_auth_detected;
      provStatus.textContent = authOk
        ? "Active: Grok Build (ACP) — next job uses Grok agent stdio."
        : "Active: Grok Build — configure xAI key or grok login auth before running jobs.";
      provStatus.style.color = authOk ? "var(--green)" : "var(--red)";
    } else {
      const authOk = s.anthropic_api_key_set || s.anthropic_api_key_env_set || s.claude_oauth_detected;
      provStatus.textContent = authOk
        ? "Active: Claude Agent SDK — ready for jobs."
        : "Active: Claude — no auth detected; set API key or run claude login.";
      provStatus.style.color = authOk ? "var(--green)" : "var(--red)";
    }
  }

  document.getElementById("auth-status").textContent = s.auth_token_set
    ? `set (${s.auth_token_masked})`
    : (s.auth_token_env_set ? "using AUTH_TOKEN from env" : "not set (auth disabled)");
}

// Live-toggle provider cards without saving (save still required).
document.getElementById("settings-form")?.addEventListener("change", (e) => {
  const t = e.target;
  if (t && t.name === "agent_provider") {
    setProviderUI(t.value);
    const provStatus = document.getElementById("provider-status");
    if (provStatus) {
      provStatus.textContent = t.value === "grok"
        ? "Grok selected (unsaved) — click Save to apply to the next job."
        : "Claude selected (unsaved) — click Save to apply to the next job.";
      provStatus.style.color = "var(--yellow)";
    }
  }
});

document.getElementById("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  // Custom-text overrides the dropdown for claude_model / grok_model.
  const custom = (fd.get("claude_model_custom") || "").toString().trim();
  if (custom) fd.set("claude_model", custom);
  fd.delete("claude_model_custom");
  const grokCustom = (fd.get("grok_model_custom") || "").toString().trim();
  if (grokCustom) fd.set("grok_model", grokCustom);
  fd.delete("grok_model_custom");

  const payload = {};
  for (const [k, v] of fd.entries()) {
    if (v === "" && (k === "anthropic_api_key" || k === "xai_api_key" || k === "auth_token")) {
      // Empty secret field: skip — keep current value
      continue;
    }
    if (k === "enable_judge") continue;  // handled explicitly below
    if (k === "enable_exploit_library_hint") continue;  // handled explicitly below
    if (v === "") {
      payload[k] = null;  // null = clear the override
      continue;
    }
    if (k === "worker_slot_mem") {
      payload[k] = String(v).trim();
    } else if (k === "job_ttl_days" || k === "job_timeout_seconds" || k === "worker_concurrency" || k === "budget_usd") {
      payload[k] = Number(v);
    } else {
      payload[k] = v;
    }
  }
  // Checkboxes are absent from FormData when unchecked — read directly
  // so the OFF state is sent as `false`, not "clear the override".
  payload.enable_judge = !!e.target.querySelector("[name=enable_judge]").checked;
  payload.enable_exploit_library_hint = !!e.target.querySelector("[name=enable_exploit_library_hint]").checked;
  // Radio always present; default claude if somehow missing.
  if (!payload.agent_provider) {
    payload.agent_provider = e.target.querySelector("[name=agent_provider]:checked")?.value || "claude";
  }
  const res = await fetch(`${API}/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    alert(`save failed: ${res.status} ${await res.text()}`);
    return;
  }
  // Clear secret fields after save
  e.target.querySelector("[name=anthropic_api_key]").value = "";
  const xaiIn = e.target.querySelector("[name=xai_api_key]");
  if (xaiIn) xaiIn.value = "";
  e.target.querySelector("[name=auth_token]").value = "";
  let applied = null;
  try { applied = (await res.clone().json()).worker_mem_applied; } catch (_) {}
  let savedView = null;
  try { savedView = await res.clone().json(); } catch (_) {}
  await loadSettings();
  const savedProvider = (savedView && savedView.agent_provider) || payload.agent_provider || "claude";
  const providerLine = savedProvider === "grok"
    ? "Agent provider: Grok Build (ACP) — next job uses Grok."
    : "Agent provider: Claude (Agent SDK) — next job uses Claude.";
  if (applied && applied.applied === false) {
    alert("Saved, but the per-slot memory limit was NOT applied to the running slots:\n\n" +
          applied.reason + "\n\nIt will take effect on the next `docker compose up -d worker-1 worker-2`.\n\n" +
          providerLine);
  } else if (applied && applied.applied) {
    alert("Saved. Per-slot memory limit applied to all " + (applied.slot_count || "") +
          " running slot(s) immediately.\n\n" + providerLine);
  } else {
    alert("Saved. Changes apply to the next job.\n\n" + providerLine);
  }
});

// The worker memory cap is a container-CREATE property, so the saved setting
// and the container's actual cgroup can diverge (a recreate resets it to the
// compose/.env default). Show what the container REALLY has, never just what
// was typed.
function fmtBytes(n) {
  if (!n || n <= 0) return "unlimited";
  const g = n / 1073741824;
  return g >= 1 ? g.toFixed(g < 10 ? 1 : 0) + " GiB" : Math.round(n / 1048576) + " MiB";
}
function renderWorkerMemLive(live) {
  const el = document.getElementById("worker-mem-live");
  if (!el) return;
  if (!live || !live.available) {
    el.innerHTML = '<br><b style="color:var(--yellow)">live value unavailable</b> (docker socket not reachable from the api container)';
    return;
  }
  // The cap is PER SLOT and there are N slots, so the number that matters for
  // "does this fit the VM" is the product. Showing only the per-slot value is
  // how an 8g-per-container setting quietly became 16 GiB of cap.
  const n = live.slot_count || (live.slots ? live.slots.length : 1);
  const lim = fmtBytes(live.limit_bytes);
  const use = live.usage_bytes ? fmtBytes(live.usage_bytes) : "?";
  const total = fmtBytes(live.total_limit_bytes || live.limit_bytes);
  let html = '<br>right now: <b>' + n + ' slot' + (n === 1 ? "" : "s") +
             ' &times; ' + lim + '</b> = ' + total + ' total cap, ' + use + ' in use';

  if (live.host_mem_total_bytes) {
    html += ' &middot; VM has ' + fmtBytes(live.host_mem_total_bytes);
  }
  if (!live.limit_bytes || live.limit_bytes <= 0) {
    html += ' <b style="color:var(--yellow)">— uncapped: one runaway job can freeze the host</b>';
  }
  if (live.limits_uniform === false) {
    html += ' <b style="color:var(--yellow)">— slots disagree on their cap' +
            ' (showing the smallest, which OOMs first); recreate to normalise</b>';
  }
  if (live.slots && live.slots.length > 1) {
    html += '<br>' + live.slots.map(function (s) {
      const u = s.usage_bytes ? fmtBytes(s.usage_bytes) : "?";
      return '&nbsp;&nbsp;slot ' + (s.slot || "?") + ': ' + fmtBytes(s.limit_bytes) +
             ' cap, ' + u + ' in use';
    }).join('<br>');
  }
  el.innerHTML = html;
}

document.getElementById("settings-reload").addEventListener("click", loadSettings);

// Load settings whenever the user clicks the Settings tab
document.querySelector('.tab[data-tab="settings"]').addEventListener("click", () => {
  loadSettings();
  loadModelPresets();
  loadTunnelStatus();
});

// --- Cloudflared tunnel ----------------------------------------------------
// Activate/stop a cloudflared OOB quick-tunnel and show live connection state.
// Backed by /api/tunnel (start/stop/status) which runs cloudflared as a sibling
// container. Status reflects reality (container + edge probe), never a flag.
let _tunnelPoll = null;
let _tunnelPollTicks = 0;

function _stopTunnelPoll() {
  if (_tunnelPoll) { clearInterval(_tunnelPoll); _tunnelPoll = null; }
  _tunnelPollTicks = 0;
}

function _setTunnelChip(state, label) {
  const chip = document.getElementById("tunnel-chip");
  if (!chip) return;
  chip.className = "rl-chip " + (
    state === "connected" ? "rl-chip--ok" :
    state === "connecting" ? "rl-chip--warn" : "rl-chip--rejected"
  );
  chip.textContent = label;
}

function renderTunnel(s) {
  const warn = document.getElementById("tunnel-warning");
  if (warn) warn.hidden = !s.exposure_warning;
  const urlEl = document.getElementById("tunnel-url");
  if (urlEl) {
    if (s.running && s.url) { urlEl.hidden = false; urlEl.textContent = s.url; urlEl.href = s.url; }
    else { urlEl.hidden = true; urlEl.textContent = ""; urlEl.removeAttribute("href"); }
  }
  if (!s.running) {
    _setTunnelChip("down", s.error ? "error" : "down");
  } else if (!s.url) {
    _setTunnelChip("connecting", "connecting…");
  } else if (s._dud) {
    _setTunnelChip("down", "up but unreachable — re-roll");
  } else if (s.reachable === false) {
    _setTunnelChip("connecting", "edge warming up…");
  } else {
    _setTunnelChip("connected", s.url_published ? "connected" : "connected (unpublished)");
  }
  const txt = document.getElementById("tunnel-status-text");
  if (txt) txt.textContent = s.error ? s.error : (s.note || "");
}

async function loadTunnelStatus(probe = false) {
  try {
    const res = await fetch(`${API}/tunnel/status${probe ? "?probe=1" : ""}`);
    if (!res.ok) { _setTunnelChip("down", "status error"); _stopTunnelPoll(); return null; }
    const s = await res.json();
    // Cap the "edge warming up" window: after ~12 gated ticks (~60s) of
    // running-but-unreachable, call it a dud (a dead quick-tunnel that came up
    // but never routes) so the chip goes terminal-red and the poller stops,
    // instead of spinning yellow forever.
    if (s.running && s.url && s.reachable === false && _tunnelPollTicks >= 12) s._dud = true;
    renderTunnel(s);
    const connecting = s.running && (!s.url || s.reachable === false) && !s._dud;
    const onSettings = document.getElementById("panel-settings").classList.contains("active");
    if (connecting && onSettings) {
      _tunnelPollTicks++;
      if (!_tunnelPoll) _tunnelPoll = setInterval(() => loadTunnelStatus(true), 5000);
    } else {
      _stopTunnelPoll();
    }
    return s;
  } catch (_) {
    _setTunnelChip("down", "unreachable"); _stopTunnelPoll(); return null;
  }
}

document.getElementById("tunnel-activate").addEventListener("click", async (e) => {
  const btn = e.target; btn.disabled = true;
  _stopTunnelPoll();
  _setTunnelChip("connecting", "starting…");
  const txt = document.getElementById("tunnel-status-text");
  if (txt) txt.textContent = "spawning cloudflared + waiting for public URL (up to ~30s)…";
  try {
    const res = await fetch(`${API}/tunnel/start`, { method: "POST" });
    const s = await res.json();
    renderTunnel(s);
    if (s.ok) {
      loadTunnelStatus(true);   // re-check reachability (does NOT clobber an error)
    } else if (txt) {
      txt.textContent = s.error || s.detail || "start failed";  // keep it visible
    }
  } catch (err) {
    if (txt) txt.textContent = `start failed: ${err}`;
    _setTunnelChip("down", "error");
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("tunnel-stop").addEventListener("click", async (e) => {
  const btn = e.target; btn.disabled = true;
  _stopTunnelPoll();
  const txt = document.getElementById("tunnel-status-text");
  if (txt) txt.textContent = "stopping…";
  try {
    const res = await fetch(`${API}/tunnel/stop`, { method: "POST" });
    const s = await res.json();
    renderTunnel(s);
    if (txt) txt.textContent = s.error || s.note || "stopped";
  } catch (err) {
    if (txt) txt.textContent = `stop failed: ${err}`;
  } finally {
    btn.disabled = false;
  }
});

document.getElementById("tunnel-refresh").addEventListener("click", () => loadTunnelStatus(true));

// --- Model presets ---------------------------------------------------------
// Named per-role model overrides (judge / report / monitor) the operator can
// save and switch between. The whole store is edited in memory and PUT as one
// blob to /api/model-presets. main stays on the per-job / global model.
let PRESET_STORE = { active: "", presets: {}, configurable_roles: ["main", "judge", "reviewer", "recon", "debugger", "triage", "report", "monitor"] };

// Human-readable default a blank role falls back to (shown in the "(inherit)" option).
const PRESET_ROLE_DEFAULTS = {
  main: "per-job pick / global Settings model",
  judge: "follows main model",
  reviewer: "follows judge slot / main",
  recon: "follows main — cache-aligned",
  debugger: "follows main — cache-aligned",
  triage: "follows main — cache-aligned",
  report: "follows main model",
  monitor: "claude-sonnet-4-6",
};

async function loadModelPresets() {
  try {
    const res = await fetch(`${API}/model-presets`);
    if (!res.ok) return;
    const s = await res.json();
    if (s && typeof s === "object") {
      PRESET_STORE = {
        active: s.active || "",
        presets: s.presets || {},
        configurable_roles: (s.configurable_roles && s.configurable_roles.length)
          ? s.configurable_roles : ["main", "judge", "reviewer", "recon", "debugger", "triage", "report", "monitor"],
      };
    }
  } catch (_) { return; }
  renderPresetControls();
}

function renderPresetControls() {
  const sel = document.getElementById("preset-active");
  if (!sel) return;
  const names = Object.keys(PRESET_STORE.presets || {}).sort();
  const active = PRESET_STORE.active || "";
  sel.innerHTML = "";
  sel.appendChild(new Option("(none — every agent inherits its default)", ""));
  for (const n of names) sel.appendChild(new Option(n, n));
  sel.value = names.includes(active) ? active : "";
  renderPresetRoles();
  updatePresetStatus();
}

function renderPresetRoles() {
  const wrap = document.getElementById("preset-roles");
  if (!wrap) return;
  const active = document.getElementById("preset-active").value;
  wrap.innerHTML = "";
  if (!active) {
    const p = document.createElement("p");
    p.className = "preset-empty";
    p.textContent =
      "No preset active — main uses the per-job pick / global Settings model & "
      + "effort; judge/report follow main; monitor runs cheap. Click “+ New” to "
      + "create one.";
    wrap.appendChild(p);
    return;
  }
  const preset = PRESET_STORE.presets[active] || {};
  for (const role of PRESET_STORE.configurable_roles) {
    const cur = preset[role] || "";
    const lbl = document.createElement("label");
    lbl.className = "preset-role";
    const inheritTxt = PRESET_ROLE_DEFAULTS[role] || "inherit";
    lbl.innerHTML =
      `<span class="preset-role-name">${role}</span>` +
      `<select data-preset-role="${role}"></select>`;
    const s = lbl.querySelector("select");
    s.appendChild(new Option(`(inherit — ${inheritTxt})`, ""));
    for (const m of CLAUDE_MODELS) s.appendChild(new Option(m, m));
    // A saved custom model that isn't in the catalog: surface it so it's editable.
    if (cur && !CLAUDE_MODELS.includes(cur)) s.appendChild(new Option(`${cur} (custom)`, cur));
    s.value = cur;
    s.addEventListener("change", () => {
      if (!PRESET_STORE.presets[active]) PRESET_STORE.presets[active] = {};
      PRESET_STORE.presets[active][role] = s.value;
      updatePresetStatus();
    });
    wrap.appendChild(lbl);
  }
  // effort row — reasoning effort for the MAIN session (mirrors the global
  // "Effort" Setting); not a model, so it's a separate control.
  const elbl = document.createElement("label");
  elbl.className = "preset-role";
  elbl.innerHTML =
    `<span class="preset-role-name">effort</span>` +
    `<select data-preset-effort></select>`;
  const es = elbl.querySelector("select");
  es.appendChild(new Option("(inherit — per-job / global Settings effort)", ""));
  for (const ef of CLAUDE_EFFORTS) es.appendChild(new Option(ef, ef));
  es.value = preset.effort || "";
  es.addEventListener("change", () => {
    if (!PRESET_STORE.presets[active]) PRESET_STORE.presets[active] = {};
    PRESET_STORE.presets[active].effort = es.value;
    updatePresetStatus();
  });
  wrap.appendChild(elbl);
}

function updatePresetStatus() {
  const el = document.getElementById("preset-status");
  if (!el) return;
  const active = PRESET_STORE.active || "";
  if (!active || !PRESET_STORE.presets[active]) {
    el.textContent = "no preset active — defaults in effect. Remember to Save.";
    return;
  }
  const p = PRESET_STORE.presets[active];
  const parts = PRESET_STORE.configurable_roles.map(
    (r) => `${r}=${p[r] ? p[r] : "inherit"}`
  );
  parts.push(`effort=${p.effort ? p.effort : "inherit"}`);
  el.textContent = `active: ${active} · ${parts.join(" · ")} · Save to apply`;
}

document.getElementById("preset-active").addEventListener("change", (e) => {
  PRESET_STORE.active = e.target.value;
  renderPresetRoles();
  updatePresetStatus();
});

document.getElementById("preset-new").addEventListener("click", () => {
  const name = (prompt("New preset name:") || "").trim();
  if (!name) return;
  if (PRESET_STORE.presets[name]) { alert(`preset "${name}" already exists`); return; }
  PRESET_STORE.presets[name] = { judge: "", report: "", monitor: "" };
  PRESET_STORE.active = name;
  renderPresetControls();
});

document.getElementById("preset-rename").addEventListener("click", () => {
  const cur = document.getElementById("preset-active").value;
  if (!cur) { alert("select a preset to rename first"); return; }
  const nn = (prompt("New name:", cur) || "").trim();
  if (!nn || nn === cur) return;
  if (PRESET_STORE.presets[nn]) { alert(`preset "${nn}" already exists`); return; }
  PRESET_STORE.presets[nn] = PRESET_STORE.presets[cur];
  delete PRESET_STORE.presets[cur];
  if (PRESET_STORE.active === cur) PRESET_STORE.active = nn;
  renderPresetControls();
});

document.getElementById("preset-delete").addEventListener("click", () => {
  const cur = document.getElementById("preset-active").value;
  if (!cur) { alert("select a preset to delete first"); return; }
  if (!confirm(`Delete preset "${cur}"?`)) return;
  delete PRESET_STORE.presets[cur];
  if (PRESET_STORE.active === cur) PRESET_STORE.active = "";
  renderPresetControls();
});

document.getElementById("preset-save").addEventListener("click", async (e) => {
  const btn = e.target;
  btn.disabled = true;
  try {
    const res = await fetch(`${API}/model-presets`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ active: PRESET_STORE.active, presets: PRESET_STORE.presets }),
    });
    if (!res.ok) { alert(`save failed: ${res.status} ${await res.text()}`); return; }
    const saved = await res.json();
    PRESET_STORE = {
      active: saved.active || "",
      presets: saved.presets || {},
      configurable_roles: (saved.configurable_roles && saved.configurable_roles.length)
        ? saved.configurable_roles : PRESET_STORE.configurable_roles,
    };
    renderPresetControls();
    const el = document.getElementById("preset-status");
    if (el) el.textContent = "saved ✓ — applies to the next job";
  } finally {
    btn.disabled = false;
  }
});

// --- Exploit Library -------------------------------------------------------
// Operator-curated library of past report.md + exploit.py pairs. Future
// jobs consult /data/exploits/<id>/ via plain Bash when the Settings
// toggle `enable_exploit_library_hint` is ON.

async function loadExploits() {
  const status = document.getElementById("exp-status");
  const list = document.getElementById("exp-list");
  if (!list) return;
  const module = document.getElementById("exp-filter-module").value;
  const search = document.getElementById("exp-filter-search").value.trim();
  const params = new URLSearchParams();
  if (module) params.set("module", module);
  if (search) params.set("search", search);
  status.textContent = "loading…";
  list.innerHTML = "";
  let data;
  try {
    const res = await fetch(`${API}/exploits?${params.toString()}`);
    if (!res.ok) {
      status.textContent = `error ${res.status}: ${await res.text()}`;
      return;
    }
    data = await res.json();
  } catch (e) {
    status.textContent = "fetch failed: " + e;
    return;
  }
  status.textContent = `${data.count} entr${data.count === 1 ? "y" : "ies"}`;
  if (!data.items.length) {
    list.innerHTML = `<li class="exp-empty">no saved exploits yet — save one via the 💾 button on any finished job's detail panel</li>`;
    return;
  }
  list.innerHTML = data.items.map((m) => {
    const id = m.id;
    const tagsHtml = (m.tags || []).map(t => `<span class="exp-tag">${escapeHtml(t)}</span>`).join("");
    const flagsHtml = (m.flags || []).map(f => `<code class="exp-flag">${escapeHtml(f)}</code>`).join(" ");
    const bug = (m.bug_classes || []).join(",") || "";
    const mit = m.mitigations ? Object.entries(m.mitigations).map(([k,v])=>`${k}=${v}`).join(" ") : "";
    return `<li class="exp-card" data-id="${id}">
      <div class="exp-card-head">
        <span class="exp-id">${escapeHtml(id)}</span>
        <span class="exp-module ${escapeHtml(m.module || "")}">${escapeHtml(m.module || "?")}</span>
        <span class="exp-saved" title="${escapeHtml(m.saved_at || "")}">${escapeHtml((m.saved_at || "").slice(0,19).replace("T"," "))}</span>
      </div>
      <div class="exp-card-meta">
        <div><b>chal:</b> ${escapeHtml(m.chal_filename || m.chal_name || "?")}${m.target_url ? ` <small>· target: ${escapeHtml(m.target_url)}</small>` : ""}</div>
        ${m.technique_name ? `<div><b>technique:</b> <code>${escapeHtml(m.technique_name)}</code></div>` : ""}
        ${(bug || m.arch || m.glibc_version) ? `<div><small>${[bug && `bug=${bug}`, m.arch && `arch=${m.arch}`, m.glibc_version && `glibc=${m.glibc_version}`].filter(Boolean).join(" · ")}</small></div>` : ""}
        ${mit ? `<div><small>mit: ${escapeHtml(mit)}</small></div>` : ""}
        ${flagsHtml ? `<div><small>🚩 ${flagsHtml}</small></div>` : ""}
        ${m.notes ? `<div class="exp-notes">${escapeHtml(m.notes)}</div>` : ""}
        ${tagsHtml ? `<div>${tagsHtml}</div>` : ""}
      </div>
      <div class="exp-card-actions">
        <a class="file-preview-link" data-name="${escapeHtml(id)}/report.md" data-url="${API}/exploits/${id}/file/report.md" href="${API}/exploits/${id}/file/report.md">📄 report.md</a>
        <a class="file-preview-link" data-name="${escapeHtml(id)}/${escapeHtml(m.script_filename || "exploit.py")}" data-url="${API}/exploits/${id}/file/${escapeHtml(m.script_filename || "exploit.py")}" href="${API}/exploits/${id}/file/${escapeHtml(m.script_filename || "exploit.py")}">🐍 ${escapeHtml(m.script_filename || "exploit.py")}</a>
        ${m.source_job_id ? `<a href="#" class="exp-jump-job" data-job-id="${escapeHtml(m.source_job_id)}">↗ source job</a>` : ""}
        <button class="exp-del-btn" data-id="${id}">🗑 delete</button>
      </div>
    </li>`;
  }).join("");

  for (const btn of list.querySelectorAll(".exp-del-btn")) {
    btn.addEventListener("click", async () => {
      const eid = btn.dataset.id;
      if (!confirm(`Delete exploit ${eid}? This cannot be undone.`)) return;
      btn.disabled = true;
      const res = await fetch(`${API}/exploits/${eid}`, { method: "DELETE" });
      if (!res.ok) {
        alert(`delete failed: ${res.status} ${await res.text()}`);
        btn.disabled = false;
        return;
      }
      loadExploits();
    });
  }
  for (const a of list.querySelectorAll(".exp-jump-job")) {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      const jid = a.dataset.jobId;
      // selectJob() opens the modal + scrolls. Works even when the
      // row isn't currently rendered (e.g. filtered out / TTL'd).
      try { selectJob(jid); }
      catch (_) { alert(`Source job ${jid} is no longer available.`); }
    });
  }
}

document.getElementById("exp-refresh").addEventListener("click", loadExploits);
document.getElementById("exp-filter-module").addEventListener("change", loadExploits);
{
  let _expSearchTimer = null;
  document.getElementById("exp-filter-search").addEventListener("input", () => {
    clearTimeout(_expSearchTimer);
    _expSearchTimer = setTimeout(loadExploits, 250);
  });
}
document.getElementById("exp-import-file").addEventListener("change", async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const mode = document.getElementById("exp-import-mode").value || "skip";
  const fd = new FormData();
  fd.set("file", file);
  fd.set("mode", mode);
  const status = document.getElementById("exp-status");
  status.textContent = `importing ${file.name}…`;
  const res = await fetch(`${API}/exploits/import`, { method: "POST", body: fd });
  e.target.value = "";  // reset so re-selecting same file fires change
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    alert(`import failed: ${res.status} — ${data.detail || ""}`);
    status.textContent = `import failed (${res.status})`;
    return;
  }
  const c = data.counts || {};
  status.textContent = `imported=${c.imported||0} · skipped=${c.skipped||0} · rejected=${c.rejected||0}`;
  loadExploits();
});

// Load the library on first click of the Exploits tab + on every
// click (cheap; the GET endpoint is just a directory walk).
document.querySelector('.tab[data-tab="exploits"]').addEventListener("click", loadExploits);

document.getElementById("refresh-jobs").addEventListener("click", () => {
  refreshJobs(); refreshStats();
});

document.getElementById("bulk-delete").addEventListener("click", async () => {
  const filter = document.getElementById("bulk-filter").value;
  let url = `${API}/jobs`;
  let label;
  if (filter === "__all__") {
    if (!confirm("Delete ALL jobs (including queued/running)?\nRunning jobs will be cancelled.")) return;
    url += "?all=true";
    label = "ALL jobs";
  } else if (filter === "") {
    if (!confirm("Delete all finished + failed jobs?")) return;
    label = "finished + failed jobs";
  } else {
    if (!confirm(`Delete all jobs with status="${filter}"?`)) return;
    url += `?status=${encodeURIComponent(filter)}`;
    label = `jobs with status=${filter}`;
  }
  const res = await fetch(url, { method: "DELETE" });
  if (!res.ok) {
    alert(`bulk delete failed: ${res.status} ${await res.text()}`);
    return;
  }
  const r = await res.json();
  alert(`Deleted ${r.deleted} ${label}${r.skipped ? ` (skipped ${r.skipped})` : ""}.`);
  if (selectedJob && r.ids && r.ids.includes(selectedJob)) {
    _closeJobModal();
  }
  await refreshJobs();
  await refreshStats();
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await fetch("/logout", { method: "POST" });
  location.href = "/login";
});

// ── Rate-limit chip rendering, shared by the Claude and Grok chips ─────────
// What an operator wants off a weekly pool is how much is LEFT, so both chips
// lead with that. `remaining_pct` is served for Grok; for Claude only
// `utilization` (a used fraction) comes back, and the API docs it as
// "frequently absent for OAuth accounts" — hence the status-word fallback
// rather than rendering a confident 0%.
function _rlRemainingLabel(rl) {
  if (typeof rl.remaining_pct === "number") return `${Math.round(rl.remaining_pct)}% left`;
  if (typeof rl.utilization === "number") {
    // utilization can exceed 1 on an overage; clamp so we never say "-40% left".
    return `${Math.round(Math.max(0, 1 - rl.utilization) * 100)}% left`;
  }
  if (rl.status === "rejected") return "limit hit";
  if (rl.status === "allowed_warning") return "near limit";
  return "usage ok";
}

function _rlResetSuffix(rl) {
  if (!rl.resets_at) return "";
  const secs = rl.resets_at - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  // Days matter: both windows are `seven_day`, and the Claude chip used to
  // render a 3-day reset as "87h30m".
  if (d > 0) return ` · resets ${d}d${h}h`;
  if (h > 0) return ` · resets ${h}h${m}m`;
  return ` · resets ${m}m`;
}

async function refreshStats() {
  try {
    const [statsRes, queueRes, usageRes] = await Promise.all([
      fetch(`${API}/jobs/stats`),
      fetch(`${API}/jobs/queue`),
      fetch(`${API}/jobs/usage`),
    ]);
    if (statsRes.ok) {
      const s = await statsRes.json();
      const el = document.getElementById("cost-total");
      el.textContent = `$${(s.total_cost_usd || 0).toFixed(3)} · ${s.count} jobs`;
      el.title = "by module: " + Object.entries(s.by_module || {})
        .map(([m, v]) => `${m}=${v.count} ($${v.cost_usd.toFixed(3)})`).join(", ");
    }
    if (queueRes.ok) {
      const q = await queueRes.json();
      const qe = document.getElementById("queue-info");
      qe.textContent = `${q.workers_busy}/${q.workers_total} workers · ${q.queued} queued`;
      qe.title = (q.workers || []).map(w =>
        `${w.name}: ${w.state}${w.job_id ? " (" + w.job_id + ")" : ""}`
      ).join("\n") || "no workers";
    }
    if (usageRes.ok) renderUsage(await usageRes.json());
  } catch (_) {}
}

// Render the operator budget pill + the account rate-limit status chip from
// GET /api/jobs/usage. Both hide gracefully when there's nothing to show
// (no budget set / no rate-limit event seen yet).
function renderUsage(u) {
  // --- budget pill: "used / budget" with a color by fraction consumed ---
  const pill = document.getElementById("usage-pill");
  if (pill) {
    const inflight0 = (u && u.in_flight_estimate_usd) || 0;
    if (u && u.budget_usd <= 0 && (u.spent_usd > 0 || inflight0 > 0)) {
      // No budget configured. The pill used to hide entirely here, which meant
      // the in-flight estimate shipped invisible on this deployment (no budget
      // is set by default). Show spend without the budget framing.
      pill.hidden = false;
      pill.classList.remove("usage-pill--warn", "usage-pill--over");
      pill.textContent = `$${(u.spent_usd || 0).toFixed(2)} spent`
        + (inflight0 > 0 ? ` +~$${inflight0.toFixed(2)}` : "");
      pill.title = `cumulative spend across all jobs — no operator budget set `
        + `(set one in Settings to get a used/budget bar).`
        + (inflight0 > 0
            ? `\n+~$${inflight0.toFixed(2)} estimated for job(s) still running `
              + `(token-based, runs high).`
            : "");
    } else if (u && u.budget_usd > 0) {
      const spent = u.spent_usd || 0, budget = u.budget_usd;
      const pct = u.pct_used != null ? u.pct_used : (spent / budget * 100);
      pill.hidden = false;
      // A RUNNING job contributes $0 to spent_usd until its ResultMessage
      // lands, so a long job is invisible here for hours. Show its token
      // estimate as a separate "+~$X" suffix — never folded into spent,
      // because the estimate runs high and the budget must stay honest.
      const inflight = u.in_flight_estimate_usd || 0;
      pill.textContent = `$${spent.toFixed(2)} / $${budget.toFixed(0)} (${pct.toFixed(0)}%)`
        + (inflight > 0 ? ` +~$${inflight.toFixed(2)}` : "");
      pill.classList.remove("usage-pill--warn", "usage-pill--over");
      if (pct >= 100) pill.classList.add("usage-pill--over");
      else if (pct >= 80) pill.classList.add("usage-pill--warn");
      const rem = u.remaining_usd != null ? u.remaining_usd : (budget - spent);
      pill.title = `operator budget — spent $${spent.toFixed(4)} of $${budget.toFixed(2)}; `
        + `$${rem.toFixed(2)} left. NOT the Claude account limit.`
        + (inflight > 0
            ? `\n+~$${inflight.toFixed(2)} estimated for job(s) still running `
              + `(token-based, runs high; excluded from the budget maths).`
            : "");
    } else {
      pill.hidden = true;  // no budget configured
    }
  }
  // --- Claude rate-limit status chip: green/amber/red + "resets in HH:MM" ---
  // Both provider chips render through the two helpers above so they cannot
  // drift apart again: the Claude chip used to APPEND `utilization` as a used
  // percentage while the Grok chip showed remaining, so the same 0.37 read as
  // "37%" on one and "63% left" on the other — opposite meanings, same number,
  // side by side in the same bar.
  const chip = document.getElementById("ratelimit-chip");
  if (chip) {
    const rl = u && u.rate_limit;
    if (rl && rl.status) {
      chip.hidden = false;
      chip.classList.remove("rl-chip--ok", "rl-chip--warn", "rl-chip--rejected");
      if (rl.status === "rejected") chip.classList.add("rl-chip--rejected");
      else if (rl.status === "allowed_warning") chip.classList.add("rl-chip--warn");
      else chip.classList.add("rl-chip--ok");
      chip.textContent = `⏳ Claude ${_rlRemainingLabel(rl)}${_rlResetSuffix(rl)}`;
      chip.title = `Claude rate-limit: ${rl.status}`
        + (rl.rate_limit_type ? ` (${rl.rate_limit_type})` : "")
        + (typeof rl.utilization === "number"
            ? `\n${Math.round(rl.utilization * 100)}% of the window used` : "")
        + (rl.resets_at ? `\nresets at ${new Date(rl.resets_at * 1000).toLocaleString()}` : "")
        + (rl.updated_at ? `\nlast event ${new Date(rl.updated_at).toLocaleString()}` : "");
    } else {
      chip.hidden = true;  // no rate-limit event seen yet
    }
  }

  // --- Grok SuperGrok weekly pool chip (remaining %) ---
  // Source: GET /api/jobs/usage → grok_rate_limit (cli-chat-proxy billing
  // poll, needs grok login OAuth). Hides when no auth / no data yet.
  const gchip = document.getElementById("grok-ratelimit-chip");
  if (gchip) {
    const gr = u && u.grok_rate_limit;
    if (gr && gr.status && gr.status !== "unknown") {
      gchip.hidden = false;
      gchip.classList.remove("rl-chip--ok", "rl-chip--warn", "rl-chip--rejected");
      if (gr.status === "rejected") gchip.classList.add("rl-chip--rejected");
      else if (gr.status === "allowed_warning") gchip.classList.add("rl-chip--warn");
      else gchip.classList.add("rl-chip--ok");
      gchip.textContent = `⏳ Grok ${_rlRemainingLabel(gr)}${_rlResetSuffix(gr)}`;
      const prod = (gr.product_usage || [])
        .map((p) => `${p.product || "?"}: ${Math.round(p.usage_percent || 0)}%`)
        .join(", ");
      gchip.title = `Grok weekly pool: ${gr.status}`
        + (gr.rate_limit_type ? ` (${gr.rate_limit_type})` : "")
        + (typeof gr.used_pct === "number" ? `\nused ${gr.used_pct}%` : "")
        + (typeof gr.remaining_pct === "number" ? ` · ${gr.remaining_pct}% remaining` : "")
        + (prod ? `\nby product: ${prod}` : "")
        + (gr.resets_at ? `\nresets at ${new Date(gr.resets_at * 1000).toLocaleString()}` : "")
        + (gr.updated_at ? `\nlast poll ${new Date(gr.updated_at).toLocaleString()}` : "");
    } else {
      gchip.hidden = true;
    }
  }
}

async function deleteJob(id, ev) {
  ev.stopPropagation();
  if (!confirm(`Delete job ${id}?`)) return;
  await fetch(`${API}/jobs/${id}`, { method: "DELETE" });
  if (selectedJob === id) {
    _closeJobModal();
  }
  refreshJobs();
  refreshStats();
}

// Pure stop — halt a running/queued job but KEEP it (record + ./work/). Unlike
// deleteJob (removes the job) and stop-&-resume (forks a fresh job), this just
// flips status to 'stopped'. Re-renders the detail so the operator sees the
// stopped pill and can then retry / run / delete at their leisure.
async function stopJob(id, btn) {
  if (!confirm(`Stop job ${id}?\nHalts the run but KEEPS the job and ./work/ artifacts (not deleted, not resumed).`)) return;
  const orig = btn ? btn.textContent : null;
  if (btn) { btn.disabled = true; btn.textContent = "■ stopping…"; }
  try {
    const res = await fetch(`${API}/jobs/${id}/stop`, { method: "POST" });
    if (!res.ok) {
      alert(`stop failed: ${res.status} ${await res.text()}`);
      if (btn) { btn.disabled = false; btn.textContent = orig; }
      return;
    }
    await refreshJobs();
    await selectJob(id);
    refreshStats();
  } catch (e) {
    alert(`stop error: ${e}`);
    if (btn) { btn.disabled = false; btn.textContent = orig; }
  }
}


// (Re)paint the "reviewer in progress" panel for `jobId` from its
// activeReviewers entry. Idempotent: creates the panel if absent, updates
// it in place otherwise (cheap on every streamed token). No-ops when this
// job's detail isn't the one on screen — the state persists in the map and
// is restored the next time renderJob() rebuilds the detail (selectJob →
// this is called just before renderJob returns). This is what makes the
// panel survive navigating away and back.
function renderReviewerPanel(jobId) {
  const detail = document.getElementById("job-detail");
  if (!detail) return;
  if (selectedJob !== jobId) return;
  const st = activeReviewers.get(jobId);
  let panel = document.getElementById("retry-panel-" + jobId);
  if (!st) { if (panel) panel.remove(); return; }

  if (!panel) {
    panel = document.createElement("div");
    panel.className = "retry-panel";
    panel.id = "retry-panel-" + jobId;
    panel.innerHTML =
      "<h4></h4>"
      + '<div class="stage"><span class="dot"></span><span class="stage-text"></span></div>'
      + '<pre class="hint-stream"></pre>';
    // Same insertion point streamRetry used: above the flag banner /
    // file-links / first heading in the detail.
    const refNode = detail.querySelector(".flag-banner")
      || detail.querySelector(".file-links")
      || detail.querySelector("h4");
    if (refNode && refNode.parentNode) refNode.parentNode.insertBefore(panel, refNode);
    else detail.appendChild(panel);
  }

  const label = st.flow === "resume" ? "Resume" : "Retry";
  const headerEl = panel.querySelector("h4");
  const stageEl = panel.querySelector(".stage-text");
  const streamEl = panel.querySelector(".hint-stream");
  const dot = panel.querySelector(".dot");

  panel.classList.toggle("retry-panel-error", st.status === "error");
  dot.classList.toggle("dot--error", st.status === "error");
  dot.classList.toggle("dot--done", st.status === "done");
  if (st.status === "error") {
    headerEl.textContent = `${st.flowEmoji} ${label} — error (no new job created)`;
  } else if (st.status === "done") {
    headerEl.textContent = `${st.flowEmoji} ${label} — ${st.isManual ? "your hint" : "reviewer"} submitted`;
  } else {
    headerEl.textContent = st.isManual
      ? `${st.flowEmoji} ${label} — your hint`
      : `${st.flowEmoji} ${label} — reviewer in progress`;
  }
  stageEl.textContent = st.stageText || "";

  const atBottom = streamEl.scrollTop + streamEl.clientHeight >= streamEl.scrollHeight - 8;
  const newText = (st.text != null && st.text !== "")
    ? st.text
    : (st.isManual ? "" : "(awaiting reviewer output…)");
  if (streamEl.textContent !== newText) streamEl.textContent = newText;
  if (atBottom) streamEl.scrollTop = streamEl.scrollHeight;

  // While the stream is live, keep every retry path disabled so a second
  // submit can't race it. A fresh renderJob() rebuilds the buttons enabled;
  // this re-disables them in the same tick. Terminal/absent entry leaves
  // them enabled.
  const running = st.status === "running";
  detail.querySelectorAll(
    ".retry-btn, .retry-manual-submit, .stop-resume-submit",
  ).forEach((b) => { b.disabled = running; });
}

async function streamRetry(jobId, btn, manualHint = null, opts = {}) {
  // Endpoint can be /retry/stream (default) or /resume/stream — same SSE
  // protocol either way, only the stage labels differ.
  const endpoint = opts.endpoint || `${API}/jobs/${jobId}/retry/stream`;
  const flow = opts.flow || "retry";   // "retry" | "resume"
  const flowVerb = flow === "resume" ? "resume" : "retry";
  const flowEmoji = flow === "resume" ? "✋" : "↻";
  const isManual = typeof manualHint === "string" && manualHint.length > 0;

  // Stop the regular polling so it doesn't fight our progress panel
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }

  // Tear down any in-flight inline form so it doesn't linger.
  const manualForm = document.getElementById("retry-manual-form-" + jobId);
  if (manualForm) manualForm.remove();
  const resumeForm = document.getElementById("stop-resume-form-" + jobId);
  if (resumeForm) resumeForm.remove();

  // Seed the PERSISTENT state + paint. From here the panel is rebuilt from
  // activeReviewers by renderReviewerPanel(), so navigating away and back
  // restores it instead of losing the "reviewer in progress" UI.
  activeReviewers.set(jobId, {
    flow, flowEmoji, flowVerb, isManual,
    stageText: isManual ? "submitting…" : "starting…",
    text: isManual ? manualHint : "",
    firstToken: !isManual,
    status: "running",
  });
  const origText = btn.textContent;
  btn.textContent = `⏳ ${flowVerb}…`;
  renderReviewerPanel(jobId);

  const setError = (kind, message) => {
    const st = activeReviewers.get(jobId);
    if (!st) return;
    st.status = "error";
    st.kind = kind;
    const kindLabel = ({
      api_error: "API error",
      auth: "auth error",
      rate_limit: "rate limit",
      policy_refusal: "usage-policy refusal",
      timeout: "timeout",
      empty: "empty response",
      no_context: "no prior context",
      gather: "context gather failed",
      halt: "stop failed",
      submit: "submit rejected",
      stream_closed: "stream closed",
      unknown: "unknown error",
    })[kind] || kind;
    st.stageText = `${kindLabel} — ${flowVerb} aborted`;
    const em = (message || "unknown error").trim();
    // Keep any partial reviewer text as forensic context above the error.
    st.text = st.firstToken ? em : `${st.text}\n\n--- ${kindLabel} ---\n${em}`;
    st.firstToken = false;
    renderReviewerPanel(jobId);
  };

  // EventSource only supports GET. Use fetch + ReadableStream to POST + stream.
  // Body fields are all optional from the server's POV: hint (manual mode
  // only) and target (always optional, blank = keep prior target).
  const targetOverride = (typeof opts.target === "string" && opts.target.trim())
    ? opts.target.trim() : null;
  const body = {};
  if (isManual) body.hint = manualHint;
  if (targetOverride) body.target = targetOverride;
  // fresh = start the retry WITHOUT forking the prior SDK conversation
  // (carried files + hint only). Defends against retry-fork-chain context
  // overflow ("Prompt is too long") on deep chains. Operator-selected.
  if (opts.fresh) body.fresh = true;
  const fetchOpts = { method: "POST" };
  if (Object.keys(body).length) {
    fetchOpts.headers = { "Content-Type": "application/json" };
    fetchOpts.body = JSON.stringify(body);
  }

  let resp;
  try {
    resp = await fetch(endpoint, fetchOpts);
  } catch (e) {
    setError("error", String(e));
    btn.textContent = origText;
    return;
  }
  if (!resp.ok) {
    const errBody = await resp.text().catch(() => "");
    setError("error", `${resp.status}: ${errBody}`);
    btn.textContent = origText;
    return;
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buf = "";

  function handleEvent(name, dataStr) {
    let data = {};
    try { data = JSON.parse(dataStr); } catch (_) {}
    const st = activeReviewers.get(jobId);
    if (!st) return;  // entry cleared (e.g. a newer retry replaced it)
    if (name === "stage") {
      const s = data.name;
      // The backend sends the resolved reviewer model (resolve_reviewer_model:
      // per-job meta.model → global claude_model → opus-4-7) so this shows the
      // ACTUAL model, not a hardcoded label.
      const reviewerModel = data.model || "reviewer";
      st.stageText = ({
        halting: "halting current job…",
        gathering: "gathering prior job context…",
        asking: `asking reviewer (${reviewerModel})…`,
        submitting: isManual
          ? (flow === "resume"
              ? "enqueueing fresh job (carrying ./work/) with your hint…"
              : "enqueueing new job with your hint…")
          : (flow === "resume"
              ? "enqueueing fresh job (carrying ./work/)…"
              : "enqueueing new job…"),
      })[s] || s;
      renderReviewerPanel(jobId);
    } else if (name === "token") {
      if (st.firstToken) { st.text = ""; st.firstToken = false; }
      st.text += data.delta || "";
      renderReviewerPanel(jobId);
    } else if (name === "done") {
      st.status = "done";
      st.newJobId = data.new_job_id;
      st.stageText = `submitted new job ${data.new_job_id}`;
      btn.textContent = origText;
      renderReviewerPanel(jobId);
      const newId = data.new_job_id;
      // Switch to the new job after a beat so user can read the hint — but
      // only if they're still on the job they launched the retry from; don't
      // yank them out of a different job they navigated to meanwhile.
      setTimeout(async () => {
        activeReviewers.delete(jobId);
        await refreshJobs();
        if (selectedJob === jobId && newId) await selectJob(newId);
        else renderReviewerPanel(jobId);  // clears the now-deleted panel
      }, 800);
    } else if (name === "error") {
      setError(data.kind || "error", data.message);
      btn.textContent = origText;
    }
  }

  // Converge EVERY loop-exit path to a terminal state. A stream that dies
  // WITHOUT delivering a done/error frame (api redeploy mid-stream, dropped
  // connection — the 73d78c failure) would otherwise leave a "running"
  // entry that the map now PERSISTS as a perpetual spinner on every
  // re-entry — strictly worse than the original disappearing-panel bug.
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      // SSE frames are separated by blank lines
      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        let evName = "message";
        let dataLines = [];
        for (const line of frame.split("\n")) {
          if (line.startsWith("event: ")) evName = line.slice(7).trim();
          else if (line.startsWith("data: ")) dataLines.push(line.slice(6));
        }
        if (dataLines.length) handleEvent(evName, dataLines.join("\n"));
      }
    }
  } catch (_) {
    // network / stream error — fall through to the terminal-state check.
  }
  // Stream closed with no done/error event → mark it terminal so it can't
  // re-render as an eternal spinner.
  const tail = activeReviewers.get(jobId);
  if (tail && tail.status === "running") {
    setError("stream_closed", "stream ended without completion");
    btn.textContent = origText;
  }
}

function openStopResumeForm(jobId, anchorBtn) {
  // If a form is already open for this job, just refocus it.
  const existing = document.getElementById("stop-resume-form-" + jobId);
  if (existing) {
    existing.querySelector("textarea")?.focus();
    return;
  }
  const form = document.createElement("div");
  form.className = "retry-manual-form stop-resume-form";
  form.id = "stop-resume-form-" + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Extra hint to add before resuming</label>
    <textarea rows="5" placeholder="What should the next attempt do differently? e.g. 'the leaked endpoint is /api/v2/profile, not /profile' — appended to the new job's description as [retry-hint]"></textarea>
    <label class="retry-manual-label" style="margin-top:0.4rem">Target (override; blank = keep prior, "(none)" = clear · <b>+ add target</b> for several)</label>
    ${targetListHtml("e.g. http://newhost:8080  ·  ctf.example.com:31337")}
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit stop-resume-submit">✋ Stop &amp; resume</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Halts this job, then enqueues a fresh one with the same files + hint appended</small>
    </div>
  `;
  const buttonRow = anchorBtn.parentElement;
  buttonRow.insertAdjacentElement("afterend", form);

  const ta = form.querySelector("textarea");
  const submit = form.querySelector(".stop-resume-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  ta.focus();

  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", async () => {
    const hint = ta.value.trim();
    if (!hint) {
      ta.focus();
      ta.classList.add("invalid");
      setTimeout(() => ta.classList.remove("invalid"), 600);
      return;
    }
    submit.disabled = true;
    cancel.disabled = true;
    const orig = submit.textContent;
    submit.textContent = "⏳ stopping & resuming…";
    // Stop polling so it doesn't fight the upcoming selectJob call.
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    try {
      const reqBody = { hint };
      const t = gatherTargets(form);
      if (t) reqBody.target = t;
      const freshCb = document.getElementById(`fresh-ctx-${jobId}`);
      if (freshCb && freshCb.checked) reqBody.fresh = true;
      const res = await fetch(`${API}/jobs/${jobId}/resume`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqBody),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail || body);
        alert(`stop-and-resume failed: ${res.status} ${detail}`);
        submit.disabled = false; cancel.disabled = false;
        submit.textContent = orig;
        return;
      }
      form.remove();
      await refreshJobs();
      await selectJob(body.new_job_id);
    } catch (e) {
      alert(`stop-and-resume error: ${e}`);
      submit.disabled = false; cancel.disabled = false;
      submit.textContent = orig;
    }
  });
  for (const el of [ta]) {
    el.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        submit.click();
      } else if (e.key === "Escape") {
        e.preventDefault();
        form.remove();
      }
    });
  }
}

function openManualHintForm(jobId, anchorBtn) {
  // If a form is already open for this job, just refocus it.
  const existing = document.getElementById("retry-manual-form-" + jobId);
  if (existing) {
    existing.querySelector("textarea")?.focus();
    return;
  }
  const form = document.createElement("div");
  form.className = "retry-manual-form";
  form.id = "retry-manual-form-" + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Your hint for the next agent</label>
    <textarea rows="5" placeholder="e.g. The bot visits /report?id= and the cookie is on .site.com — exfiltrate via document.cookie to \$COLLECTOR_URL. Or: the heap leak comes from the formatted error on /api/echo, not /api/profile."></textarea>
    <label class="retry-manual-label" style="margin-top:0.4rem">Target (override; blank = keep prior, "(none)" = clear · <b>+ add target</b> for several)</label>
    ${targetListHtml("e.g. http://newhost:8080  ·  ctf.example.com:31337")}
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit">Submit hint &amp; retry</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Skips reviewer · appended to new job's description as <code>[retry-hint]</code></small>
    </div>
  `;
  // Place the form right after the button row.
  const buttonRow = anchorBtn.parentElement;
  buttonRow.insertAdjacentElement("afterend", form);

  const ta = form.querySelector("textarea");
  const submit = form.querySelector(".retry-manual-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  ta.focus();

  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", () => {
    const hint = ta.value.trim();
    if (!hint) {
      ta.focus();
      ta.classList.add("invalid");
      setTimeout(() => ta.classList.remove("invalid"), 600);
      return;
    }
    const freshCb = document.getElementById(`fresh-ctx-${jobId}`);
    streamRetry(jobId, submit, hint, {
      target: gatherTargets(form),
      fresh: !!(freshCb && freshCb.checked),
    });
  });
  // Ctrl/Cmd+Enter shortcut
  for (const el of [ta]) {
    el.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        submit.click();
      } else if (e.key === "Escape") {
        e.preventDefault();
        form.remove();
      }
    });
  }
}

// Continue-in-place form: an operator note (folded into the SAME job's
// session as priority guidance) + optional new target (a restarted DreamHack
// instance often comes back on a new port). NOT a retry — same job/cwd/session.
function openContinueForm(jobId, anchorBtn) {
  const existing = document.getElementById("continue-form-" + jobId);
  if (existing) { existing.querySelector("textarea")?.focus(); return; }
  const form = document.createElement("div");
  form.className = "retry-manual-form continue-form";
  form.id = "continue-form-" + jobId;
  form.innerHTML = `
    <label class="retry-manual-label">Operator note (the agent CONTINUES the same session — no re-investigation)</label>
    <textarea rows="4" placeholder="e.g. I restarted the instance — the registration slot is fresh now. Run your existing exploit (BASE72 long-pw oracle) in one shot; don't probe."></textarea>
    <label class="retry-manual-label" style="margin-top:0.4rem">New target (blank = keep prior; a restarted instance usually has a new port · <b>+ add target</b> for several)</label>
    ${targetListHtml("e.g. http://host8.dreamhack.games:NEWPORT")}
    <div class="retry-manual-row">
      <button type="button" class="retry-manual-submit continue-submit">💬 Continue with note</button>
      <button type="button" class="retry-manual-cancel">Cancel</button>
      <small>Same job · resumes the session · note added as <code>[retry-hint]</code></small>
    </div>
  `;
  anchorBtn.parentElement.insertAdjacentElement("afterend", form);
  const ta = form.querySelector("textarea");
  const submit = form.querySelector(".continue-submit");
  const cancel = form.querySelector(".retry-manual-cancel");
  ta.focus();
  cancel.addEventListener("click", () => form.remove());
  submit.addEventListener("click", async () => {
    const comment = ta.value.trim();
    if (!comment) {
      ta.focus(); ta.classList.add("invalid");
      setTimeout(() => ta.classList.remove("invalid"), 600);
      return;
    }
    submit.disabled = true;
    submit.textContent = "Continuing…";
    try {
      const body = { comment };
      const _tg = gatherTargets(form);
      if (_tg) body.target = _tg;
      const res = await fetch(`${API}/jobs/${jobId}/continue`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) { alert(`continue error: ${res.status} ${await res.text()}`); submit.disabled = false; submit.textContent = "💬 Continue with note"; return; }
      form.remove();
      await refreshJobs();
      selectJob(jobId);
    } catch (e) {
      alert(`continue failed: ${e}`);
      submit.disabled = false; submit.textContent = "💬 Continue with note";
    }
  });
  for (const el of [ta]) {
    el.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); submit.click(); }
      else if (e.key === "Escape") { e.preventDefault(); form.remove(); }
    });
  }
}

// Short two-note chirp via WebAudio (no asset). Autoplay policy may
// suspend the context until the first user gesture — the visual toast
// always shows regardless; the beep just catches up once the page has
// been interacted with.
let _flagBeepAt = 0;             // last beep, for the burst throttle below

function _flagBeep() {
  // One pass can now legitimately raise several toasts (that is the fix —
  // every fresh value alarms, not just the last). Without this guard those
  // would start N overlapping oscillators in the same audio frame and stack
  // into one loud blast. The toasts are all still shown; only the sound is
  // coalesced.
  const now = Date.now();
  if (now - _flagBeepAt < 1200) return;
  _flagBeepAt = now;
  try {
    _flagAudioCtx = _flagAudioCtx ||
      new (window.AudioContext || window.webkitAudioContext)();
    const ctx = _flagAudioCtx;
    if (ctx.state === "suspended") ctx.resume();
    const t = ctx.currentTime;
    [0, 0.18].forEach((dt, i) => {
      const o = ctx.createOscillator();
      const g = ctx.createGain();
      o.type = "sine";
      o.frequency.value = i === 0 ? 880 : 1320;
      g.gain.setValueAtTime(0.0001, t + dt);
      g.gain.exponentialRampToValueAtTime(0.25, t + dt + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t + dt + 0.15);
      o.connect(g);
      g.connect(ctx.destination);
      o.start(t + dt);
      o.stop(t + dt + 0.16);
    });
  } catch (_) { /* no WebAudio / autoplay-blocked — visual toast still shows */ }
}

function _flagToastContainer() {
  let c = document.getElementById("flag-toast-container");
  if (!c) {
    c = document.createElement("div");
    c.id = "flag-toast-container";
    document.body.appendChild(c);
  }
  return c;
}

// kind: "flag" (promoted 🚩) | "cand" ([FLAG?] candidate)
function _showFlagToast(kind, job, text) {
  const c = _flagToastContainer();
  const el = document.createElement("div");
  el.className = "flag-toast " + kind;
  const isFlag = kind === "flag";
  const icon = isFlag ? "🚩" : "🏁";
  const title = isFlag ? "FLAG FOUND" : "[FLAG?] candidate";
  const mod = escapeHtml(job.module || "job");
  const sid = escapeHtml(String(job.id || "").slice(0, 12));
  el.innerHTML =
    `<button class="flag-toast-x" title="dismiss">×</button>` +
    `<div class="flag-toast-h">${icon} <strong>${title}</strong></div>` +
    `<div class="flag-toast-sub">${mod} · <span class="flag-toast-id">${sid}</span></div>` +
    (text ? `<div class="flag-toast-body"><code>${escapeHtml(text)}</code></div>` : "");
  el.addEventListener("click", (e) => {
    if (e.target.closest(".flag-toast-x")) return;
    selectJob(job.id);
    el.remove();
  });
  el.querySelector(".flag-toast-x").addEventListener("click", (e) => {
    e.stopPropagation();
    el.remove();
  });
  c.appendChild(el);
  // STICKY: both FLAG FOUND and [FLAG?] candidate toasts persist until the
  // operator acknowledges them — clicking the toast (opens the job) or the ×
  // removes it. No auto-fade: a flag / candidate must never silently vanish
  // before it has been seen (operator request 2026-06-17). Pile-up is bounded
  // by per-candidate dedup in _detectFlagTransitions + the container's
  // max-height scroll (style.css).
  _flagBeep();
  // OS-level notification too — but only if already granted; never auto-prompt.
  // Clicking it focuses the tab AND opens the job, same as the in-page toast.
  try {
    if (window.Notification && Notification.permission === "granted") {
      const n = new Notification(`${icon} ${title} — ${mod}`,
        // requireInteraction keeps the OS notification on screen until the
        // operator dismisses/clicks it (supported browsers) — mirrors the
        // sticky in-page toast so a flag isn't lost to an auto-timeout.
        { body: text || sid, tag: "flag-" + job.id, requireInteraction: true });
      n.onclick = () => {
        try { window.focus(); } catch (_) {}
        selectJob(job.id);
        n.close();
      };
    }
  } catch (_) {}
}

function _detectFlagTransitions(jobs) {
  for (const job of jobs || []) {
    if (!job || !job.id) continue;
    let seen = _flagSeen[job.id];
    if (!seen) {
      seen = { flags: new Set(), cands: new Set() };
      _flagSeen[job.id] = seen;
    }
    const flags = job.flags || [];
    // Candidates already promoted to real flags are not candidates any more —
    // same rule the [FLAG?] box uses, so the alarm and the box agree.
    const cands = (job.flag_candidates || []).filter((x) => !flags.includes(x));
    // Tracked per KIND, so a value that was alarmed as a candidate alarms once
    // more when it is promoted to a flag. Promotion is news; a re-poll is not.
    const freshFlags = flags.filter((v) => v && !seen.flags.has(v));
    const freshCands = cands.filter((v) => v && !seen.cands.has(v));
    if (_flagAlarmReady) {
      for (const v of freshFlags) _showFlagToast("flag", job, v);
      for (const v of freshCands) _showFlagToast("cand", job, v);
    }
    for (const v of freshFlags) seen.flags.add(v);
    for (const v of freshCands) seen.cands.add(v);
  }
  _flagAlarmReady = true;   // baseline seeded after the first pass
}

async function refreshJobs() {
  const res = await fetch(`${API}/jobs`);
  const data = await res.json();
  _detectFlagTransitions(data.jobs);
  const ul = document.getElementById("jobs-list");
  ul.innerHTML = "";
  for (const job of data.jobs) {
    const li = document.createElement("li");
    li.dataset.id = job.id;
    const cost = job.cost_usd ? `· $${Number(job.cost_usd).toFixed(3)}` : "";
    // HOW the flag was obtained, not just that there is one. `marker` means the
    // solver printed `FLAG_CANDIDATE: <flag>` — it declared that exact string as
    // its capture. `runner_regex` means only that a flag-SHAPED string appeared
    // somewhere in the runner's output; nobody declared anything. Job
    // 0c04e636633c shipped its solver's own diagnostic banner that way, and this
    // pill was indistinguishable from a real capture. Promotes and drops
    // nothing — curation stays MANUAL; it just stops the two looking alike.
    // `flag_sweep_suppressed` OVERRIDES the tier note and must be checked
    // first. When the runner printed a flag-shaped string and the same output
    // then declared failure, the scanner drops it and the NARRATIVE tier can
    // re-find the string in report.md — leaving provenance honestly
    // "narrative", whose note claims the runner's output does not contain it.
    // It does. Two different facts; show the one that is not misleading.
    const provNote = job.flag_sweep_suppressed
      ? "\n\n⚑ The runner's own output DID contain this string — and the same output declares it found nothing. Dropped from the trusted tier; whatever promoted this flag was something else."
      : ({
          runner_regex: "\n\n⚑ SWEPT, not declared — the solver printed no `FLAG_CANDIDATE:` marker, so nothing asserts this IS the flag; only that it is flag-shaped.",
          narrative: "\n\n⚑ From the agent's report.md / findings.json only — the runner's own stdout/stderr does not contain it.",
        }[job.flag_provenance] || "");
    const flagPill = (job.flags && job.flags.length)
      ? `<span class="flag-pill" title="${escapeHtml(job.flags.join('\n') + provNote)}">🚩 ${job.flags.length}${provNote ? "⚑" : ""}</span>` : "";
    // Unreproduced candidate badge. A job can end no_flag while the REAL flag is
    // already in flag_candidates: only a TRUSTED source (runner stdout / OOB
    // collector) promotes a flag, so a sandbox run that died for an ENVIRONMENT
    // reason leaves a genuine capture stranded (job e1b933afc137 — confirmed-
    // correct flag, status no_flag). Shown ONLY when flags is empty: `finished`
    // jobs routinely carry decoy candidates too (DH{**fake_flag**},
    // DH{32alphanumeric}), so badging them would be pure noise. This promotes
    // nothing — curation stays MANUAL — it just makes the candidate visible.
    const candPill = (!(job.flags && job.flags.length) && job.flag_candidates && job.flag_candidates.length)
      ? `<span class="flag-pill" style="background:var(--yellow-solid);color:var(--yellow-soft)"
           title="${escapeHtml(job.flag_candidates.join('\n'))}\n\nUNVERIFIED — the sandbox never reproduced these. Confirm against the challenge, then pin in the UI.">⚑ ${job.flag_candidates.length}</span>`
      : "";
    li.innerHTML = `<strong>${job.module}</strong> · ${escapeHtml(job.filename || "")}
      <span class="status ${job.status}">${job.status}</span>${flagPill}${candPill}
      <button class="delete-btn">×</button>
      <div style="font-size:0.75rem;color:var(--fg-muted);"><span class="jobid-text">${job.id}</span><button class="copy-jobid-btn" data-jobid="${job.id}" title="Copy job ID">⧉</button> ${cost}</div>`;
    li.addEventListener("click", () => selectJob(job.id));
    li.querySelector(".delete-btn").addEventListener("click", (e) => deleteJob(job.id, e));
    li.querySelector(".copy-jobid-btn").addEventListener("click", (e) => copyJobId(job.id, e));
    if (job.id === selectedJob) li.classList.add("selected");
    ul.appendChild(li);
  }
}

async function selectJob(id) {
  selectedJob = id;
  document.querySelectorAll("#jobs-list li").forEach((li) => {
    li.classList.toggle("selected", li.dataset.id === id);
  });
  _openJobModal(id);
  await renderJob(id, { force: true });
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    const job = await renderJob(id);
    if (job && ["finished", "failed", "no_flag"].includes(job.status)) {
      clearInterval(pollTimer);
      pollTimer = null;
      await refreshJobs();
      await refreshStats();
    }
  }, 2000);
  // Live SSE feed on top of the poller. backfill_done widens the
  // poller's interval; onerror lets it fall back to fast-polling.
  _openLiveStream(id);
}

function _openJobModal(id) {
  const m = document.getElementById("job-modal");
  if (!m) return;
  const title = m.querySelector(".job-modal-title");
  if (title) title.textContent = `Job ${id}`;
  m.hidden = false;
  // Lock background scroll while the modal is open.
  document.body.classList.add("modal-open");
}

function _closeJobModal() {
  const m = document.getElementById("job-modal");
  if (m) m.hidden = true;
  document.body.classList.remove("modal-open");
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  _closeLiveStream();
  selectedJob = null;
  document.querySelectorAll("#jobs-list li").forEach((li) =>
    li.classList.remove("selected"),
  );
  // Wipe the detail body so a stale render doesn't flash on the next open.
  const detail = document.getElementById("job-detail");
  if (detail) detail.innerHTML = "";
}

async function renderJob(id, opts = {}) {
  const detail = document.getElementById("job-detail");
  // If the user is actively typing in an inline form (manual retry hint
  // or stop-and-resume hint), the 2-second polling re-render would blow
  // it away mid-keystroke. Skip this poll cycle. selectJob() passes
  // {force:true} so explicit job switches still re-render.
  if (
    !opts.force
    && detail.querySelector(".retry-manual-form, .stop-resume-form")
  ) {
    return null;
  }
  // While a reviewer/retry stream is live for THIS job, skip the 2s poll
  // re-render — it would tear down and rebuild the retry-panel every cycle
  // (flicker) and fight the live token updates written by streamRetry.
  // selectJob() passes {force:true}, so explicit (re-)entry still rebuilds
  // the detail and restores the panel via renderReviewerPanel() below.
  if (!opts.force && activeReviewers.get(id)?.status === "running") {
    return null;
  }
  // Same idea for an active selection inside the run log: the polling
  // re-render replaces the text nodes and collapses the user's
  // selection, which makes copying live logs miserable. Skip the
  // cycle whenever the user has any selection inside the run log.
  if (!opts.force) {
    try {
      const sel = window.getSelection();
      if (sel && !sel.isCollapsed) {
        const anchor = sel.anchorNode;
        const focus = sel.focusNode;
        const inRunLog = (n) =>
          !!n && !!(n.nodeType === 1 ? n : n.parentElement)?.closest?.(".run-log");
        if (inRunLog(anchor) || inRunLog(focus)) {
          return null;
        }
      }
      // Don't yank the run-log search box out from under the user mid-type.
      const ae = document.activeElement;
      if (ae && ae.classList && ae.classList.contains("run-log-search")) {
        return null;
      }
    } catch (_) {}
  }
  const res = await fetch(`${API}/jobs/${id}`);
  if (!res.ok) {
    detail.textContent = "job not found";
    return null;
  }
  const job = await res.json();

  // Cap the polling fetch at 256 KB so verbose Claude output (after a
  // big Read or Bash dump) doesn't make every 2s poll re-ship megabytes.
  const logRes = await fetch(`${API}/jobs/${id}/log?tail=262144`);
  const log = await logRes.text();

  // Curated MONITOR feed (LLM-narrated signal commentary). Fetched every
  // render so it stays authoritative; live SSE `monitor` events fill the gap
  // between polls. Hitting this endpoint also ensures the job's monitor task
  // is running api-side. Language variants live in each entry — switching
  // language re-renders from the same data, no refetch.
  let monitorEntries = [];
  try {
    const mr = await fetch(`${API}/jobs/${id}/monitor?tail=400`);
    if (mr.ok) monitorEntries = (await mr.json()).entries || [];
  } catch (_) {}
  const monitorFeedHTML = renderMonitorEntries(monitorEntries, monitorLang);
  const prevMonFeed = detail.querySelector(".monitor-feed");
  const prevMonAtBottom = prevMonFeed
    ? (prevMonFeed.scrollTop + prevMonFeed.clientHeight >= prevMonFeed.scrollHeight - 12)
    : true;
  const prevMonScrollTop = prevMonFeed ? prevMonFeed.scrollTop : 0;

  // Preserve log scroll position across re-renders. If the user was already
  // at (or near) the bottom, snap to bottom after re-render so new entries
  // are visible (tail behavior). Otherwise keep their scroll position.
  const prevPre = detail.querySelector("pre.run-log");
  const prevAtBottom = prevPre
    ? (prevPre.scrollTop + prevPre.clientHeight >= prevPre.scrollHeight - 12)
    : true;
  const prevScrollTop = prevPre ? prevPre.scrollTop : 0;
  const isSameJob = prevPre && prevPre.dataset.jobId === id;
  // Same idea for the OUTER modal-body scroll: detail.innerHTML = ... resets
  // scrollTop to 0, so anywhere the user scrolled to read the description /
  // retry-hint chip / result links gets snapped back to the top on every
  // 2-second poll. Capture it now and restore after the replace, but only
  // if we're still on the same job (a fresh job starts at the top).
  const prevModalScrollTop = detail.scrollTop;

  // Preserve the live SDK panel state too. Without this, every poll
  // re-render rebuilds .sdk-live with its `hidden` attribute set, and
  // the panel only re-appears on the next SDK event — i.e. it
  // "flickers in and out" every poll cycle.
  const prevSdkPanel = detail.querySelector(".sdk-live");
  const prevSdkFeedHTML = (prevSdkPanel && isSameJob)
    ? prevSdkPanel.querySelector(".sdk-live-feed")?.innerHTML || null
    : null;
  const prevSdkFeedScroll = (prevSdkPanel && isSameJob)
    ? (prevSdkPanel.querySelector(".sdk-live-feed")?.scrollTop ?? 0)
    : 0;
  const prevSdkFeedAtBottom = (() => {
    if (!prevSdkPanel || !isSameJob) return true;
    const f = prevSdkPanel.querySelector(".sdk-live-feed");
    if (!f) return true;
    return f.scrollTop + f.clientHeight >= f.scrollHeight - 8;
  })();
  const prevSdkVisible = !!(prevSdkPanel && isSameJob && !prevSdkPanel.hidden);
  const prevSdkCollapsed = !!(prevSdkPanel && prevSdkPanel.classList.contains("collapsed"));

  // File-link helper. Left-click opens the syntax-highlighting preview
  // modal; middle-click / Ctrl+click / right-click "Open in new tab" still
  // gets the raw response since the underlying href is the API URL.
  const fileLink = (label, url, name) =>
    `<a href="${url}" target="_blank" class="file-preview-link"
        data-url="${url}" data-name="${escapeHtml(name)}">${escapeHtml(label)}</a>`;

  let resultBlock = "";
  if (["finished", "running", "no_flag"].includes(job.status)) {
    const links = [
      fileLink("result.json", `${API}/jobs/${id}/result`, "result.json"),
      fileLink("report.md", `${API}/jobs/${id}/file/report.md`, "report.md"),
    ];
    // WHY_STOPPED.md only exists on abnormal stops — gate on the API's
    // presence flag so a clean flag-capture run doesn't show a dead link.
    if (job.has_why_stopped) {
      links.push(fileLink("WHY_STOPPED.md", `${API}/jobs/${id}/file/WHY_STOPPED.md`, "WHY_STOPPED.md"));
    }
    if (job.module === "web" || job.module === "pwn") {
      links.push(fileLink("exploit.py", `${API}/jobs/${id}/file/exploit.py`, "exploit.py"));
      links.push(fileLink("stdout", `${API}/jobs/${id}/file/exploit.py.stdout`, "exploit.py.stdout"));
      links.push(fileLink("stderr", `${API}/jobs/${id}/file/exploit.py.stderr`, "exploit.py.stderr"));
    }
    if (job.module === "crypto" || job.module === "rev") {
      links.push(fileLink("solver.py", `${API}/jobs/${id}/file/solver.py`, "solver.py"));
      links.push(fileLink("stdout", `${API}/jobs/${id}/file/solver.py.stdout`, "solver.py.stdout"));
      links.push(fileLink("stderr", `${API}/jobs/${id}/file/solver.py.stderr`, "solver.py.stderr"));
    }
    if (job.module === "forensic") {
      links.push(fileLink("summary.json", `${API}/jobs/${id}/file/summary.json`, "summary.json"));
      links.push(fileLink("log_findings.json", `${API}/jobs/${id}/file/log_findings.json`, "log_findings.json"));
      links.push(fileLink("collector.log", `${API}/jobs/${id}/file/collector.log`, "collector.log"));
    }
    if (job.module === "misc") {
      links.push(fileLink("findings.json", `${API}/jobs/${id}/file/findings.json`, "findings.json"));
      links.push(fileLink("analyze.log", `${API}/jobs/${id}/file/analyze.log`, "analyze.log"));
    }
    links.push(`<a href="/terminal?job_id=${encodeURIComponent(id)}" target="_blank">⌨ open terminal</a>`);
    resultBlock = `<div class="file-links">${links.join(" ")}</div>`;
  }

  const cost = job.cost_usd ? ` · cost: $${Number(job.cost_usd).toFixed(4)}` : "";
  const stage = job.stage ? ` · stage: ${job.stage}` : "";
  const timeout = job.job_timeout ? ` · timeout: ${job.job_timeout}s` : "";
  const providerInfo = job.agent_provider
    ? ` · agent: ${escapeHtml(job.agent_provider_label || job.agent_provider)}`
    : "";
  const modelInfo = job.model ? ` · model: ${escapeHtml(job.model)}` : "";

  // Elapsed (running) / duration (terminal). Now rendered as a
  // standalone badge next to the status pill so it doesn't get
  // buried at the end of the small meta line. The running variant
  // is also driven by a tiny per-second interval (see further down)
  // independent of the 2-second poll re-render.
  let timingPill = "";
  if (job.started_at) {
    const start = new Date(job.started_at).getTime();
    const end = job.finished_at ? new Date(job.finished_at).getTime() : Date.now();
    const sec = Math.max(0, Math.round((end - start) / 1000));
    const fmt = (s) => {
      if (s < 60) return `${s}s`;
      if (s < 3600) return `${Math.floor(s/60)}m ${s%60}s`;
      const h = Math.floor(s/3600); const m = Math.floor((s%3600)/60);
      return `${h}h ${m}m`;
    };
    if (job.finished_at) {
      timingPill = `<span class="timing-pill done" title="started ${escapeHtml(job.started_at)}\nfinished ${escapeHtml(job.finished_at)}">⏱ ${fmt(sec)}</span>`;
    } else if (job.status === "running") {
      timingPill = `<span class="timing-pill live" data-started-at="${escapeHtml(job.started_at)}" title="started ${escapeHtml(job.started_at)}">⏱ ${fmt(sec)} <span class="timing-tag">running</span></span>`;
    } else if (job.status === "queued") {
      timingPill = `<span class="timing-pill queued">⏱ queued</span>`;
    }
  }

  // A liveness chip used to live here (active / silent / warming / dead) and
  // was REMOVED, not moved. Measured on job e601cd358ad6 — 3303 agent events
  // over 5.7 h — the agent's emission gaps have a median of 0 s but a p99 of
  // 121 s and a max of 16 min, and eighteen silences over five minutes account
  // for 52% of the run. Time-weighted, a perfectly healthy job showed amber
  // "silent" 75.3% of the time and green "active" only 24.7%. A warning colour
  // that is the normal state for three quarters of a run is not a signal, and
  // no single threshold can separate "thinking" from "stuck" on a distribution
  // that skewed.
  //
  // The one genuinely actionable state, "dead", was also the least trustworthy:
  // it keyed on `rq:worker:<name>`, which answers "is the process called
  // htct-sN-w0 alive?" — a name permanently bound to a slot and reused by every
  // job that runs there — not "is THIS job alive?". After a work horse is
  // SIGKILLed without writing a terminal status, the slot's container returns
  // under the same name and heartbeats every 30 s, so the chip would show
  // silent/warming forever and never dead.
  //
  // Whether a job is still going is answered by the run log and the monitor
  // feed, both of which are already on screen.

  // What DOES belong here is the underlying fact, stated without a verdict.
  // The chip above failed because it CLASSIFIED — it painted a warning colour
  // on a distribution whose normal state is silence. Age alone classifies
  // nothing, and the operator reads liveness from the one event the chip could
  // never show: the counter RESETTING to 0s. A number that snaps back is proof
  // the stream is alive; a number that keeps climbing is the raw fact, not an
  // accusation. So: no colour, no threshold, no label — deliberately.
  //
  // Measured on THIS UI's own data, job 729c62380722 while healthy: an 8m05s
  // gap between agent events (09:33:26 → 09:41:31) with run.log silent the
  // whole time. Gaps that long are ordinary — heap/crypto synthesis runs 15-40
  // min silent (memory opus-long-think-not-wedged). The tooltip says so,
  // because a bare "8m" invites exactly the panic the old chip trained.
  //
  // NO FALLBACK when the field is absent. During the pre-agent `analyze` phase
  // nothing writes it, and every chain that substituted started_at / updated_at
  // ended up measuring "time since the job started" — which crosses any
  // threshold on literally every job. That is the bug that put Stop AND Retry
  // on screen at once (43d896f). Absent means render nothing.
  let agentPill = "";
  if (job.status === "running" && job.last_agent_event_at) {
    const agentSec = Math.max(0, Math.round(
      (Date.now() - new Date(job.last_agent_event_at).getTime()) / 1000));
    agentPill = `<span class="agent-pill" data-agent-at="${escapeHtml(job.last_agent_event_at)}"
      title="${escapeHtml(
        "Time since the agent's last SDK event (meta.last_agent_event_at, "
        + "written on every message with a 5s throttle).\n\n"
        + "Watch it RESET — that is the liveness signal. A climbing number is "
        + "not a fault: a healthy run is silent for minutes at a time while the "
        + "model thinks, and 15-40 min is normal for heap/crypto synthesis.\n\n"
        + "Covers every SDK loop, not just main: pre-recon, delegated "
        + "subagents and the report phase all report here.\n\n"
        + "last event: " + (job.last_event_actor || "main") + " · "
        + (job.last_event_kind || "?") + " at " + job.last_agent_event_at)}"
      >⚡ ${_fmtAgentAge(agentSec)}</span>`;
  }

  // Live token meter — reflects meta.agent_tokens (Anthropic usage,
  // SUMMED across turns; cache_read is per-call too so we sum it as
  // well). Hidden until at least one token has been observed.
  let tokensPill = "";
  const tk = job.agent_tokens || {};
  const ti = +tk.input_tokens || 0;
  const to = +tk.output_tokens || 0;
  const tcc = +tk.cache_creation_input_tokens || 0;
  const tcr = +tk.cache_read_input_tokens || 0;
  const turns = +job.agent_turns || 0;
  const tTotal = ti + to + tcc + tcr;
  if (tTotal > 0) {
    const fmtN = (n) => {
      if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + "M";
      if (n >= 1_000)     return (n / 1_000).toFixed(1) + "k";
      return String(n);
    };
    const cost = typeof job.cost_usd === "number"
      ? ` · $${job.cost_usd.toFixed(4)}` : "";
    const turnTag = turns > 0 ? ` · ${turns}t` : "";
    const fullTitle =
      `summed across ${turns} turns:\n` +
      `  input (fresh):  ${ti.toLocaleString()}\n` +
      `  output:         ${to.toLocaleString()}\n` +
      `  cache create:   ${tcc.toLocaleString()}\n` +
      `  cache read:     ${tcr.toLocaleString()}` +
      (typeof job.cost_usd === "number" ? `\n  cost:           $${job.cost_usd.toFixed(6)}` : "");
    // Δ since previous poll — gives the run-log footer a live
    // "↓ X tokens" counter like Claude Code's status line. Cache
    // bumps usually dwarf output (per-turn input is mostly cached
    // prompt + tool results), so we surface both arrows separately.
    let deltaTag = "";
    if (job.status === "running") {
      const prev = _prevTokens[id];
      const turnsRegressed = prev && prev.turns != null && turns < prev.turns;
      if (prev && !turnsRegressed) {
        const dCache = tcr - (prev.cache_read || 0);
        const dOut = to - (prev.output || 0);
        const dIn = ti - (prev.input || 0);
        const upTotal = dCache + dIn;
        const parts = [];
        if (dOut > 0) parts.push(`↓${fmtN(dOut)}`);
        if (upTotal > 0) parts.push(`↑${fmtN(upTotal)}`);
        if (parts.length) deltaTag = ` <span class="tokens-delta">(${parts.join(" ")})</span>`;
        else                 deltaTag = ` <span class="tokens-delta idle">(idle)</span>`;
      }
      _prevTokens[id] = { cache_read: tcr, output: to, input: ti, turns };
    } else {
      delete _prevTokens[id];
    }
    // Always show cache_read — for prompt-cache-heavy runs it's
    // where almost all the input lives.
    tokensPill = `<span class="tokens-pill" title="${escapeHtml(fullTitle)}">📊 in ${fmtN(ti)} · out ${fmtN(to)} · cache ${fmtN(tcr)}${turnTag}${cost}${deltaTag}</span>`;
  }

  // The soft-timeout decision banner was removed with the watchdog that fed
  // it (2026-07-30): nothing sets meta.awaiting_decision any more, so this
  // block could never render. `timeoutBlock` stays as an empty string so
  // the template that interpolates it is untouched.
  const timeoutBlock = "";

  // Description block: render the original description and any appended
  // `[retry-hint]` segment in a separate, color-coded chip so the user can
  // see at a glance which run is a retry and what hint was used.
  let descBlock = "";
  const rawDesc = (job.description || "").trim();
  if (rawDesc) {
    const marker = "[retry-hint]";
    const idx = rawDesc.indexOf(marker);
    let baseHtml = "";
    let hintHtml = "";
    if (idx === -1) {
      baseHtml = `<pre class="description-text">${escapeHtml(rawDesc)}</pre>`;
    } else {
      const base = rawDesc.slice(0, idx).trim();
      const hint = rawDesc.slice(idx + marker.length).trim();
      if (base) baseHtml = `<pre class="description-text">${escapeHtml(base)}</pre>`;
      if (hint) hintHtml = `
        <div class="description-hint">
          <span class="description-hint-label">retry hint</span>
          <pre class="description-text">${escapeHtml(hint)}</pre>
        </div>`;
    }
    descBlock = `<details class="description-block" open>
      <summary>Description${idx !== -1 ? " <span class=\"description-retry-chip\">retry</span>" : ""}</summary>
      ${baseHtml}${hintHtml}
    </details>`;
  }

  // Run-now button: show whenever the job dir actually contains a runnable
  // script (exploit.py / solver.py / solver.sage). Don't gate on status —
  // even 'failed' jobs sometimes have a usable partial script.
  let runBlock = "";
  const isExploitableModule = ["web", "pwn", "crypto", "rev"].includes(job.module);
  // Retry is offered for every TERMINAL status on an exploitable module
  // — including 'finished' with a flag, so the user can rerun against a
  // suspect / placeholder flag or grab additional flags. The reviewer
  // path is still useful in that case ("the captured value looks like a
  // dummy — find the real flag").
  // TERMINAL ONLY — deliberately no "looks orphaned" escape hatch here.
  // There was one: `running` also qualified when the newest of
  // last_agent_event_at / updated_at / started_at was over 3 minutes old.
  // It fired on healthy jobs constantly, which is how a panel ends up showing
  // Stop AND Retry at once (showStopResume below is true for every running
  // job, and the two are computed independently):
  //   * nothing writes meta during the pre-agent `analyze` phase, so
  //     updated_at stays pinned to started_at and last_agent_event_at does
  //     not exist yet — the fallback chain then measures "time since the job
  //     started" and crosses 3 min at T+3min on literally every job;
  //   * a healthy agent is routinely silent far longer than 3 minutes.
  // Job 476158d89fc1, measured live: status=running, stage=analyze,
  // updated_at == started_at 443s ago, last_agent_event_at absent — while
  // rq_status=started and the worker heartbeat was 24s old. The job was
  // fine; the panel lied. (235ee5080a6a read identically earlier.)
  // Removing it costs no capability: a running job already offers ■ Stop and
  // ↻/✋ Stop & resume, and the resume backend halts the source job first —
  // exactly what a genuinely orphaned job needs. It also stops rendering
  // 💬 Continue on running jobs, which the backend 409s anyway.
  // If a real orphan affordance is ever wanted, key it on rq_status plus the
  // WORKER heartbeat (both already in the payload), never on updated_at.
  const showRetry = isExploitableModule && [
    "failed", "no_flag", "finished", "stopped",
  ].includes(job.status);
  // Stop & resume: only meaningful while the job is still in flight.
  const showStopResume = isExploitableModule && (
    job.status === "queued" || job.status === "running"
  );
  // Pure stop: halt a live job of ANY module WITHOUT deleting it or forking a
  // resume — keeps the record + ./work/ artifacts, just stops the work.
  const showStop = job.status === "queued" || job.status === "running";
  // "Change target" only makes sense for modules that take a target
  // (web/pwn/crypto/rev) — same set as retry. Visible at any status.
  const showChangeTarget = isExploitableModule;
  if (
    job.runnable_script || job.exploit_present || job.solver_present
    || showRetry || showStopResume || showChangeTarget || showStop
  ) {
    const scriptName = job.runnable_script || (job.exploit_present ? "exploit.py" : "solver.py");
    const runHtml = (job.runnable_script || job.exploit_present || job.solver_present)
      ? `<button class="run-now-btn" data-action="run">▶ Run ${escapeHtml(scriptName)} in sandbox</button>`
      : "";
    const retryHtml = showRetry
      ? `<button class="retry-btn" data-action="retry">↻ Retry with reviewer hint</button>
         <button class="retry-btn retry-manual-open-btn" data-action="retry-manual">✏ Retry with my hint</button>` : "";
    // Continue-in-place: same job/cwd/session + an operator note. For when the
    // agent solved it but was blocked on an external action (instance restart,
    // remote back up). NOT a retry — no re-investigation.
    const continueHtml = showRetry
      ? `<button class="retry-btn continue-open-btn" data-action="continue">💬 Continue (operator note)</button>` : "";
    const stopResumeHtml = showStopResume
      ? `<button class="retry-btn retry-stop-resume-btn" data-action="stop-resume-reviewer">↻ Stop &amp; resume with reviewer hint</button>
         <button class="retry-btn retry-stop-resume-btn" data-action="stop-resume">✋ Stop &amp; resume with my hint</button>` : "";
    // Pure stop — halt only, keep everything (no delete, no resume).
    const stopHtml = showStop
      ? `<button class="stop-job-btn" data-action="stop" title="Halt this job but KEEP the record + ./work/ artifacts (not deleted, not resumed)">■ Stop</button>` : "";
    const targetHtml = showChangeTarget
      ? `<button class="retry-btn change-target-btn" data-action="change-target">✎ Change target</button>` : "";
    const helperBits = [];
    if (stopHtml) helperBits.push("stop = halt this run, keep the job + ./work/ (no delete, no resume)");
    if (runHtml) helperBits.push("re-runs the produced script");
    if (retryHtml) helperBits.push("reviewer hint = Claude diagnoses the failure · my hint = you write the hint yourself");
    if (stopResumeHtml) helperBits.push("stop & resume = halt this job, carry over ./work/, and start fresh with a reviewer-written or hand-written hint");
    if (targetHtml) helperBits.push("change target = update only meta.target_url; no retry, no resume");
    // "Fresh context" toggle — applies to any retry/resume launched from this
    // panel. When checked, the new job carries ./work/ + the hint but does NOT
    // fork the prior SDK conversation, so a deep retry chain can't accumulate
    // context until "Prompt is too long". id is job-scoped so each card is
    // independent.
    const freshToggleHtml = (showRetry || showStopResume)
      ? `<label class="fresh-toggle" title="Start the retry with a clean Claude context (carry ./work/ + hint, but do NOT fork the prior conversation). Use on deep retry chains that hit 'Prompt is too long'.">
           <input type="checkbox" class="fresh-ctx-cb" id="fresh-ctx-${job.id}">
           <span class="fresh-box" aria-hidden="true"></span>
           <span class="fresh-label">✨ fresh context</span>
         </label>` : "";
    runBlock = `<div class="retry-row" style="margin:0.5rem 0">
      ${stopHtml} ${runHtml} ${targetHtml} ${retryHtml} ${continueHtml} ${stopResumeHtml}
      ${freshToggleHtml}
      <small style="color:var(--fg-muted)">${helperBits.join(" · ")}</small>
    </div>`;
  }

  let errorBlock = "";
  if (job.error_kind === "policy_refusal") {
    errorBlock = `<div class="refusal-banner">
      <h4>⚠ Claude Usage Policy refusal</h4>
      <div>The agent stopped mid-job because Claude refused to continue.
        Try switching the model in <strong>Settings → Claude model</strong> to
        <code>claude-sonnet-4-6</code> and re-run the job. Sonnet often
        completes CTF tasks where Opus declines.</div>
    </div>`;
  } else if (job.error) {
    errorBlock = `<div class="refusal-banner">
      <h4>⚠ Job error (${escapeHtml(job.error_kind || "unknown")})</h4>
      <div><code>${escapeHtml(String(job.error).slice(0, 400))}</code></div>
    </div>`;
  }

  // Forensic-only: log-miner findings panel. Shows category counts so the
  // user can see at a glance whether the run captured anything actionable.
  let logFindingsBlock = "";
  if (job.module === "forensic" && job.log_findings_counts) {
    const c = job.log_findings_counts;
    const cells = [
      ["passwords", c.passwords],
      ["sqli", c.sqli_attempts],
      ["xss", c.xss_attempts],
      ["lfi", c.lfi_attempts],
      ["rce", c.rce_attempts],
      ["auth events", c.auth_events],
      ["flag candidates", c.flag_candidates],
    ];
    const chips = cells
      .filter(([, v]) => typeof v === "number")
      .map(([label, v]) =>
        `<span class="lf-chip ${v > 0 ? "hit" : "zero"}">${escapeHtml(label)}: ${v}</span>`
      ).join(" ");
    const scanned = typeof c.scanned_files === "number"
      ? `<small style="color:var(--fg-muted)">scanned ${c.scanned_files} log/history files</small>` : "";
    logFindingsBlock = `<div class="log-findings-panel">
      <h4>🔎 Log mining</h4>
      <div class="lf-chips">${chips}</div>
      ${scanned}
      <small style="color:var(--fg-muted);margin-left:0.5rem">
        full report: <a href="${API}/jobs/${id}/file/log_findings.json" target="_blank">log_findings.json</a>
      </small>
    </div>`;
  }

  // [FLAG?] — flag candidates spotted live during the run (separate from
  // the curated 🚩 Flag found). Lets the operator submit fast in a CTF
  // while the job is still running. Hide ones already promoted to flags.
  let candBlock = "";
  const cands = (job.flag_candidates || []).filter(
    (c) => !(job.flags || []).includes(c));
  if (cands.length) {
    const rows = cands.map((f) =>
      `<div class="flag-row">
         <code>${escapeHtml(f)}</code>
         <button class="copy-btn" data-flag="${escapeHtml(f)}">Copy</button>
       </div>`).join("");
    candBlock = `<div class="flag-cand-banner">
        <h4>🏁 <span class="flag-q">[FLAG?]</span>
          <small>candidate(s) spotted mid-run — verify &amp; submit (not yet confirmed)</small>
        </h4>
        ${rows}
      </div>`;
  }

  let flagBlock = "";
  if (job.flags && job.flags.length) {
    const multiFlags = job.flags.length > 1;
    const rows = job.flags.map((f, i) =>
      `<div class="flag-row">
         <code id="flag-${id}-${i}">${escapeHtml(f)}</code>
         <button class="copy-btn" data-flag="${escapeHtml(f)}">Copy</button>
         <button class="flag-del-btn" data-job-id="${id}" data-flag-index="${i}" title="Delete this flag entry">🗑️ delete</button>
         ${multiFlags ? `<button class="flag-keep-btn" data-job-id="${id}" data-flag-index="${i}" title="Delete every OTHER flag, keep only this one">📌 keep only this</button>` : ""}
       </div>`).join("");
    const dummyHint = multiFlags
      ? `<small class="flag-hint">여러 flag가 캡처됨 — dummy는 🗑️로 지우거나, 진짜 flag에서 📌 keep only this 를 누르세요.</small>`
      : "";
    // Save-to-exploit-DB button. Only shown for terminal-success jobs
    // (the API also rejects no-flag jobs with 400). The button calls
    // POST /api/exploits/save with operator-supplied tags + notes.
    const saveBtn = (job.status === "finished")
      ? `<button class="exp-save-btn" data-job-id="${id}" title="Copy report.md + exploit.py into the Exploit Library (Phase: operator-curated)">💾 Save to exploit DB</button>`
      : "";
    flagBlock = `<div class="flag-banner">
        <h4>🚩 Flag${job.flags.length > 1 ? "s" : ""} found ${saveBtn}</h4>
        ${dummyHint}
        ${rows}
      </div>`;
  }

  // Multi-target jobs carry target_urls (primary first); show "+N" next to the
  // primary and the full list as a hover title so the operator can confirm all
  // their targets registered.
  const _tgts = Array.isArray(job.target_urls) ? job.target_urls.filter(Boolean) : [];
  const targetExtra = _tgts.length > 1
    ? ` <span class="target-more" title="${escapeHtml(_tgts.join("\n"))}">+${_tgts.length - 1} more</span>`
    : "";

  detail.innerHTML = `
    <h3>Job <span class="jobid-text">${job.id}</span><button class="copy-jobid-btn" data-jobid="${job.id}" title="Copy job ID">⧉</button>
      <span class="status ${job.status}">${job.status}</span>
      ${timingPill}${agentPill}
    </h3>
    <div><small>module: ${job.module} · file: ${escapeHtml(job.filename || "")} · target: ${escapeHtml(job.target_url || "(none)")}${targetExtra}${stage}${cost}${timeout}${providerInfo}${modelInfo}</small></div>
    ${timeoutBlock}
    ${descBlock}
    ${candBlock}
    ${runBlock}
    ${errorBlock}
    ${flagBlock}
    ${logFindingsBlock}
    ${resultBlock}
    <div class="sdk-live" data-job-id="${id}" hidden>
      <div class="sdk-live-head">
        <span class="sdk-live-dot"></span>
        <span class="sdk-live-label">live agent activity</span>
        <button class="sdk-live-toggle" data-action="toggle-sdk-live">hide</button>
      </div>
      <div class="sdk-live-feed"></div>
    </div>
    <h4>Run log <small style="color:var(--fg-muted);font-weight:normal">(auto-follows when scrolled to bottom)</small></h4>
    <div class="run-log-window" data-view="${monitorView ? "monitor" : "log"}">
      <div class="run-log-titlebar">
        <span class="run-log-dot run-log-dot-r"></span>
        <span class="run-log-dot run-log-dot-y"></span>
        <span class="run-log-dot run-log-dot-g"></span>
        <div class="rl-viewtabs">
          <button class="rl-viewtab ${monitorView ? "" : "active"}" data-action="view-log"
                  title="Raw run log">Run log</button>
          <button class="rl-viewtab ${monitorView ? "active" : ""}" data-action="view-monitor"
                  title="Curated, LLM-narrated monitor commentary">Monitor</button>
        </div>
        <input class="run-log-search" data-job-id="${id}" type="search"
               spellcheck="false" autocomplete="off"
               placeholder="🔎 filter log…" value="${escapeHtml(_logSearch[id] || "")}" />
        <span class="run-log-search-count" data-job-id="${id}"></span>
        <select class="monitor-lang" data-action="monitor-lang" title="Monitor language">
          <option value="ko" ${monitorLang === "ko" ? "selected" : ""}>한국어</option>
          <option value="en" ${monitorLang === "en" ? "selected" : ""}>English</option>
        </select>
        <button class="run-log-tz-toggle" data-action="toggle-tz"
                title="Toggle timestamps (UTC ↔ ${escapeHtml(_localTzName())})"
        >${runlogTz === "utc" ? "UTC" : "Local"}</button>
      </div>
      <pre class="run-log" data-job-id="${id}" data-status="${escapeHtml(job.status || "")}">${log ? colorizeRunLog(log, job.started_at) : "(empty)"}</pre>
      <div class="monitor-feed" data-job-id="${id}">${monitorFeedHTML}</div>
      ${tokensPill ? `
      <div class="run-log-footer">
        ${tokensPill}
      </div>` : ""}
    </div>
  `;

  // Spin up the per-second live timer when a running pill is on screen.
  if (job.status === "running") _ensureLivePillTimer();

  // Restore the live SDK panel FIRST — visibility before scroll. The
  // rebuilt markup starts with `hidden`, so if we touched scroll while
  // the panel was hidden the browser would clamp to 0. Same applies to
  // the outer detail.scrollTop below: hidden panel = shorter document
  // = clamped scroll. Sequence: feed content → visibility → collapsed
  // → feed scroll → outer scroll.
  const newSdkPanel = detail.querySelector(".sdk-live");
  if (newSdkPanel) {
    const f = newSdkPanel.querySelector(".sdk-live-feed");
    if (f && prevSdkFeedHTML !== null) {
      f.innerHTML = prevSdkFeedHTML;
    }
    if (prevSdkVisible) newSdkPanel.hidden = false;
    if (_sdkLiveHidden || prevSdkCollapsed) {
      newSdkPanel.classList.add("collapsed");
      const tBtn = newSdkPanel.querySelector('.sdk-live-toggle');
      if (tBtn) tBtn.textContent = "show";
    }
    if (f && prevSdkFeedHTML !== null) {
      // Now that the feed is visible + populated, scrollHeight is real.
      f.scrollTop = prevSdkFeedAtBottom ? f.scrollHeight : prevSdkFeedScroll;
    }
  }

  const newPre = detail.querySelector("pre.run-log");
  if (newPre) {
    if (!isSameJob || prevAtBottom) {
      newPre.scrollTop = newPre.scrollHeight;
    } else {
      newPre.scrollTop = prevScrollTop;
    }
  }
  const newMonFeed = detail.querySelector(".monitor-feed");
  if (newMonFeed) {
    if (!isSameJob || prevMonAtBottom) {
      newMonFeed.scrollTop = newMonFeed.scrollHeight;
    } else {
      newMonFeed.scrollTop = prevMonScrollTop;
    }
  }
  // Restore the modal-body scroll for same-job re-renders so reading the
  // retry-hint chip / description / result links isn't yanked back to the
  // top every 2 seconds. Runs AFTER the SDK panel visibility restore so
  // the document height matches what it was at capture time.
  if (isSameJob) {
    detail.scrollTop = prevModalScrollTop;
  }

  // Read the per-card "fresh context (no conversation fork)" checkbox.
  const _freshCtx = () => {
    const cb = detail.querySelector(`#fresh-ctx-${id}`);
    return !!(cb && cb.checked);
  };
  // Mirror checked state onto the label as a class, so the chip styles work
  // even on engines without :has() support (older WebKit/Firefox).
  const _freshCb = detail.querySelector(`#fresh-ctx-${id}`);
  if (_freshCb) {
    const _lbl = _freshCb.closest(".fresh-toggle");
    const _sync = () => _lbl && _lbl.classList.toggle("checked", _freshCb.checked);
    _freshCb.addEventListener("change", _sync);
    _sync();
  }
  const retryBtn = detail.querySelector('.retry-btn[data-action="retry"]');
  if (retryBtn) {
    // Reviewer-mode retry: open an inline form with an optional MULTI-target
    // override (+/× list). Blank = keep prior, "(none)" = clear. The reviewer
    // auto-generates the hint; this form only collects target(s).
    // If the source job is still queued/running (incl. orphaned "running"),
    // use /resume/stream so the backend halts it first — plain /retry would
    // leave a ghost worker/meta race.
    retryBtn.addEventListener("click", () => {
      const live = job.status === "queued" || job.status === "running";
      openReviewerRetryForm(id, retryBtn, live ? {
        formKey: "retry",
        submitLabel: "↻ Halt & retry (reviewer)",
        streamOpts: {
          endpoint: `${API}/jobs/${id}/resume/stream`,
          flow: "resume",
        },
      } : undefined);
    });
  }
  const retryManualBtn = detail.querySelector('.retry-btn[data-action="retry-manual"]');
  if (retryManualBtn) {
    retryManualBtn.addEventListener("click", () => openManualHintForm(id, retryManualBtn));
  }
  const continueNoteBtn = detail.querySelector('.retry-btn[data-action="continue"]');
  if (continueNoteBtn) {
    continueNoteBtn.addEventListener("click", () => openContinueForm(id, continueNoteBtn));
  }
  const stopResumeBtn = detail.querySelector('.retry-btn[data-action="stop-resume"]');
  if (stopResumeBtn) {
    stopResumeBtn.addEventListener("click", () => openStopResumeForm(id, stopResumeBtn));
  }
  const stopResumeReviewerBtn = detail.querySelector(
    '.retry-btn[data-action="stop-resume-reviewer"]',
  );
  if (stopResumeReviewerBtn) {
    // No manual hint: streamRetry fetches the reviewer over SSE, backend halts
    // the source job first, carries ./work/, and submits with a [RESUMING]
    // preamble. Inline form collects an optional MULTI-target override.
    stopResumeReviewerBtn.addEventListener("click", () =>
      openReviewerRetryForm(id, stopResumeReviewerBtn, {
        formKey: "resume",
        submitLabel: "↻ Stop & resume (reviewer)",
        streamOpts: { endpoint: `${API}/jobs/${id}/resume/stream`, flow: "resume" },
      }),
    );
  }

  // (soft-timeout decision buttons removed with the watchdog — 2026-07-30)

  const stopBtn = detail.querySelector('.stop-job-btn[data-action="stop"]');
  if (stopBtn) {
    stopBtn.addEventListener("click", () => stopJob(id, stopBtn));
  }

  const changeTargetBtn = detail.querySelector('.change-target-btn[data-action="change-target"]');
  if (changeTargetBtn) {
    changeTargetBtn.addEventListener("click", () => {
      // Prefill with the job's current target(s) so the operator edits in place.
      const curList = (Array.isArray(job.target_urls) && job.target_urls.length
        ? job.target_urls
        : (job.target_url ? [job.target_url] : [])).filter(Boolean);
      // Inline form anchored right after the button row, mirroring
      // the retry-manual-form layout.
      if (changeTargetBtn.dataset.openForm === "1") return;
      changeTargetBtn.dataset.openForm = "1";
      const form = document.createElement("div");
      form.className = "retry-manual-form";
      form.innerHTML = `
        <label class="retry-manual-label">New target(s) · <b>+ add target</b> for several · clear all = remove</label>
        ${targetListHtml("http://challenge.example.com:8080  ·  ctf.example.com:31337", curList.join("\n"))}
        <div style="display:flex;gap:0.5rem;align-items:center">
          <button class="retry-manual-submit change-target-save" type="button">Save target</button>
          <button class="retry-manual-cancel change-target-cancel" type="button">Cancel</button>
          <small style="color:var(--fg-muted)">updates meta only · run / retry afterwards picks up the new value</small>
        </div>
      `;
      changeTargetBtn.parentNode.insertBefore(form, changeTargetBtn.nextSibling);
      const firstInput = form.querySelector(".target-input");
      if (firstInput) { firstInput.focus(); firstInput.select(); }
      const close = () => {
        form.remove();
        delete changeTargetBtn.dataset.openForm;
      };
      form.querySelector(".change-target-cancel").addEventListener("click", close);
      form.querySelector(".change-target-save").addEventListener("click", async () => {
        // PATCH /target: "" clears the target (change-target semantics), a
        // joined list sets target_url (primary) + target_urls (the rest).
        const val = gatherTargets(form);
        try {
          const res = await fetch(`${API}/jobs/${id}/target`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: val }),
          });
          const body = await res.json();
          if (!res.ok) {
            alert(`change-target failed: ${res.status} ${JSON.stringify(body)}`);
            return;
          }
          close();
          await renderJob(id, { force: true });
          // Surface the note whenever the API says so — for a RUNNING job it
          // now explains that the orchestrator hands the new endpoint over at
          // the next turn boundary; for queued/analyzing it explains the
          // timing. A finished job stays quiet. (Gating this on
          // `applies_live === false` broke once `running` became live-applying:
          // the operator got no feedback at all.)
          const showNote = body.show_note !== undefined
            ? body.show_note
            : body.applies_live === false;
          if (showNote && body.note) alert(body.note);
        } catch (e) {
          alert(`change-target error: ${e}`);
        }
      });
      form.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && e.target.classList.contains("target-input")) {
          e.preventDefault();
          form.querySelector(".change-target-save").click();
        } else if (e.key === "Escape") { close(); }
      });
    });
  }

  const runBtn = detail.querySelector('.run-now-btn[data-action="run"]');
  if (runBtn) {
    runBtn.addEventListener("click", async () => {
      // dreamhack-style instances expire fast, so the stored target is often
      // stale by re-run time — and this button used to silently reuse it,
      // which made "Run in sandbox" appear to ignore a fresh target. Prompt
      // (prefilled with the job's current target) so the operator confirms or
      // overrides it; the override is passed as ?target= and persisted to
      // meta server-side BEFORE the run (else the runner's proactive
      // meta-refresh would clobber it back to the stale value).
      const curTgt = job.target_url || "";
      const tgt = prompt(
        "Run against target (host:port or URL).\n"
        + "Edit to point at a fresh instance, or keep as-is:",
        curTgt,
      );
      if (tgt === null) return;  // cancelled — don't run
      const q = tgt.trim() ? `?target=${encodeURIComponent(tgt.trim())}` : "";
      runBtn.disabled = true;
      const origText = runBtn.textContent;
      runBtn.textContent = "⏳ running…";
      try {
        const res = await fetch(`${API}/jobs/${id}/run${q}`, { method: "POST" });
        const body = await res.json();
        if (!res.ok) {
          alert(`run failed: ${res.status} ${JSON.stringify(body)}`);
        } else {
          const sb = body.sandbox || {};
          const msg = `exit=${sb.exit_code} · stdout ${sb.stdout?.length || 0}B · `
            + `flags: ${(body.flags || []).length ? body.flags.join(", ") : "(none)"}`;
          alert(msg);
        }
      } catch (e) {
        alert(`run error: ${e}`);
      } finally {
        runBtn.disabled = false;
        runBtn.textContent = origText;
        await renderJob(id, { force: true });
        await refreshJobs();
      }
    });
  }

  // Run-log search: stash this poll's raw log + anchor, wire the input, and
  // re-apply an active filter (the poll just rebuilt the <pre> with the full
  // log). Typing is protected by the poll-skip guard up top.
  _runLogRaw[id] = log;
  _runLogAnchor[id] = job.started_at || null;
  const logSearchInput = detail.querySelector(".run-log-search");
  if (logSearchInput) {
    logSearchInput.addEventListener("input", () => {
      _logSearch[id] = logSearchInput.value;
      applyLogSearch(id);
    });
    if ((_logSearch[id] || "").trim()) applyLogSearch(id);
  }

  const tzBtn = detail.querySelector('.run-log-tz-toggle[data-action="toggle-tz"]');
  if (tzBtn) {
    tzBtn.addEventListener("click", () => {
      _setRunlogTz(runlogTz === "utc" ? "local" : "utc");
    });
  }

  // Run-log ↔ Monitor view toggle + monitor language select.
  const viewLogBtn = detail.querySelector('.rl-viewtab[data-action="view-log"]');
  if (viewLogBtn) {
    viewLogBtn.addEventListener("click", () => { if (monitorView) _setMonitorView(false); });
  }
  const viewMonBtn = detail.querySelector('.rl-viewtab[data-action="view-monitor"]');
  if (viewMonBtn) {
    viewMonBtn.addEventListener("click", () => { if (!monitorView) _setMonitorView(true); });
  }
  const monLangSel = detail.querySelector('.monitor-lang[data-action="monitor-lang"]');
  if (monLangSel) {
    monLangSel.addEventListener("change", () => _setMonitorLang(monLangSel.value));
  }

  const sdkLiveBtn = detail.querySelector('.sdk-live-toggle[data-action="toggle-sdk-live"]');
  if (sdkLiveBtn) {
    sdkLiveBtn.addEventListener("click", () => {
      _sdkLiveHidden = !_sdkLiveHidden;
      try { localStorage.setItem("sdk_live_hidden", _sdkLiveHidden ? "1" : "0"); } catch (_) {}
      const panel = detail.querySelector('.sdk-live');
      if (panel) {
        panel.classList.toggle("collapsed", _sdkLiveHidden);
        sdkLiveBtn.textContent = _sdkLiveHidden ? "show" : "hide";
      }
    });
    // Apply the saved preference on initial render.
    const panel = detail.querySelector('.sdk-live');
    if (panel && _sdkLiveHidden) {
      panel.classList.add("collapsed");
      sdkLiveBtn.textContent = "show";
    }
  }

  for (const btn of detail.querySelectorAll(".copy-jobid-btn")) {
    btn.addEventListener("click", (e) => copyJobId(btn.dataset.jobid, e));
  }

  for (const btn of detail.querySelectorAll(".copy-btn")) {
    btn.addEventListener("click", async () => {
      const flag = btn.dataset.flag;
      try {
        await navigator.clipboard.writeText(flag);
      } catch (_) {
        // Fallback: select + execCommand
        const tmp = document.createElement("textarea");
        tmp.value = flag; document.body.appendChild(tmp);
        tmp.select(); document.execCommand("copy"); tmp.remove();
      }
      const orig = btn.textContent;
      btn.textContent = "✓ Copied"; btn.classList.add("copied");
      setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1500);
    });
  }

  // Manual flag pruning. Challenges that pad stdout with flag-shaped noise
  // leave meta.flags full of dummies — let the operator delete them (or keep
  // only the real one). After the server prunes, re-render from fresh meta.
  const _pruneFlags = async (jid, indices, btn, confirmMsg) => {
    if (confirmMsg && !confirm(confirmMsg)) return;
    const orig = btn.textContent;
    btn.disabled = true; btn.textContent = "…";
    try {
      const res = await fetch(`${API}/jobs/${jid}/flags/delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indices }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(`flag delete failed: ${res.status} — ${data.detail || ""}`);
        btn.disabled = false; btn.textContent = orig;
        return;
      }
      await renderJob(jid);   // re-fetch + re-render with the pruned list
    } catch (e) {
      alert(`flag delete failed: ${e}`);
      btn.disabled = false; btn.textContent = orig;
    }
  };

  for (const btn of detail.querySelectorAll(".flag-del-btn")) {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.dataset.flagIndex, 10);
      if (Number.isNaN(idx)) return;
      _pruneFlags(btn.dataset.jobId, [idx], btn, null);
    });
  }

  for (const btn of detail.querySelectorAll(".flag-keep-btn")) {
    btn.addEventListener("click", () => {
      const keep = parseInt(btn.dataset.flagIndex, 10);
      const total = (job.flags || []).length;
      if (Number.isNaN(keep) || total <= 1) return;
      const others = [];
      for (let i = 0; i < total; i++) if (i !== keep) others.push(i);
      _pruneFlags(btn.dataset.jobId, others, btn,
        `Delete the other ${others.length} flag(s) and keep only this one?`);
    });
  }

  for (const btn of detail.querySelectorAll(".exp-save-btn")) {
    btn.addEventListener("click", async () => {
      if (btn.disabled) return;
      const jid = btn.dataset.jobId;
      const tags = prompt(
        "Tags (comma-separated, optional)\n"
        + "e.g. heap, fsop, glibc-2.35, large-bin",
        ""
      );
      if (tags === null) return;  // cancelled
      const notes = prompt(
        "Notes (one line, optional)\n"
        + "e.g. House of Apple 2 chain; one_gadget rejected — pivoted to _IO_str_jumps",
        ""
      );
      if (notes === null) return;  // cancelled
      const body = {
        job_id: jid,
        tags: tags.split(",").map(s => s.trim()).filter(Boolean),
        notes: notes || "",
        overwrite: true,
      };
      btn.disabled = true;
      const orig = btn.textContent;
      btn.textContent = "saving…";
      try {
        const res = await fetch(`${API}/exploits/save`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          alert(`save failed: ${res.status} — ${data.detail || ""}`);
          btn.textContent = orig;
        } else {
          btn.textContent = `✓ saved ${data.id || ""}`;
          btn.classList.add("copied");
          setTimeout(() => {
            btn.textContent = orig;
            btn.classList.remove("copied");
            btn.disabled = false;
          }, 2500);
        }
      } catch (e) {
        alert(`save failed: ${e}`);
        btn.textContent = orig;
        btn.disabled = false;
      }
    });
  }
  // Restore the "reviewer in progress" panel after a full detail rebuild.
  // The stream state lives in activeReviewers (not the DOM), so this brings
  // the panel back when the operator navigates away from an in-flight retry
  // and returns — the disappearing-panel bug this fixes.
  renderReviewerPanel(id);
  return job;
}

// Copy a job id to the clipboard. Used by the ⧉ button in both the job
// list cards and the detail header. stopPropagation so clicking it inside a
// list card does NOT also trigger the card's selectJob().
async function copyJobId(id, ev) {
  if (ev) { ev.stopPropagation(); ev.preventDefault(); }
  let ok = true;
  try {
    await navigator.clipboard.writeText(id);
  } catch (_) {
    try {
      const tmp = document.createElement("textarea");
      tmp.value = id; document.body.appendChild(tmp);
      tmp.select(); document.execCommand("copy"); tmp.remove();
    } catch (_) { ok = false; }
  }
  const btn = ev && ev.currentTarget;
  if (btn) {
    const orig = btn.textContent;
    btn.textContent = ok ? "✓" : "✗";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1200);
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// --- Run-log colorizer ------------------------------------------------------
// Lines look like: "[HH:MM:SS] LABEL[: body...]". Classify by LABEL and wrap
// the timestamp + label + body in spans so the run.log <pre> can show
// agent text, tool calls, tool results, thinking, and errors at a glance.

const _RUNLOG_PATTERNS = [
  // AGENT_ERROR (kind): body  — must come before plain ERROR
  { re: /^(AGENT_ERROR)(\s*\([^)]*\))?\s*:\s*([\s\S]*)$/,
    cls: "rl-agent-error",
    render: (m) => `<span class="rl-label rl-agent-error">${escapeHtml(m[1])}${escapeHtml(m[2] || "")}</span>: <span class="rl-body rl-error-body">${escapeHtml(m[3])}</span>` },
  // TOOL_RESULT: body
  { re: /^(TOOL_RESULT)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-tool-result">${escapeHtml(m[1])}</span>: <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // TOOL_ERROR: body
  { re: /^(TOOL_ERROR)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-tool-error">${escapeHtml(m[1])}</span>: <span class="rl-body rl-error-body">${escapeHtml(m[2])}</span>` },
  // TOOL <name>: body
  { re: /^(TOOL)\s+(\S+)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-tool">${escapeHtml(m[1])}</span> <span class="rl-toolname">${escapeHtml(m[2])}</span>: <span class="rl-body">${escapeHtml(m[3])}</span>` },
  // AGENT: body
  { re: /^(AGENT)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-agent">${escapeHtml(m[1])}</span>: <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // THINK: body
  { re: /^(THINK)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-think">${escapeHtml(m[1])}</span>: <span class="rl-body rl-think-body">${escapeHtml(m[2])}</span>` },
  // DONE: body
  { re: /^(DONE)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-done">${escapeHtml(m[1])}</span>: <span class="rl-body rl-done-body">${escapeHtml(m[2])}</span>` },
  // ERROR: body  (catastrophic — exception in run_job etc.)
  { re: /^(ERROR)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-error">${escapeHtml(m[1])}</span>: <span class="rl-body rl-error-body">${escapeHtml(m[2])}</span>` },
  // BUDGET_ABORT: body  — investigation budget tripwire fired
  { re: /^(BUDGET_ABORT)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-budget">${escapeHtml(m[1])}</span>: <span class="rl-body rl-budget-body">${escapeHtml(m[2])}</span>` },
  // RUNAWAY_OUTPUT detected (NNN MB)... — Bash command flooded the SDK,
  // which auto-truncated to a 2KB preview. Highlight so the agent (and
  // the human operator) doesn't blunder past it.
  { re: /^(RUNAWAY_OUTPUT)\s+([\s\S]*)$/,
    render: (m) => `<span class="rl-label rl-runaway">${escapeHtml(m[1])}</span> <span class="rl-body rl-runaway-body">${escapeHtml(m[2])}</span>` },
  // Lifecycle: ⏰ Soft timeout reached … (watchdog warning)
  { re: /^(⏰\s+Soft timeout reached[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-warn">${escapeHtml(m[1])}</span>` },
  // Lifecycle: Launching Claude agent (model=...)
  { re: /^(Launching Claude (?:agent|summary agent)[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-info">▸ ${escapeHtml(m[1])}</span>` },
  // Lifecycle: Forking prior Claude session abc12345…
  { re: /^(Forking prior Claude session[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-info">↻ ${escapeHtml(m[1])}</span>` },
  // Lifecycle: User chose CONTINUE / STOP — soft-timeout decision
  { re: /^(User chose (?:CONTINUE|STOP)[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-decision">⚑ ${escapeHtml(m[1])}</span>` },
  // Lifecycle: Source root: ... (web/crypto)
  { re: /^(Source root)\s*:\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-info">${escapeHtml(m[1])}</span>: <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // Lifecycle: [manual-run] executing exploit.py ...
  { re: /^(\[manual-run\])\s*([\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-cyan">${escapeHtml(m[1])}</span> <span class="rl-body">${escapeHtml(m[2])}</span>` },
  // Lifecycle: Spawning forensic|misc … sibling-container start
  { re: /^(Spawning [a-z]+[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-info">▸ ${escapeHtml(m[1])}</span>` },
  // Lifecycle: Skipping Claude summary (forensic/misc)
  { re: /^(Skipping Claude summary[\s\S]*)$/,
    render: (m) => `<span class="rl-lifecycle rl-system">${escapeHtml(m[1])}</span>` },
];

// Format a `HH:MM:SS` timestamp for display. The on-disk log records
// UTC time-of-day only; this helper anchors the time-of-day on the
// job's `started_at` UTC date, advances the day-counter on midnight
// rollover, and (in local mode) converts to the user's timezone via
// the browser's Date object. State is per-render, mutated as the
// caller walks lines top-to-bottom.
function _formatLogTs(hms, anchor, state) {
  const parts = hms.split(":");
  if (parts.length !== 3) return hms;
  const hh = +parts[0], mm = +parts[1], ss = +parts[2];
  if (Number.isNaN(hh) || Number.isNaN(mm) || Number.isNaN(ss)) return hms;
  const sod = hh * 3600 + mm * 60 + ss;
  // Day rollover: if the new line's seconds-of-day is well below
  // the last seen, assume we crossed at least one UTC midnight. The
  // 60-second slack tolerates concurrent-thread log lines arriving a
  // hair out of order so we don't mistakenly bump the day counter.
  if (state.lastSod >= 0 && sod < state.lastSod - 60) {
    state.dayOffset += 1;
  }
  state.lastSod = sod;
  if (runlogTz !== "local" || !anchor) {
    return hms;
  }
  const d = new Date(Date.UTC(
    anchor.getUTCFullYear(),
    anchor.getUTCMonth(),
    anchor.getUTCDate() + state.dayOffset,
    hh, mm, ss,
  ));
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  const s = String(d.getSeconds()).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function _colorizeRunLogLine(line, anchor, state) {
  // Header injected by /api/jobs/{id}/log?tail=… (e.g. "…(showing last X
  // of Y bytes — download full log via …)…"). Render dim+italic.
  if (line.startsWith("…(showing last")) {
    return `<span class="rl-system">${escapeHtml(line)}</span>`;
  }
  const m = line.match(/^\[(\d{2}:\d{2}:\d{2})\]\s+([\s\S]*)$/);
  if (!m) {
    if (!line) return "";
    return `<span class="rl-system">${escapeHtml(line)}</span>`;
  }
  const ts = _formatLogTs(m[1], anchor, state);
  let rest = m[2];

  // Per-line agent tag: analyzers prefix lines with "[main] " /
  // "[recon] " / "[judge] " / "[debugger] " right after the
  // timestamp. The isolated subagent path tags with a per-spawn
  // counter, e.g. "[recon#1] " — both forms should colorize the
  // chip identically (the # suffix is just the spawn index).
  // Strip the tag and render it as a colored chip; subagent lines
  // (recon / judge / debugger) get a slight indent so the
  // delegation reads visually like a nested call.
  let agentChip = "";
  let isSubagent = false;
  const tagMatch = rest.match(
    /^\[(main|recon|judge|debugger)(#\d+)?\]\s+([\s\S]*)$/,
  );
  if (tagMatch) {
    const tag = tagMatch[1];
    const idxSuffix = tagMatch[2] || "";
    isSubagent = tag !== "main";
    rest = tagMatch[3];
    agentChip = `<span class="rl-agent-tag rl-agent-tag-${tag}">${tag}${idxSuffix}</span>`;
  }

  const indent = isSubagent ? '<span class="rl-recon-indent">↳ </span>' : "";

  for (const p of _RUNLOG_PATTERNS) {
    const mm = rest.match(p.re);
    if (mm) {
      return `<span class="rl-ts">[${ts}]</span> ${agentChip}${indent}${p.render(mm)}`;
    }
  }
  // System / unrecognised lines (e.g. "Launching Claude agent…",
  // "User chose CONTINUE…", "⏰ Soft timeout reached…").
  return `<span class="rl-ts">[${ts}]</span> ${agentChip}${indent}<span class="rl-system">${escapeHtml(rest)}</span>`;
}

// ---- run-log search (client-side filter + highlight of the loaded log) ----
// Searches the displayed log (the 256 KB tail the poll fetches — the whole log
// for most jobs). State is keyed by job so it survives the 2s poll re-render.
const _logSearch = {};      // jobId -> query string
const _runLogRaw = {};      // jobId -> raw log text (last poll fetch)
const _runLogAnchor = {};   // jobId -> started_at iso (for timestamp colorize)

function _escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Highlight `q` only in the TEXT segments of colorized HTML (never inside a
// tag), so the run-log's colored spans aren't mangled.
function _highlightLogHtml(html, q) {
  if (!q) return html;
  const rx = new RegExp(_escapeRegExp(q), "gi");
  return html.replace(/(<[^>]+>)|([^<]+)/g, (m, tag, text) =>
    tag ? tag : text.replace(rx, '<mark class="log-hit">$&</mark>'));
}

// Re-render the run-log <pre> for `id`: the full colorized log when the query
// is empty, else only the matching lines (case-insensitive) with hits marked.
function applyLogSearch(id) {
  const esc = (window.CSS && CSS.escape) ? CSS.escape(id) : id;
  const pre = document.querySelector(`pre.run-log[data-job-id="${esc}"]`);
  if (!pre) return;
  const raw = _runLogRaw[id] || "";
  const q = (_logSearch[id] || "").trim();
  const anchor = _runLogAnchor[id] || null;
  const countEl = document.querySelector(`.run-log-search-count[data-job-id="${esc}"]`);
  if (!q) {
    try { pre.innerHTML = raw ? colorizeRunLog(raw, anchor) : "(empty)"; } catch (_) {}
    if (countEl) countEl.textContent = "";
    return;
  }
  const ql = q.toLowerCase();
  const lines = raw.split("\n");
  const matching = lines.filter((l) => l.toLowerCase().includes(ql));
  if (!matching.length) {
    pre.innerHTML = '<span style="color:var(--fg-muted)">(no matching lines)</span>';
    if (countEl) countEl.textContent = "0";
    return;
  }
  try {
    pre.innerHTML = _highlightLogHtml(colorizeRunLog(matching.join("\n"), anchor), q);
  } catch (_) {
    pre.textContent = matching.join("\n");
  }
  if (countEl) countEl.textContent = `${matching.length} / ${lines.length} lines`;
}

function colorizeRunLog(text, anchorIso) {
  if (!text) return "";
  let anchor = null;
  if (anchorIso) {
    const d = new Date(anchorIso);
    if (!Number.isNaN(d.getTime())) anchor = d;
  }
  // dayOffset / lastSod are mutated by _formatLogTs as we walk lines
  // top-to-bottom; reset for each call so toggling between jobs (or
  // re-rendering after a TZ flip) starts clean.
  const state = { dayOffset: 0, lastSod: -1 };
  return text.split("\n").map(
    (line) => _colorizeRunLogLine(line, anchor, state),
  ).join("\n");
}

// --- File preview modal -----------------------------------------------------
// Pretty-prints JSON, renders Markdown, and syntax-highlights source code
// using highlight.js + marked (loaded from CDN in index.html). Falls back
// to plain text if the libraries didn't load (e.g. offline).

const _LANG_FROM_EXT = {
  py: "python", sage: "python",
  js: "javascript", ts: "typescript",
  json: "json", jsonl: "json",
  md: "markdown", markdown: "markdown",
  html: "xml", xml: "xml",
  css: "css",
  sh: "bash", bash: "bash",
  c: "c", h: "c", cpp: "cpp", hpp: "cpp", cc: "cpp",
  rb: "ruby", go: "go", rs: "rust",
  yml: "yaml", yaml: "yaml",
  sql: "sql",
  log: "plaintext", stdout: "plaintext", stderr: "plaintext", txt: "plaintext",
};

function _languageFor(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return _LANG_FROM_EXT[ext] || "plaintext";
}

function _isMarkdown(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return ext === "md" || ext === "markdown";
}

function _isJson(name) {
  const ext = (name.split(".").pop() || "").toLowerCase();
  return ext === "json" || name === "result.json";
}

async function openFileModal(name, sourceUrl) {
  const modal = document.getElementById("file-modal");
  if (!modal) return;
  const body = modal.querySelector(".file-modal-body");
  const nameEl = modal.querySelector(".file-modal-name");
  const metaEl = modal.querySelector(".file-modal-meta");
  const rawLink = modal.querySelector(".file-modal-raw");
  const copyBtn = modal.querySelector(".file-modal-copy");

  nameEl.textContent = name;
  metaEl.textContent = "loading…";
  rawLink.href = sourceUrl;
  body.innerHTML = "";
  modal.hidden = false;
  modal.dataset.url = sourceUrl;
  modal.dataset.name = name;

  let text;
  try {
    const res = await fetch(sourceUrl);
    if (!res.ok) {
      metaEl.textContent = `error ${res.status}`;
      body.innerHTML = `<pre class="file-modal-error">${escapeHtml(await res.text())}</pre>`;
      return;
    }
    text = await res.text();
  } catch (e) {
    metaEl.textContent = "fetch failed";
    body.innerHTML = `<pre class="file-modal-error">${escapeHtml(String(e))}</pre>`;
    return;
  }
  modal.dataset.raw = text;
  metaEl.textContent = `${text.length.toLocaleString()} bytes`;

  // Render based on extension.
  if (_isJson(name)) {
    let pretty = text;
    try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch (_) {}
    const code = `<pre><code class="language-json">${escapeHtml(pretty)}</code></pre>`;
    body.innerHTML = code;
  } else if (_isMarkdown(name)) {
    if (window.marked) {
      const html = window.marked.parse(text, { mangle: false, headerIds: false });
      body.innerHTML = `<div class="markdown-rendered">${html}</div>`;
    } else {
      body.innerHTML = `<pre><code class="language-markdown">${escapeHtml(text)}</code></pre>`;
    }
  } else {
    const lang = _languageFor(name);
    body.innerHTML = `<pre><code class="language-${lang}">${escapeHtml(text)}</code></pre>`;
  }

  // Highlight every code block (including those produced by marked).
  if (window.hljs) {
    body.querySelectorAll("pre code").forEach((el) => {
      try { window.hljs.highlightElement(el); } catch (_) {}
    });
  }

  // Wire one-shot Copy that pulls from the cached raw.
  // navigator.clipboard is only defined in secure contexts (HTTPS / localhost);
  // over HTTP via a LAN IP it's undefined and `.writeText` throws TypeError.
  // Fall back to a transient textarea + document.execCommand("copy"), which
  // works on plain HTTP too.
  copyBtn.onclick = async () => {
    const text = modal.dataset.raw || "";
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        ok = true;
      }
    } catch (_) { /* fall through to legacy path */ }
    if (!ok) {
      try {
        const tmp = document.createElement("textarea");
        tmp.value = text;
        tmp.setAttribute("readonly", "");
        tmp.style.position = "fixed";
        tmp.style.left = "-9999px";
        document.body.appendChild(tmp);
        tmp.select();
        ok = document.execCommand("copy");
        tmp.remove();
      } catch (_) { ok = false; }
    }
    if (ok) {
      const orig = copyBtn.textContent;
      copyBtn.textContent = "✓ Copied";
      setTimeout(() => (copyBtn.textContent = orig), 1200);
    } else {
      alert("Copy failed. Select the text manually and use Ctrl+C.");
    }
  };
}

function _closeFileModal() {
  const modal = document.getElementById("file-modal");
  if (!modal) return;
  modal.hidden = true;
  modal.dataset.url = "";
  modal.dataset.name = "";
  modal.dataset.raw = "";
}

// Single delegated click handler for all file-preview links + the modal's
// own close/backdrop/Escape. Set up once at load.
document.addEventListener("click", (e) => {
  const link = e.target.closest("a.file-preview-link");
  if (link) {
    // Allow modifier-clicks (new tab / window / download) to fall through
    // to the browser's normal link behavior.
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) {
      return;
    }
    e.preventDefault();
    openFileModal(link.dataset.name, link.dataset.url);
    return;
  }
  if (e.target.closest(".file-modal-close, .file-modal-backdrop")) {
    _closeFileModal();
    return;
  }
  if (e.target.closest(".job-modal-close, .job-modal-backdrop")) {
    _closeJobModal();
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  // File preview is on top of the job modal — close that one first.
  const fileModal = document.getElementById("file-modal");
  if (fileModal && !fileModal.hidden) {
    _closeFileModal();
    return;
  }
  const jobModal = document.getElementById("job-modal");
  if (jobModal && !jobModal.hidden) {
    _closeJobModal();
  }
});

fillModelSelects();
fillEffortSelects();
// Load Settings once at boot so agent_provider is known before the
// operator opens a form (per-job model catalogs follow the provider).
loadSettings().catch(() => {});
loadModelPresets();
loadTunnelStatus();
refreshJobs();
refreshStats();

// Global heartbeat — keeps the job list AND the flag alarm live even when
// no detail panel is open (the per-job pollers only run for the open job).
// Guarded so a slow /jobs fetch can't pile up overlapping refreshes. ~7s
// is cheap (a dir scan) and well under a run's flag-capture latency.
let _globalPollBusy = false;
setInterval(async () => {
  if (_globalPollBusy) return;
  _globalPollBusy = true;
  try { await refreshJobs(); await refreshStats(); } catch (_) {} finally { _globalPollBusy = false; }
}, 7000);

// --- Version / last-patch badge -------------------------------------------
// Fills the header #version-badge from GET /api/version so the operator can
// confirm at a glance that a redeploy actually took (recurring "container ran
// the old image / stale code" class of bug). `commit` is stamped at deploy;
// `patched_at` is the live newest source mtime (always current). Shows the
// most recent of the two as the date, and flags when live code is newer than
// the stamped commit (i.e. an un-deployed/hot edit).
(function initVersionBadge() {
  const el = document.getElementById('version-badge');
  if (!el) return;
  const fmt = (iso) => {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d)) return '';
    return d.toLocaleString('ko-KR', {
      year: '2-digit', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hour12: false,
    });
  };
  fetch('/api/version', { credentials: 'same-origin' })
    .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
    .then((v) => {
      const ver = v.commit ? ('#' + v.commit) : ('v' + (v.version || '?'));
      // "last patch" = the freshest signal we have
      const dates = [v.patched_at, v.deployed_at, v.commit_date].filter(Boolean);
      dates.sort();
      const latest = dates.length ? dates[dates.length - 1] : null;
      el.textContent = ver + (latest ? ' · ' + fmt(latest) : '');
      // warn (amber) if live source is newer than the stamped commit date
      const stale = v.patched_at && v.commit_date && v.patched_at > v.commit_date
        && (!v.deployed_at || v.patched_at > v.deployed_at);
      el.classList.toggle('version-badge--dirty', !!stale);
      el.title =
        'version ' + (v.version || '?') +
        '\ncommit ' + (v.commit || 'n/a') + (v.commit_date ? ' (' + fmt(v.commit_date) + ')' : '') +
        '\ndeployed ' + (v.deployed_at ? fmt(v.deployed_at) : 'n/a') +
        '\nlast patch (live) ' + (v.patched_at ? fmt(v.patched_at) : 'n/a') +
        (stale ? '\n⚠ live code newer than stamped commit — redeploy/stamp pending' : '');
    })
    .catch(() => { el.textContent = ''; });
})();

// --- Containers tab ---------------------------------------------------------
// Inventory + manual cleanup. Exists because agent-started challenge containers
// have no lifecycle owner: `_hard_stop_job` reaps a job's siblings by the
// `hextech_ctf_tool_job_id` label, and a container the agent starts from Bash
// carries no label, so nothing ever removes it. Three from job fd844946db78
// were still running 11-19h after it finished, each holding a 2 GiB cgroup
// reservation. This is the operator's way to see and clear that.
let _containersPoll = null;

function _fmtPct(v) { return v == null ? "—" : v.toFixed ? v.toFixed(1) + "%" : v + "%"; }

function _memCell(c) {
  if (c.state !== "running") return '<span class="c-dim">—</span>';
  const use = c.mem_usage ? fmtBytes(c.mem_usage) : "?";
  const cap = c.mem_cap ? fmtBytes(c.mem_cap) : "uncapped";
  // A high `usage` that is mostly reclaimable page cache is not a container
  // about to OOM, so only the unreclaimable figure drives the warning colour.
  const real = c.mem_unreclaimable || c.mem_usage || 0;
  const hot = c.mem_cap && real > c.mem_cap * 0.8;
  const nocap = !c.mem_cap;
  const cls = hot ? "c-hot" : nocap ? "c-warn" : "";
  return `<span class="${cls}">${use} / ${cap}</span>` +
         (c.mem_pct != null ? ` <span class="c-dim">(${_fmtPct(c.mem_pct)})</span>` : "");
}

function _catBadge(cat) {
  return `<span class="c-badge c-badge--${cat}">${cat}</span>`;
}

// Attribution, with its provenance made visible. `label` is authoritative —
// the container was tagged at creation. `name` is a GUESS off an 8-12 hex run
// in the container name, which is all an older container has, so it is marked
// with ~ and says so on hover. Anything else genuinely cannot be attributed:
// the containers carry no JOB_ID env and no /data/jobs bind, and by the time
// they are noticed the job that made them has usually been deleted.
function _jobCell(c) {
  if (!c.job_id) {
    return '<span class="c-dim" title="no job label, and the name carries no job id — ' +
           'created before container labelling shipped">unknown</span>';
  }
  if (c.job_source === "label") {
    return `<code>${escapeHtml(c.job_id)}</code>`;
  }
  return `<code class="c-guess" title="guessed from the container name, not a label — verify before acting on it">` +
         `~${escapeHtml(c.job_id)}</code>`;
}

function renderContainers(data) {
  const el = document.getElementById("containers-list");
  if (!el) return;
  const cs = data.containers || [];
  const sum = document.getElementById("containers-summary");
  if (sum) {
    const k = data.counts || {};
    sum.textContent = `${cs.length} total — ${k.challenge || 0} challenge · ` +
      `${k.sandbox || 0} sandbox · ${k.tunnel || 0} tunnel · ${k.core || 0} core` +
      (data.running_jobs && data.running_jobs.length
        ? ` · running jobs: ${data.running_jobs.join(", ")}` : "");
  }
  if (!cs.length) { el.innerHTML = '<p style="color:var(--fg-muted)">No containers.</p>'; return; }

  const rows = cs.map((c) => {
    const disk = c.size_rw != null ? fmtBytes(c.size_rw) : "—";
    const running = c.state === "running";
    const btn = c.protected
      ? `<button class="btn btn-sm" disabled title="${escapeHtml(c.warn || "protected")}">protected</button>`
      : `<button class="btn btn-sm c-del" data-id="${escapeHtml(c.id)}" data-name="${escapeHtml(c.name)}"` +
        ` data-warn="${escapeHtml(c.warn || "")}"` +
        ` data-job="${escapeHtml(c.job_id ? (c.job_source === "label" ? c.job_id : "~" + c.job_id) : "")}">delete</button>`;
    const age = c.age_days == null ? "" :
      `<br><span class="${c.age_days >= 7 ? "c-warn" : "c-dim"}">${c.age_days}d old</span>`;
    return `<tr class="${c.warn ? "c-row--warn" : ""}">
      <td><code>${escapeHtml(c.name)}</code><br><span class="c-dim">${escapeHtml(c.id)}</span></td>
      <td>${_jobCell(c)}${age}</td>
      <td>${_catBadge(c.category)}${c.compose_service ? `<br><span class="c-dim">${escapeHtml(c.compose_service)}</span>` : ""}</td>
      <td><span class="c-state c-state--${running ? "up" : "down"}">${escapeHtml(c.state)}</span></td>
      <td>${_memCell(c)}</td>
      <td>${running ? _fmtPct(c.cpu_pct) : '<span class="c-dim">—</span>'}</td>
      <td>${disk}</td>
      <td><span class="c-dim">${escapeHtml(c.image || "")}</span><br><span class="c-dim">${escapeHtml(c.created || "")}</span></td>
      <td>${btn}</td>
    </tr>` + (c.warn ? `<tr class="c-warnrow"><td colspan="9">⚠ ${escapeHtml(c.warn)}</td></tr>` : "");
  }).join("");

  el.innerHTML = `<table class="containers-table">
    <thead><tr><th>Name / id</th><th>Job / age</th><th>Kind</th><th>State</th><th>Memory</th><th>CPU</th>
    <th>Disk (rw)</th><th>Image / created</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table>`;

  el.querySelectorAll(".c-del").forEach((b) => {
    b.addEventListener("click", () => deleteContainer(b.dataset.id, b.dataset.name, b.dataset.warn, b.dataset.job));
  });
}

async function loadContainers() {
  const el = document.getElementById("containers-list");
  try {
    const res = await fetch("/api/containers");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderContainers(await res.json());
  } catch (e) {
    if (el) el.innerHTML = `<p style="color:var(--red)">Could not list containers: ${escapeHtml(String(e))}</p>`;
  }
}

async function deleteContainer(id, name, warn, job) {
  // Two-step ONLY when the backend flagged a cost — an unflagged leftover is
  // the common case and should not need a second click.
  let msg = `Delete container ${name} (${id})?`;
  if (job) msg += `\nJob: ${job}${job.startsWith("~") ? "  (guessed from the name)" : ""}`;
  if (warn) msg += `\n\n⚠ ${warn}\n\nThis cannot be undone. Continue?`;
  if (!confirm(msg)) return;
  if (warn && !confirm(`Really delete ${name}?\n\n${warn}`)) return;
  try {
    const res = await fetch(`/api/containers/${encodeURIComponent(id)}`, { method: "DELETE" });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { alert(`Delete failed:\n\n${body.detail || res.status}`); return; }
    if (body.note) alert(`Removed ${body.removed}.\n\n${body.note}`);
  } catch (e) {
    alert(`Delete failed: ${e}`);
  }
  loadContainers();
}

function _stopContainersPoll() {
  if (_containersPoll) { clearInterval(_containersPoll); _containersPoll = null; }
}

document.getElementById("containers-refresh")?.addEventListener("click", loadContainers);
document.getElementById("containers-auto")?.addEventListener("change", (e) => {
  _stopContainersPoll();
  // 15s, not the usual few seconds: each refresh costs ~2s of docker stats
  // calls on the daemon (one sample per running container, in parallel).
  if (e.target.checked) _containersPoll = setInterval(() => {
    if (document.getElementById("panel-containers").classList.contains("active")) loadContainers();
    else _stopContainersPoll();
  }, 15000);
});
document.querySelector('.tab[data-tab="containers"]')?.addEventListener("click", loadContainers);
