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
  "claude-opus-4-8",
  "claude-opus-4-8[1m]",
  "claude-opus-4-7",
  "claude-opus-4-7[1m]",
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

function fillModelSelects() {
  // Per-job selects: empty = "default from Settings"
  document.querySelectorAll('[data-role="model-select"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(default — Settings value)", ""));
    for (const m of CLAUDE_MODELS) sel.appendChild(new Option(m, m));
  });
  // Global Settings select: no empty entry, but a leading blank means
  // "no override saved". Actual current value populated by loadSettings().
  document.querySelectorAll('[data-role="model-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use env / default)", ""));
    for (const m of CLAUDE_MODELS) sel.appendChild(new Option(m, m));
  });
}

function fillEffortSelects() {
  // Per-job: empty = Settings value (falls through to SDK default if
  // Settings is also empty). Same UX as fillModelSelects.
  document.querySelectorAll('[data-role="effort-select"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(default — Settings value)", ""));
    for (const e of CLAUDE_EFFORTS) sel.appendChild(new Option(e, e));
  });
  document.querySelectorAll('[data-role="effort-select-settings"]').forEach((sel) => {
    sel.innerHTML = "";
    sel.appendChild(new Option("(use SDK default)", ""));
    for (const e of CLAUDE_EFFORTS) sel.appendChild(new Option(e, e));
  });
}

let selectedJob = null;
let pollTimer = null;

// Per-job token snapshots used to render Δ in the tokens pill so the
// run-log footer shows live "↓X k tokens" deltas the way Claude
// Code's status line does. Keyed by job id; reset whenever the job
// changes or its turn count regresses (= retry/resume forked it).
const _prevTokens = {};

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
// Lightweight 1-second tick that updates ONLY the timing pill's
// textContent on running jobs. Independent of pollTimer (which
// re-renders the whole detail panel and is paused on selection /
// open forms), so the elapsed counter stays smooth.
let livePillTimer = null;
function _tickLivePill() {
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
  // Refresh the liveness pill class on the same tick so the color
  // (active → silent → dead) updates without waiting for the 2s
  // re-render. The pill's data- timestamps are written by render and
  // never go stale within the lifetime of this DOM node.
  document.querySelectorAll(".liveness-pill").forEach((pill) => {
    const ageMs = (iso) => iso ? (Date.now() - new Date(iso).getTime()) : null;
    const a = ageMs(pill.dataset.agentAt);
    const w = ageMs(pill.dataset.workerAt);
    let cls;
    if (w != null && w > 60_000) cls = "dead";
    else if (a != null && a <= 30_000) cls = "active";
    else if (a != null) cls = "silent";
    else if (w != null) cls = "warming";
    if (cls) {
      pill.className = "liveness-pill liveness-" + cls;
      const labelText = pill.firstChild && pill.firstChild.nodeValue;
      if (labelText && labelText.startsWith("● ")) {
        pill.firstChild.nodeValue = "● " + cls + " ";
      }
    }
  });

  if (!document.querySelector(".timing-pill.live")
      && !document.querySelector(".liveness-pill")) {
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
  const crf = form.querySelector(".capture-remote-flag-cb");
  if (crf && crf.checked) {
    const cur = (fd.get("description") || "").trim();
    if (!cur.toLowerCase().includes("capture remote flag")) {
      fd.set("description", cur
        ? `${cur}\n\n${CAPTURE_REMOTE_FLAG_DIRECTIVE}`
        : CAPTURE_REMOTE_FLAG_DIRECTIVE);
    }
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

async function loadSettings() {
  const res = await fetch(`${API}/settings`);
  if (!res.ok) return;
  const s = await res.json();
  const f = document.getElementById("settings-form");
  const modelSel = f.querySelector("[name=claude_model]");
  const modelCustom = f.querySelector("[name=claude_model_custom]");
  const cur = s.claude_model || "";
  // If the saved value is one we know, select it; otherwise stash it
  // in the custom-text input so the user can see/edit it.
  if (CLAUDE_MODELS.includes(cur)) {
    modelSel.value = cur; modelCustom.value = "";
  } else {
    modelSel.value = ""; modelCustom.value = cur;
  }
  // Claude effort (mirrors model: empty = SDK default; otherwise one
  // of low/medium/high/xhigh/max). Stored under `claude_effort` in the
  // settings blob; per-job submissions inherit it when their own
  // effort dropdown is left blank.
  const effortSel = f.querySelector("[name=claude_effort]");
  if (effortSel) {
    const curEffort = s.claude_effort || "";
    effortSel.value = CLAUDE_EFFORTS.includes(curEffort) ? curEffort : "";
  }
  f.querySelector("[name=job_ttl_days]").value =
    s.job_ttl_days != null ? s.job_ttl_days : "";
  f.querySelector("[name=job_timeout_seconds]").value =
    s.job_timeout_seconds != null ? s.job_timeout_seconds : "";
  f.querySelector("[name=worker_concurrency]").value =
    s.worker_concurrency != null ? s.worker_concurrency : "";
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
  document.getElementById("oauth-status").style.color = s.claude_oauth_detected ? "#3fb950" : "#8b949e";
  document.getElementById("auth-status").textContent = s.auth_token_set
    ? `set (${s.auth_token_masked})`
    : (s.auth_token_env_set ? "using AUTH_TOKEN from env" : "not set (auth disabled)");
}

document.getElementById("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  // Custom-text overrides the dropdown for claude_model.
  const custom = (fd.get("claude_model_custom") || "").toString().trim();
  if (custom) fd.set("claude_model", custom);
  fd.delete("claude_model_custom");

  const payload = {};
  for (const [k, v] of fd.entries()) {
    if (v === "" && (k === "anthropic_api_key" || k === "auth_token")) {
      // Empty secret field: skip — keep current value
      continue;
    }
    if (k === "enable_judge") continue;  // handled explicitly below
    if (k === "enable_exploit_library_hint") continue;  // handled explicitly below
    if (v === "") {
      payload[k] = null;  // null = clear the override
      continue;
    }
    if (k === "job_ttl_days" || k === "job_timeout_seconds" || k === "worker_concurrency") {
      payload[k] = Number(v);
    } else {
      payload[k] = v;
    }
  }
  // Checkboxes are absent from FormData when unchecked — read directly
  // so the OFF state is sent as `false`, not "clear the override".
  payload.enable_judge = !!e.target.querySelector("[name=enable_judge]").checked;
  payload.enable_exploit_library_hint = !!e.target.querySelector("[name=enable_exploit_library_hint]").checked;
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
  e.target.querySelector("[name=auth_token]").value = "";
  await loadSettings();
  alert("Saved. Changes apply to the next job.");
});

document.getElementById("settings-reload").addEventListener("click", loadSettings);

// Load settings whenever the user clicks the Settings tab
document.querySelector('.tab[data-tab="settings"]').addEventListener("click", loadSettings);

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

async function refreshStats() {
  try {
    const [statsRes, queueRes] = await Promise.all([
      fetch(`${API}/jobs/stats`),
      fetch(`${API}/jobs/queue`),
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
  } catch (_) {}
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

async function decideTimeout(jobId, decision, btn) {
  // Disable both decision buttons in the same banner
  const banner = btn.closest(".timeout-banner");
  if (banner) banner.querySelectorAll("button").forEach((b) => (b.disabled = true));
  const orig = btn.textContent;
  btn.textContent = decision === "continue" ? "▶ continuing…" : "■ stopping…";
  try {
    const res = await fetch(`${API}/jobs/${jobId}/timeout/${decision}`, { method: "POST" });
    if (!res.ok) {
      const body = await res.text();
      alert(`timeout/${decision} failed: ${res.status} ${body}`);
      if (banner) banner.querySelectorAll("button").forEach((b) => (b.disabled = false));
      btn.textContent = orig;
      return;
    }
    // Refresh the job view; meta.awaiting_decision should now be false
    // (and on 'kill', status flips to 'failed').
    await refreshJobs();
    await selectJob(jobId);
  } catch (e) {
    alert(`timeout/${decision} error: ${e}`);
    if (banner) banner.querySelectorAll("button").forEach((b) => (b.disabled = false));
    btn.textContent = orig;
  }
}

async function streamRetry(jobId, btn, manualHint = null, opts = {}) {
  // Endpoint can be /retry/stream (default) or /resume/stream — same SSE
  // protocol either way, only the stage labels differ.
  const endpoint = opts.endpoint || `${API}/jobs/${jobId}/retry/stream`;
  const flow = opts.flow || "retry";   // "retry" | "resume"
  const flowVerb = flow === "resume" ? "resume" : "retry";
  const flowEmoji = flow === "resume" ? "✋" : "↻";

  // Disable every retry button on the detail panel — only one path runs.
  const allRetryBtns = document.querySelectorAll(
    `#job-detail .retry-btn, #job-detail .retry-manual-submit, #job-detail .stop-resume-submit`,
  );
  allRetryBtns.forEach((b) => (b.disabled = true));
  const origText = btn.textContent;
  btn.textContent = `⏳ ${flowVerb}…`;
  const isManual = typeof manualHint === "string" && manualHint.length > 0;

  // Stop the regular polling so it doesn't fight our progress panel
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }

  // Tear down any in-flight inline form so it doesn't linger.
  const manualForm = document.getElementById("retry-manual-form-" + jobId);
  if (manualForm) manualForm.remove();
  const resumeForm = document.getElementById("stop-resume-form-" + jobId);
  if (resumeForm) resumeForm.remove();

  // Insert a live progress panel right above the run-log heading
  const detail = document.getElementById("job-detail");
  const panel = document.createElement("div");
  panel.className = "retry-panel";
  panel.id = "retry-panel-" + jobId;
  const headerText = isManual
    ? `${flowEmoji} ${flow === "resume" ? "Resume" : "Retry"} — your hint`
    : `${flowEmoji} ${flow === "resume" ? "Resume" : "Retry"} — reviewer in progress`;
  panel.innerHTML = `
    <h4>${headerText}</h4>
    <div class="stage"><span class="dot"></span><span class="stage-text">${isManual ? "submitting…" : "starting…"}</span></div>
    <pre class="hint-stream"></pre>
  `;
  // Place panel before the runBlock area (just under the meta line)
  const flagBanner = detail.querySelector(".flag-banner");
  const refNode = flagBanner || detail.querySelector(".file-links") || detail.querySelector("h4");
  if (refNode) refNode.parentNode.insertBefore(panel, refNode);
  else detail.appendChild(panel);

  const stageEl = panel.querySelector(".stage-text");
  const streamEl = panel.querySelector(".hint-stream");
  // Manual hint: show it immediately. Reviewer hint: wait for the first token.
  let firstToken = !isManual;
  if (isManual) streamEl.textContent = manualHint;
  else streamEl.textContent = "(awaiting reviewer output…)";

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
    streamEl.textContent = "[err] " + e;
    allRetryBtns.forEach((b) => (b.disabled = false));
    btn.textContent = origText;
    return;
  }
  if (!resp.ok) {
    const body = await resp.text();
    streamEl.textContent = `[err] ${resp.status}: ${body}`;
    allRetryBtns.forEach((b) => (b.disabled = false));
    btn.textContent = origText;
    return;
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buf = "";

  function handleEvent(name, dataStr) {
    let data = {};
    try { data = JSON.parse(dataStr); } catch (_) {}
    if (name === "stage") {
      const s = data.name;
      stageEl.textContent = ({
        halting: "halting current job…",
        gathering: "gathering prior job context…",
        asking: "asking reviewer (Opus 4.7)…",
        submitting: isManual
          ? (flow === "resume"
              ? "enqueueing fresh job (carrying ./work/) with your hint…"
              : "enqueueing new job with your hint…")
          : (flow === "resume"
              ? "enqueueing fresh job (carrying ./work/)…"
              : "enqueueing new job…"),
      })[s] || s;
    } else if (name === "token") {
      if (firstToken) { streamEl.textContent = ""; firstToken = false; }
      streamEl.textContent += data.delta || "";
      streamEl.scrollTop = streamEl.scrollHeight;
    } else if (name === "done") {
      panel.querySelector(".dot").style.animation = "none";
      panel.querySelector(".dot").style.background = "#56d364";
      stageEl.textContent = `submitted new job ${data.new_job_id}`;
      // Switch to the new job after a beat so user can read the hint
      allRetryBtns.forEach((b) => (b.disabled = false));
      btn.textContent = origText;
      setTimeout(async () => {
        await refreshJobs();
        await selectJob(data.new_job_id);
      }, 800);
    } else if (name === "error") {
      const dot = panel.querySelector(".dot");
      dot.style.background = "#f85149";
      dot.style.animation = "none";
      panel.classList.add("retry-panel-error");
      const headerEl = panel.querySelector("h4");
      if (headerEl) headerEl.textContent =
        `${flowEmoji} ${flow === "resume" ? "Resume" : "Retry"} — error (no new job created)`;
      const kind = data.kind || "error";
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
        unknown: "unknown error",
      })[kind] || kind;
      stageEl.textContent = `${kindLabel} — ${flowVerb} aborted`;
      const errMsg = (data.message || "unknown error").trim();
      // If the reviewer streamed partial text before erroring, keep it as
      // forensic context above the error block. Otherwise just show error.
      if (firstToken) {
        streamEl.textContent = errMsg;
      } else {
        streamEl.textContent += `\n\n--- ${kindLabel} ---\n${errMsg}`;
      }
      streamEl.scrollTop = streamEl.scrollHeight;
      allRetryBtns.forEach((b) => (b.disabled = false));
      btn.textContent = origText;
    }
  }

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

async function refreshJobs() {
  const res = await fetch(`${API}/jobs`);
  const data = await res.json();
  const ul = document.getElementById("jobs-list");
  ul.innerHTML = "";
  for (const job of data.jobs) {
    const li = document.createElement("li");
    li.dataset.id = job.id;
    const cost = job.cost_usd ? `· $${Number(job.cost_usd).toFixed(3)}` : "";
    const flagPill = (job.flags && job.flags.length)
      ? `<span class="flag-pill" title="${escapeHtml(job.flags.join('\n'))}">🚩 ${job.flags.length}</span>` : "";
    li.innerHTML = `<strong>${job.module}</strong> · ${escapeHtml(job.filename || "")}
      <span class="status ${job.status}">${job.status}</span>${flagPill}
      <button class="delete-btn">×</button>
      <div style="font-size:0.75rem;color:#8b949e;"><span class="jobid-text">${job.id}</span><button class="copy-jobid-btn" data-jobid="${job.id}" title="Copy job ID">⧉</button> ${cost}</div>`;
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

  // Liveness chip — ground truth from two heartbeats:
  //   A. meta.last_agent_event_at  (analyzer writes on each SDK msg, throttled 5s)
  //   B. job.rq_worker_heartbeat_at (RQ refreshes every ~10s while alive)
  //
  // Rules:
  //   worker stale (>60s)  → "dead"        red, urgent
  //   agent fresh (≤30s)   → "active"      green, live
  //   agent stale + worker fresh → "silent" amber (thinking / first-token wait)
  //   neither timestamp    → omit (queued / pre-startup / non-agent module)
  let livenessPill = "";
  if (job.status === "running") {
    const ageMs = (iso) => iso ? (Date.now() - new Date(iso).getTime()) : null;
    const agentAge = ageMs(job.last_agent_event_at);
    const workerAge = ageMs(job.rq_worker_heartbeat_at);
    const fmtAge = (ms) => {
      if (ms == null) return "?";
      const s = Math.max(0, Math.round(ms / 1000));
      if (s < 60) return `${s}s`;
      if (s < 3600) return `${Math.floor(s/60)}m`;
      return `${Math.floor(s/3600)}h`;
    };
    let cls, label, title;
    if (workerAge != null && workerAge > 60_000) {
      cls = "dead";
      label = "dead";
      title = `worker heartbeat ${fmtAge(workerAge)} ago — process likely gone`;
    } else if (agentAge != null && agentAge <= 30_000) {
      cls = "active";
      label = "active";
      title = `agent event ${fmtAge(agentAge)} ago / worker ${fmtAge(workerAge)} ago`;
    } else if (agentAge != null) {
      cls = "silent";
      label = "silent";
      title = `agent ${fmtAge(agentAge)} silent (thinking or API wait) · worker ${fmtAge(workerAge)} ago`;
    } else if (workerAge != null) {
      cls = "warming";
      label = "warming";
      title = `worker alive (${fmtAge(workerAge)} ago) · agent has not emitted yet`;
    }
    if (cls) {
      livenessPill = `<span class="liveness-pill liveness-${cls}"
        data-agent-at="${escapeHtml(job.last_agent_event_at || "")}"
        data-worker-at="${escapeHtml(job.rq_worker_heartbeat_at || "")}"
        title="${escapeHtml(title)}">● ${label}</span>`;
    }
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

  // Soft-timeout decision banner. Fires when the worker's wall-clock
  // watchdog sets meta.awaiting_decision=true. The agent is still running
  // — the user picks Continue (let it run) or Stop (hard-kill).
  let timeoutBlock = "";
  if (job.awaiting_decision) {
    const at = job.decision_at ? new Date(job.decision_at).toLocaleTimeString() : "";
    const budget = job.soft_timeout_s || job.job_timeout || "?";
    timeoutBlock = `<div class="timeout-banner" data-job-id="${id}">
      <h4>⏰ Soft timeout reached${at ? ` at ${escapeHtml(at)}` : ""}</h4>
      <div class="timeout-msg">
        The agent has been running for ~${escapeHtml(String(budget))}s and is still working.
        It will keep running until you decide. Pick one:
      </div>
      <div class="timeout-actions">
        <button class="timeout-continue-btn" data-action="continue">▶ Continue running</button>
        <button class="timeout-kill-btn" data-action="kill">■ Stop now</button>
      </div>
    </div>`;
  }

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
  const showRetry = isExploitableModule && [
    "failed", "no_flag", "finished", "stopped",
  ].includes(job.status);
  // Stop & resume: only meaningful while the job is still in flight.
  const showStopResume = isExploitableModule && (
    job.status === "queued" || job.status === "running"
  );
  // "Change target" only makes sense for modules that take a target
  // (web/pwn/crypto/rev) — same set as retry. Visible at any status.
  const showChangeTarget = isExploitableModule;
  if (
    job.runnable_script || job.exploit_present || job.solver_present
    || showRetry || showStopResume || showChangeTarget
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
    const targetHtml = showChangeTarget
      ? `<button class="retry-btn change-target-btn" data-action="change-target">✎ Change target</button>` : "";
    const helperBits = [];
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
      ${runHtml} ${targetHtml} ${retryHtml} ${continueHtml} ${stopResumeHtml}
      ${freshToggleHtml}
      <small style="color:#8b949e">${helperBits.join(" · ")}</small>
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
      ? `<small style="color:#8b949e">scanned ${c.scanned_files} log/history files</small>` : "";
    logFindingsBlock = `<div class="log-findings-panel">
      <h4>🔎 Log mining</h4>
      <div class="lf-chips">${chips}</div>
      ${scanned}
      <small style="color:#8b949e;margin-left:0.5rem">
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
      ${timingPill}
    </h3>
    <div><small>module: ${job.module} · file: ${escapeHtml(job.filename || "")} · target: ${escapeHtml(job.target_url || "(none)")}${targetExtra}${stage}${cost}${timeout}${modelInfo}</small></div>
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
    <h4>Run log <small style="color:#8b949e;font-weight:normal">(auto-follows when scrolled to bottom)</small></h4>
    <div class="run-log-window">
      <div class="run-log-titlebar">
        <span class="run-log-dot run-log-dot-r"></span>
        <span class="run-log-dot run-log-dot-y"></span>
        <span class="run-log-dot run-log-dot-g"></span>
        <span class="run-log-title">job ${escapeHtml(id)} — ${escapeHtml(job.module || "?")}</span>
        <input class="run-log-search" data-job-id="${id}" type="search"
               spellcheck="false" autocomplete="off"
               placeholder="🔎 filter log…" value="${escapeHtml(_logSearch[id] || "")}" />
        <span class="run-log-search-count" data-job-id="${id}"></span>
        <button class="run-log-tz-toggle" data-action="toggle-tz"
                title="Toggle run-log timestamps (UTC ↔ ${escapeHtml(_localTzName())})"
        >${runlogTz === "utc" ? "UTC" : "Local"}</button>
      </div>
      <pre class="run-log" data-job-id="${id}" data-status="${escapeHtml(job.status || "")}">${log ? colorizeRunLog(log, job.started_at) : "(empty)"}</pre>
      ${livenessPill || tokensPill ? `
      <div class="run-log-footer">
        ${livenessPill}
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
    retryBtn.addEventListener("click", () => openReviewerRetryForm(id, retryBtn));
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

  const continueBtn = detail.querySelector('.timeout-continue-btn[data-action="continue"]');
  if (continueBtn) {
    continueBtn.addEventListener("click", () => decideTimeout(id, "continue", continueBtn));
  }
  const killBtn = detail.querySelector('.timeout-kill-btn[data-action="kill"]');
  if (killBtn) {
    killBtn.addEventListener("click", () => decideTimeout(id, "kill", killBtn));
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
          <small style="color:#8b949e">updates meta only · run / retry afterwards picks up the new value</small>
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
      runBtn.disabled = true;
      const origText = runBtn.textContent;
      runBtn.textContent = "⏳ running…";
      try {
        const res = await fetch(`${API}/jobs/${id}/run`, { method: "POST" });
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
    pre.innerHTML = '<span style="color:#8b949e">(no matching lines)</span>';
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
refreshJobs();
refreshStats();
