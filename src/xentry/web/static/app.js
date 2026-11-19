const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    "X-Xentry-CSRF": csrf,
    ...(options.headers || {}),
  };
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || data.error?.message || response.statusText);
  }
  return data;
}

function setMessage(text, isError = false) {
  const element = document.getElementById("message");
  if (!element) return;
  element.textContent = text;
  element.classList.toggle("error", isError);
  offerTheReply(element, text);
}

/* ------------------------------------------- what the model actually said --- */

// Every refusal names the check it came from - "[c7b13dfbbc184bf2b...]" - and
// that id is a directory holding the exact prompt and the exact reply. Until
// now reading it meant curl against /api/checks/<id>/log by hand, so this:
//
//   validator_error [c7b13dfb...]: extractor returned invalid JSON
//   [finish_reason=unknown, 9417 chars of reply]
//
// was the end of the road from the page that reported it, while the 9,417
// characters - a reasoning model talking itself through the extraction and
// stopping at "Final JSON." without ever writing any - sat on disk unread.
//
// A reasoning reply IS evidence: it says what the model understood the task to
// be, which is the difference between a wrong answer and a misread question.
// BRACKETED, not any 32 hex characters. A refusal names its check as
// "[c7b13dfb...]", but a path like
//   /var/lib/xentry/jobs/7132a1d9835b4b268732247b72f73928/network.xml
// also contains 32 hex characters - the JOB id - so the bare pattern offered
// to show a transcript for a job and got "no transcript for that check".
const CHECK_IN_TEXT = /\[([0-9a-f]{32})\]/;
// A bare id is still valid when something hands one over deliberately, as
// the audit page's data-check does.
const CHECK_ID = /^[0-9a-f]{32}$/;

function offerTheReply(element, text) {
  const found = CHECK_IN_TEXT.exec(String(text || ""));
  if (!found) return;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "linklike";
  button.textContent = "show what the model answered";
  button.addEventListener("click", () => showTheReply(found[1], button));
  element.append(" ", button);
}

// The plan pre-block on the submit page, or one made next to the message when
// there is none - the job page shows failures through setMessage too.
function replyPanel(button) {
  const plan = document.getElementById("plan");
  if (plan) return plan;
  let panel = document.getElementById("model-reply");
  if (!panel) {
    panel = document.createElement("pre");
    panel.id = "model-reply";
    panel.className = "plan";
    button.parentElement?.after(panel);
  }
  return panel;
}

// The job page prints a failed step's detail from the template, not through
// setMessage, so the offer has to be attached to what the server rendered:
//
//   <pre class="cmdtext">validator_error [b1f5d037...]: extractor returned
//   invalid JSON [finish_reason=unknown, 11754 chars of reply]</pre>
//
// Same button, same endpoint. A job page shows the stage transcripts under
// "Audit bundle" as well, but that is a page away and lists the job's own
// calls - this is the reply that the failure in front of you came from.
function wireRenderedDetails() {
  const seen = new Set();
  document.querySelectorAll("pre.cmdtext").forEach((block) => {
    const found = CHECK_IN_TEXT.exec(block.textContent || "");
    if (!found || seen.has(found[1])) return;
    seen.add(found[1]);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "linklike";
    button.textContent = "show what the model answered";
    button.addEventListener("click", () => showTheReply(found[1], button));
    const holder = document.createElement("p");
    holder.className = "muted";
    holder.append(button);
    block.after(holder);
  });
  // The audit page names the check the extraction ran under. Its stages render
  // in the same shape the template gives the job's own calls - heading, sizes,
  // Question, Response - because "the same thing, somewhere else" should not
  // look like a different kind of thing.
  document.querySelectorAll("[data-check-stages]").forEach((holder) => {
    const id = holder.dataset.check;
    if (id && CHECK_ID.test(id)) renderCheckStages(holder, id);
  });
}

// One stage block, built to match audit.html's loop exactly.
function stageBlock(stage, prompt, response, reasoning) {
  const frag = document.createDocumentFragment();
  const head = document.createElement("h3");
  head.className = "mono";
  head.id = `stage-${stage}`;
  head.textContent = stage;
  const aside = document.createElement("span");
  aside.className = "muted";
  aside.textContent = " - ran at check time";
  head.append(aside);
  frag.append(head);

  // NO FACTS LIST HERE. A check's transcript is files on disk with no artifact
  // row, so there is no sha256 to show - which left this list holding nothing
  // but the two lengths, directly above two carets that now carry them. The
  // same number twice, once in a place nobody reads while deciding whether to
  // open a transcript.
  // Question, Response, then Reasoning - a caret inside the stage it belongs
  // to. It was briefly its own block with its own question and answer, which
  // made one model call read as two unrelated things.
  const boxes = [["Question", prompt], ["Response", response]];
  if (reasoning) boxes.push(["Reasoning", reasoning]);
  for (const [label, text] of boxes) {
    const box = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = label;
    // Every one of them, not just Reasoning. The point of a closed caret is
    // to say whether opening it is worth it, and a reply holding nothing
    // should be distinguishable from one holding 11,754 characters without
    // clicking. "characters" rather than "bytes" because this path measures a
    // JS string from a file on disk, not a recorded artifact's byte count.
    const size = document.createElement("span");
    size.className = "muted";
    size.textContent = text ? ` \u00b7 ${text.length} characters` : " \u00b7 empty";
    summary.append(size);
    const pre = document.createElement("pre");
    pre.className = "plan";
    pre.textContent = text || "[not captured]";
    box.append(summary, pre);
    frag.append(box);
  }
  return frag;
}

async function renderCheckStages(holder, id) {
  const note = holder.querySelector("p");
  try {
    const log = await api(`/api/checks/${id}/log`);
    const items = log.items || {};
    // "extract.response.txt"           -> stage extract, part response
    // "extract.reasoning.response.txt"  -> stage extract, its reasoning
    //
    // The part is always the last field, so the stage is everything before
    // it - which is what lets a stage name carry a dot.
    const stages = new Map();
    for (const [name, text] of Object.entries(items)) {
      const bits = name.replace(/\.txt$/, "").split(".");
      const part = bits.pop();
      const stage = bits.join(".");
      if (!stage || !part) continue;
      const mind = stage.endsWith(".reasoning");
      const base = mind ? stage.slice(0, -".reasoning".length) : stage;
      const entry = stages.get(base) || { prompt: "", response: "", reasoning: "" };
      if (!mind) entry[part] = text;
      else if (part === "response") entry.reasoning = text;
      stages.set(base, entry);
    }
    if (!stages.size) {
      if (note) note.textContent = `Check ${id.slice(0, 12)} recorded nothing.`;
      return;
    }
    if (note) {
      note.textContent =
        `Ran when the links were checked, before this job existed, under check ${id.slice(0, 12)}.` +
        " A job reuses the facts its check stored rather than extracting again," +
        " so these calls belong to the check, not to the job.";
    }
    for (const stage of [...stages.keys()].sort()) {
      const { prompt, response, reasoning } = stages.get(stage);
      holder.append(stageBlock(stage, prompt, response, reasoning));
    }
  } catch (error) {
    if (note) note.textContent = `Could not load check ${id.slice(0, 12)}: ${error.message}`;
  }
}

async function showTheReply(id, button) {
  button.disabled = true;
  const was = button.textContent;
  button.textContent = "loading the transcript...";
  try {
    const log = await api(`/api/checks/${id}/log`);
    const items = log.items || {};
    const names = Object.keys(items).sort();
    const panel = replyPanel(button);
    panel.textContent = names.length
      ? names
          .map((name) => {
            const body = items[name] || "";
            // The byte count matters: a 9,417-character "reply" that holds no
            // JSON is a different failure from an empty one, and the heading
            // is where a reader sees which they have.
            // "reasoning.response.txt" is the model's thinking, which ADK
            // hands back as a separate thought part; "extract.response.txt"
            // is the answer it then gave. Naming both beats guessing.
            return `=== ${name}  (${body.length} characters)\n\n${body}`;
          })
          .join("\n\n\n")
      : "Nothing was recorded for that check.";
    panel.hidden = false;
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    button.textContent = `check ${id.slice(0, 12)} shown below`;
  } catch (error) {
    // The label is restored from what it was BEFORE this click, not from
    // whatever the last failure left behind - appending to it produced
    // "show what the model answered (failed: ...) (failed: ...)".
    //
    // A 404 means there is genuinely nothing filed under that id, so the
    // offer is withdrawn rather than left inviting another click.
    if (/no transcript/i.test(error.message || "")) {
      button.remove();
      return;
    }
    button.disabled = false;
    button.textContent = `${was} (${error.message})`;
  }
}

/* ---------------------------------------------------------------- time --- */

// Python writes datetime.now(UTC).isoformat(), which carries six fractional
// digits. Trim to milliseconds so this does not rely on engine leniency.
function parseTs(value) {
  if (!value) return null;
  const ms = Date.parse(String(value).replace(/\.(\d{3})\d+/, ".$1"));
  return Number.isNaN(ms) ? null : ms;
}

// The server writes UTC, which is right for a record and wrong for a reader:
// "2026-11-16T03:09:46.321712+00:00" makes you do timezone arithmetic to answer
// "was that before or after the thing I just did". Rendered here instead of on
// the server, because only the browser knows which zone the reader is in.
//
// The ISO string stays in data-ts, so the UTC value is still there to copy and
// still what a bug report should quote.
// 24-hour, always. toLocaleTimeString() with no options follows the locale,
// and an en-US browser renders "10:09:46 AM" - which is wider, sorts wrong by
// eye in a column, and reads badly next to the UTC timestamps the records
// keep. hour12: false pins it without hardcoding a locale, so day, month and
// separator order still follow the reader's.
const CLOCK = { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false };

function formatLocal(ms, fmt) {
  const when = new Date(ms);
  if (fmt === "time") return when.toLocaleTimeString(undefined, CLOCK);
  if (fmt === "date") return when.toLocaleDateString();
  return `${when.toLocaleDateString()} ${when.toLocaleTimeString(undefined, CLOCK)}`;
}

// Full precision and the zone name, for the tooltip: the visible text is
// shortened for a table, and this is where someone checks what it really was.
function localTitle(ms, iso) {
  const long = new Date(ms).toLocaleString(undefined, {
    ...CLOCK,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    timeZoneName: "short",
  });
  return `${long}\nUTC: ${iso}`;
}

// Converts every .ts[data-ts] under `root`. Called on load AND after each
// re-render, because the job page rebuilds its step rows from the stream.
function wireTimestamps(root) {
  const scope = root || document;
  for (const element of scope.querySelectorAll(".ts[data-ts]")) {
    const iso = element.dataset.ts;
    const ms = parseTs(iso);
    // A failed parse leaves the server's own text in place rather than
    // printing "Invalid Date" over it.
    if (ms === null) continue;
    element.textContent = formatLocal(ms, element.dataset.fmt);
    element.title = localTitle(ms, iso);
  }
}

// A step cell, which JS builds rather than the template.
function timeCell(cell, value, fmt) {
  const ms = parseTs(value);
  if (ms === null) {
    cell.textContent = value ? String(value) : "-";
    return;
  }
  cell.className = "mono ts";
  cell.dataset.ts = String(value);
  cell.textContent = formatLocal(ms, fmt || "time");
  cell.title = localTitle(ms, String(value));
}

function formatDuration(ms) {
  if (ms < 0) ms = 0;
  const total = Math.floor(ms / 1000);
  const seconds = String(total % 60).padStart(2, "0");
  const minutes = Math.floor(total / 60) % 60;
  const hours = Math.floor(total / 3600);
  if (hours > 0) return `${hours}:${String(minutes).padStart(2, "0")}:${seconds}`;
  return `${minutes}:${seconds}`;
}

// Ticks an element with the time since `start`. Returns a stop function.
function runClock(element, start) {
  if (!element) return () => {};
  const from = typeof start === "number" ? start : Date.now();
  const tick = () => {
    element.textContent = formatDuration(Date.now() - from);
  };
  tick();
  const timer = window.setInterval(tick, 1000);
  return () => window.clearInterval(timer);
}

/* ------------------------------------------------------------ progress --- */

// A progress region: an indeterminate bar plus a label. Nothing here claims a
// percentage - neither the link check nor a job run has a knowable total, so
// the bar reports "working" and the label and clock report what and how long.
function progressRegion(id) {
  const region = document.getElementById(id);
  if (!region) return null;
  const bar = region.querySelector(".progress");
  const what = region.querySelector(".what");
  const clock = region.querySelector(".elapsed");
  let stop = () => {};

  const set = (state, label, startAt) => {
    region.hidden = false;
    region.classList.remove("stale");
    bar.classList.remove("indeterminate", "complete", "failed");
    if (state) bar.classList.add(state);
    bar.setAttribute("aria-busy", state === "indeterminate" ? "true" : "false");
    if (label !== undefined) what.textContent = label;
    stop();
    stop = state === "indeterminate" ? runClock(clock, startAt) : () => {};
  };

  return {
    start: (label, startAt) => set("indeterminate", label, startAt),
    done: (label) => set("complete", label),
    fail: (label) => set("failed", label),
    label: (text) => { what.textContent = text; },
    stale: (isStale) => region.classList.toggle("stale", isStale),
    hide: () => { stop(); region.hidden = true; },
  };
}

function setBusy(button, isBusy) {
  if (!button) return;
  const spinner = button.querySelector(".spinner");
  if (spinner) spinner.hidden = !isBusy;
  button.disabled = isBusy;
}

function setStage(id, state) {
  const stage = document.getElementById(id);
  if (!stage) return;
  stage.classList.toggle("current", state === "current");
  stage.classList.toggle("done", state === "done");
}

/* ---------------------------------------------------------------- help --- */

function wireHelp() {
  const button = document.getElementById("help-button");
  const dialog = document.getElementById("help-dialog");
  const close = document.getElementById("help-close");
  if (!button || !dialog || !close) return;
  button.addEventListener("click", () => dialog.showModal());
  close.addEventListener("click", () => dialog.close());
}

/* -------------------------------------------------------------- submit --- */

// A retry arrives as ?cve=&poc=&from=. The links are filled in and the two
// stage gates are left untouched: a check is single use and expires, so a retry
// has to re-fetch and re-extract, and the plan is reviewed before anything runs.
function prefillFromQuery(cve, poc) {
  const params = new URLSearchParams(window.location.search);
  const carried = { cve: params.get("cve") || "", poc: params.get("poc") || "" };
  const http = (value) => /^https?:\/\//i.test(value);
  let filled = false;
  if (http(carried.cve)) {
    cve.value = carried.cve;
    filled = true;
  }
  if (http(carried.poc)) {
    poc.value = carried.poc;
    filled = true;
  }
  if (!filled) return;
  const from = params.get("from") || "";
  setMessage(
    from
      ? `Links loaded from job ${from.slice(0, 12)}. Check them, then start the job.`
      : "Links loaded. Check them, then start the job.",
  );
  // Drop the query string so a reload does not silently refill the form.
  window.history.replaceState({}, "", window.location.pathname);
}

// What was tried, in the order it was tried. The point of showing this is
// that approving a download is a judgement, and the operator cannot make it
// without knowing which archives were already asked.
function renderChannels(result) {
  const lines = [`${result.cve_id}: no archive carries this.`, ""];
  for (const item of result.channels || []) {
    lines.push(`tried  ${item.channel}`);
    lines.push(`       -> ${item.verdict}`);
  }
  lines.push("");
  lines.push(`This harness can install: ${(result.accepts || []).join(", ")}`);
  return lines.join("\n");
}

// Taken down whenever a check starts, because an approval belongs to the one
// check that offered it. The handler is dropped too: a detached closure over
// a stale check_id is the part that could do damage.
function hideApproval() {
  const region = document.getElementById("approval");
  const url = document.getElementById("approval-url");
  const button = document.getElementById("approval-button");
  const detail = document.getElementById("approval-detail");
  if (region) region.hidden = true;
  if (url) url.value = "";
  if (button) button.onclick = null;
  if (detail) {
    detail.textContent = "";
    detail.hidden = true;
  }
}

// The approval is of bytes, not of a URL: the host fetches the file, and the
// digest and size it reports are what the job will install.
function showApproval(result, submitButton) {
  const region = document.getElementById("approval");
  const url = document.getElementById("approval-url");
  const button = document.getElementById("approval-button");
  const detail = document.getElementById("approval-detail");
  if (!region || !url || !button) return;
  region.hidden = false;
  // An archive's own .deb for the affected version, if one was found. Filled
  // in, not submitted: the operator still reads it and still clicks Approve,
  // and can replace it. Empty leaves whatever was typed alone.
  // Every URL the job wants, one per line, so the operator reads a set and
  // deletes a line rather than approving them one decision at a time.
  if (result.suggested_urls && result.suggested_urls.length) {
    url.value = result.suggested_urls.join("\n");
    url.title = "found for the affected version; delete any line you do not want";
  }
  if (detail) {
    // Hidden until it has a digest in it. An empty box with the plan's
    // styling, sitting where the plan goes, reads as a plan that came back
    // empty - which is how this was first reported.
    detail.textContent = "";
    detail.hidden = true;
  }
  button.onclick = async () => {
    setBusy(button, true);
    try {
      const approved = await api("/api/artifacts/approve", {
        method: "POST",
        body: JSON.stringify({
          check_id: result.check_id,
          urls: url.value.split("\n").map((line) => line.trim()).filter(Boolean),
        }),
      });
      if (detail) {
        detail.textContent = (approved.files || [])
          .map((file) =>
            [
              `${file.filename}  ${file.bytes} bytes  install ${file.install}`,
              `  sha256 ${file.sha256}`,
            ].join("\n"),
          )
          .join("\n");
        detail.hidden = false;
      }
      if (submitButton) submitButton.disabled = false;
      setStage("stage-start", "current");
      setMessage(`Approved ${approved.filename}; this job will install those bytes.`);
    } catch (error) {
      setMessage(error.message, true);
    } finally {
      setBusy(button, false);
    }
  };
}

function wireSubmitPage() {
  const form = document.getElementById("submit-form");
  if (!form) return;
  const cve = document.getElementById("cve-url");
  const poc = document.getElementById("poc-url");
  const harness = document.getElementById("harness-switch");
  const checkButton = document.getElementById("check-button");
  const submitButton = document.getElementById("submit-button");
  const preflightButton = document.getElementById("preflight-button");
  const plan = document.getElementById("plan");
  const expiry = document.getElementById("check-expiry");
  const bar = progressRegion("submit-progress");
  let checkId = "";
  let expiryTimer = 0;

  prefillFromQuery(cve, poc);

  const clearExpiry = () => {
    if (expiryTimer) window.clearInterval(expiryTimer);
    expiryTimer = 0;
    if (expiry) expiry.textContent = "";
  };

  // The server rejects a stale check with 409, so count it down rather than
  // letting the user find out by pressing the button.
  const watchExpiry = (expiresAt) => {
    clearExpiry();
    const deadline = parseTs(expiresAt);
    if (!deadline || !expiry) return;
    const tick = () => {
      const left = deadline - Date.now();
      if (left <= 0) {
        clearExpiry();
        expiry.textContent = "This check has expired - check the links again.";
        checkId = "";
        submitButton.disabled = true;
        setStage("stage-start", "");
        setStage("stage-check", "current");
        bar?.fail("Check expired");
        return;
      }
      expiry.textContent = `Check valid for ${formatDuration(left)}`;
    };
    tick();
    expiryTimer = window.setInterval(tick, 1000);
  };

  checkButton.addEventListener("click", async () => {
    clearExpiry();
    plan.hidden = true;
    submitButton.disabled = true;
    checkId = "";
    // The card belongs to the check that offered it. Leaving it up means its
    // button still holds the previous check_id in its closure, so approving
    // would attach a download to a check that is expired or already used -
    // and the URL typed for the last CVE would be sitting there for the next.
    hideApproval();
    setStage("stage-check", "current");
    setStage("stage-start", "");
    setBusy(checkButton, true);
    bar?.start("Fetching both links and extracting the plan");
    setMessage("");
    try {
      const result = await api("/api/links/check", {
        method: "POST",
        body: JSON.stringify({ cve_url: cve.value, poc_url: poc.value }),
      });
      checkId = result.check_id;
      watchExpiry(result.expires_at);
      if (result.state === "needs_artifact") {
        // Not a refusal. Every channel was tried and only a download is
        // missing, so the channel table is shown as the reason and the
        // approval is offered against it - which is what makes it a last
        // resort rather than a shortcut past the archives.
        plan.textContent = renderChannels(result);
        plan.hidden = false;
        submitButton.disabled = true;
        showApproval(result, submitButton);
        setStage("stage-check", "done");
        bar?.fail("Cannot be installed from any archive");
        setMessage(result.detail, true);
        return;
      }
      plan.textContent = JSON.stringify(result.plan, null, 2);
      plan.hidden = false;
      submitButton.disabled = false;
      setStage("stage-check", "done");
      setStage("stage-start", "current");
      bar?.done(`Matched ${result.target_id}`);
      setMessage(`Target: ${result.target_id}; CVE: ${result.cve_id}`);
    } catch (error) {
      bar?.fail("Link check failed");
      setMessage(error.message, true);
    } finally {
      setBusy(checkButton, false);
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!checkId) {
      setMessage("Check the links first.", true);
      return;
    }
    setBusy(submitButton, true);
    checkButton.disabled = true;
    bar?.start("Claiming the check and queueing the job");
    setMessage("");
    try {
      const result = await api("/api/jobs", {
        method: "POST",
        body: JSON.stringify({
          cve_url: cve.value,
          poc_url: poc.value,
          check_id: checkId,
          // Read at submit, not at check: the link check is the same work for
          // both routes, so flipping the switch after checking must not need
          // the links checked again.
          harness: Boolean(harness && harness.checked),
        }),
      });
      clearExpiry();
      setStage("stage-start", "done");
      bar?.done("Job queued - opening it now");
      window.location.href = `/jobs/${result.job_id}`;
    } catch (error) {
      bar?.fail("Could not start the job");
      setMessage(error.message, true);
      setBusy(submitButton, false);
      checkButton.disabled = false;
    }
  });

  preflightButton.addEventListener("click", async () => {
    setBusy(preflightButton, true);
    try {
      const result = await api("/api/preflight", { method: "POST", body: "{}" });
      const failed = Object.entries(result.checks || {})
        .filter(([, ok]) => !ok)
        .map(([name]) => name);
      setMessage(
        result.ok ? "Preflight checks pass." : `Preflight failed: ${failed.join(", ")}`,
        !result.ok,
      );
    } catch (error) {
      setMessage(error.message, true);
    } finally {
      setBusy(preflightButton, false);
    }
  });
}

/* ----------------------------------------------------------------- job --- */

const STEP_FIELDS = ["seq", "name", "step_id", "state", "reason_code", "started_at", "finished_at"];
const PROVISION_STEP = "provision";

// The provisioning commands sit in a row beneath the provision step. The script
// is recorded before the step runs, so it stands in until the real trace
// arrives. Open by default; the reader's choice lives out here so it survives
// the re-render on every stream tick.
// Traces the runner collected, keyed by step name, plus the provisioning
// script standing in until its own trace arrives.
let stepRows = { traced: {}, plan: [] };
// Keyed so each expandable row keeps its own state, and absent means open.
const openRows = new Map();

function isOpen(key) {
  return openRows.get(key) !== false;
}

function setStepRows(commands, plan) {
  // A payload carrying neither leaves what is already shown alone.
  const hasCommands = commands && typeof commands === "object";
  if (!hasCommands && !Array.isArray(plan)) return;
  stepRows = {
    traced: hasCommands ? commands : {},
    plan: Array.isArray(plan) ? plan : [],
  };
}

function provisionMeta(count, traced) {
  const noun = count === 1 ? "command" : "commands";
  return `${count} ${noun} \u00b7 ${traced ? "run" : "not yet run"}`;
}

function attachToggle(row, detail, key) {
  if (!row || !detail) return;
  row.classList.add("expandable");
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  const paint = () => {
    detail.hidden = !isOpen(key);
    row.setAttribute("aria-expanded", String(isOpen(key)));
  };
  const toggle = () => {
    openRows.set(key, !isOpen(key));
    paint();
  };
  row.addEventListener("click", toggle);
  // A table row is not natively focusable, so it is given a tab stop and the
  // keys a button would answer to.
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggle();
    }
  });
  paint();
}

function buildCommandDetail(step) {
  const stepName = String(step.name || "");
  const collected = stepRows.traced[stepName];
  const traced = Array.isArray(collected) && collected.length > 0;
  const rows = traced ? collected : stepName === PROVISION_STEP ? stepRows.plan : [];
  if (!rows.length) return null;
  const detail = document.createElement("tr");
  detail.className = "step-detail";
  detail.dataset.detail = `cmd:${stepName}`;
  const cell = document.createElement("td");
  cell.colSpan = STEP_FIELDS.length;

  const block = document.createElement("div");
  block.className = "cmdblock";
  const title = document.createElement("p");
  title.className = "cmdblock-title";
  const name = document.createElement("span");
  name.className = "name";
  name.textContent = `${step.step_id || step.name}.sh`;
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = provisionMeta(rows.length, traced);
  title.appendChild(name);
  title.appendChild(meta);

  const list = document.createElement("ol");
  list.className = traced ? "cmdlog" : "cmdlog planned";
  for (const command of rows) {
    const item = document.createElement("li");
    // textContent: a command line is data, never markup.
    item.textContent = command;
    list.appendChild(item);
  }
  block.appendChild(title);
  block.appendChild(list);
  cell.appendChild(block);
  detail.appendChild(cell);
  return detail;
}

function buildFailureDetail(step) {
  if (!step.detail) return null;
  const detail = document.createElement("tr");
  detail.className = "step-detail";
  detail.dataset.detail = `fail:${step.seq}`;
  const cell = document.createElement("td");
  cell.colSpan = STEP_FIELDS.length;
  const block = document.createElement("div");
  block.className = "cmdblock";
  const title = document.createElement("p");
  title.className = "cmdblock-title";
  const name = document.createElement("span");
  name.className = "name";
  name.textContent = `${step.name} failed`;
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = String(step.reason_code || "no reason code");
  title.appendChild(name);
  title.appendChild(meta);
  const text = document.createElement("pre");
  text.className = "cmdtext";
  // textContent: a failure message is whatever the guest or a model emitted.
  text.textContent = String(step.detail);
  block.appendChild(title);
  block.appendChild(text);
  cell.appendChild(block);
  detail.appendChild(cell);
  return detail;
}

/* ------------------------------------ the model's session, as it runs --- */

// Harness mode only (ADR 0003). A harness job's provision row carries the
// session the model is driving: what it thought, every tool call with its
// parameters, what came back, each readiness verdict, and how it ended.
//
// The array is the feed and the DOM is a view of it. That is not a style
// choice: renderSteps() rebuilds the whole steps table on every stream tick,
// so a feed that lived only in the table would be thrown away each time the
// runner touched a step. New records are appended to both - to the array
// always, to the list when one is on the page.
//
// The records are served with their `hash` and `prev_hash`, and each line
// carries them in its tooltip. The chain is the reason this card can be
// believed: a reader can check that the sequence of commands shown is the
// sequence that ran and that nothing was spliced out of it.
let sessionEvents = [];
let sessionCursor = 0;
let sessionHarness = false;
let sessionFeed = null;
let sessionMeta = null;

// Short, because the kind is a label beside the content rather than a heading.
const SESSION_LABELS = {
  reasoning: "thinking",
  tool_call: "call",
  tool_result: "result",
  readiness: "readiness",
  declaration: "declaration",
};

// The feed's state, read and written in one place. The route decides whether
// there is a session to poll for at all, and the cursor is how far the reader
// has been served. A function rather than bare assignment because these are
// module-level `let`s: nothing outside this file can reach them otherwise, the
// node tests included.
function sessionState(patch) {
  if (patch && "harness" in patch) sessionHarness = Boolean(patch.harness);
  if (patch && "cursor" in patch) sessionCursor = Number(patch.cursor) || 0;
  return { harness: sessionHarness, cursor: sessionCursor, count: sessionEvents.length };
}

function sessionKind(record) {
  return String((record || {}).type || "").replace(/^session_/, "");
}

function sessionSpan(className, text) {
  const span = document.createElement("span");
  span.className = className;
  // textContent everywhere in this card: every field below is either a model's
  // output or a VM's, and ADR 0004 says both are untrusted data.
  span.textContent = text;
  return span;
}

// The one line of each record that is worth reading first.
function sessionBody(kind, payload) {
  if (kind === "tool_call") {
    const params = payload.params && typeof payload.params === "object" ? payload.params : {};
    // A command is the whole point of a free_exec, so it is shown as itself.
    // Anything else shows its parameters without vm_id: the tool layer
    // substitutes the job's own target VM there, so it is never news.
    if (params.command !== undefined) return String(params.command);
    const shown = { ...params };
    delete shown.vm_id;
    return JSON.stringify(shown);
  }
  if (kind === "tool_result") return String(payload.body === undefined ? "" : payload.body);
  if (kind === "reasoning") return String(payload.text === undefined ? "" : payload.text);
  if (kind === "readiness") return String(payload.detail || payload.summary || "");
  if (kind === "declaration") {
    return String(payload.summary || payload.what_was_missing || payload.script || "");
  }
  return JSON.stringify(payload);
}

// What sits to the right of the label: the small facts that say whether to
// read the body.
function sessionNote(kind, payload) {
  const parts = [];
  if (kind === "tool_result") {
    if (payload.status !== undefined && payload.status !== null) parts.push(`${payload.status}`);
    // A digest of the whole output, beside a body that is truncated. The
    // digest is what pins what was returned; the body is what you read.
    if (payload.sha256) parts.push(`sha256 ${String(payload.sha256).slice(0, 12)}`);
    if (payload.truncated) parts.push("truncated");
  }
  if (kind === "readiness") {
    parts.push(payload.passed ? "passed" : "failed");
    if (payload.reason_code) parts.push(String(payload.reason_code));
  }
  if (kind === "declaration") {
    if (payload.declaration) parts.push(String(payload.declaration));
    if (payload.reason_code) parts.push(String(payload.reason_code));
  }
  return parts.join(" · ");
}

function sessionLine(record) {
  const kind = sessionKind(record);
  const payload =
    record.payload && typeof record.payload === "object" ? record.payload : {};
  const item = document.createElement("li");
  item.className = `sessionline kind-${kind}`;
  // The chain, where a reader can find it without the audit bundle.
  item.title = `hash ${record.hash || "?"}\nprev ${record.prev_hash || "(first)"}`;

  const head = document.createElement("div");
  head.className = "sessionhead";
  const ms = parseTs(record.ts);
  if (ms !== null) head.appendChild(sessionSpan("sessionts", formatLocal(ms, "time")));
  head.appendChild(sessionSpan("sessionkind", SESSION_LABELS[kind] || kind));

  const verb = String(payload.verb || "");
  if (verb) {
    // free_exec is a logged root shell and exec is a digest-checked registered
    // step. ADR 0004: "a card where the two verbs look alike is a card that
    // hides the only thing worth noticing" - so the verb is a badge of its
    // own, and data-verb is what the stylesheet colours it by.
    const badge = sessionSpan("sessionverb", verb);
    badge.dataset.verb = verb;
    if (verb === "free_exec") badge.title = "a root shell in the target VM, recorded";
    head.appendChild(badge);
  }
  const note = sessionNote(kind, payload);
  if (note) head.appendChild(sessionSpan("sessionnote", note));

  const body = sessionBody(kind, payload);
  item.appendChild(head);
  if (body) {
    const text = document.createElement("pre");
    // Reasoning is prose and a command is code; the class decides which font
    // and which wrapping, so the two cannot be mistaken for each other.
    text.className = kind === "reasoning" ? "sessiontext prose" : "sessiontext";
    text.textContent = body;
    item.appendChild(text);
  }
  return item;
}

function paintSessionMeta() {
  if (!sessionMeta) return;
  const count = sessionEvents.length;
  sessionMeta.textContent = count
    ? `hash-chained · ${count} event${count === 1 ? "" : "s"}`
    : "hash-chained · waiting for the model's first call";
}

function appendSession(records) {
  let added = 0;
  for (const record of records || []) {
    if (!sessionKind(record)) continue;
    sessionEvents.push(record);
    added += 1;
    // Appended, not re-rendered: the reader may be part-way up a long session.
    if (sessionFeed) sessionFeed.appendChild(sessionLine(record));
  }
  if (added) paintSessionMeta();
  // Follow the tail only when the reader is already at it.
  if (added && sessionFeed) {
    const atEnd =
      sessionFeed.scrollHeight - sessionFeed.scrollTop - sessionFeed.clientHeight < 40;
    if (atEnd) sessionFeed.scrollTop = sessionFeed.scrollHeight;
  }
  return added;
}

// Rebuilt from the array on every stream tick, which is why the array exists.
function buildSessionDetail(step) {
  if (String(step.name || "") !== PROVISION_STEP) return null;
  if (!sessionHarness && sessionEvents.length === 0) return null;
  const detail = document.createElement("tr");
  detail.className = "step-detail";
  detail.dataset.detail = `session:${PROVISION_STEP}`;
  const cell = document.createElement("td");
  cell.colSpan = STEP_FIELDS.length;
  const block = document.createElement("div");
  block.className = "cmdblock";
  const title = document.createElement("p");
  title.className = "cmdblock-title";
  title.appendChild(sessionSpan("name", "model session"));
  sessionMeta = sessionSpan("meta", "");
  sessionMeta.id = "session-meta";
  title.appendChild(sessionMeta);
  const list = document.createElement("ol");
  list.className = "cmdlog sessionlog";
  list.id = "session-feed";
  for (const record of sessionEvents) list.appendChild(sessionLine(record));
  sessionFeed = list;
  paintSessionMeta();
  block.appendChild(title);
  block.appendChild(list);
  cell.appendChild(block);
  detail.appendChild(cell);
  return detail;
}

// One request, one SELECT and one sequential read of the attempt's journal.
// The cursor is an index into that whole journal, so it cannot replay a record
// it has already been served and cannot skip one written in between.
async function pollSession(jobId) {
  try {
    const data = await api(`/api/jobs/${jobId}/session?cursor=${sessionCursor}`);
    const cursor = Number(data.cursor);
    if (Number.isFinite(cursor) && cursor > sessionCursor) sessionCursor = cursor;
    return appendSession(Array.isArray(data.items) ? data.items : []);
  } catch {
    // Left alone deliberately: the feed keeps what it has and the next tick
    // retries. A failed poll is not news worth taking the page's status line
    // for, and the progress bar already says when the stream is stale.
    return 0;
  }
}

// What each step does, in one place because the steps table is built twice:
// the server renders it for a finished job, renderSteps rebuilds it while one
// runs, and a description that lived in only one of them would appear and
// disappear as the stream closed. Keyed by the step name the runner records.
const STEP_HELP = {
  fetch: "Downloads the advisory and the PoC and hashes them. A link check stores those exact bytes, so this reuses them rather than re-fetching: a page served through a CDN hashes differently every time.",
  extract: "Asks the extractor model for the facts of the CVE - product, affected range, protocol, ports, the PoC's entrypoint - with every quote checked back against the artifact it came from.",
  select_target: "Looks the CVE up among the checked-in targets. Only a rebuilt environment takes this path; a pasted CVE is derived in extract instead.",
  plan: "Records what will run before anything runs: the target, the bundle digest, and for a derived target the claims the job will be allowed to make.",
  create_network: "Creates this job's isolated bridge, with no route off it, and starts the host services the guest may reach while provisioning: the artifact mirror, the apt snapshot proxy, and the dated registry mirror.",
  create_target: "Boots the target VM from a digest-pinned image, seeded by cloud-init with two accounts and this job's keys.",
  stage_approved: "Copies the file an operator approved for this job into the target. The bytes were fetched on the host at approval time and their digest recorded with the check, so this re-verifies rather than trusts - and it runs before provisioning, because nothing can be downloaded after the network locks.",
  stage_app: "Fetches the PoC repository and copies the lab's source into the target. Only an ecosystem target does this, and it happens before the network locks because nothing can be downloaded afterwards.",
  provision: "Installs the affected software, from the apt snapshot or from the dated registry mirror. No command here comes from the advisory or the PoC: the step is a checked-in script taking validated arguments.",
  reboot: "Reboots into the pinned kernel the target needs.",
  readiness: "Proves the target is actually serving before anything is aimed at it: the ports accept, and the installed version is checked or recorded.",
  readiness_after_boot: "The same readiness check again, after the reboot, because the kernel changed underneath it.",
  create_attacker: "Boots the attacker VM on the same bridge. The PoC runs here, never on the host.",
  setup_attacker:
    "Installs what the PoC needs to run - a JDK, a compiler - on the attacker, " +
    "from Ubuntu's archive at the current serial rather than the target's. This " +
    "is the attacker's only chance: lock_network takes its network next.",
  lock_network: "Closes the provisioning channel. The mirror and both proxies stop and the firewall drops everything except the attacker reaching the target's ports - before any PoC code runs.",
  author_poc: "Asks a model to write the exploit from the advisory alone. Experimental runs only.",
  stage_poc: "Fetches the PoC repository and hands it to the broker with its digest, which the broker re-verifies.",
  copy_poc: "Copies the PoC archive into the attacker VM.",
  build_poc: "Unpacks the PoC and builds it if it declares a build. There is no network here, so a PoC whose dependencies are missing fails rather than reaching for them.",
  freeze: "Takes a memory snapshot of the target, so the run that follows can be undone and repeated from the same state.",
  null_actor: "Runs the same wrapper without the exploit. It must not produce the marker - that is what shows a later success is not the harness printing a constant.",
  probe_null: "Checks the null run's transcript for the marker. Finding it fails the job.",
  control_actor: "Runs the identical PoC against the same stack with one dependency moved to the version the advisory says fixes it. It runs before the real exploit, on a target the exploit has not touched.",
  probe_control: "Requires the control run to have failed. If the exploit also works against the fixed version, the job has not shown that the vulnerability is why it works.",
  restore: "Restores the frozen snapshot, so the real run starts from the same state the null run did.",
  fresh_boot: "Boots the target fresh instead of restoring a snapshot, for a target whose evidence depends on a clean boot.",
  real_actor: "Runs the pinned PoC for real, from the attacker, against the target.",
  target_probe: "Collects the decisive evidence and checks it against the marker that was placed on the target. For a derived target that evidence is the attacker's own transcript, which is why its authority says guest-attested.",
};

// The circle is added here rather than in the template for the same reason the
// text is: one implementation, both render paths.
function stepHelp(name) {
  const text = STEP_HELP[name];
  if (!text) return null;
  const mark = document.createElement("span");
  mark.className = "stephelp";
  mark.tabIndex = 0;
  mark.setAttribute("role", "note");
  // NO title attribute. It used to carry the same sentence as data-help, and
  // the two tooltips are drawn by different things: the CSS one opens the
  // instant you hover, the browser's native one follows about a second later -
  // so the same text appeared twice, the second time overlapping the first.
  //
  // The comment that used to be here claimed title was needed "for the
  // pointer, since the CSS tooltip only opens on keyboard focus". That was
  // wrong: style.css says
  //     .stephelp:hover::after, .stephelp:focus-visible::after
  // so the CSS tooltip already covers hover AND focus, and title was pure
  // duplication. aria-label is what a screen reader reads, and it is not
  // rendered, so it cannot collide.
  mark.setAttribute("aria-label", `${name}: ${text}`);
  mark.dataset.help = text;
  mark.textContent = "i";
  return mark;
}

// Walks children rather than running a selector, the way wireRenderedDetail
// does: the name is the second cell of any row that carries a step name.
function annotateStepNames(tbody) {
  for (const row of tbody.children || []) {
    const name = row.dataset ? row.dataset.step || "" : "";
    const cell = name && row.children ? row.children[1] : null;
    if (!cell) continue;
    const already = [...(cell.children || [])].some((kid) => kid.className === "stephelp");
    if (already) continue;
    const mark = stepHelp(name);
    if (mark) cell.appendChild(mark);
  }
}

function renderSteps(tbody, steps) {
  tbody.replaceChildren();
  for (const step of steps) {
    const row = document.createElement("tr");
    row.dataset.step = String(step.name || "");
    if (step.state === "running") row.classList.add("is-running");
    if (step.state === "failed") row.classList.add("is-failed");
    for (const field of STEP_FIELDS) {
      const cell = document.createElement("td");
      const value = step[field];
      if (field === "state") {
        const pill = document.createElement("span");
        pill.className = "pill";
        pill.dataset.status = String(value || "");
        pill.textContent = String(value || "-");
        cell.appendChild(pill);
      } else if (field === "started_at" || field === "finished_at") {
        timeCell(cell, value, "time");
      } else {
        // textContent throughout: step names and reason codes are data.
        cell.textContent = value === null || value === undefined || value === "" ? "-" : String(value);
        if (field === "step_id") cell.className = "mono";
        if (field === "name") {
          const mark = stepHelp(String(value || ""));
          if (mark) cell.appendChild(mark);
        }
      }
      row.appendChild(cell);
    }
    tbody.appendChild(row);
    // Directly under the provision row, and before the command trace, in the
    // same order the server renders them: the session is what a reader of a
    // harness job came for.
    const session = buildSessionDetail(step);
    if (session) {
      tbody.appendChild(session);
      attachToggle(row, session, `session:${step.name}`);
    }
    const commandDetail = buildCommandDetail(step);
    if (commandDetail) {
      tbody.appendChild(commandDetail);
      attachToggle(row, commandDetail, `cmd:${step.name}`);
    }
    if (step.state === "failed") {
      const detail = buildFailureDetail(step);
      if (detail) {
        tbody.appendChild(detail);
        attachToggle(row, detail, `fail:${step.seq}`);
      }
    }
  }
}

// Wires the rows the server rendered, which is all a finished job has: its
// stream has closed, so renderSteps never runs. Each detail row hangs off its
// step row, so one caret on "provision" opens everything under it.
//
// Not the row above it: a failed step emits two detail rows, the failure then
// the command trace, so the second one was pairing with the first - which put a
// caret on the "provision failed" block and made it a toggle of its own.
function wireRenderedDetail() {
  const tbody = document.getElementById("steps-body");
  if (!tbody) return;
  annotateStepNames(tbody);
  const rows = [...tbody.children];
  let owner = null;
  rows.forEach((row, index) => {
    if (!row.classList.contains("step-detail")) {
      owner = row;
      return;
    }
    attachToggle(owner, row, String(row.dataset.detail || index));
  });
}

function updateFacts(job) {
  for (const [field, value] of Object.entries(job || {})) {
    const target = document.querySelector(`[data-field="${field}"]`);
    if (!target) continue;
    const text = value === null || value === undefined || value === "" ? "-" : String(value);
    if (target.classList.contains("ts")) {
      const ms = parseTs(value);
      if (ms !== null) {
        target.dataset.ts = String(value);
        target.textContent = formatLocal(ms, target.dataset.fmt);
        target.title = localTitle(ms, String(value));
      } else {
        target.textContent = text;
      }
      continue;
    }
    const pill = target.querySelector(".pill");
    if (pill) {
      pill.textContent = text;
      pill.dataset.status = text;
    } else {
      target.textContent = text;
    }
  }
}

function wireJobPage() {
  const data = document.getElementById("job-data");
  if (!data) return;
  const jobId = data.dataset.jobId;
  const cancel = document.getElementById("cancel-button");
  const stepsBody = document.getElementById("steps-body");
  const counter = document.getElementById("step-counter");
  const bar = progressRegion("job-progress");
  wireRenderedDetail();

  // The session feed. The server renders the empty container for a harness
  // job, so this picks it up rather than building it, and renderSteps rebuilds
  // it from sessionEvents on every tick after that.
  sessionState({ harness: data.dataset.kind === "harness_job" });
  sessionFeed = document.getElementById("session-feed");
  sessionMeta = document.getElementById("session-meta");
  paintSessionMeta();
  // One read for a job that has already finished: polling stops when the job
  // ends, and the record is still worth seeing afterwards.
  if (sessionHarness) pollSession(jobId);

  if (cancel) {
    cancel.addEventListener("click", async () => {
      setBusy(cancel, true);
      try {
        await api(`/api/jobs/${jobId}/cancel`, { method: "POST", body: "{}" });
        setMessage("Cancellation requested.");
        bar?.label("Cancellation requested - finishing the current step");
      } catch (error) {
        setMessage(error.message, true);
        setBusy(cancel, false);
      }
    });
  }

  if (data.dataset.outcome) return;

  const startedAt = parseTs(data.dataset.startedAt) || parseTs(data.dataset.createdAt) || Date.now();
  bar?.start("Waiting for the first step", startedAt);

  // The server already streams {job, steps} on every change, so the page is
  // patched in place instead of polling or reloading mid-run.
  const events = new EventSource(`/api/jobs/${jobId}/events`);

  // The session is polled rather than carried on that stream (ADR 0003): the
  // endpoint is one SELECT and one sequential read, the feed only has to keep
  // up with one model's calls, and a dropped poll costs nothing because the
  // cursor is where the reader got to rather than where the stream was.
  const sessionTimer = sessionHarness ? window.setInterval(() => pollSession(jobId), 2000) : 0;

  events.addEventListener("state", (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }
    bar?.stale(false);
    const steps = Array.isArray(payload.steps) ? payload.steps : [];
    const job = payload.job || {};

    setStepRows(payload.commands, payload.plan);
    if (stepsBody) renderSteps(stepsBody, steps);
    updateFacts(job);

    const done = steps.filter((step) => step.state !== "running").length;
    const running = steps.find((step) => step.state === "running");
    if (counter) {
      counter.textContent = done === 1 ? "1 step complete" : `${done} steps complete`;
    }

    if (job.outcome) {
      events.close();
      // Polling stops with the job. One last read first, for whatever the
      // model emitted between the final tick and the outcome.
      window.clearInterval(sessionTimer);
      if (sessionHarness) pollSession(jobId);
      const failed = job.outcome !== "completed" && job.outcome !== "passed";
      if (failed) {
        bar?.fail(`Finished: ${job.outcome}`);
      } else {
        bar?.done(`Finished: ${job.outcome}`);
      }
      setMessage("Job finished - loading the results.");
      window.setTimeout(() => window.location.reload(), 1200);
      return;
    }

    if (running) {
      bar?.label(`Running: ${running.name}`);
    } else {
      bar?.label(job.started_at ? "Between steps" : "Queued - waiting for the runner");
    }
  });

  // EventSource retries on its own; say so rather than looking frozen.
  events.addEventListener("error", () => {
    bar?.stale(true);
    bar?.label("Connection lost - reconnecting");
  });
}

/* ------------------------------------------------------------ held VMs --- */

function wireHeldVms() {
  const cards = document.querySelectorAll("[data-held-job]");
  for (const card of cards) {
    const ttl = card.querySelector(".ttl");
    const heldAt = parseTs(card.dataset.heldAt);
    const holdSeconds = Number(card.dataset.holdS) || 0;
    // A negative hold has no deadline, so there is nothing to count down.
    if (ttl && heldAt && holdSeconds > 0) {
      // The runner stores when the hold began and how long it lasts; the
      // countdown is derived here rather than stored.
      const expiresAt = heldAt + holdSeconds * 1000;
      const tick = () => {
        const left = expiresAt - Date.now();
        ttl.textContent = left > 0 ? formatDuration(left) : "now";
      };
      tick();
      window.setInterval(tick, 1000);
    }

    const button = card.querySelector("button.release");
    if (!button) continue;
    button.addEventListener("click", async () => {
      setBusy(button, true);
      try {
        await api(`/api/jobs/${button.dataset.job}/release`, {
          method: "POST",
          body: "{}",
        });
        // No page-wide message. The card has its own status slot, two lines
        // down, and a sentence about THIS card rendered at the top of the page
        // is a sentence about something the reader is not looking at.
        cardState(card, "destroying - waiting for the VMs to be gone");
        awaitTeardown(card, button.dataset.job, button);
      } catch (error) {
        // The failure belongs to this card as much as the progress does.
        cardState(card, error.message, true);
        setBusy(button, false);
      }
    });
  }
}

// A card's status goes IN the card. vms.html gives the held card a
// .release-state span for exactly this; the rebuilt card has none, so one is
// made next to its button. Anything else ends up in the page-wide message
// strip at the top, describing a card the reader is not looking at - which is
// what "Release requested - waiting for the VMs to be destroyed." did.
function cardState(card, text, isError = false) {
  let slot = card.querySelector(".release-state");
  if (!slot) {
    slot = document.createElement("span");
    slot.className = "muted release-state";
    const row = card.querySelector(".row span") || card.querySelector(".row");
    row?.prepend(slot);
  }
  slot.textContent = text;
  slot.classList.toggle("error", isError);
}

/* ----------------------------------------------------------- copying --- */

// navigator.clipboard exists only in a secure context, and this app is served
// over plain http on the LAN, so outside localhost it is undefined. The
// textarea path is not a fallback here - it is the one that runs.
function copyWithTextarea(text) {
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.top = "-1000px";
  document.body.appendChild(area);
  area.select();
  let copied = false;
  try {
    copied = document.execCommand("copy") === true;
  } catch (error) {
    copied = false;
  }
  area.remove();
  return copied;
}

async function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      // Denied or unavailable: fall through rather than report success.
    }
  }
  return copyWithTextarea(text);
}

function wireCopyButtons() {
  for (const block of document.querySelectorAll(".copyable")) {
    const button = block.querySelector("button.copy");
    const pre = block.querySelector("pre");
    if (!button || !pre) continue;
    button.addEventListener("click", async () => {
      const copied = await copyText(pre.textContent || "");
      // Says what happened. A button that says "Copied" when nothing was
      // copied is worse than no button.
      button.textContent = copied ? "Copied" : "Select it and press ctrl+c";
      button.classList.toggle("failed", !copied);
      window.setTimeout(() => {
        button.textContent = "Copy";
        button.classList.remove("failed");
      }, 2000);
    });
  }
}

/* ------------------------------------------------------- VM cards --- */

// Collapsed, a card shows only its id, its CVE and its one action, so a page
// with several VMs on it stays readable. Expanded is the default: the facts are
// the reason to open the page at all.
function setCard(card, open) {
  const toggle = card.querySelector("button.cardtoggle");
  const body = card.querySelector(".cardbody");
  if (!toggle || !body) return;
  body.hidden = !open;
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
}

function cardIsOpen(card) {
  const toggle = card.querySelector("button.cardtoggle");
  return !!toggle && toggle.getAttribute("aria-expanded") !== "false";
}

function wireVmCards() {
  const cards = document.querySelectorAll("[data-section]");
  for (const card of cards) {
    const toggle = card.querySelector("button.cardtoggle");
    if (!toggle) continue;
    setCard(card, true);
    toggle.addEventListener("click", () => setCard(card, !cardIsOpen(card)));
  }
  for (const button of document.querySelectorAll("button.collapse-all")) {
    button.addEventListener("click", () => {
      const section = button.dataset.section;
      const mine = [...document.querySelectorAll("[data-section]")].filter(
        (card) => card.dataset.section === section
      );
      // One button for both directions: collapse while anything is open, then
      // put them back.
      const open = mine.some(cardIsOpen);
      for (const card of mine) setCard(card, !open);
      button.textContent = open ? "Expand all" : "Collapse all";
    });
  }
}

/* ------------------------------------------------------ experimental --- */

function wireExperimentForm() {
  const form = document.getElementById("experiment-form");
  if (!form) return;
  const button = document.getElementById("experiment-button");
  const field = document.getElementById("experiment-cve");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const cveUrl = (field && field.value ? field.value : "").trim();
    if (!cveUrl) {
      setMessage("A CVE link is needed.", true);
      return;
    }
    setBusy(button, true);
    try {
      const queued = await api("/api/experiments", {
        method: "POST",
        body: JSON.stringify({ cve_url: cveUrl }),
      });
      setMessage(`Queued ${queued.job_id} - a model is writing the PoC.`);
      window.setTimeout(() => window.location.reload(), 2000);
    } catch (error) {
      setMessage(error.message, true);
      setBusy(button, false);
    }
  });
}

/* ------------------------------------------------------- rebuilt VMs --- */

function wireRebuildForm() {
  const form = document.getElementById("rebuild-form");
  if (!form) return;
  const button = document.getElementById("rebuild-button");
  const select = document.getElementById("rebuild-source");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!select || !select.value) {
      setMessage("Choose what to rebuild.", true);
      return;
    }
    setBusy(button, true);
    try {
      const queued = await api("/api/environments", {
        method: "POST",
        body: JSON.stringify({ job_id: select.value }),
      });
      // One runner: a rebuild behind a running or held job waits for it.
      setMessage(
        queued.waiting_for
          ? "Queued behind a running job - it starts once that job is released."
          : "Queued - the VMs come up once the build finishes."
      );
      window.setTimeout(() => window.location.reload(), 2000);
    } catch (error) {
      setMessage(error.message, true);
      setBusy(button, false);
    }
  });
}

// Removes a card and, if its section is now empty, says so - otherwise the
// last card leaves behind a heading with nothing under it.
function dropCard(card, emptyText) {
  const section = card.dataset.section;
  card.remove();
  if (!section) return;
  const left = document.querySelectorAll(
    `div.held[data-section="${section}"]`,
  ).length;
  const count = document.querySelector(`[data-count="${section}"]`);
  if (count) count.textContent = String(left);
  if (left > 0) return;
  const collapse = document.querySelector(`button.collapse-all[data-section="${section}"]`);
  if (collapse) collapse.hidden = true;
  const note = document.createElement("p");
  note.className = "muted";
  note.textContent = emptyText;
  const heading = document.querySelector(`[data-section-heading="${section}"]`);
  if (heading && heading.parentNode) {
    heading.parentNode.appendChild(note);
  }
}

// Waits for the job to actually finish, then drops the card. "Release and
// destroy" only WRITES A MARKER - the runner notices it, tears the VMs down
// and then validates - so the 200 means "asked", not "gone". Hiding the card
// on click would claim a teardown that has not happened; polling until the job
// has an outcome makes the card's disappearance mean what a reader assumes it
// means.
// "held" is reported for a job whose steps have passed while its VMs are
// still up. The states that mean "nothing more will happen here" are the
// outcomes; held is not one of them, which is why the teardown watcher
// below keeps polling through it.
const FINISHED = new Set(["completed", "failed", "cancelled", "interrupted"]);

async function awaitTeardown(card, jobId, button) {
  const label = card.querySelector(".release-state");
  for (let attempt = 0; attempt < 120; attempt += 1) {
    await new Promise((resolve) => window.setTimeout(resolve, 2000));
    let job = null;
    try {
      const payload = await api(`/api/jobs/${jobId}`);
      job = payload && payload.job;
    } catch (error) {
      // A read that fails is not a teardown that failed; keep waiting and let
      // the deadline below be the thing that gives up.
      continue;
    }
    if (job && job.outcome) {
      // No message. The card going away IS the signal, and the banner this
      // used to write appeared outside the card it was about. The timeout
      // path below still speaks, because VMs that are STILL UP after four
      // minutes is the case a reader cannot see for themselves.
      dropCard(card, "No held VMs.");
      return;
    }
    if (label) label.textContent = "destroying...";
  }
  // Still held after four minutes: say so rather than leaving a stuck spinner.
  // In the card, like every other thing said about a card - this was the last
  // one writing to the page-wide strip, and the card is still on screen in
  // exactly this case, so there is nowhere better for it to go.
  cardState(card, "still up after 4 minutes - reload to check", true);
  if (button) setBusy(button, false);
}

function wireEnvironments() {
  for (const card of document.querySelectorAll("[data-env-job]")) {
    const button = card.querySelector("button.destroy-env");
    if (!button) continue;
    button.addEventListener("click", async () => {
      setBusy(button, true);
      try {
        await api(`/api/environments/${button.dataset.job}/destroy`, {
          method: "POST",
          body: "{}",
        });
        // Unlike release, this endpoint destroys before it answers:
        // destroy_environment() runs synchronously and only returns
        // {"destroyed": true} if it did not raise. So the card can go now -
        // the 200 is the backend confirmation, not a request for one.
        // Same reason the release banner went: the card vanishing IS the
        // signal, and this sentence described a card that was no longer on
        // screen to be described.
        dropCard(card, "No rebuilt environments.");
      } catch (error) {
        cardState(card, error.message, true);
        setBusy(button, false);
      }
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  wireHelp();
  wireSubmitPage();
  wireJobPage();
  wireHeldVms();
  wireVmCards();
  wireCopyButtons();
  wireExperimentForm();
  wireRebuildForm();
  wireEnvironments();
  wireTimestamps();
  wireRenderedDetails();
});
