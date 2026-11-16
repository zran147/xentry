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
        setMessage("Release requested - waiting for the VMs to be destroyed.");
        const label = card.querySelector(".release-state");
        if (label) label.textContent = "destroying...";
        awaitTeardown(card, button.dataset.job, button);
      } catch (error) {
        setMessage(error.message, true);
        setBusy(button, false);
      }
    });
  }
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
  setMessage(
    "Release was requested but the VMs are still up after 4 minutes - reload to check.",
    true,
  );
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
        setMessage("Destroyed - the VMs and the subnet are gone.");
        dropCard(card, "No rebuilt environments.");
      } catch (error) {
        setMessage(error.message, true);
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
});
