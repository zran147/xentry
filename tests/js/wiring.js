// wireJobPage is the real entry point, and the only thing that makes a
// server-rendered provision row clickable. Driven by tests/test_frontend.py.
const { load, makeEl } = require("./dom.js");

const path = process.argv[2];
let failures = 0;
process.on("exit", (code) => {
  if (code !== 0) return;
  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
});
const check = (name, cond, detail = "") => {
  if (cond) {
    console.log(`PASS ${name}`);
    return;
  }
  failures += 1;
  console.log(`FAIL ${name} ${detail}`);
  // Set here, not in the exit handler: process.exitCode assigned while
  // exiting is ignored, so the summary would read "1 FAILURE(S)" and the
  // run would still report success.
  process.exitCode = 1;
};

// Build the page a finished job renders: no stream, so only wireRenderedDetail
// can attach the toggle.
function buildPage(document) {
  const jobData = makeEl("div");
  jobData.dataset.jobId = "job-1";
  jobData.dataset.outcome = "failed";
  jobData.dataset.createdAt = "2026-11-12T07:00:00+00:00";
  document.byId["job-data"] = jobData;

  const progress = makeEl("div");
  const bar = makeEl("div");
  bar.className = "progress";
  const what = makeEl("span");
  what.className = "what";
  const elapsed = makeEl("span");
  elapsed.className = "elapsed";
  progress.appendChild(bar);
  progress.appendChild(what);
  progress.appendChild(elapsed);
  progress.querySelector = (sel) =>
    sel === ".progress" ? bar : sel === ".what" ? what : sel === ".elapsed" ? elapsed : null;
  document.byId["job-progress"] = progress;

  const tbody = makeEl("tbody");
  tbody.id = "steps-body";
  document.byId["steps-body"] = tbody;

  const provision = makeEl("tr");
  provision.dataset.step = "provision";
  const seqCell = makeEl("td");
  seqCell.textContent = "6";
  provision.appendChild(seqCell);

  // A failed step renders two detail rows: the failure, then the command
  // trace. Both belong to the provision row above them.
  const failDetail = makeEl("tr");
  failDetail.className = "step-detail";
  failDetail.dataset.detail = "fail:6";

  const detail = makeEl("tr");
  detail.className = "step-detail";
  detail.dataset.detail = "provision";

  tbody.appendChild(provision);
  tbody.appendChild(failDetail);
  tbody.appendChild(detail);
  document.root.appendChild(tbody);
  return { provision, failDetail, detail };
}

const { context, document } = load(path, ["message", "cancel-button"]);
const { provision, failDetail, detail } = buildPage(document);

check("wireJobPage is defined", typeof context.wireJobPage === "function");
context.wireJobPage();

check("the provision row is made expandable", provision.classList.contains("expandable"));
check("the provision row gets a tab stop", provision.tabIndex === 0);
check("the provision row announces itself as a button",
  provision.getAttribute("role") === "button");
check("it starts expanded", detail.hidden === false);
check("aria-expanded starts true", provision.getAttribute("aria-expanded") === "true");

provision.dispatch("click");
check("a click collapses it", detail.hidden === true);
check("aria-expanded follows the click", provision.getAttribute("aria-expanded") === "false");

provision.dispatch("click");
check("a second click expands it", detail.hidden === false);

provision.dispatch("keydown", { key: "Enter", preventDefault() {} });
check("Enter collapses it", detail.hidden === true);

// The "provision failed" block is a detail row, not a step row: pairing each
// detail with the row above it made this one a toggle of its own, which drew a
// caret inside the failure block.
check("the failure block is not itself expandable",
  !failDetail.classList.contains("expandable"));
check("the failure block gets no tab stop", failDetail.tabIndex !== 0);
check("the failure block claims no role", failDetail.getAttribute("role") === null);
check("one row drives both details", failDetail.hidden === true && detail.hidden === true);

provision.dispatch("click");
check("and opens both again", failDetail.hidden === false && detail.hidden === false);


// --- the information circle beside each step name -------------------------
// The steps table is built twice: the server renders it for a finished job and
// renderSteps rebuilds it while one runs. A description in only one of them
// would appear and vanish as the stream closed, so both paths are driven here.
const markOf = (row) =>
  [...((row.children[1] || {}).children || [])].find((kid) => kid.className === "stephelp");

{
  const live = load(path, ["steps-body", "message"]);
  const tbody = live.document.byId["steps-body"];
  live.context.renderSteps(tbody, [
    { seq: 1, name: "fetch", step_id: null, state: "passed", reason_code: null },
    { seq: 7, name: "provision", step_id: "setup-npm", state: "running", reason_code: null },
    { seq: 99, name: "a_step_nobody_described", step_id: null, state: "passed", reason_code: null },
  ]);
  const rows = tbody.children.filter((row) => row.dataset && row.dataset.step);
  check("renderSteps marks a known step", Boolean(markOf(rows[0])));
  check("the mark is a circled i", markOf(rows[0]).textContent === "i");
  check(
    "the mark carries the description for the CSS tooltip",
    (markOf(rows[0]).dataset.help || "").includes("Downloads the advisory"),
  );
  check(
    "and for a screen reader, named",
    (markOf(rows[0]).getAttribute("aria-label") || "").startsWith("fetch:"),
  );
  check("and it can be reached by keyboard", markOf(rows[0]).tabIndex === 0);
  // ONE rendered tooltip. title used to carry the same sentence as data-help,
  // and the browser draws a title about a second after CSS draws ::after, so
  // the description appeared twice - the second time over the first. The CSS
  // rule covers :hover AND :focus-visible, so nothing is lost by dropping it.
  check("and no second, delayed tooltip", !markOf(rows[0]).title);
  check("a step with no description gets no mark", markOf(rows[2]) === undefined);
  check(
    "the name itself is still the cell's text",
    rows[1].children[1].textContent === "provision",
  );
}

{
  // The server-rendered path, through wireJobPage -> annotateStepNames.
  const served = load(path, ["steps-body", "message", "job-data", "job-progress", "step-counter"]);
  const jobData = makeEl("div");
  jobData.dataset.jobId = "job-2";
  jobData.dataset.outcome = "completed";
  served.document.byId["job-data"] = jobData;
  served.document.byId["job-progress"].querySelector = () => null;
  const tbody = served.document.byId["steps-body"];
  const row = makeEl("tr");
  row.dataset.step = "lock_network";
  const seq = makeEl("td");
  seq.textContent = "10";
  const name = makeEl("td");
  name.textContent = "lock_network";
  row.appendChild(seq);
  row.appendChild(name);
  tbody.appendChild(row);
  served.document.root.appendChild(tbody);

  served.context.wireJobPage();
  check("a server-rendered row is annotated on load", Boolean(markOf(row)));
  check(
    "with the description of that step",
    (((markOf(row) || {}).dataset || {}).help || "").includes(
      "Closes the provisioning channel",
    ),
  );
  served.context.wireJobPage();
  const marks = [...(name.children || [])].filter((kid) => kid.className === "stephelp");
  check("and not annotated twice", marks.length === 1);
}


// --- the approval card belongs to one check -------------------------------
// Clicking Check links again must take it down. Left up, its button still
// holds the previous check_id in its closure, so an approval would attach a
// download to a check that is expired or already used - and the URL typed for
// the last CVE would be sitting there for the next one.
{
  const { context, document } = load(path, [
    "approval", "approval-url", "approval-button", "approval-detail",
  ]);
  const region = document.byId["approval"];
  const url = document.byId["approval-url"];
  const button = document.byId["approval-button"];
  const detail = document.byId["approval-detail"];

  // The state a needs_artifact check leaves behind.
  context.showApproval({ check_id: "stale", channels: [], accepts: [] }, null);
  check("the card is shown for a needs_artifact check", region.hidden === false);
  check("and its button is wired", typeof button.onclick === "function");
  url.value = "https://example.invalid/old.tar.gz";
  detail.textContent = "sha256 abc";
  detail.hidden = false;

  context.hideApproval();
  check("a new check hides the card", region.hidden === true);
  check("the typed url is cleared", url.value === "");
  check("the digest box is cleared", detail.textContent === "");
  check("the digest box is hidden", detail.hidden === true);
  // The closure over the old check_id is what could actually do damage.
  check("the stale handler is dropped", button.onclick === null);
}

// --- the approval input is prefilled from the plan -------------------------
// An archive's own .deb for the affected version, offered rather than used:
// the field is filled, the operator still reads it and still clicks Approve.
{
  const { context, document } = load(path, [
    "approval", "approval-url", "approval-button", "approval-detail",
  ]);
  const url = document.byId["approval-url"];

  context.showApproval(
    {
      check_id: "c1",
      channels: [],
      accepts: [],
      suggested_urls: [
        "https://snapshot.debian.org/file/d2e9d4de",
        "https://raw.githubusercontent.com/o/r/HEAD/000-default.conf",
      ],
    },
    null,
  );
  check(
    "every suggested url is filled in, one per line",
    url.value ===
      "https://snapshot.debian.org/file/d2e9d4de\n" +
        "https://raw.githubusercontent.com/o/r/HEAD/000-default.conf",
    `got ${url.value}`,
  );

  // And a check with no suggestion must not wipe what the operator typed.
  url.value = "https://vendor.example/mine.tar.gz";
  context.showApproval({ check_id: "c2", channels: [], accepts: [] }, null);
  check(
    "no suggestions leave typed urls alone",
    url.value === "https://vendor.example/mine.tar.gz",
    `got ${url.value}`,
  );
}
