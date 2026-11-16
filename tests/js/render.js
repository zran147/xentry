// The browser code, exercised against a minimal DOM. Driven by
// tests/test_frontend.py.
//
// app.js is a plain script rather than a module, so it is evaluated in a vm
// context and its top-level functions are read back off that context.
const { load, makeEl } = require("./dom.js");

const path = process.argv[2];
let failures = 0;
const check = (name, cond, detail = "") => {
  if (cond) console.log(`PASS ${name}`);
  else { failures += 1; console.log(`FAIL ${name} ${detail}`); }
};

// ---------------------------------------------------- provisioning commands
{
  const { context, document } = load(path, ["steps-body", "message"]);
  const tbody = document.byId["steps-body"];
  const steps = [
    { seq: 5, name: "create_target", state: "passed" },
    { seq: 6, name: "provision", step_id: "setup-php", state: "running" },
    { seq: 7, name: "readiness", state: "passed" },
  ];
  const detailOf = () => tbody.children[2];
  const parentOf = () => tbody.children[1];
  const cellOf = () => detailOf().children[0];
  const blockOf = () => cellOf().children[0];
  const listOf = () => blockOf().children[1];
  const nameOf = () => blockOf().children[0].children[0];
  const metaOf = () => blockOf().children[0].children[1];
  const DOT = "\u00b7";

  context.setStepRows({}, []);
  context.renderSteps(tbody, steps);
  check("no detail row when there are no commands", tbody.children.length === 3);

  context.setStepRows({}, ["set -eu", "make -j4"]);
  context.renderSteps(tbody, steps);
  check("a detail row is added", tbody.children.length === 4);
  check("it sits directly after the provision row", detailOf().classList.contains("step-detail"));
  check("the row above it is provision", parentOf().dataset.step === "provision");
  check("the commands row is keyed to the step", detailOf().dataset.detail === "cmd:provision");
  check("the detail spans every column", cellOf().colSpan === 7);
  check("the commands sit in an editor block", blockOf().classList.contains("cmdblock"));
  check("the block is titled with the step script", nameOf().textContent === "setup-php.sh",
    nameOf().textContent);
  check("it is open by default", detailOf().hidden === false);
  check("aria-expanded says open", parentOf().getAttribute("aria-expanded") === "true");
  check("the provision row takes a tab stop", parentOf().tabIndex === 0);
  check("the provision row is marked expandable", parentOf().classList.contains("expandable"));
  check("plan rows are dimmed", listOf().className.includes("planned"));
  check("the plan meta says it has not run",
    metaOf().textContent === `2 commands ${DOT} not yet run`, metaOf().textContent);

  parentOf().dispatch("click");
  check("clicking the provision row collapses it", detailOf().hidden === true);
  check("aria-expanded says collapsed", parentOf().getAttribute("aria-expanded") === "false");

  parentOf().dispatch("click");
  check("clicking it again expands it", detailOf().hidden === false);

  // The stream re-renders the table on every tick; the reader's choice must
  // survive that.
  parentOf().dispatch("click");
  check("collapsed before the re-render", detailOf().hidden === true);
  context.renderSteps(tbody, steps);
  check("still collapsed after a re-render", detailOf().hidden === true);
  check("aria survives the re-render", parentOf().getAttribute("aria-expanded") === "false");

  let prevented = false;
  parentOf().dispatch("keydown", { key: "Enter", preventDefault() { prevented = true; } });
  check("Enter toggles", detailOf().hidden === false);
  check("Enter's default is prevented", prevented === true);
  parentOf().dispatch("keydown", { key: " ", preventDefault() {} });
  check("Space toggles", detailOf().hidden === true);
  parentOf().dispatch("keydown", { key: "a", preventDefault() {} });
  check("another key does nothing", detailOf().hidden === true);
  parentOf().dispatch("click");

  context.setStepRows({ provision: ["+ set -eu", "+ make -j4", "+ make install"] }, ["set -eu"]);
  context.renderSteps(tbody, steps);
  check("a trace wins over the plan", listOf().className === "cmdlog");
  check("the trace meta says run",
    metaOf().textContent === `3 commands ${DOT} run`, metaOf().textContent);
  check("the trace renders every line", listOf().children.length === 3);

  context.setStepRows(undefined, undefined);
  context.renderSteps(tbody, steps);
  check("a payload with neither list leaves the rows alone",
    metaOf().textContent === `3 commands ${DOT} run`);

  context.setStepRows({ provision: ["<b>x</b>"] }, []);
  context.renderSteps(tbody, steps);
  check("a command is text, never markup",
    listOf().children[0].textContent === "<b>x</b>");
  check("one command reads singular",
    metaOf().textContent === `1 command ${DOT} run`, metaOf().textContent);
}

// ------------------------------------------------ a traced run-poc step
{
  const { context, document } = load(path, ["steps-body", "message"]);
  const tbody = document.byId["steps-body"];
  const steps = [
    { seq: 6, name: "provision", step_id: "setup-php", state: "passed" },
    { seq: 15, name: "real_actor", step_id: "run-poc-php", state: "passed" },
  ];
  context.setStepRows(
    { provision: ["+ make -j4"], real_actor: ["+ gcc -O0 -o exp exp.c", "+ ./exp"] },
    ["set -eu"],
  );
  context.renderSteps(tbody, steps);
  check("both traced steps get a row", tbody.children.length === 4,
    `got ${tbody.children.length}`);
  const pocDetail = tbody.children[3];
  check("the run-poc row is keyed to its step", pocDetail.dataset.detail === "cmd:real_actor");
  const pocBlock = pocDetail.children[0].children[0];
  check("it is titled with the poc step script",
    pocBlock.children[0].children[0].textContent === "run-poc-php.sh",
    pocBlock.children[0].children[0].textContent);
  check("it lists the commands the poc ran",
    pocBlock.children[1].children.map((c) => c.textContent).join(" ; ")
      === "+ gcc -O0 -o exp exp.c ; + ./exp");
  check("a traced step is not dimmed", pocBlock.children[1].className === "cmdlog");

  // A step with no trace and no plan gets nothing.
  context.setStepRows({ real_actor: ["+ ./exp"] }, []);
  context.renderSteps(tbody, steps);
  check("an untraced step with no plan gets no row", tbody.children.length === 3,
    `got ${tbody.children.length}`);
}

// --------------------------------------------------- failed step messages
{
  const { context, document } = load(path, ["steps-body", "message"]);
  const tbody = document.byId["steps-body"];
  const steps = [
    { seq: 6, name: "provision", step_id: "setup-php", state: "passed" },
    {
      seq: 7, name: "readiness", step_id: "readiness-php", state: "failed",
      reason_code: "target_unhealthy", detail: "trace: Permission denied",
    },
  ];
  context.setStepRows({}, ["set -eu"]);
  context.renderSteps(tbody, steps);

  // provision, its commands, readiness, its message
  check("a failed step gets a message row", tbody.children.length === 4,
    `got ${tbody.children.length}`);
  const failRow = () => tbody.children[2];
  const failDetail = () => tbody.children[3];
  const failBlock = () => failDetail().children[0].children[0];
  check("the failed row is expandable", failRow().classList.contains("expandable"));
  check("the message row is keyed to the step", failDetail().dataset.detail === "fail:7");
  check("the message is open by default", failDetail().hidden === false);
  check("the block names the step",
    failBlock().children[0].children[0].textContent === "readiness failed");
  check("the block shows the reason code",
    failBlock().children[0].children[1].textContent === "target_unhealthy");
  check("the message is text, never markup",
    failBlock().children[1].textContent === "trace: Permission denied");

  // Each row keeps its own state.
  failRow().dispatch("click");
  check("collapsing the failure leaves provisioning open",
    failDetail().hidden === true && tbody.children[1].hidden === false);
  tbody.children[0].dispatch("click");
  check("collapsing provisioning leaves the failure collapsed",
    tbody.children[1].hidden === true && failDetail().hidden === true);
  context.renderSteps(tbody, steps);
  check("both states survive a re-render",
    tbody.children[1].hidden === true && tbody.children[3].hidden === true);

  context.setStepRows({}, []);
  context.renderSteps(tbody, [
    { seq: 7, name: "readiness", state: "failed", reason_code: "x", detail: null },
  ]);
  check("a failed step with no message gets no row", tbody.children.length === 1,
    `got ${tbody.children.length}`);
}

// ------------------------------------------------------------- timestamps
{
  const { context } = load(path, ["message"]);
  const parseTs = context.parseTs;
  const fd = context.formatDuration;

  // Python writes datetime.now(UTC).isoformat(), which carries six fractional
  // digits; the spec allows three.
  check("parseTs handles 6-digit fractions",
    parseTs("2026-11-12T03:49:46.841064+00:00") === Date.parse("2026-11-12T03:49:46.841Z"));
  check("parseTs handles no fraction",
    parseTs("2026-11-12T03:49:46+00:00") === Date.parse("2026-11-12T03:49:46Z"));
  check("parseTs returns null on junk", parseTs("not a date") === null);
  check("parseTs returns null on empty", parseTs("") === null && parseTs(null) === null);

  check("formatDuration m:ss", fd(65 * 1000) === "1:05", fd(65 * 1000));
  check("formatDuration zero", fd(0) === "0:00", fd(0));
  check("formatDuration clamps negative", fd(-500) === "0:00", fd(-500));
  check("formatDuration h:mm:ss", fd(3725 * 1000) === "1:02:05", fd(3725 * 1000));
  check("formatDuration 30 minutes", fd(1800 * 1000) === "30:00", fd(1800 * 1000));
}

// ------------------------------------------------------------- steps table
{
  const { context, document } = load(path, ["steps-body", "message"]);
  const body = document.byId["steps-body"];
  context.renderSteps(body, [
    { seq: 1, name: "fetch", step_id: null, state: "passed",
      reason_code: null, started_at: "t1", finished_at: "t2" },
    { seq: 6, name: "provision", step_id: "setup-php", state: "running",
      reason_code: null, started_at: "t3", finished_at: null },
  ]);
  check("renderSteps makes a row per step", body.children.length === 2);
  const row = body.children[1];
  check("a running row is marked", row.classList.contains("is-running"));
  check("an empty cell becomes a dash", row.children[6].textContent === "-");
  check("the state cell holds a pill", row.children[3].children.length === 1);
  check("the pill carries the status", row.children[3].children[0].dataset.status === "running");

  context.renderSteps(body, []);
  check("renderSteps clears on empty", body.children.length === 0);

  context.renderSteps(body, [{ seq: 1, name: "<b>x</b>", state: "passed" }]);
  check("a step name is text, never markup",
    body.children[0].children[1].textContent === "<b>x</b>");
}

// ------------------------------------------------------------------- facts
{
  const { context, document } = load(path, ["message"]);
  const cell = makeEl("dd");
  const pill = makeEl("span");
  pill.dataset.status = "queued";
  pill.textContent = "queued";
  cell.querySelector = () => pill;
  document.fields["state"] = cell;
  document.fields["finished_at"] = makeEl("dd");

  context.updateFacts({ state: "completed", finished_at: null });
  check("updateFacts writes through a pill", pill.textContent === "completed");
  check("updateFacts sets the pill status", pill.dataset.status === "completed");
  check("updateFacts dashes a null",
    document.fields["finished_at"].textContent === "-");
}

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
