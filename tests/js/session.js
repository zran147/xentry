// The live feed's render path, exercised under node. Driven by
// tests/test_frontend.py.
//
// Two things here cannot be tested from Python. The first is that the feed
// survives a re-render: renderSteps() rebuilds the whole steps table on every
// stream tick, so a feed that lived only in the DOM would be wiped each time
// the runner touched a step - which during provisioning is often.
//
// The second is ADR 0004's requirement: free_exec and exec must not look
// alike. "A card where the two verbs look alike is a card that hides the only
// thing worth noticing."
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
  process.exitCode = 1;
};

const TS = "2026-11-18T10:04:11+00:00";
let seq = 0;
function record(type, payload) {
  seq += 1;
  return { type, ts: TS, payload, hash: `h${seq}`, prev_hash: seq === 1 ? "" : `h${seq - 1}` };
}

const STEPS = [
  { seq: 5, name: "create_target", state: "passed" },
  { seq: 6, name: "provision", step_id: "setup-generic", state: "running" },
  { seq: 7, name: "readiness", state: "queued" },
];

// A line's parts: [head, body]. The head holds the timestamp, the kind, the
// verb badge when there is one, and the small facts.
const headOf = (line) => line.children[0];
const bodyOf = (line) => line.children[1];
const badgeOf = (line) =>
  (headOf(line).children || []).find((kid) => kid.classList.contains("sessionverb"));
const kindOf = (line) =>
  (headOf(line).children || []).find((kid) => kid.classList.contains("sessionkind"));
const noteOf = (line) =>
  (headOf(line).children || []).find((kid) => kid.classList.contains("sessionnote"));

// --- the row, and that it is open ----------------------------------------
{
  const { context } = load(path, ["steps-body", "message"]);
  const tbody = makeEl("tbody");

  context.setStepRows({}, []);
  context.renderSteps(tbody, STEPS);
  check("a job with no session gets no feed row", tbody.children.length === 3);

  context.sessionState({ harness: true });
  context.renderSteps(tbody, STEPS);
  check("a harness job gets one", tbody.children.length === 4);
  const detail = tbody.children[2];
  check("directly under the provision row", detail.classList.contains("step-detail"));
  check("named so the reader's open/closed choice survives a re-render",
    detail.dataset.detail === "session:provision");
  // The whole point of putting it here: the operator should not have to find
  // it while the model is working.
  check("and it is open", detail.hidden === false);
  check("the provision row announces itself expanded",
    tbody.children[1].getAttribute("aria-expanded") === "true");

  const block = detail.children[0].children[0];
  check("it is titled as the session", block.children[0].children[0].textContent === "model session");
  check("the empty feed says what it is waiting for",
    block.children[0].children[1].textContent.includes("waiting for the model's first call"));
  check("and claims the chain", block.children[0].children[1].textContent.includes("hash-chained"));
  check("the list is the feed", block.children[1].id === "session-feed");
}

// --- a call does not look like a thought, and free_exec does not look like
//     exec ---------------------------------------------------------------
{
  const { context } = load(path, ["steps-body", "message"]);
  const reasoning = context.sessionLine(record("session_reasoning", { text: "redis 5.0.14" }));
  const free = context.sessionLine(
    record("session_tool_call", { verb: "free_exec", params: { command: "apt-get update", vm_id: "t1" } }),
  );
  const restricted = context.sessionLine(
    record("session_tool_call", { verb: "exec", params: { step_id: "setup-generic" } }),
  );

  check("reasoning is its own kind of line", reasoning.classList.contains("kind-reasoning"));
  check("a call is another", free.classList.contains("kind-tool_call"));
  check("reasoning carries no verb badge", badgeOf(reasoning) === undefined);
  check("reasoning is set as prose, not as code",
    bodyOf(reasoning).classList.contains("prose"));
  check("a command is not", !bodyOf(free).classList.contains("prose"));
  check("the model's words are shown", bodyOf(reasoning).textContent === "redis 5.0.14");
  check("the label says which is which", kindOf(reasoning).textContent === "thinking");

  // ADR 0004. The badge is what the stylesheet colours, so this is the
  // assertion that the two verbs cannot be drawn alike.
  check("free_exec is badged as itself", badgeOf(free) !== undefined);
  check("and tagged for the stylesheet", badgeOf(free).dataset.verb === "free_exec");
  check("exec is badged too", badgeOf(restricted).dataset.verb === "exec");
  check("the two verbs are distinguishable",
    badgeOf(free).dataset.verb !== badgeOf(restricted).dataset.verb);
  check("free_exec says what it is", (badgeOf(free).title || "").includes("root shell"));

  check("the command itself is the body", bodyOf(free).textContent === "apt-get update");
  // vm_id is substituted by the tool layer, so it is never news.
  check("a call with no command shows its parameters",
    bodyOf(restricted).textContent === '{"step_id":"setup-generic"}');

  // The chain, on every line, where a reader can find it.
  check("each line carries its hash and the one before it",
    free.title.includes("hash h2") && free.title.includes("prev h1"));
}

// --- the facts that say whether to read the body --------------------------
{
  const { context } = load(path, ["steps-body", "message"]);
  const result = context.sessionLine(
    record("session_tool_result", {
      verb: "free_exec",
      status: 0,
      sha256: "abcdef0123456789",
      body: "Setting up redis-server",
      truncated: true,
    }),
  );
  const note = noteOf(result).textContent;
  check("a result shows its exit status", note.includes("0"));
  // A digest of the WHOLE output beside a body that is not the whole output.
  check("and the digest of the whole output", note.includes("sha256 abcdef012345"));
  check("and says the body is cut", note.includes("truncated"));
  check("the body is what was returned", bodyOf(result).textContent === "Setting up redis-server");

  const verdict = context.sessionLine(
    record("session_readiness", { passed: false, reason_code: "port_closed", detail: "6379 shut" }),
  );
  check("a readiness verdict reads as pass or fail", noteOf(verdict).textContent.includes("failed"));
  check("with its reason code", noteOf(verdict).textContent.includes("port_closed"));

  const gaveUp = context.sessionLine(
    record("session_declaration", {
      declaration: "give_up",
      reason_code: "version_unavailable",
      summary: "the mirror serves 6.0.16 and nothing affected",
    }),
  );
  check("a give-up names itself", noteOf(gaveUp).textContent.includes("give_up"));
  check("and its code", noteOf(gaveUp).textContent.includes("version_unavailable"));
  check("and reads as a sentence", bodyOf(gaveUp).textContent.includes("nothing affected"));
}

// --- appended, and it survives the re-render ------------------------------
{
  const { context } = load(path, ["steps-body", "message"]);
  const tbody = makeEl("tbody");
  context.sessionState({ harness: true });
  context.renderSteps(tbody, STEPS);
  const listOf = () => tbody.children[2].children[0].children[0].children[1];

  check("the feed starts empty", listOf().children.length === 0);
  context.appendSession([record("session_reasoning", { text: "one" })]);
  check("a record is appended", listOf().children.length === 1);
  context.appendSession([
    record("session_tool_call", { verb: "free_exec", params: { command: "ls" } }),
    record("session_tool_result", { verb: "free_exec", status: 0, body: "bin" }),
  ]);
  check("and the next two are added, not swapped in", listOf().children.length === 3);
  check("in the order they arrived",
    bodyOf(listOf().children[0]).textContent === "one" &&
      bodyOf(listOf().children[1]).textContent === "ls");

  // The re-render that would wipe a DOM-only feed: a step changed state, so
  // the stream ticks and the whole table is rebuilt.
  context.renderSteps(tbody, [{ ...STEPS[0] }, { ...STEPS[1], state: "passed" }, STEPS[2]]);
  check("the feed survives a steps re-render", listOf().children.length === 3);
  check("with the same records", bodyOf(listOf().children[2]).textContent === "bin");

  // A record with no type is not a session record and must not be drawn.
  const before = listOf().children.length;
  context.appendSession([{ ts: TS, payload: { text: "nope" } }]);
  check("a record with no type is ignored", listOf().children.length === before);
}

// --- the cursor only ever moves forward ----------------------------------
async function pollChecks() {
  const served = [];
  const { context } = load(path, ["steps-body", "message"], {
    fetch: async (url) => {
      served.push(url);
      return {
        ok: true,
        json: async () => ({ items: [record("session_reasoning", { text: "x" })], cursor: 7 }),
      };
    },
  });
  await context.pollSession("job-1");
  check("the first poll asks from the start", served[0].endsWith("/session?cursor=0"));
  await context.pollSession("job-1");
  check("the next asks from the cursor it was given",
    served[1].endsWith("/session?cursor=7"), served[1]);

  // A cursor that went backwards would replay the session into the card.
  const back = load(path, ["steps-body", "message"], {
    fetch: async () => ({ ok: true, json: async () => ({ items: [], cursor: 2 }) }),
  });
  back.context.sessionState({ cursor: 9 });
  await back.context.pollSession("job-1");
  check("a cursor that goes backwards is ignored",
    back.context.sessionState().cursor === 9);

  // A failed poll keeps what is shown and does not throw into the page.
  const broken = load(path, ["steps-body", "message"], {
    fetch: async () => {
      throw new Error("network");
    },
  });
  broken.context.appendSession([record("session_reasoning", { text: "kept" })]);
  const added = await broken.context.pollSession("job-1");
  check("a failed poll adds nothing and raises nothing", added === 0);
  check("and the feed keeps what it had", broken.context.sessionState().count === 1);
}

pollChecks().catch((error) => {
  console.log(`FAIL pollSession threw ${error}`);
  process.exitCode = 1;
});
