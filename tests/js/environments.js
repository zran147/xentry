// The Running VMs page: a rebuild has to be requested with the CSRF header and
// the chosen job, and a destroy has to name the environment it is on. Driven by
// tests/test_frontend.py.
const { load, makeEl } = require("./dom.js");

const path = process.argv[2];
let failures = 0;
const check = (name, cond, detail = "") => {
  if (cond) console.log(`PASS ${name}`);
  else { failures += 1; console.log(`FAIL ${name} ${detail}`); }
};

const sent = [];
const replies = [];
const fakeFetch = async (url, options) => {
  sent.push({ url, options });
  const reply = replies.shift();
  if (reply) return reply;
  return { ok: true, json: async () => ({}) };
};

const { context, document } = load(path, ["message"], { fetch: fakeFetch });

// The rebuild form, as the template renders it.
const form = makeEl("form");
form.id = "rebuild-form";
const select = makeEl("select");
select.id = "rebuild-source";
select.value = "job-123";
const button = makeEl("button");
button.id = "rebuild-button";
button.appendChild(Object.assign(makeEl("span"), { className: "spinner" }));
button.querySelector = (sel) => (sel === ".spinner" ? button.children[0] : null);
document.byId["rebuild-form"] = form;
document.byId["rebuild-source"] = select;
document.byId["rebuild-button"] = button;

// One running environment, with its destroy button.
const card = makeEl("div");
card.dataset.envJob = "env-9";
const destroy = makeEl("button");
destroy.className = "destroy-env";
destroy.dataset.job = "env-9";
destroy.appendChild(Object.assign(makeEl("span"), { className: "spinner" }));
destroy.querySelector = (sel) => (sel === ".spinner" ? destroy.children[0] : null);
card.appendChild(destroy);
// cardState() looks for an existing status slot, then for a row to put a new
// one in. The rebuilt card template has neither, so it creates the slot - the
// fake has to let it, or the refusal has nowhere to land.
let slot = null;
const row = makeEl("span");
row.prepend = (el) => {
  slot = el;
  row.appendChild(el);
};
card.appendChild(row);
card.querySelector = (sel) => {
  if (sel === "button.destroy-env") return destroy;
  if (sel === ".release-state") return slot;
  if (sel === ".row span" || sel === ".row") return row;
  return null;
};
document.root.appendChild(card);

// Two cards in the held section and one rebuilt, as the template renders them.
function makeCard(section) {
  const card = makeEl("div");
  card.dataset.section = section;
  const toggle = makeEl("button");
  toggle.className = "cardtoggle";
  const body = makeEl("div");
  body.className = "cardbody";
  card.appendChild(toggle);
  card.appendChild(body);
  card.querySelector = (sel) =>
    sel === "button.cardtoggle" ? toggle : sel === ".cardbody" ? body : null;
  document.root.appendChild(card);
  return { card, toggle, body };
}

const heldA = makeCard("held");
const heldB = makeCard("held");
const rebuilt = makeCard("rebuilt");

const collapseAll = makeEl("button");
collapseAll.className = "collapse-all";
collapseAll.dataset.section = "held";
document.root.appendChild(collapseAll);

check("wireVmCards is defined", typeof context.wireVmCards === "function");
context.wireVmCards();

check("a card starts expanded", heldA.body.hidden === false);
check("and says so", heldA.toggle.getAttribute("aria-expanded") === "true");

heldA.toggle.dispatch("click");
check("clicking the id collapses that card", heldA.body.hidden === true);
check("aria-expanded follows", heldA.toggle.getAttribute("aria-expanded") === "false");
check("its neighbour is untouched", heldB.body.hidden === false);

heldA.toggle.dispatch("click");
check("clicking again expands it", heldA.body.hidden === false);

collapseAll.dispatch("click");
check("collapse all closes every held card",
  heldA.body.hidden === true && heldB.body.hidden === true);
check("and leaves the other section alone", rebuilt.body.hidden === false);
check("the button offers the way back", collapseAll.textContent === "Expand all");

collapseAll.dispatch("click");
check("expand all reopens them",
  heldA.body.hidden === false && heldB.body.hidden === false);
check("and the label returns", collapseAll.textContent === "Collapse all");

check("wireRebuildForm is defined", typeof context.wireRebuildForm === "function");
check("wireEnvironments is defined", typeof context.wireEnvironments === "function");
context.wireRebuildForm();
context.wireEnvironments();

let defaulted = true;
form.dispatch("submit", { preventDefault() { defaulted = false; } });
check("the form does not navigate", defaulted === false);

setTimeout(() => {
  check("one request was sent", sent.length === 1, JSON.stringify(sent));
  const build = sent[0] || {};
  check("it posts to the environments endpoint", build.url === "/api/environments", build.url);
  check("it is a POST", (build.options || {}).method === "POST");
  check("it carries the CSRF header",
    ((build.options || {}).headers || {})["X-Xentry-CSRF"] === "tok");
  check("it names the chosen job",
    (build.options || {}).body === JSON.stringify({ job_id: "job-123" }),
    String((build.options || {}).body));
  check("the button is busy while it runs", button.classList.contains("busy")
    || button.disabled === true);

  destroy.dispatch("click");
  setTimeout(() => {
    check("the destroy request was sent", sent.length === 2, JSON.stringify(sent));
    const gone = sent[1] || {};
    check("it addresses that environment",
      gone.url === "/api/environments/env-9/destroy", gone.url);
    check("it is a POST with the header",
      (gone.options || {}).method === "POST"
      && ((gone.options || {}).headers || {})["X-Xentry-CSRF"] === "tok");

    // A refusal has to surface rather than disappear.
    replies.push({ ok: false, statusText: "Conflict", json: async () => ({ detail: "no such environment" }) });
    destroy.dispatch("click");
    setTimeout(() => {
      // IN THE CARD now, not the page-wide strip: a sentence about this card
      // rendered at the top of the page is a sentence about something the
      // reader is not looking at.
      check("a refusal is shown in the card",
        slot !== null && slot.textContent === "no such environment",
        slot === null ? "no status slot was created" : slot.textContent);
      check("and it is marked as an error",
        slot !== null && slot.classList.contains("error"));
      check("and nothing was written to the page strip",
        document.byId["message"].textContent !== "no such environment",
        document.byId["message"].textContent);
      check("and the button is usable again",
        !destroy.classList.contains("busy") || destroy.disabled === false);
      console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
      process.exit(failures === 0 ? 0 : 1);
    }, 0);
  }, 0);
}, 0);
