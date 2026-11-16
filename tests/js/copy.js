// The ssh lines are only useful if the copy button works where the app runs:
// plain http on the LAN, where navigator.clipboard does not exist. Driven by
// tests/test_frontend.py.
const { load, makeEl } = require("./dom.js");

const path = process.argv[2];
let failures = 0;
const check = (name, cond, detail = "") => {
  if (cond) console.log(`PASS ${name}`);
  else { failures += 1; console.log(`FAIL ${name} ${detail}`); }
};

const SSH = "sudo ssh -i /var/lib/xentry/jobs/a/keys/actor xentry-guest@10.42.1.10";

function build(document) {
  const block = makeEl("div");
  block.className = "copyable";
  const button = makeEl("button");
  button.className = "copy";
  button.textContent = "Copy";
  const pre = makeEl("pre");
  pre.textContent = SSH;
  block.appendChild(button);
  block.appendChild(pre);
  block.querySelector = (sel) =>
    sel === "button.copy" ? button : sel === "pre" ? pre : null;
  document.root.appendChild(block);
  return { button, pre };
}

// --- 1. no clipboard API, execCommand works: the http case ------------------
{
  const { context, document } = load(path, ["message"], { navigator: {} });
  const { button } = build(document);
  let copied = null;
  document.execCommand = (verb) => {
    // The text must be in a selected textarea by the time this runs.
    const area = document.body.children[document.body.children.length - 1];
    copied = verb === "copy" && area && area.selected ? area.value : null;
    return true;
  };
  check("wireCopyButtons is defined", typeof context.wireCopyButtons === "function");
  context.wireCopyButtons();
  button.dispatch("click");
  setTimeout(() => {
    check("it copies the ssh line without the clipboard API", copied === SSH, String(copied));
    check("and says so", button.textContent === "Copied", button.textContent);
    check("the textarea is removed again",
      document.body.children.every((child) => child.removed));

    // --- 2. execCommand refuses: it must not claim success ------------------
    const second = load(path, ["message"], { navigator: {} });
    const twin = build(second.document);
    second.document.execCommand = () => false;
    second.context.wireCopyButtons();
    twin.button.dispatch("click");
    setTimeout(() => {
      check("a refused copy does not claim to have copied",
        twin.button.textContent !== "Copied", twin.button.textContent);
      check("it tells the reader what to do instead",
        twin.button.textContent.includes("ctrl+c"), twin.button.textContent);
      check("and is marked as failed", twin.button.classList.contains("failed"));

      // --- 3. a secure context: use the real API ---------------------------
      let written = null;
      const third = load(path, ["message"], {
        navigator: { clipboard: { writeText: async (text) => { written = text; } } },
      });
      const triple = build(third.document);
      third.document.execCommand = () => { throw new Error("must not be used"); };
      third.context.wireCopyButtons();
      triple.button.dispatch("click");
      setTimeout(() => {
        check("the clipboard API is preferred when it exists", written === SSH, String(written));
        check("and reports success", triple.button.textContent === "Copied");
        console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
        process.exit(failures === 0 ? 0 : 1);
      }, 0);
    }, 0);
  }, 0);
}
