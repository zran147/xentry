// Minimal DOM stand-in: enough to run app.js's render functions in node and
// assert on what they actually do to the page.
function makeEl(tag = "div") {
  const el = {
    tagName: tag,
    children: [],
    textContent: "",
    hidden: false,
    dataset: {},
    scrollTop: 0,
    scrollHeight: 1000,
    clientHeight: 100,
    classList: {
      set: new Set(),
      add(...c) { c.forEach((x) => this.set.add(x)); },
      remove(...c) { c.forEach((x) => this.set.delete(x)); },
      toggle(c, on) { if (on === undefined) { this.set.has(c) ? this.set.delete(c) : this.set.add(c); } else if (on) { this.set.add(c); } else { this.set.delete(c); } },
      contains(c) { return this.set.has(c); },
    },
    get childElementCount() { return this.children.length; },
    appendChild(child) { this.children.push(child); return child; },
    replaceChildren(...kids) { this.children = kids; },
    tabIndex: -1,
    colSpan: 1,
    attributes: {},
    listeners: {},
    querySelector() { return null; },
    setAttribute(name, value) { this.attributes[name] = String(value); },
    getAttribute(name) { return name in this.attributes ? this.attributes[name] : null; },
    addEventListener(type, handler) {
      if (!this.listeners[type]) this.listeners[type] = [];
      this.listeners[type].push(handler);
    },
    // Not a DOM API: lets a test fire what a reader would do.
    dispatch(type, event = {}) {
      for (const handler of this.listeners[type] || []) handler(event);
    },
  };
  // The real DOM keeps className and classList in step; code under test sets
  // one and asserts on the other.
  Object.defineProperty(el, "className", {
    get() { return [...el.classList.set].join(" "); },
    set(value) {
      el.classList.set = new Set(String(value).split(/\s+/).filter(Boolean));
    },
  });
  return el;
}

// Enough of a selector engine for the forms app.js actually uses:
// "tag", ".class", "[attr=\"value\"]" and combinations of them.
function matches(el, selector) {
  const shape = /^([a-z]+)?((?:\.[\w-]+)*)((?:\[[^\]]+\])*)$/.exec(selector.trim());
  if (!shape) return false;
  const [, tag, classes, attrs] = shape;
  if (tag && el.tagName !== tag) return false;
  for (const cls of classes.match(/\.[\w-]+/g) || []) {
    if (!el.classList.contains(cls.slice(1))) return false;
  }
  for (const attr of attrs.match(/\[[^\]]+\]/g) || []) {
    const pair = /^\[([\w-]+)(?:="([^"]*)")?\]$/.exec(attr);
    if (!pair) return false;
    const [, name, value] = pair;
    const actual = name.startsWith("data-")
      ? el.dataset[name.slice(5).replace(/-(\w)/g, (_, c) => c.toUpperCase())]
      : el.getAttribute(name);
    if (value === undefined) {
      if (actual === undefined || actual === null) return false;
    } else if (String(actual) !== value) {
      return false;
    }
  }
  return true;
}

function walk(el, visit) {
  for (const child of el.children || []) {
    visit(child);
    walk(child, visit);
  }
}

function makeDocument(ids) {
  const byId = {};
  for (const id of ids) byId[id] = makeEl(id === "provision-commands" ? "ol" : "div");
  return {
    byId,
    getElementById(id) { return byId[id] || null; },
    fields: {},
    // Elements the test puts in the page, for querySelector to search.
    root: makeEl("body"),
    querySelector(sel) {
      if (sel.includes("csrf")) return { content: "tok" };
      const field = /\[data-field="([^"]+)"\]/.exec(sel);
      if (field) return this.fields[field[1]] || null;
      let found = null;
      walk(this.root, (el) => {
        if (!found && matches(el, sel)) found = el;
      });
      return found;
    },
    querySelectorAll(sel) {
      const found = [];
      walk(this.root, (el) => {
        if (matches(el, sel)) found.push(el);
      });
      return found;
    },
    createElement(tag) {
      const el = makeEl(tag);
      el.style = {};
      el.select = () => { el.selected = true; };
      el.remove = () => { el.removed = true; };
      return el;
    },
    body: makeEl("body"),
    // Set per test: the http path uses execCommand, so both outcomes matter.
    execCommand() { return false; },
    addEventListener() {},
  };
}

function load(appJsPath, ids, overrides = {}) {
  const fs = require("node:fs");
  const vm = require("node:vm");
  const document = makeDocument(ids);
  const sandbox = {
    document,
    window: { setInterval: () => 0, clearInterval: () => {}, setTimeout: () => 0, location: { href: "", reload() {} } },
    EventSource: function () { return { addEventListener() {}, close() {} }; },
    fetch: async () => ({ ok: true, json: async () => ({}) }),
    console,
    JSON,
    Array,
    Object,
    String,
    Number,
    Math,
    Date,
    RegExp,
    Error,
  };
  Object.assign(sandbox, overrides);
  const context = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(appJsPath, "utf8"), context);
  return { context, document };
}

module.exports = { load, makeEl, matches };
