// Does every module actually import what it calls?
//
// This exists because `node --check` says nothing about it. It parses, reports
// no error, and the file still dies at runtime the first time it reaches the
// call — which is what happened to replay.js: a function was moved into
// verdict.js, the import that was supposed to accompany it silently did not
// apply, `node --check` passed, and the failure surfaced as
// `{"status":"error","error":"verdict is not defined"}` on someone else's box.
//
// The two entry points cannot be import-ed here to find that out, because they
// pull in puppeteer-real-browser at module load and a test run has no browser.
// That is the whole reason the testable pieces were split into modules of their
// own, and it is also why nothing was checking the files that remain.
//
// So this reads them as text. Crude, and it only knows about names this package
// exports to itself — which is exactly the class of mistake that splitting a
// module creates.

import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const dir = import.meta.dirname;
const sources = fs
  .readdirSync(dir)
  .filter((f) => f.endsWith(".js") && !f.endsWith(".test.js"));

// Every name this package exports, and which file exports it.
function exportedNames() {
  const owner = new Map();
  for (const file of sources) {
    const text = fs.readFileSync(path.join(dir, file), "utf8");
    for (const m of text.matchAll(/^export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/gm)) {
      owner.set(m[1], file);
    }
    for (const m of text.matchAll(/^export\s+(?:const|let|class)\s+([A-Za-z_$][\w$]*)/gm)) {
      owner.set(m[1], file);
    }
  }
  return owner;
}

// What this file has in scope by its own doing: anything it declares at any
// depth, and anything it imports. Depth is deliberately ignored — a name
// declared anywhere in the file is enough to make a call to it not-a-bug, which
// keeps this from guessing about scope it cannot see.
function declaredIn(text) {
  const names = new Set();
  for (const m of text.matchAll(
    /(?:^|\s)(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/g
  )) {
    names.add(m[1]);
  }
  for (const m of text.matchAll(/(?:^|\s)(?:export\s+)?(?:const|let|var|class)\s+([A-Za-z_$][\w$]*)/g)) {
    names.add(m[1]);
  }
  // Destructured bindings and parameters: `const { a, b } = ...`, `(a, b) =>`.
  for (const m of text.matchAll(/(?:const|let|var)\s*\{([^}]*)\}/g)) {
    for (const part of m[1].split(",")) {
      const name = part.split(":").pop().trim();
      if (name) names.add(name);
    }
  }
  for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from/g)) {
    for (const part of m[1].split(",")) {
      // `a as b` binds b.
      const name = part.split(/\s+as\s+/).pop().trim();
      if (name) names.add(name);
    }
  }
  for (const m of text.matchAll(/import\s+([A-Za-z_$][\w$]*)\s+from/g)) {
    names.add(m[1]);
  }
  // Parameters. A callback passed in is called by name and declared nowhere
  // else — onFatal, onLate, newSession, the reject of a Promise executor.
  const params = [
    ...text.matchAll(/function\s*[A-Za-z_$][\w$]*\s*\(([^)]*)\)/g),
    ...text.matchAll(/\(([^)]*)\)\s*=>/g),
    ...text.matchAll(/(?:^|[^\w$])([A-Za-z_$][\w$]*)\s*=>/g),
  ];
  for (const m of params) {
    for (const part of (m[1] || "").split(",")) {
      const name = part.replace(/[{}[\]]/g, "").split(/[:=]/)[0].trim();
      if (/^[A-Za-z_$][\w$]*$/.test(name)) names.add(name);
    }
  }
  return names;
}

// Everything a call can legitimately resolve to that this package did not
// declare: language builtins, the Node globals these files use, and the browser
// ones, because several of these functions are serialised and run inside the
// page.
const AMBIENT = new Set([
  "Array", "Boolean", "Date", "Error", "JSON", "Map", "Math", "Number", "Object",
  "Promise", "RegExp", "Set", "String", "Symbol", "TypeError", "URL", "WeakMap",
  "BigInt", "Infinity", "NaN", "isNaN", "parseInt", "parseFloat", "encodeURIComponent",
  "decodeURIComponent", "structuredClone", "queueMicrotask", "fetch", "WebSocket",
  "setTimeout", "clearTimeout", "setInterval", "clearInterval", "require",
  "process", "console", "globalThis", "Buffer", "__dirname", "import",
  // In-page: these run inside evaluate()/evaluateOnNewDocument().
  "document", "window", "navigator", "location", "getComputedStyle",
  // Control flow and operators the call regex cannot tell from a call.
  "if", "for", "while", "switch", "catch", "return", "typeof", "function",
  "await", "new", "do", "else", "try", "throw", "yield", "of", "in", "delete", "void",
  "async", "Int32Array", "SharedArrayBuffer", "Atomics", "Event", "CustomEvent",
  "Uint8Array", "ArrayBuffer", "Proxy", "Reflect", "Intl", "AbortController",
]);

// The check this file exists for, in the form that would have caught both bugs
// it was written after.
//
// The first version only looked at names some sibling module exports. That
// caught replay.js calling verdict() without importing it, and missed the very
// next one of the same shape: simulateHumanBehavior moved to behavior.js and
// took calls to sleep() and rand() with it — helpers that live in index.js and
// are exported by nobody, so there was no owner to look up. It failed at the
// first solve, after the browser had already launched, as
// `solver: sleep is not defined`.
//
// So the rule is now the general one: a call has to resolve to something the
// file declares, something it imports, or a language or host global. Anything
// else is a name that does not exist at runtime.
test("every module resolves the names it calls", () => {
  const owner = exportedNames();
  const problems = [];

  for (const file of sources) {
    const text = fs.readFileSync(path.join(dir, file), "utf8");
    // Comments hold prose that mentions function names constantly, and this
    // file's own subject is naming functions, so they have to go first.
    const code = text
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "")
      .replace(/([^:])\/\/.*$/gm, "$1")
      // String and template literals hold things that look like calls and are
      // not — a CSS selector `a:not([src])`, a message mentioning a function.
      .replace(/`(?:\\.|[^`\\])*`/g, '""')
      .replace(/'(?:\\.|[^'\\\n])*'/g, '""')
      .replace(/"(?:\\.|[^"\\\n])*"/g, '""');
    const have = declaredIn(code);

    for (const m of code.matchAll(/(^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(/gm)) {
      const name = m[2];
      if (AMBIENT.has(name)) continue;
      if (have.has(name)) continue; // declared here, or imported
      const from = owner.has(name) ? ` — exported by ${owner.get(name)}` : "";
      problems.push(`${file} calls ${name}()${from}, but neither declares nor imports it`);
    }
  }

  assert.deepEqual([...new Set(problems)], [], `\n${[...new Set(problems)].join("\n")}\n`);
});
