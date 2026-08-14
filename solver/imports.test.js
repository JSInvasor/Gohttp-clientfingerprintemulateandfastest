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
  return names;
}

test("every module imports the names it calls", () => {
  const owner = exportedNames();
  const problems = [];

  for (const file of sources) {
    const text = fs.readFileSync(path.join(dir, file), "utf8");
    // Comments hold prose that mentions function names constantly, and this
    // file's own subject is naming functions, so they have to go first.
    const code = text
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "")
      .replace(/([^:])\/\/.*$/gm, "$1");
    const have = declaredIn(text);

    for (const m of code.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)) {
      const name = m[1];
      if (!owner.has(name)) continue; // not one of ours
      if (owner.get(name) === file) continue; // its own
      if (have.has(name)) continue; // imported, or shadowed by a local
      problems.push(`${file} calls ${name}() — exported by ${owner.get(name)} — without importing it`);
    }
  }

  assert.deepEqual([...new Set(problems)], [], `\n${[...new Set(problems)].join("\n")}\n`);
});
