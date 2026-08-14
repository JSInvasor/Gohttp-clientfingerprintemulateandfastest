// Does the process still have its results when it exits?
//
// This is a spawned child rather than a unit test because the bug only exists
// against a real pipe: a stream that drains as fast as it is written loses
// nothing, and every test that writes into a fast reader passes either way. The
// reader below is deliberately slow, which is what a caller doing work per line
// is — send writes a cache entry and logs per exit.

import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { spawn } from "node:child_process";

const here = import.meta.dirname;

// LINES x PAD comfortably exceeds a 64 KiB pipe buffer, which is what makes the
// writes queue in the first place. A solved exit's line is a couple of kilobytes
// — two full cookie renderings — so this is the size of a real batch, not a
// contrived one.
const LINES = 200;
const PAD = 4000;

// Run a child that prints LINES result lines and then ends, and read its stdout
// a second late so the pipe is full when it exits.
function collect(ending) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import { exitAfterFlush } from ${JSON.stringify(path.join(here, "flush.js"))};
         const pad = "x".repeat(${PAD});
         for (let i = 0; i < ${LINES}; i++) {
           process.stdout.write(JSON.stringify({ exit: String(i), pad }) + "\\n");
         }
         ${ending}`,
      ],
      { stdio: ["ignore", "pipe", "ignore"] }
    );

    let bytes = 0;
    let lines = 0;
    // Nothing is read for a second: the child fills the pipe and reaches its
    // exit with most of the batch still queued.
    setTimeout(() => {
      child.stdout.on("data", (chunk) => {
        bytes += chunk.length;
        lines += chunk.toString().split("\n").length - 1;
      });
    }, 1000);

    child.on("error", reject);
    child.on("close", () => setTimeout(() => resolve({ bytes, lines }), 300));
  });
}

test("exitAfterFlush does not exit on top of results still in the pipe", async () => {
  const flushed = await collect("exitAfterFlush(0);");
  assert.equal(
    flushed.lines,
    LINES,
    `${LINES - flushed.lines} of ${LINES} result lines were lost on the way out`
  );
});

// The same child, ending the way solveBatch used to. This is the measurement
// rather than an argument: without it the fix above reads as a precaution.
test("a bare process.exit loses most of a batch, which is why the above exists", async () => {
  const truncated = await collect("process.exit(0);");
  assert.ok(
    truncated.lines < LINES,
    "process.exit() delivered every line, so this box does not reproduce the bug " +
      "the drain exists for — check whether stdout is still a pipe here"
  );
});

// A reader that never arrives must not turn a finished run into a hang. The
// backstop is 2s, so a child whose pipe is never read still ends.
test("a stdout that never drains is not waited on forever", async () => {
  const child = spawn(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `import { exitAfterFlush } from ${JSON.stringify(path.join(here, "flush.js"))};
       const pad = "x".repeat(${PAD});
       for (let i = 0; i < ${LINES}; i++) {
         process.stdout.write(JSON.stringify({ exit: String(i), pad }) + "\\n");
       }
       exitAfterFlush(7);`,
    ],
    { stdio: ["ignore", "pipe", "ignore"] }
  );

  const code = await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (c) => resolve(c));
    setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("the child never exited with its stdout unread"));
    }, 15_000).unref();
  });
  assert.equal(code, 7, "the exit code the caller asked for did not survive the backstop");
});
