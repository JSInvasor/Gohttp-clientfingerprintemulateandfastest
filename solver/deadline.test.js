import assert from "node:assert/strict";
import test from "node:test";

import { withDeadline } from "./deadline.js";

const soon = () => Date.now() + 50;

test("a promise that settles in time is passed through", async () => {
  let late = false;
  const value = await withDeadline(Promise.resolve("ok"), soon(), "too slow", () => {
    late = true;
  });
  assert.equal(value, "ok");
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(late, false, "onLate ran for a promise that won the race");
});

test("a rejection before the deadline is the caller's error, not a timeout", async () => {
  await assert.rejects(
    withDeadline(Promise.reject(new Error("connect failed")), soon(), "too slow"),
    /connect failed/
  );
});

// The leak this file was written for: a launch that loses the race still comes
// up, and the browser it produces has to be closed by somebody.
test("a value that arrives after the deadline is handed to onLate", async () => {
  const disposed = [];
  const slow = new Promise((resolve) => setTimeout(() => resolve("browser"), 60));

  await assert.rejects(
    withDeadline(slow, Date.now() + 10, "too slow", (v) => disposed.push(v)),
    /too slow/
  );
  assert.deepEqual(disposed, [], "disposed before the value even existed");

  await new Promise((r) => setTimeout(r, 90));
  assert.deepEqual(disposed, ["browser"], "the abandoned value was never disposed of");
});

// A deadline already in the past is not a reason to skip the disposal: the work
// was started before the check, so it is running either way.
test("an expired deadline still disposes of the value", async () => {
  const disposed = [];
  const slow = new Promise((resolve) => setTimeout(() => resolve("browser"), 30));

  await assert.rejects(
    withDeadline(slow, Date.now() - 1000, "too slow", (v) => disposed.push(v)),
    /too slow/
  );
  await new Promise((r) => setTimeout(r, 60));
  assert.deepEqual(disposed, ["browser"]);
});

// A late failure must not become an unhandledRejection: that handler exits the
// process, which would truncate a result line already on its way to stdout.
test("a late rejection is swallowed rather than left unhandled", async () => {
  const rejections = [];
  const watch = (err) => rejections.push(err);
  process.on("unhandledRejection", watch);

  const slow = new Promise((_, reject) => setTimeout(() => reject(new Error("late boom")), 30));
  await assert.rejects(withDeadline(slow, Date.now() + 5, "too slow"), /too slow/);
  await new Promise((r) => setTimeout(r, 80));

  process.off("unhandledRejection", watch);
  assert.deepEqual(rejections, []);
});

// onLate is the unhappy path already; a throw inside it must not replace the
// timeout the caller was correctly told about.
test("a throwing onLate does not escape", async () => {
  const slow = new Promise((resolve) => setTimeout(() => resolve("v"), 20));
  await assert.rejects(
    withDeadline(slow, Date.now() + 5, "too slow", () => {
      throw new Error("dispose blew up");
    }),
    /too slow/
  );
  await new Promise((r) => setTimeout(r, 60));
});
