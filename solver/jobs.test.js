import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";

import { parseJobs, readAll } from "./jobs.js";

test("a job list becomes exits and a concurrency", () => {
  const job = parseJobs(
    JSON.stringify({
      exits: [
        { id: "203.0.113.10", proxy: "http://user:pass@a.test:8080" },
        { id: "203.0.113.11", proxy: "socks5://b.test:1080" },
      ],
      parallel: 2,
    })
  );
  assert.deepEqual(job.exits, [
    { id: "203.0.113.10", proxy: "http://user:pass@a.test:8080" },
    { id: "203.0.113.11", proxy: "socks5://b.test:1080" },
  ]);
  assert.equal(job.parallel, 2);
});

// The caller keys results by id, so two exits sharing one would make a result
// ambiguous — and the ambiguity would land on a cookie.
test("duplicate ids are refused", () => {
  const dup = JSON.stringify({ exits: [{ id: "a", proxy: "" }, { id: "a", proxy: "" }] });
  assert.throws(() => parseJobs(dup), /duplicate exit id/);
});

test("a job list that cannot be run is refused rather than partly run", () => {
  assert.throws(() => parseJobs(""), /no job list/);
  assert.throws(() => parseJobs("   "), /no job list/);
  assert.throws(() => parseJobs("not json"), /not JSON/);
  assert.throws(() => parseJobs("[]"), /must be a JSON object/);
  assert.throws(() => parseJobs("{}"), /no exits/);
  assert.throws(() => parseJobs(JSON.stringify({ exits: [] })), /no exits/);
  assert.throws(() => parseJobs(JSON.stringify({ exits: ["nope"] })), /exit 0 is not an object/);
});

test("concurrency is clamped to something runnable", () => {
  const two = { exits: [{ id: "a" }, { id: "b" }] };
  // Never more than there are exits: the extra runners would find an empty
  // queue and exit, having cost a scheduling slot for nothing.
  assert.equal(parseJobs(JSON.stringify({ ...two, parallel: 99 })).parallel, 2);
  assert.equal(parseJobs(JSON.stringify({ ...two, parallel: 0 })).parallel, 1);
  assert.equal(parseJobs(JSON.stringify({ ...two, parallel: -3 })).parallel, 1);
  assert.equal(parseJobs(JSON.stringify({ ...two, parallel: 1.9 })).parallel, 1);
  assert.equal(parseJobs(JSON.stringify(two)).parallel, 1);
  assert.equal(parseJobs(JSON.stringify({ ...two, parallel: "nope" })).parallel, 1);
});

test("an exit may be direct, and an id may be left to the position", () => {
  const job = parseJobs(JSON.stringify({ exits: [{}, { proxy: "http://a.test:1" }] }));
  assert.deepEqual(job.exits, [
    { id: "0", proxy: "" },
    { id: "1", proxy: "http://a.test:1" },
  ]);
});

// A job list large enough to matter arrives split across chunks.
test("readAll drains a chunked stream", async () => {
  const body = JSON.stringify({ exits: [{ id: "a", proxy: "http://a.test:1" }] });
  const stream = Readable.from([body.slice(0, 10), body.slice(10)]);
  assert.equal(await readAll(stream), body);
  assert.equal(parseJobs(await readAll(Readable.from([body]))).exits.length, 1);
});
