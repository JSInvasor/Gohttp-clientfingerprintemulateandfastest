// The exits a batch solve works through, read from stdin.
//
// stdin rather than argv or the environment, because these carry proxy
// credentials. /proc/<pid>/cmdline is world-readable, so a proxy password in
// argv is visible to every user on the box for as long as the solve runs — and
// a solve runs for minutes. The environment is not in cmdline, but it is in
// /proc/<pid>/environ and it is inherited by the Chromium tree, which is a
// larger surface than it needs to be. A pipe is read once and is gone.
//
// The job list is one JSON object:
//
//   {"exits": [{"id": "203.0.113.10", "proxy": "http://user:pass@host:8080"},
//              {"id": "203.0.113.11", "proxy": "socks5://host:1080"}],
//    "parallel": 2}
//
// id is what the caller calls this exit; it is echoed back on the result line
// and never used for anything else, so it can be an address, a label, or a
// number. proxy is what the browser dials, and may be empty for a direct solve.

// parseJobs turns the stdin text into the batch to run, rejecting anything it
// cannot run rather than silently solving a subset.
export function parseJobs(input) {
  const text = String(input || "").trim();
  if (!text) throw new Error("no job list on stdin: expected a JSON object with an exits array");

  let job;
  try {
    job = JSON.parse(text);
  } catch (err) {
    throw new Error(`job list is not JSON: ${err.message}`);
  }
  if (!job || typeof job !== "object" || Array.isArray(job)) {
    throw new Error("job list must be a JSON object");
  }
  if (!Array.isArray(job.exits) || job.exits.length === 0) {
    throw new Error("job list has no exits");
  }

  const exits = job.exits.map((raw, i) => {
    if (!raw || typeof raw !== "object") {
      throw new Error(`exit ${i} is not an object`);
    }
    const id = raw.id === undefined || raw.id === null ? String(i) : String(raw.id);
    const proxy = raw.proxy === undefined || raw.proxy === null ? "" : String(raw.proxy);
    return { id, proxy };
  });

  const seen = new Set();
  for (const { id } of exits) {
    if (seen.has(id)) {
      // The caller keys results by id. Two exits sharing one would make a
      // result ambiguous, and the ambiguity would land on a cookie.
      throw new Error(`duplicate exit id ${JSON.stringify(id)}`);
    }
    seen.add(id);
  }

  return { exits, parallel: parallelism(job.parallel, exits.length) };
}

// parallelism clamps the requested concurrency to something runnable. A batch
// shares one browser, so this is how many tabs are challenged at once rather
// than how many browsers are up — much cheaper, but not free: each one is a
// live page running Cloudflare's JavaScript.
function parallelism(requested, exits) {
  const n = Number(requested);
  if (!Number.isFinite(n) || n < 1) return 1;
  return Math.min(Math.floor(n), exits);
}

// readAll drains a stream to a string. stdin arrives in chunks and a job list
// large enough to matter is large enough to be split across them.
export async function readAll(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
}
