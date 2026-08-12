// Process-tree teardown shared by index.js and fingerprint.js.
//
// puppeteer-real-browser launches Chromium plus an Xvfb wrapper plus
// renderer/GPU children. browser.close() is best-effort: if the node process
// dies first — a parent's timeout, SIGTERM, an uncaught throw, our own
// watchdog — the Chromium tree is orphaned and keeps eating CPU and RAM. Both
// entry points need the same teardown, so it lives here rather than being
// implemented once and merely documented in the other.
//
// Two things this deliberately does NOT do:
//
//   - match processes on an inherited environment variable. `pgrep -f` matches
//     /proc/<pid>/cmdline, which never contains the environment, so a marker
//     exported into process.env is invisible to it. The previous sweep here
//     matched exactly one process: the `sh -c` that execSync spawned to run the
//     sweep, whose own command line carried the pattern — so it killed its own
//     shell and no browser. Every child launched here is found by parentage
//     instead, via `pgrep -P`.
//
//   - escalate to SIGKILL on a timer. setTimeout callbacks never run once
//     process.exit() has been called or the 'exit' event is being dispatched,
//     so a deferred kill is a kill that never happens. The grace window here is
//     a synchronous wait, which works on every exit path.

import { execFileSync } from "node:child_process";

const trackedPids = new Set();
const trackedBrowsers = new Set();
let cleanedUp = false;

// Track a PID whose whole process group should die with us.
export function trackPid(pid) {
  if (Number.isInteger(pid) && pid > 0) trackedPids.add(pid);
}

// Track a live browser handle so cleanup can attempt a graceful close first.
export function trackBrowser(browser) {
  if (browser) trackedBrowsers.add(browser);
  try {
    const proc = browser && browser.process && browser.process();
    if (proc && proc.pid) trackPid(proc.pid);
  } catch {}
}

// Drop a browser we already closed ourselves, so cleanup does not operate on a
// dead handle. Its PID stays tracked: the handle closing does not guarantee the
// process tree is gone.
export function untrackBrowser(browser) {
  if (browser) trackedBrowsers.delete(browser);
}

// Block the thread for ms without yielding to the event loop. Needed because
// the grace window between SIGTERM and SIGKILL has to elapse inside an exit
// handler, where no timer will ever fire.
function sleepSync(ms) {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {}
}

// Direct children of pid, via pgrep. Spawned with execFileSync rather than a
// shell so no intermediate `sh -c` exists to be matched or killed.
function childrenOf(pid) {
  try {
    const out = execFileSync("pgrep", ["-P", String(pid)], {
      encoding: "utf8",
      timeout: 2000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out
      .split("\n")
      .map((line) => parseInt(line.trim(), 10))
      .filter((n) => Number.isInteger(n) && n > 0);
  } catch {
    // Exit status 1 just means "no matches"; anything else (no pgrep on this
    // box, a timeout) leaves us with the tracked PIDs, which is the common case.
    return [];
  }
}

// Every descendant of pid, deepest last. Bounded so a pathological tree cannot
// spin here during teardown.
function descendantsOf(pid, limit = 200) {
  const found = [];
  const queue = [pid];
  const seen = new Set([pid]);
  while (queue.length && found.length < limit) {
    for (const child of childrenOf(queue.shift())) {
      if (seen.has(child)) continue;
      seen.add(child);
      found.push(child);
      queue.push(child);
    }
  }
  return found;
}

function signal(pid, sig) {
  // A negative PID signals the whole process group. Puppeteer spawns Chromium
  // detached on non-Windows, so the browser and its renderers share a group and
  // one call reaches all of them. The direct kill is the fallback for anything
  // that is not a group leader.
  try {
    process.kill(-pid, sig);
  } catch {}
  try {
    process.kill(pid, sig);
  } catch {}
}

// Kill everything this process started. Safe to call repeatedly and from any
// exit path; only the first call does work.
export function cleanup() {
  if (cleanedUp) return;
  cleanedUp = true;

  // 1) Ask the live browser handles to close. This is the only step that can
  //    shut Chromium down cleanly, but it is asynchronous and will not finish
  //    if we are already exiting — hence the kills below.
  for (const browser of trackedBrowsers) {
    try {
      const closing = browser.close();
      if (closing && typeof closing.catch === "function") closing.catch(() => {});
    } catch {}
  }
  trackedBrowsers.clear();

  // 2) Collect our own descendants (the Xvfb wrapper, chrome-launcher's
  //    children, anything still parented to us) alongside the PIDs we tracked.
  const targets = new Set(trackedPids);
  for (const pid of descendantsOf(process.pid)) targets.add(pid);
  targets.delete(process.pid);

  // 3) SIGTERM, a short synchronous grace window, then SIGKILL for whatever
  //    ignored it.
  for (const pid of targets) signal(pid, "SIGTERM");
  if (targets.size) sleepSync(300);
  for (const pid of targets) signal(pid, "SIGKILL");
}

// Wire cleanup into every way this process can end.
//
// onFatal receives the error for uncaughtException/unhandledRejection so the
// caller can emit its own result line before the process dies; it must not
// throw. Signal exit codes follow the 128+signum convention.
export function installExitHandlers({ onFatal } = {}) {
  const fatal = (err, code) => {
    if (onFatal) {
      try {
        onFatal(err);
      } catch {}
    }
    cleanup();
    process.exit(code);
  };

  process.on("SIGINT", () => fatal(null, 130));
  process.on("SIGTERM", () => fatal(null, 143));
  process.on("SIGHUP", () => fatal(null, 129));
  process.on("uncaughtException", (err) => fatal(err, 1));
  process.on("unhandledRejection", (err) => fatal(err, 1));
  process.on("exit", cleanup);
}

// errorMessage normalises whatever landed in a catch or a rejection handler.
export function errorMessage(err) {
  if (!err) return "unknown error";
  if (typeof err === "string") return err;
  return err.message || String(err);
}
