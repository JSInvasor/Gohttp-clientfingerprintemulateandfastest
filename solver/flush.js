// Ending the process without throwing away what it just printed.
//
// stdout to a pipe is asynchronous on Linux, and process.exit() discards
// whatever is still queued in the stream. Every result this solver produces goes
// out that way — send reads it through cmd.StdoutPipe — so an exit taken one
// statement after a write is an exit that can lose the answer.
//
// finish() has known this since it was written; its write callback is there for
// exactly this reason. solveBatch did not: it ended with a bare process.exit(0)
// immediately after its last emit(), and results land in bursts — `parallel` of
// them finish within moments of each other, and the final burst is followed
// straight away by the exit. Measured with a reader one second behind, 200 lines
// of the size a solved exit produces:
//
//   process.exit(0) straight after the writes   64358 of 804690 bytes arrived
//   the drain callback below                   804690 of 804690 bytes arrived
//
// 168 of 200 exits lost against none, and each one is a cf_clearance that was
// earned, paid for, and then dropped between two processes. send reports those
// as "the solver exited without reporting this exit", which reads like the
// browser failed.
//
// One implementation rather than two: the batch path and the single-result path
// need the same guarantee, and the second place is where it gets forgotten.

import { cleanup } from "./cleanup.js";

// exitAfterFlush writes line (if any), waits for stdout to drain, then tears the
// browser tree down and exits.
//
// An empty line is the drain probe on its own: stream writes complete in order,
// so this callback cannot run before everything queued ahead of it has gone out.
//
// The timer is the backstop for a reader that never drains at all — a closed
// pipe, a consumer that died — where waiting forever would turn a finished run
// into a hang. It is unref'd so it cannot itself keep the process alive.
export function exitAfterFlush(code, line = "") {
  let done = false;
  const end = () => {
    if (done) return;
    done = true;
    cleanup();
    process.exit(code);
  };
  try {
    process.stdout.write(line, end);
  } catch {
    end();
    return;
  }
  setTimeout(end, 2000).unref();
}
