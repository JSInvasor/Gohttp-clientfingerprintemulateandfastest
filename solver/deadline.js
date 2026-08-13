// Deadlines for work that cannot be cancelled.
//
// Nothing here can abort a browser launch mid-flight: puppeteer's connect()
// takes no signal, and there is no way to reach into it. So a deadline can only
// stop *waiting* — the work carries on regardless. What matters is what happens
// to work that finishes after nobody is waiting for it.
//
// That was the leak. A launch that lost the race left a Chromium coming up with
// no owner: attempt() never received the handle, so its finally closed nothing,
// and the retry then ran beside a full browser on a box sized for one. Only
// cleanup() at process exit collected it, which is minutes too late on the small
// VPS this whole solver is tuned for.
//
// onLate is the fix. The value the race discarded is handed back so the caller
// can dispose of it — for a launch, close the browser nobody is going to use.

// withDeadline rejects with message if promise has not settled by deadline (a
// wall-clock ms timestamp). onLate, when given, receives the promise's value if
// it arrives after the deadline has already been reported.
export function withDeadline(promise, deadline, message, onLate) {
  let expired = false;

  // Attached before anything else, and unconditionally: it is what disposes of
  // a late value, and it also means promise always has a rejection handler, so
  // a late failure can never surface as an unhandledRejection and take the
  // process down after the result line is already out.
  promise.then(
    (value) => {
      if (expired) dispose(value, onLate);
    },
    () => {}
  );

  const remaining = deadline - Date.now();
  if (remaining <= 0) {
    // Already past. The work is running anyway — it was started before the
    // check — so this still has to be marked expired or its result leaks.
    expired = true;
    return Promise.reject(new Error(message));
  }

  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => {
        expired = true;
        reject(new Error(message));
      }, remaining);
    }),
  ]);
}

// dispose runs the caller's cleanup without letting it become the new failure:
// this is already the unhappy path, and a throw here would replace a timeout
// that was reported correctly with something the caller never asked about.
function dispose(value, onLate) {
  if (typeof onLate !== "function") return;
  try {
    const result = onLate(value);
    if (result && typeof result.catch === "function") result.catch(() => {});
  } catch {}
}
