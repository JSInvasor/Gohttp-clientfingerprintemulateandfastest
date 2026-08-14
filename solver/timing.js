// The two helpers every timed thing here needs.
//
// They were local to index.js, and moving simulateHumanBehavior out to
// behavior.js left that copy calling them across a module boundary that does not
// exist — `sleep is not defined`, at the first solve, after the browser had
// already launched. A module of their own is the smallest thing that cannot
// happen to twice.

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export function rand(a, b) {
  return Math.floor(Math.random() * (b - a + 1)) + a;
}
