// Which of four cases a replay describes, and how to say it in words.
//
// Separate from replay.js because that file imports puppeteer at load, and the
// decision this makes is the part most worth testing: it is the answer the tool
// exists to produce, and getting it backwards would send someone to rewrite a
// fingerprint that was never the problem.

// verdict names which of four cases the three attempts describe. It is the
// answer the whole file exists to produce, so it is computed once and reported
// rather than left for the reader to assemble.
//
//   travels          the carried-in cookie was accepted. -solve works here, and
//                    a 403 from the Go client is the Go client's problem.
//   zone_challenges  a clearance the browser earned itself, in the context it
//                    earned it in, was challenged on the next navigation. No
//                    client can hold a session on this address: there is nothing
//                    for -solve to earn that would ever be reusable, and the
//                    answer is a different exit rather than a change here.
//   does_not_travel  that same in-context clearance worked, but the carried-in
//                    one did not. The cookie is bound to the session that earned
//                    it. Also not fixable from the client side.
//   challenge_state  the carried cookies failed but the clearance alone passed,
//                    so it was the challenge bookkeeping being replayed
//                    alongside it. That one *is* fixable here.
export function verdict(carried, inSession, clearanceOnly) {
  if (!carried.challenged) return "travels";
  if (clearanceOnly && !clearanceOnly.challenged) return "challenge_state";
  if (inSession && inSession.challenged) return "zone_challenges";
  if (inSession && !inSession.challenged) return "does_not_travel";
  return "inconclusive";
}

export function explain(v) {
  switch (v) {
    case "travels":
      return (
        "the clearance was accepted — a browser presenting it from this address is not\n" +
        "challenged. So -solve has something to offer here, and a 403 from the Go client\n" +
        "is about the client rather than the cookie."
      );
    case "zone_challenges":
      return (
        "this address is challenged whatever presents it.\n\n" +
        "The measurement that says so: a real Chromium solved the challenge itself, then\n" +
        "navigated again in the very context that had just solved it — and was challenged\n" +
        "again. Not a carried cookie, not this client, not a fingerprint. A browser cannot\n" +
        "hold a session here either.\n\n" +
        "Nothing in this repo changes that outcome, and no amount of emulation would. The\n" +
        "aim is not to replay a clearance, it is to not be challenged, and that is a\n" +
        "question about the address. Try a different exit:\n\n" +
        "  send -solve -proxy http://user:pass@host:port <url>\n" +
        "  send -solve -proxy-file proxies.txt <url>\n\n" +
        "Worth knowing before re-running this: each failed challenge from an address makes\n" +
        "the next one harder, so measuring this repeatedly is not free. If the same target\n" +
        "passed from this address earlier today, that is the likeliest reason it no longer\n" +
        "does — leave it alone for a while rather than solving against it in a loop."
      );
    case "does_not_travel":
      return (
        "the clearance works, but only inside the session that earned it.\n\n" +
        "A challenge solved in a fresh context and continued in it was accepted; the same\n" +
        "cookie carried into another context was not. So the cookie is bound to more than\n" +
        "the address, the User-Agent and the TLS fingerprint — and nothing on this side\n" +
        "reproduces whatever the rest of it is. -solve cannot help against this zone."
      );
    case "challenge_state":
      return (
        "the clearance travels; the challenge bookkeeping beside it is what was refused.\n\n" +
        "Presented alone it was accepted, presented with the cf_chl_* cookies it was not.\n" +
        "That is fixable here, and send already withholds those by default — check you are\n" +
        "not running with -solve-all-cookies."
      );
    default:
      return (
        "inconclusive: the carried cookie was challenged and the follow-up did not\n" +
        "complete. Re-run when the target is reachable, or read the JSON above."
      );
  }
}
