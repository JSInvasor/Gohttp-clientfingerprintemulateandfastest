// The few seconds after a clearance is issued, which are not idle time.
//
// Shared because replay.js needs to do exactly what the solver does before it
// can claim to have measured the same thing. Its in-session probe — solve a
// challenge in a fresh context, navigate again in that context — is the
// measurement the whole verdict turns on, and it was re-navigating the instant
// the interstitial cleared, which is precisely the case the dwell below exists
// to avoid. A "the zone challenges everything" verdict taken that way could just
// be a cookie read too early.

// Real-user behavior between challenge solve and cookie capture. CF samples
// mouse/scroll/dwell events for the first few seconds after issuance and
// uses them to score the cookie. A cookie captured cold dies under load
// within seconds; one captured after 3-5 s of believable activity holds up.
export async function simulateHumanBehavior(page) {
  // Initial settle pause (RUM beacons fire here).
  await sleep(rand(900, 1600));

  // Mouse move into a believable region.
  try {
    await page.mouse.move(rand(220, 1100), rand(180, 600), { steps: 12 });
  } catch {}
  await sleep(rand(280, 600));

  // First scroll - slow, smooth.
  try {
    await page.evaluate(
      (y) => window.scrollBy({ top: y, behavior: "smooth" }),
      rand(280, 600)
    );
  } catch {}
  await sleep(rand(800, 1300));

  // Second mouse move + smaller scroll.
  try {
    await page.mouse.move(rand(400, 1500), rand(300, 800), { steps: 10 });
  } catch {}
  try {
    await page.evaluate(
      (y) => window.scrollBy({ top: y, behavior: "smooth" }),
      rand(150, 380)
    );
  } catch {}
  await sleep(rand(700, 1100));

  // Dispatch a focus/blur event, simulating tab switching back.
  try {
    await page.evaluate(() => {
      window.dispatchEvent(new Event("focus"));
      document.body && document.body.click();
    });
  } catch {}
  await sleep(rand(500, 900));

  // Final dwell - lets __cf_bm settle and any post-load JS finish.
  await sleep(rand(600, 1100));
}
