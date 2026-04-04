import { connect } from "puppeteer-real-browser";

const url = process.argv[2];
const timeout = parseInt(process.argv[3] || "30", 10) * 1000;

if (!url) {
  console.error(JSON.stringify({ status: "error", error: "usage: node solver/index.js <url> [timeout_sec]" }));
  process.exit(1);
}

async function solve() {
  let browser;
  try {
    const result = await connect({
      headless: "new",
      turnstile: true,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--start-maximized",
      ],
      connectOption: {
        defaultViewport: null,
      },
      disableXvfb: false,
    });

    browser = result.browser;
    const page = result.page;

    // Navigate to target and wait for challenge to resolve
    await page.goto(url, { waitUntil: "domcontentloaded", timeout });

    // Wait for cf_clearance cookie to appear (challenge solved)
    const startTime = Date.now();
    let cookies = [];
    let cfClearance = null;

    while (Date.now() - startTime < timeout) {
      cookies = await browser.cookies(url);
      cfClearance = cookies.find((c) => c.name === "cf_clearance");

      if (cfClearance) break;

      // Check if page already loaded without challenge
      const title = await page.title().catch(() => "");
      if (
        title &&
        !title.includes("Just a moment") &&
        !title.includes("Attention Required") &&
        !title.includes("Checking")
      ) {
        // Page loaded normally, grab whatever cookies exist
        cookies = await browser.cookies(url);
        cfClearance = cookies.find((c) => c.name === "cf_clearance");
        break;
      }

      await new Promise((r) => setTimeout(r, 1000));
    }

    if (!cfClearance) {
      // One last attempt - maybe challenge passed but cookie name differs
      cookies = await browser.cookies(url);
    }

    const userAgent = await page.evaluate(() => navigator.userAgent);
    const finalUrl = page.url();

    // Format cookies as header string
    const cookieHeader = cookies
      .map((c) => `${c.name}=${c.value}`)
      .join("; ");

    const output = {
      status: cfClearance ? "ok" : "no_clearance",
      url: finalUrl,
      user_agent: userAgent,
      cookies: cookieHeader,
      cookie_list: cookies.map((c) => ({
        name: c.name,
        value: c.value,
        domain: c.domain,
        expires: c.expires,
      })),
    };

    console.log(JSON.stringify(output));
  } catch (err) {
    console.log(
      JSON.stringify({
        status: "error",
        error: err.message,
      })
    );
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}

solve();
