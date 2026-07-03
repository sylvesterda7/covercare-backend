#!/usr/bin/env node
// Standalone diagnostic for the PCGhana pharmacist verification scraper.
// Run this directly (no server, no env vars) whenever verification starts
// failing in production, to see exactly what changed on PCGhana's site.
//
// Usage:
//   node scripts/debug-pcghana.js "HPA 5057"
//
// Prints: which strategy produced results (deep-link vs form fallback),
// the table headers/rows found (if any), and saves a screenshot +
// full-page HTML snapshot to scripts/debug-output/ for inspection.

const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");

const registrationNumber = process.argv[2];
if (!registrationNumber) {
  console.error('Usage: node scripts/debug-pcghana.js "HPA 5057"');
  process.exit(1);
}

const OUT_DIR = path.join(__dirname, "debug-output");

async function extractTable(page) {
  return await page.evaluate(() => {
    const cleanHeader = (h) => (h || "").toLowerCase().replace(/[^a-z]+/g, " ").trim();
    const tables = Array.from(document.querySelectorAll("table"));
    for (const t of tables) {
      const headerCells = Array.from(t.querySelectorAll("th")).map(th => cleanHeader(th.textContent));
      const hasRegNumber = headerCells.some(h => h.includes("registration number"));
      const hasName = headerCells.some(h => h.includes("last name")) || headerCells.some(h => h.includes("first name"));
      if (!hasRegNumber || !hasName) continue;
      const rows = Array.from(t.querySelectorAll("tbody tr")).map(tr => {
        const cells = Array.from(tr.querySelectorAll("td")).map(td => td.textContent.trim());
        const row = {};
        headerCells.forEach((h, i) => { row[h] = cells[i] || ""; });
        return row;
      }).filter(r => Object.values(r).some(v => v));
      return { headers: headerCells, rows };
    }
    return null;
  });
}

async function waitForResults(page, timeoutMs) {
  await page.waitForFunction(
    () => {
      const hasTableRows = Array.from(document.querySelectorAll("table")).some(t => t.querySelectorAll("tbody tr").length > 0);
      const bodyText = (document.body.innerText || "").toLowerCase();
      const noResults = /no result|not found|no record|no entries|no data|there are no/.test(bodyText);
      return hasTableRows || noResults;
    },
    { timeout: timeoutMs }
  ).catch(() => {});
}

async function dumpDiagnostics(page, label) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const safeLabel = label.replace(/[^a-z0-9]+/gi, "-");
  await page.screenshot({ path: path.join(OUT_DIR, `${safeLabel}.png`), fullPage: true });
  const html = await page.content();
  fs.writeFileSync(path.join(OUT_DIR, `${safeLabel}.html`), html);
  console.log(`  [saved ${safeLabel}.png + .html to scripts/debug-output/]`);
}

(async () => {
  console.log(`Testing PCGhana pharmacist verification for: "${registrationNumber}"\n`);

  const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900 });
  await page.setUserAgent(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  );

  try {
    console.log("STRATEGY A — deep link into search results");
    const deepLinkUrl = `https://forms.pcghana.org/#/search?param=${encodeURIComponent(registrationNumber)}&search_type=Pharmacists&advanced=no&t=${Date.now()}`;
    console.log(`  Navigating to: ${deepLinkUrl}`);
    await page.goto(deepLinkUrl, { waitUntil: "networkidle2", timeout: 15000 });
    await waitForResults(page, 10000);

    let table = await extractTable(page);
    await dumpDiagnostics(page, "strategy-a-deeplink");

    if (table) {
      console.log(`  ✓ Table found — headers: ${JSON.stringify(table.headers)}`);
      console.log(`  ✓ Rows: ${table.rows.length}`);
      console.log(JSON.stringify(table.rows, null, 2));
    } else {
      console.log("  ✗ No recognizable table found via deep link.\n");
      console.log("STRATEGY B — driving the search form directly");

      await page.waitForSelector("select", { timeout: 8000 }).catch(() => {});
      const selectFound = await page.evaluate(() => {
        const selects = Array.from(document.querySelectorAll("select"));
        for (const s of selects) {
          const opt = Array.from(s.options).find(o => /pharmacists?\b/i.test(o.text) && !/pharmacy/i.test(o.text));
          if (opt) {
            s.value = opt.value;
            s.dispatchEvent(new Event("change", { bubbles: true }));
            return true;
          }
        }
        return false;
      });
      console.log(`  Dropdown "Pharmacists" option ${selectFound ? "found and selected" : "NOT FOUND"}`);

      const inputSelector = await page.evaluate(() => {
        const inputs = Array.from(document.querySelectorAll("input")).filter(i =>
          !["hidden", "checkbox", "radio", "submit", "button"].includes(i.type) && i.offsetParent !== null
        );
        const input = inputs[0];
        if (!input) return null;
        if (!input.id) input.setAttribute("data-cc-target", "1");
        return input.id ? `#${CSS.escape(input.id)}` : 'input[data-cc-target="1"]';
      });
      console.log(`  Search input selector: ${inputSelector || "NOT FOUND"}`);

      if (inputSelector) {
        await page.click(inputSelector, { clickCount: 3 }).catch(() => {});
        await page.type(inputSelector, registrationNumber, { delay: 15 }).catch(() => {});
        const clicked = await page.evaluate(() => {
          const btns = Array.from(document.querySelectorAll("button, input[type='submit']"));
          const btn = btns.find(b => /search/i.test((b.textContent || b.value || "").trim()));
          if (btn) { btn.click(); return true; }
          return false;
        });
        console.log(`  Search button ${clicked ? "found and clicked" : "NOT FOUND"}`);
        await waitForResults(page, 8000);
        table = await extractTable(page);
        await dumpDiagnostics(page, "strategy-b-form");

        if (table) {
          console.log(`  ✓ Table found — headers: ${JSON.stringify(table.headers)}`);
          console.log(`  ✓ Rows: ${table.rows.length}`);
          console.log(JSON.stringify(table.rows, null, 2));
        } else {
          console.log("  ✗ Still no recognizable table. Inspect the saved .html/.png — the site's markup likely changed.");
          console.log("    Update pcGhanaExtractTable()'s header-matching keywords in server.js to match.");
        }
      }
    }
  } catch (err) {
    console.error("ERROR:", err.message);
    await dumpDiagnostics(page, "error-state").catch(() => {});
  } finally {
    await browser.close();
  }
})();
