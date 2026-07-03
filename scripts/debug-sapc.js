#!/usr/bin/env node
// Standalone diagnostic for the SAPC (South African Pharmacy Council)
// pharmacist verification scraper. Run this directly (no server, no env
// vars) whenever verification starts failing in production, to see exactly
// what changed on SAPC's site.
//
// Usage:
//   node scripts/debug-sapc.js "P48564"
//
// Prints: whether the "Registered Person" radio and "Search Text" input
// were located, whether Search was clicked, the table headers/rows found
// (if any), and saves a screenshot + full-page HTML snapshot to
// scripts/debug-output/ for inspection.

const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");

const registrationNumber = process.argv[2];
if (!registrationNumber) {
  console.error('Usage: node scripts/debug-sapc.js "P48564"');
  process.exit(1);
}

const OUT_DIR = path.join(__dirname, "debug-output");

async function findControlNearLabel(page, labelKeyword, tagSelector) {
  return await page.evaluate((keyword, tagSel) => {
    const kw = keyword.toLowerCase();
    const isCloseMatch = (text) => {
      const t = (text || "").trim().toLowerCase();
      return !!t && (t === kw || (t.includes(kw) && t.length <= kw.length + 15));
    };
    const candidates = Array.from(document.querySelectorAll("body *")).filter(el =>
      el.children.length <= 2 && isCloseMatch(el.textContent)
    );
    function resolveSelector(el) {
      if (el.id) return `#${CSS.escape(el.id)}`;
      el.setAttribute("data-cc-found", "1");
      return '[data-cc-found="1"]';
    }
    for (const label of candidates) {
      if (label.tagName === "LABEL" && label.htmlFor) {
        const el = document.getElementById(label.htmlFor);
        if (el && el.matches(tagSel)) return resolveSelector(el);
      }
      let container = label.closest("label, td, th, div, li, tr, span");
      for (let hops = 0; container && hops < 4; hops++) {
        const el = container.matches(tagSel) ? container : container.querySelector(tagSel);
        if (el) return resolveSelector(el);
        container = container.nextElementSibling;
      }
    }
    return null;
  }, labelKeyword, tagSelector);
}

async function waitForResults(page, timeoutMs) {
  await page.waitForFunction(
    () => {
      const hasTableRows = Array.from(document.querySelectorAll("table")).some(t => t.querySelectorAll("tbody tr").length > 0);
      const bodyText = (document.body.innerText || "").toLowerCase();
      const noResults = /no records|0 records|no results|not found|no record|no entries|no data|there are no/.test(bodyText);
      return hasTableRows || noResults;
    },
    { timeout: timeoutMs }
  ).catch(() => {});
}

async function extractTable(page) {
  return await page.evaluate(() => {
    const cleanHeader = (h) => (h || "").toLowerCase().replace(/[^a-z]+/g, " ").trim();
    const tables = Array.from(document.querySelectorAll("table"));
    for (const t of tables) {
      const headerCells = Array.from(t.querySelectorAll("th")).map(th => cleanHeader(th.textContent));
      const hasPNumber = headerCells.some(h => h.includes("p number"));
      const hasNameCol = headerCells.some(h => h.includes("surname")) || headerCells.some(h => h.includes("first name"));
      if (!hasPNumber || !hasNameCol) continue;
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

async function dumpDiagnostics(page, label) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const safeLabel = label.replace(/[^a-z0-9]+/gi, "-");
  await page.screenshot({ path: path.join(OUT_DIR, `${safeLabel}.png`), fullPage: true });
  const html = await page.content();
  fs.writeFileSync(path.join(OUT_DIR, `${safeLabel}.html`), html);
  console.log(`  [saved ${safeLabel}.png + .html to scripts/debug-output/]`);
}

(async () => {
  console.log(`Testing SAPC pharmacist verification for: "${registrationNumber}"\n`);

  const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900 });
  await page.setUserAgent(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  );

  try {
    console.log("Navigating to https://interns.pharma.mm3.co.za/SearchRegister");
    await page.goto("https://interns.pharma.mm3.co.za/SearchRegister", { waitUntil: "networkidle2", timeout: 15000 });
    await dumpDiagnostics(page, "01-initial-load");

    const radioSelector = await findControlNearLabel(page, "registered person", 'input[type="radio"]');
    console.log(`"Registered Person" radio: ${radioSelector ? `found (${radioSelector})` : "NOT FOUND (relying on site default)"}`);
    if (radioSelector) {
      await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (el) { el.checked = true; el.dispatchEvent(new Event("change", { bubbles: true })); el.click(); }
      }, radioSelector);
    }

    const searchInputSelector = await findControlNearLabel(
      page, "search text",
      'input:not([type="hidden"]):not([type="radio"]):not([type="checkbox"]):not([type="submit"]):not([type="button"])'
    );
    console.log(`"Search Text" input: ${searchInputSelector || "NOT FOUND"}`);

    if (!searchInputSelector) {
      console.log("Cannot proceed without the search input. Inspect the saved HTML/screenshot to find the real selector,");
      console.log("then update sapcFindControlNearLabel's keyword or the label-matching logic in server.js.");
      await dumpDiagnostics(page, "02-no-input-found");
      return;
    }

    await page.click(searchInputSelector, { clickCount: 3 }).catch(() => {});
    await page.type(searchInputSelector, registrationNumber, { delay: 15 }).catch(() => {});
    await dumpDiagnostics(page, "03-filled-input");

    const clicked = await page.evaluate(() => {
      const btns = Array.from(document.querySelectorAll("button, input[type='submit'], input[type='button'], a"));
      const btn = btns.find(b => /^\s*search\s*$/i.test((b.textContent || b.value || "").trim()));
      if (btn) { btn.click(); return true; }
      return false;
    });
    console.log(`Search button: ${clicked ? "found and clicked" : "NOT FOUND"}`);

    await waitForResults(page, 10000);
    const table = await extractTable(page);
    await dumpDiagnostics(page, "04-after-search");

    if (table) {
      console.log(`\n✓ Table found — headers: ${JSON.stringify(table.headers)}`);
      console.log(`✓ Rows: ${table.rows.length}`);
      console.log(JSON.stringify(table.rows, null, 2));
    } else {
      console.log("\n✗ No recognizable table found. Inspect scripts/debug-output/04-after-search.html —");
      console.log("  the site's table markup or column headers likely changed. Update sapcExtractTable()");
      console.log("  in server.js to match the real header text.");
    }
  } catch (err) {
    console.error("ERROR:", err.message);
    await dumpDiagnostics(page, "error-state").catch(() => {});
  } finally {
    await browser.close();
  }
})();
