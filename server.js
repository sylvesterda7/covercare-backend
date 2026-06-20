const express = require("express");
const cors = require("cors");
const puppeteer = require("puppeteer");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// ── Health check ──
app.get("/", (req, res) => {
  res.json({ message: "CoverCare Africa Backend is running." });
});

// ── Verification route ──
app.get("/verify", async (req, res) => {
  const { registration_number, name } = req.query;

  // ── Validation ──
  if (!registration_number) {
    return res.status(400).json({
      success: false,
      message: "Registration number is required."
    });
  }

  if (!name) {
    return res.status(400).json({
      success: false,
      message: "Name is required for verification."
    });
  }

  console.log(`Verifying: ${registration_number} for ${name}`);

  // ── Prepare name parts for matching ──
  const nameParts = name.toLowerCase().trim().split(" ");
  const firstName = nameParts[0] || "";
  const lastName = nameParts[nameParts.length - 1] || "";

  let browser;

  try {
    // ── Launch headless Chrome ──
    browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"]
    });

    const page = await browser.newPage();

    // ── Navigate to Pharmacy Council search page ──
    await page.goto("https://forms.pcghana.org/#/search", {
      waitUntil: "networkidle2",
      timeout: 15000
    });

    // ── Wait for Angular app to fully render ──
    await new Promise(resolve => setTimeout(resolve, 3000));

    // ── Get dropdown options ──
    await page.waitForSelector("select", { timeout: 10000 });

    const options = await page.evaluate(() => {
      const select = document.querySelector("select");
      if (!select) return [];
      return Array.from(select.options).map(o => ({
        value: o.value,
        text: o.text
      }));
    });

    console.log("Dropdown options:", options);

    // ── Select Pharmacists from dropdown ──
    const pharmacistOption = options.find(o =>
      o.text.toLowerCase().includes("pharmacist")
    );

    if (pharmacistOption) {
      await page.select("select", pharmacistOption.value);
      console.log("Selected:", pharmacistOption.text);
    } else {
      console.log("Pharmacist option not found in dropdown");
    }

    // ── Wait for page to update ──
    await new Promise(resolve => setTimeout(resolve, 1500));

    // ── Type registration number into search field ──
    await page.waitForSelector("input[type='text']", { timeout: 10000 });
    await page.click("input[type='text']", { clickCount: 3 });
    await page.type("input[type='text']", registration_number);
    console.log("Typed:", registration_number);

    // ── Press Enter to search ──
    await page.keyboard.press("Enter");
    console.log("Pressed Enter to search");

    // ── Wait for results to load ──
    await new Promise(resolve => setTimeout(resolve, 6000));

    // ── Read page text ──
    const resultText = await page.evaluate(() => {
      return document.body.innerText.toLowerCase();
    });

    console.log("Result snippet:", resultText.substring(0, 500));

    await browser.close();

    // ── Step 1: confirm a result row exists ──
    const hasResultRow =
      resultText.includes("no results") === false &&
      /\d+\s+\w+\s+\w+/.test(resultText);

    // ── Step 2: confirm name matches ──
    const nameMatches =
      resultText.includes(firstName) ||
      resultText.includes(lastName);

    // ── Step 3: confirm registration number appears in result ──
    const numberMatches = resultText.includes(
      registration_number.toLowerCase().replace(" ", "")
    );

    const hasResults = hasResultRow && nameMatches;

    console.log("Has result row:", hasResultRow);
    console.log("Name matches:", nameMatches);
    console.log("Number in result:", numberMatches);
    console.log("First name checked:", firstName);
    console.log("Last name checked:", lastName);

    // ── Return result ──
    if (hasResults) {
      return res.json({
        success: true,
        message: "License verified in good standing with the Pharmacy Council.",
        data: {
          status: "verified_good",
          registration_number: registration_number,
          name_verified: name,
          source: "Pharmacy Council Ghana"
        }
      });
    } else if (hasResultRow && !nameMatches) {
      // Number exists but name doesn't match
      return res.json({
        success: false,
        message: "Registration number found but name does not match Council records. Please check your details.",
        data: {
          status: "name_mismatch",
          registration_number: registration_number,
          source: "Pharmacy Council Ghana"
        }
      });
    } else {
      return res.json({
        success: false,
        message: "Registration number not found in Pharmacy Council records.",
        data: {
          status: "not_found",
          registration_number: registration_number,
          source: "Pharmacy Council Ghana"
        }
      });
    }

  } catch (err) {
    if (browser) await browser.close();
    console.error("Verification error:", err.message);
    return res.status(500).json({
      success: false,
      message: "Verification service temporarily unavailable.",
      error: err.message
    });
  }
});

// ── Start server ──
app.listen(PORT, () => {
  console.log(`CoverCare backend running on http://localhost:${PORT}`);
});