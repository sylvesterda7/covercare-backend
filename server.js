const express = require("express");
const cors = require("cors");
const puppeteer = require("puppeteer");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || "dev-key-123";

// ── Supabase client ──
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_KEY
);

app.use(cors());
app.use(express.json());

// ── Health check ──
app.get("/", (req, res) => {
  res.json({ message: "CoverCare Africa Backend is running." });
});

// ── Save worker signup ──
app.post("/worker", async (req, res) => {
  const api_key = req.headers["x-api-key"];

  if (api_key !== API_KEY) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized."
    });
  }

  const {
    full_name,
    email,
    phone,
    role,
    license_number,
    license_verified,
    city,
    experience
  } = req.body;

  const { data, error } = await supabase
    .from("workers")
    .insert([{
      full_name,
      email,
      phone,
      role,
      license_number,
      license_verified,
      city,
      experience
    }]);

  if (error) {
    console.error("Worker save error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to save worker.",
      error: error.message
    });
  }

  return res.json({
    success: true,
    message: "Worker saved successfully."
  });
});

// ── Save facility signup ──
app.post("/facility", async (req, res) => {
  const api_key = req.headers["x-api-key"];

  if (api_key !== API_KEY) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized."
    });
  }

  const {
    facility_name,
    facility_type,
    city,
    contact_name,
    contact_role,
    email,
    phone,
    staff_needs,
    frequency
  } = req.body;

  const { data, error } = await supabase
    .from("facilities")
    .insert([{
      facility_name,
      facility_type,
      city,
      contact_name,
      contact_role,
      email,
      phone,
      staff_needs,
      frequency
    }]);

  if (error) {
    console.error("Facility save error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to save facility.",
      error: error.message
    });
  }

  return res.json({
    success: true,
    message: "Facility saved successfully."
  });
});

// ── Save shift posting ──
app.post("/shift", async (req, res) => {
  const api_key = req.headers["x-api-key"];

  if (api_key !== API_KEY) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized."
    });
  }

  const {
    facility_name,
    facility_type,
    city,
    contact_name,
    contact_email,
    contact_phone,
    role_needed,
    shift_date,
    start_time,
    duration,
    pay_rate,
    total_pay,
    experience_required,
    urgency,
    notes
  } = req.body;

  const { data, error } = await supabase
    .from("shifts")
    .insert([{
      facility_name,
      facility_type,
      city,
      contact_name,
      contact_email,
      contact_phone,
      role_needed,
      shift_date,
      start_time,
      duration,
      pay_rate,
      total_pay,
      experience_required,
      urgency,
      notes
    }]);

  if (error) {
    console.error("Shift save error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to save shift.",
      error: error.message
    });
  }

  return res.json({
    success: true,
    message: "Shift saved successfully."
  });
});

// ── Verify pharmacist license ──
app.get("/verify", async (req, res) => {
  const { registration_number, name, api_key } = req.query;

  if (api_key !== API_KEY) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized. Invalid API key."
    });
  }

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

  const nameParts = name.toLowerCase().trim().split(" ");
  const firstName = nameParts[0] || "";
  const lastName = nameParts[nameParts.length - 1] || "";

  let browser;

  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"]
    });

    const page = await browser.newPage();

    await page.goto("https://forms.pcghana.org/#/search", {
      waitUntil: "networkidle2",
      timeout: 15000
    });

    await new Promise(resolve => setTimeout(resolve, 3000));

    await page.waitForSelector("select", { timeout: 10000 });

    const options = await page.evaluate(() => {
      const select = document.querySelector("select");
      if (!select) return [];
      return Array.from(select.options).map(o => ({
        value: o.value,
        text: o.text
      }));
    });

    const pharmacistOption = options.find(o =>
      o.text.toLowerCase().includes("pharmacist")
    );

    if (pharmacistOption) {
      await page.select("select", pharmacistOption.value);
    }

    await new Promise(resolve => setTimeout(resolve, 1500));

    await page.waitForSelector("input[type='text']", { timeout: 10000 });
    await page.click("input[type='text']", { clickCount: 3 });
    await page.type("input[type='text']", registration_number);

    await page.keyboard.press("Enter");

    await new Promise(resolve => setTimeout(resolve, 6000));

    const resultText = await page.evaluate(() => {
      return document.body.innerText.toLowerCase();
    });

    await browser.close();

    const hasResultRow =
      resultText.includes("no results") === false &&
      /\d+\s+\w+\s+\w+/.test(resultText);

    const nameMatches =
      resultText.includes(firstName) ||
      resultText.includes(lastName);

    const hasResults = hasResultRow && nameMatches;

    console.log("Has result row:", hasResultRow);
    console.log("Name matches:", nameMatches);
    console.log("First name checked:", firstName);
    console.log("Last name checked:", lastName);

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
      return res.json({
        success: false,
        message: "Registration number found but name does not match Council records.",
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
// ── Update identity verified status ──
app.post("/verify-identity", async (req, res) => {
  const api_key = req.headers["x-api-key"];

  if (api_key !== API_KEY) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized."
    });
  }

  const { email, selfie_url, id_document_url } = req.body;

if (!email) {
  return res.status(400).json({
    success: false,
    message: "Email is required."
  });
}

const updateData = {
  identity_verified: true,
  identity_verified_at: new Date().toISOString()
};

if (selfie_url) updateData.selfie_url = selfie_url;
if (id_document_url) updateData.id_document_url = id_document_url;

const { data, error } = await supabase
  .from("workers")
  .update(updateData)
  .eq("email", email)
  .select();

  if (error) {
    return res.status(500).json({
      success: false,
      message: "Failed to update identity status.",
      error: error.message
    });
  }

  return res.json({
    success: true,
    message: "Identity verified successfully.",
    data
  });
});
// ── Initialize Paystack payment ──
app.post("/payment/initialize", async (req, res) => {
  const api_key = req.headers["x-api-key"];

  if (api_key !== API_KEY) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized."
    });
  }

  const { email, amount, shift_data } = req.body;

  if (!email || !amount) {
    return res.status(400).json({
      success: false,
      message: "Email and amount are required."
    });
  }

  try {
    // ── Initialize transaction with Paystack ──
    const response = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email,
        amount: Math.round(amount * 100), // Paystack uses pesewas
        currency: "GHS",
        metadata: {
          shift_data: JSON.stringify(shift_data)
        }
      })
    });

    const data = await response.json();

    if (!data.status) {
      return res.status(400).json({
        success: false,
        message: "Payment initialization failed.",
        error: data.message
      });
    }

    return res.json({
      success: true,
      authorization_url: data.data.authorization_url,
      access_code: data.data.access_code,
      reference: data.data.reference
    });

  } catch (err) {
    console.error("Payment error:", err);
    return res.status(500).json({
      success: false,
      message: "Payment service unavailable.",
      error: err.message
    });
  }
});

// ── Verify Paystack payment ──
app.post("/payment/verify", async (req, res) => {
  const api_key = req.headers["x-api-key"];

  if (api_key !== API_KEY) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized."
    });
  }

  const { reference } = req.body;

  if (!reference) {
    return res.status(400).json({
      success: false,
      message: "Payment reference is required."
    });
  }

  try {
    const response = await fetch(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          "Authorization": `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    );

    const data = await response.json();

    if (!data.status || data.data.status !== "success") {
      return res.status(400).json({
        success: false,
        message: "Payment verification failed."
      });
    }

    // ── Payment verified — save shift to database ──
    const metadata = data.data.metadata;
    const shift_data = metadata.shift_data ? JSON.parse(metadata.shift_data) : null;

    if (shift_data) {
      const { error } = await supabase
        .from("shifts")
        .insert([{
          ...shift_data,
          payment_reference: reference,
          payment_status: "paid",
          status: "open"
        }]);

      if (error) {
        console.error("Shift save error after payment:", error);
      }
    }

    return res.json({
      success: true,
      message: "Payment verified successfully.",
      amount: data.data.amount / 100,
      reference
    });

  } catch (err) {
    console.error("Verification error:", err);
    return res.status(500).json({
      success: false,
      message: "Verification service unavailable.",
      error: err.message
    });
  }
});
// ── Start server ──
app.listen(PORT, () => {
  console.log(`CoverCare backend running on http://localhost:${PORT}`);
});