const express = require("express");
const cors = require("cors");
const puppeteer = require("puppeteer");
const { createClient } = require("@supabase/supabase-js");

// ── App setup ──
const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || "dev-key-123";

// ── Supabase client ──
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_KEY
);

// ── CORS — only allow our frontend ──
app.use(cors({
  origin: [
    "https://covercare-africa.vercel.app",
    "http://localhost:5500",
    "http://127.0.0.1:5500"
  ],
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "x-api-key"]
}));

app.use(express.json());

// ── Security headers ──
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

// ── Input sanitization ──
function sanitize(str) {
  if (!str) return "";
  return str.toString().replace(/[<>'";&]/g, "").trim().substring(0, 200);
}

// ── Rate limiting ──
const rateLimit = {};

function checkRateLimit(ip, maxRequests = 10, windowMs = 60000) {
  const now = Date.now();
  if (!rateLimit[ip]) {
    rateLimit[ip] = { count: 1, start: now };
    return true;
  }
  const window = rateLimit[ip];
  if (now - window.start > windowMs) {
    rateLimit[ip] = { count: 1, start: now };
    return true;
  }
  if (window.count >= maxRequests) {
    return false;
  }
  window.count++;
  return true;
}

// ── Logger ──
function log(level, message, data = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...data
  };
  console.log(JSON.stringify(entry));
}

// ── Health check ──
app.get("/", (req, res) => {
  res.json({ message: "CoverCare Africa Backend is running." });
});

// ── Save worker signup ──
app.post("/worker", async (req, res) => {
  const api_key = req.headers["x-api-key"];
  if (api_key !== API_KEY) {
    return res.status(401).json({ success: false, message: "Unauthorized." });
  }

  // Sanitize inputs
  const body = req.body;
  Object.keys(body).forEach(key => {
    if (typeof body[key] === "string") body[key] = sanitize(body[key]);
  });

  const {
    full_name, email, phone, role,
    license_number, license_verified, city, experience
  } = body;

  const { data, error } = await supabase
    .from("workers")
    .insert([{
      full_name, email, phone, role,
      license_number, license_verified, city, experience
    }]);

  if (error) {
    log("error", "Worker save error", { error: error.message });
    return res.status(500).json({
      success: false,
      message: "Failed to save worker.",
      error: error.message
    });
  }

  log("info", "Worker saved", { email });
  return res.json({ success: true, message: "Worker saved successfully." });
});

// ── Save facility signup ──
app.post("/facility", async (req, res) => {
  const api_key = req.headers["x-api-key"];
  if (api_key !== API_KEY) {
    return res.status(401).json({ success: false, message: "Unauthorized." });
  }

  const body = req.body;
  Object.keys(body).forEach(key => {
    if (typeof body[key] === "string") body[key] = sanitize(body[key]);
  });

  const {
    facility_name, facility_type, city, contact_name,
    contact_role, email, phone, staff_needs, frequency
  } = body;

  const { data, error } = await supabase
    .from("facilities")
    .insert([{
      facility_name, facility_type, city, contact_name,
      contact_role, email, phone, staff_needs, frequency
    }]);

  if (error) {
    log("error", "Facility save error", { error: error.message });
    return res.status(500).json({
      success: false,
      message: "Failed to save facility.",
      error: error.message
    });
  }

  log("info", "Facility saved", { facility_name });
  return res.json({ success: true, message: "Facility saved successfully." });
});

// ── Save shift posting ──
app.post("/shift", async (req, res) => {
  const api_key = req.headers["x-api-key"];
  if (api_key !== API_KEY) {
    return res.status(401).json({ success: false, message: "Unauthorized." });
  }

  const body = req.body;
  Object.keys(body).forEach(key => {
    if (typeof body[key] === "string") body[key] = sanitize(body[key]);
  });

  const {
    facility_name, facility_type, city, contact_name,
    contact_email, contact_phone, role_needed, shift_date,
    start_time, duration, pay_rate, total_pay,
    experience_required, urgency, notes
  } = body;

  const { data, error } = await supabase
    .from("shifts")
    .insert([{
      facility_name, facility_type, city, contact_name,
      contact_email, contact_phone, role_needed, shift_date,
      start_time, duration, pay_rate, total_pay,
      experience_required, urgency, notes
    }]);

  if (error) {
    log("error", "Shift save error", { error: error.message });
    return res.status(500).json({
      success: false,
      message: "Failed to save shift.",
      error: error.message
    });
  }

  log("info", "Shift saved", { facility_name, role_needed });
  return res.json({ success: true, message: "Shift saved successfully." });
});

// ── Verify pharmacist license ──
app.get("/verify", async (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  // ── Rate limit — max 5 verifications per minute per IP ──
  if (!checkRateLimit(ip, 5, 60000)) {
    return res.status(429).json({
      success: false,
      message: "Too many verification requests. Please wait a minute and try again."
    });
  }

  const registration_number = sanitize(req.query.registration_number);
  const name = sanitize(req.query.name);
  const api_key = req.query.api_key;

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

  log("info", "Verifying license", { registration_number, name });

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
      return Array.from(select.options).map(o => ({ value: o.value, text: o.text }));
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

    log("info", "Verification result", {
      registration_number,
      hasResultRow,
      nameMatches
    });

    if (hasResults) {
      return res.json({
        success: true,
        message: "License verified in good standing with the Pharmacy Council.",
        data: {
          status: "verified_good",
          registration_number,
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
          registration_number,
          source: "Pharmacy Council Ghana"
        }
      });
    } else {
      return res.json({
        success: false,
        message: "Registration number not found in Pharmacy Council records.",
        data: {
          status: "not_found",
          registration_number,
          source: "Pharmacy Council Ghana"
        }
      });
    }

  } catch (err) {
    if (browser) await browser.close();
    log("error", "Verification error", { error: err.message });
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
    return res.status(401).json({ success: false, message: "Unauthorized." });
  }

  const email = sanitize(req.body.email);
  const selfie_url = req.body.selfie_url;
  const id_document_url = req.body.id_document_url;

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
    log("error", "Identity update error", { error: error.message });
    return res.status(500).json({
      success: false,
      message: "Failed to update identity status.",
      error: error.message
    });
  }

  log("info", "Identity verified", { email });
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
    return res.status(401).json({ success: false, message: "Unauthorized." });
  }

  const email = sanitize(req.body.email);
  const amount = parseFloat(req.body.amount);
  const shift_data = req.body.shift_data;

  if (!email || !amount) {
    return res.status(400).json({
      success: false,
      message: "Email and amount are required."
    });
  }

  try {
    const response = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email,
        amount: Math.round(amount * 100),
        currency: "GHS",
        metadata: {
          shift_data: JSON.stringify(shift_data)
        }
      })
    });

    const data = await response.json();

    if (!data.status) {
      log("error", "Paystack init failed", { error: data.message });
      return res.status(400).json({
        success: false,
        message: "Payment initialization failed.",
        error: data.message
      });
    }

    log("info", "Payment initialized", { email, amount, reference: data.data.reference });
    return res.json({
      success: true,
      authorization_url: data.data.authorization_url,
      access_code: data.data.access_code,
      reference: data.data.reference
    });

  } catch (err) {
    log("error", "Payment init error", { error: err.message });
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
    return res.status(401).json({ success: false, message: "Unauthorized." });
  }

  const reference = sanitize(req.body.reference);

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
      log("error", "Payment verification failed", { reference });
      return res.status(400).json({
        success: false,
        message: "Payment verification failed."
      });
    }

    // ── Save shift to database after payment ──
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
        log("error", "Shift save error after payment", { error: error.message });
      }
    }

    log("info", "Payment verified", { reference, amount: data.data.amount / 100 });
    return res.json({
      success: true,
      message: "Payment verified successfully.",
      amount: data.data.amount / 100,
      reference
    });

  } catch (err) {
    log("error", "Payment verify error", { error: err.message });
    return res.status(500).json({
      success: false,
      message: "Verification service unavailable.",
      error: err.message
    });
  }
});

// ── Start server ──
app.listen(PORT, () => {
  log("info", "Server started", { port: PORT });
});