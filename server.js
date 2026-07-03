const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const puppeteer = require("puppeteer");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_KEY
);

const ADMINS = (process.env.ADMIN_EMAILS || "sdenyoh-abayateye@st.ug.edu.gh")
  .split(",")
  .map(e => e.trim().toLowerCase());

// ── License verification receipts ──
// /verify performs a real, server-side lookup against the professional
// regulator (e.g. PC Ghana) and, on a genuine match, signs a short-lived
// receipt binding {registration_number, name, country, role}. /worker signup
// requires and validates this receipt before auto-setting license_verified —
// so the client can prove a real check happened, but can't just assert it.
const LICENSE_VERIFY_SECRET = process.env.LICENSE_VERIFY_SECRET || process.env.SUPABASE_SECRET_KEY || "dev-only-insecure-secret";
const LICENSE_VERIFY_TOKEN_TTL_MS = 30 * 60 * 1000; // 30 minutes

function normalizeForMatch(str) {
  return (str || "").toString().trim().toLowerCase();
}

function signLicenseVerification(payload) {
  const json = JSON.stringify(payload);
  const encoded = Buffer.from(json).toString("base64url");
  const signature = crypto.createHmac("sha256", LICENSE_VERIFY_SECRET).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function verifyLicenseVerificationToken(token, { registration_number, name, country, role }) {
  if (!token || typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [encoded, signature] = parts;

  const expectedSignature = crypto.createHmac("sha256", LICENSE_VERIFY_SECRET).update(encoded).digest("base64url");
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expectedSignature);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return false;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return false;
  }

  if (Date.now() - payload.iat > LICENSE_VERIFY_TOKEN_TTL_MS) return false;
  if (normalizeForMatch(payload.registration_number) !== normalizeForMatch(registration_number)) return false;
  if (normalizeForMatch(payload.name) !== normalizeForMatch(name)) return false;
  if (normalizeForMatch(payload.country) !== normalizeForMatch(country)) return false;
  if (normalizeForMatch(payload.role) !== normalizeForMatch(role)) return false;
  return true;
}

app.use(cors({
  origin: [
    "https://covercare-africa.vercel.app",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5501",
    "http://127.0.0.1:5501"
  ],
  methods: ["GET", "POST", "PUT"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "5mb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

// Trims/length-caps string input for storage. Does NOT strip characters like
// quotes/apostrophes/ampersands — that corrupts legitimate data (e.g. "O'Brien").
// SQL injection is not a concern here since all queries go through the
// Supabase client (parameterized), and any HTML rendering of this data must
// escape it at render time (see escapeHtml() on the frontend).
function sanitize(str) {
  if (!str) return "";
  return str.toString().trim().substring(0, 200);
}

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

function log(level, message, data = {}) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), level, message, ...data }));
}

const browserPool = {
  instance: null,
  async getBrowser() {
    if (!this.instance || !this.instance.connected) {
      this.instance = await puppeteer.launch({
        headless: true,
        args: ["--no-sandbox", "--disable-setuid-sandbox"]
      });
    }
    return this.instance;
  },
  async close() {
    if (this.instance) {
      await this.instance.close();
      this.instance = null;
    }
  }
};

async function requireAuth(req, res) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ success: false, message: "Authentication required." });
    return null;
  }
  const token = authHeader.split(" ")[1];
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) {
    res.status(401).json({ success: false, message: "Invalid or expired session." });
    return null;
  }
  req.user = user;
  return user;
}

function requireAdmin(req, res) {
  if (!req.user || !ADMINS.includes(req.user.email.toLowerCase())) {
    res.status(403).json({ success: false, message: "Admin access required." });
    return false;
  }
  return true;
}

function rateLimitRoute(req, res, max = 30) {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (!checkRateLimit(ip, max, 60000)) {
    res.status(429).json({ success: false, message: "Too many requests. Please try again shortly." });
    return false;
  }
  return true;
}

const SHIFT_FIELDS = [
  "facility_name", "facility_type", "city", "contact_name",
  "contact_email", "contact_phone", "role_needed", "shift_date",
  "start_time", "duration", "pay_rate", "total_pay",
  "duration_hours", "days_needed", "workers_needed",
  "experience_required", "urgency", "notes",
  "assigned_to_worker_id", "branch_id", "branch_name"
];

function pickShiftFields(data) {
  if (!data || typeof data !== "object") return {};
  const picked = {};
  SHIFT_FIELDS.forEach((key) => {
    if (data[key] !== undefined && data[key] !== null) {
      picked[key] = typeof data[key] === "string" ? sanitize(data[key]) : data[key];
    }
  });
  return picked;
}

function computeShiftAmounts(shiftData) {
  const perDayHours = parseFloat(shiftData.duration_hours) || parseFloat(String(shiftData.duration || "").replace(/[^0-9.]/g, "")) || 0;
  const days = parseInt(shiftData.days_needed) || 1;
  const workers = parseInt(shiftData.workers_needed) || 1;
  const totalHours = perDayHours * days * workers;
  const rate = parseFloat(String(shiftData.pay_rate || "").replace(/[^0-9.]/g, "")) || 0;
  const workerTotal = Math.round(rate * totalHours * 100) / 100;
  const facilityTotal = Math.round(workerTotal * 1.25 * 100) / 100;
  return { hours: totalHours, rate, workerTotal, facilityTotal, perDayHours, days, workers };
}

function isPharmacyRole(role) {
  const r = (role || "").toLowerCase();
  return r.includes("pharmacist") || r.includes("pharmacy");
}

function generateQrToken() {
  return crypto.randomBytes(32).toString("hex");
}

const ARRIVE_BASE_URL = process.env.ARRIVE_URL || "https://covercare-africa.vercel.app/arrive";

function buildQrUrl(shiftId, workerId, token) {
  const params = new URLSearchParams({ shift_id: shiftId, worker_id: workerId, token });
  return `${ARRIVE_BASE_URL}?${params.toString()}`;
}

const GRACE_PERIOD_MINUTES = 15;

function getShiftStartTime(shift) {
  if (!shift.shift_date || !shift.start_time) return null;
  const d = new Date(`${shift.shift_date}T${shift.start_time}:00`);
  return isNaN(d.getTime()) ? null : d;
}

function getShiftDurationHours(shift) {
  if (shift.duration_hours) return parseFloat(shift.duration_hours) || 0;
  return parseFloat((shift.duration || "").replace(/[^0-9.]/g, "")) || 0;
}

function getShiftEndTime(shift) {
  const start = getShiftStartTime(shift);
  if (!start) return null;
  const hours = getShiftDurationHours(shift);
  return new Date(start.getTime() + hours * 60 * 60 * 1000);
}

function calcLateMinutes(shift, arrivalDate) {
  const start = getShiftStartTime(shift);
  if (!start) return 0;
  const late = Math.round((arrivalDate.getTime() - start.getTime()) / 60000) - GRACE_PERIOD_MINUTES;
  return Math.max(0, late);
}

function calcAdjustedPay(totalPay, durationHours, lateMinutes) {
  if (!totalPay || !durationHours || durationHours <= 0) return totalPay;
  const hourlyRate = parsePayAmount(totalPay) / durationHours;
  const deduction = hourlyRate * (lateMinutes / 60);
  const adjusted = Math.max(0, parsePayAmount(totalPay) - deduction);
  return `GHS ${adjusted.toLocaleString()}`;
}

function parsePayAmount(totalPay) {
  if (!totalPay) return 0;
  return parseFloat(totalPay.toString().replace(/[^0-9.]/g, "")) || 0;
}

async function getShiftById(shiftId) {
  const { data, error } = await supabase.from("shifts").select("*").eq("id", shiftId).single();
  if (error || !data) return null;
  return data;
}

async function validateQrCredentials(shiftId, workerId, token) {
  const shift = await getShiftById(shiftId);
  if (!shift) return { ok: false, status: 404, message: "Shift not found." };
  if (shift.worker_id !== workerId) return { ok: false, status: 403, message: "Worker does not match this shift." };
  if (!shift.qr_token || shift.qr_token !== token) return { ok: false, status: 403, message: "Invalid or expired QR token." };
  if (isShiftWindowPassed(shift)) return { ok: false, status: 400, message: "This shift has already ended. Check-in is no longer available." };
  return { ok: true, shift };
}

async function getOrCreatePaystackRecipient(worker) {
  if (worker.paystack_recipient_code) return worker.paystack_recipient_code;

  const phone = (worker.phone || "").replace(/\D/g, "");
  if (!phone) throw new Error("Worker phone number is required for payout.");

  const bankCode = phone.startsWith("02") || phone.startsWith("24") || phone.startsWith("54") ? "VOD" : "MTN";

  const response = await fetch("https://api.paystack.co/transferrecipient", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      type: "mobile_money",
      name: worker.full_name,
      account_number: phone,
      bank_code: bankCode,
      currency: "GHS"
    })
  });

  const data = await response.json();
  if (!data.status) throw new Error(data.message || "Failed to create Paystack recipient.");

  const recipientCode = data.data.recipient_code;

  const { error: recipientUpdateError } = await supabase
    .from("workers")
    .update({ paystack_recipient_code: recipientCode })
    .eq("id", worker.id);

  if (recipientUpdateError) {
    log("warn", "Could not save recipient code", { error: recipientUpdateError.message });
  }

  return recipientCode;
}

async function initiateWorkerPayout(worker, shift) {
  const amountGhs = parsePayAmount(shift.total_pay);
  if (amountGhs <= 0) throw new Error("Invalid shift payout amount.");

  const recipientCode = await getOrCreatePaystackRecipient(worker);

  const response = await fetch("https://api.paystack.co/transfer", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      source: "balance",
      amount: Math.round(amountGhs * 100),
      recipient: recipientCode,
      reason: `CoverCare shift payout — ${shift.facility_name}`
    })
  });

  const data = await response.json();
  if (!data.status) throw new Error(data.message || "Paystack transfer failed.");

  return { transfer_code: data.data.transfer_code, amount: amountGhs };
}

app.get("/", (req, res) => {
  res.json({ message: "CoverCare Africa Backend is running." });
});

app.post("/worker", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const body = req.body;
  Object.keys(body).forEach(key => {
    if (typeof body[key] === "string") body[key] = sanitize(body[key]);
  });

  const { full_name, email, phone, role, license_number, city, country, experience, profile_photo_url, bio, license_file_url, license_verification_token } = body;

  if (!full_name || !email || !phone || !role || !city) {
    return res.status(400).json({ success: false, message: "full_name, email, phone, role, and city are required." });
  }

  if (user.email.toLowerCase() !== email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "Email does not match your authenticated account." });
  }

  // license_verified is never taken directly from client input. It's only set
  // to true here if the client presents a signed receipt proving /verify
  // actually confirmed this exact registration_number + name + country + role
  // against the regulator moments earlier. Otherwise it starts false and can
  // only be flipped later by an admin via /admin/toggle-license.
  const licenseAutoVerified = license_number && verifyLicenseVerificationToken(license_verification_token, {
    registration_number: license_number, name: full_name, country, role
  });

  const insertData = {
    full_name, email, phone, role, license_number, license_verified: !!licenseAutoVerified, city, country, experience, bio
  };
  if (profile_photo_url) insertData.profile_photo_url = profile_photo_url;
  if (license_file_url) insertData.license_file_url = license_file_url;

  const { error } = await supabase.from("workers").insert([insertData]);

  if (error) {
    log("error", "Worker save error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to save worker." });
  }

  log("info", "Worker saved", { email });
  return res.json({ success: true, message: "Worker saved successfully." });
});

app.post("/facility", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const body = req.body;
  Object.keys(body).forEach(key => {
    if (typeof body[key] === "string") body[key] = sanitize(body[key]);
  });

  const { facility_name, facility_type, city, country, contact_name, contact_role, email, phone, staff_needs, frequency, incorporation_doc_url, hefra_license_url, pharmacy_council_url } = body;

  if (user.email.toLowerCase() !== email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "Email does not match your authenticated account." });
  }

  const insertData = {
    facility_name, facility_type, city, country, contact_name, contact_role, email, phone, staff_needs, frequency
  };
  if (incorporation_doc_url) insertData.incorporation_doc_url = incorporation_doc_url;
  if (hefra_license_url) insertData.hefra_license_url = hefra_license_url;
  if (pharmacy_council_url) insertData.pharmacy_council_url = pharmacy_council_url;

  const { error } = await supabase.from("facilities").insert([insertData]);

  if (error) {
    log("error", "Facility save error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to save facility." });
  }

  log("info", "Facility saved", { facility_name });
  return res.json({ success: true, message: "Facility saved successfully." });
});

// ── Client (individual) signup ──
app.post("/client", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { full_name, phone, city, country, gender } = req.body;
  const email = user.email.toLowerCase();

  if (!full_name || !phone || !city) {
    return res.status(400).json({ success: false, message: "Name, phone, and city are required." });
  }

  // Check if client already exists
  const { data: existing } = await supabase.from("clients").select("id").eq("email", email).maybeSingle();
  if (existing) {
    return res.status(409).json({ success: false, message: "A client account with this email already exists." });
  }

  const { error } = await supabase.from("clients").insert([{
    full_name: sanitize(full_name),
    email,
    phone: sanitize(phone),
    city: sanitize(city),
    country: country ? sanitize(country) : null,
    gender: gender ? sanitize(gender) : null,
    user_id: user.id
  }]);

  if (error) {
    log("error", "Client save error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to save client." });
  }

  log("info", "Client saved", { email });
  return res.json({ success: true, message: "Account created successfully." });
});

app.post("/shift", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  return res.status(403).json({ success: false, message: "Direct shift creation is disabled. Post shifts through the payment flow." });
});

app.get("/verify", async (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (!checkRateLimit(ip, 5, 60000)) {
    return res.status(429).json({ success: false, message: "Too many verification requests. Please wait a minute and try again." });
  }

  const registration_number = sanitize(req.query.registration_number);
  const name = sanitize(req.query.name);
  const country = (req.query.country || "").toUpperCase();
  const role = (req.query.role || "").toLowerCase();

  if (!registration_number) {
    return res.status(400).json({ success: false, message: "Registration number is required." });
  }
  if (!name) {
    return res.status(400).json({ success: false, message: "Name is required for verification." });
  }

  log("info", "Verifying license", { registration_number, name, country, role });

  // Currently only auto-verify for Ghana pharmacists
  if (country === "GH" && role === "pharmacist") {
    return await verifyGhanaPharmacist(req, res, registration_number, name, country, role);
  }

  return res.json({
    success: false,
    message: `Auto-verification is not yet available for this profession in your country. Please upload your license document for manual review.`,
    data: { status: "manual_review", registration_number, country, role }
  });
});

async function verifyGhanaPharmacist(req, res, registration_number, name, country, role) {
  const nameParts = name.toLowerCase().trim().split(/\s+/);
  const firstName = nameParts[0] || "";
  const lastName = nameParts[nameParts.length - 1] || "";

  // ── Strategy A: Try direct HTTP API calls (lighter, faster) ──
  // The PC Ghana SPA likely calls a JSON API — probe common endpoint patterns.
  const https = require("https");
  const http = require("http");

  async function tryApiUrl(url) {
    return new Promise(resolve => {
      const client = url.startsWith("https") ? https : http;
      const req = client.get(url, {
        timeout: 2000,
        headers: {
          "Accept": "application/json, text/plain, */*",
          "User-Agent": "Mozilla/5.0 (compatible; CoverCareAfrica/1.0)"
        }
      }, resp => {
        let data = "";
        resp.on("data", chunk => data += chunk);
        resp.on("end", () => {
          try { resolve({ status: resp.statusCode, body: JSON.parse(data) }); }
          catch { resolve({ status: resp.statusCode, body: data }); }
        });
      });
      req.on("error", () => resolve(null));
      req.on("timeout", () => { req.destroy(); resolve(null); });
    });
  }

  const apiCandidates = [
    `https://forms.pcghana.org/api/search?registration=${encodeURIComponent(registration_number)}`,
    `https://forms.pcghana.org/api/v1/pharmacists/${encodeURIComponent(registration_number)}`,
    `https://forms.pcghana.org/api/pharmacists/search/${encodeURIComponent(registration_number)}`,
    `https://forms.pcghana.org/api/search?q=${encodeURIComponent(registration_number)}`,
    `https://forms.pcghana.org/search?registration_number=${encodeURIComponent(registration_number)}`,
    `https://forms.pcghana.org/api/public/search?number=${encodeURIComponent(registration_number)}`
  ];

  // Run all API probes in parallel — max ~2s total
  const apiResults = await Promise.all(apiCandidates.map(tryApiUrl));
  for (const apiResp of apiResults) {
    if (!apiResp || apiResp.status >= 500) continue;
    const bodyStr = typeof apiResp.body === "object" ? JSON.stringify(apiResp.body).toLowerCase() : String(apiResp.body).toLowerCase();
    if (bodyStr.includes(registration_number.toLowerCase()) || bodyStr.includes(firstName) || bodyStr.includes(lastName)) {
      log("info", "PC Ghana API hit", { url: "matched", status: apiResp.status, body: bodyStr.substring(0, 500) });
      const nameInResponse = bodyStr.includes(firstName) || bodyStr.includes(lastName);
      if (nameInResponse) {
        const verification_token = signLicenseVerification({ registration_number, name, country, role, iat: Date.now() });
        return res.json({
          success: true,
          message: "License verified in good standing with the relevant regulatory body.",
          data: { status: "verified_good", registration_number, name_verified: name, verification_token }
        });
      }
      return res.json({
        success: false,
        message: "Registration number found but name does not match regulatory records.",
        data: { status: "name_mismatch", registration_number }
      });
    }
  }

  log("info", "PC Ghana direct API calls all missed — falling back to Puppeteer (with 12s timeout)");

  // ── Strategy B: Puppeteer browser scraping (with hard timeout) ──
  // Puppeteer/Chromium is unreliable on Railway free tier, so we wrap
  // the entire flow in a timeout to avoid hanging the response.
  let puppeteerTimedOut = false;
  const PUPPETEER_TIMEOUT = 12000;

  const puppeteerResult = await new Promise(resolve => {
    const timer = setTimeout(() => {
      puppeteerTimedOut = true;
      resolve(null);
    }, PUPPETEER_TIMEOUT);

    (async () => {
      let page;
      let browser;
      try {
        browser = await browserPool.getBrowser();
        page = await browser.newPage();
        await page.setViewport({ width: 1280, height: 800 });

        await page.goto("https://forms.pcghana.org/#/search", {
          waitUntil: "domcontentloaded",
          timeout: 10000
        });

        await new Promise(r => setTimeout(r, 2000));

        // Try to find select
        const hasSelect = await page.evaluate(() => !!document.querySelector("select"));
        if (!hasSelect) {
          const bodySnippet = await page.evaluate(() => document.body.innerText.substring(0, 500));
          log("info", "PC Ghana no select found", { body: bodySnippet });
          resolve(null); return;
        }

        const allSelects = await page.evaluate(() => {
          const selects = document.querySelectorAll("select");
          return Array.from(selects).map((s, i) => ({
            index: i,
            options: Array.from(s.options).map(o => ({ value: o.value, text: o.text }))
          }));
        });

        // Select pharmacist option
        for (const sel of allSelects) {
          const pharmOpt = sel.options.find(o => o.text.toLowerCase().includes("pharmacist"));
          if (pharmOpt) {
            await page.evaluate(({ idx, val }) => {
              const s = document.querySelectorAll("select")[idx];
              if (s) { s.value = val; s.dispatchEvent(new Event("change", { bubbles: true })); }
            }, { idx: sel.index, val: pharmOpt.value });
            break;
          }
        }

        await new Promise(r => setTimeout(r, 1500));

        // Find the first visible input
        const inputSel = await page.evaluate(() => {
          const inputs = document.querySelectorAll("input:not([type='hidden']):not([type='submit']):not([type='button']):not([type='checkbox']):not([type='radio'])");
          for (const inp of inputs) {
            if (inp.offsetParent !== null) return inp.id || inp.name || "";
          }
          return "";
        });

        if (!inputSel) {
          resolve(null); return;
        }

        const selStr = inputSel.startsWith("#") ? `#${CSS.escape(inputSel)}` :
                       `#${CSS.escape(inputSel)}, input[name="${CSS.escape(inputSel)}"]`;

        await page.type(selStr, registration_number);
        await new Promise(r => setTimeout(r, 300));

        // Submit
        await page.evaluate(() => {
          const btns = document.querySelectorAll("button, input[type='submit']");
          for (const b of btns) {
            const t = (b.textContent || b.value || "").toLowerCase().trim();
            if (t.includes("search") || t.includes("find") || t.includes("go") || t === "ok") {
              b.click(); return;
            }
          }
          // No button found — press Enter on the focused input
          const inp = document.querySelector("input:focus");
          if (inp) {
            inp.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent("keypress", { key: "Enter", bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent("keyup", { key: "Enter", bubbles: true }));
          }
        });

        await new Promise(r => setTimeout(r, 6000));

        const bodyText = await page.evaluate(() => document.body.innerText);
        const resultText = bodyText.toLowerCase();

        log("info", "PC Ghana search result", { text: bodyText.substring(0, 2000) });

        // Parse the results
        const noResultPhrases = ["no results", "no record", "not found", "nothing found", "0 results", "no entries", "no data", "there are no"];
        const showsNoResults = noResultPhrases.some(p => resultText.includes(p));
        const hasRegPattern = /\b[A-Za-z]{2,}\s*\d{3,}\b/.test(resultText);
        const hasDigits = /\b\d{3,}\b/.test(resultText);
        const nameFound = resultText.includes(firstName) || resultText.includes(lastName);
        const hasData = (hasRegPattern || hasDigits) && !showsNoResults;

        if (hasData && nameFound) {
          const verification_token = signLicenseVerification({ registration_number, name, country, role, iat: Date.now() });
          resolve({
            success: true,
            message: "License verified in good standing with the relevant regulatory body.",
            data: { status: "verified_good", registration_number, name_verified: name, verification_token }
          });
          clearTimeout(timer);
          return;
        }

        if (hasData && !nameFound) {
          resolve({
            success: false,
            message: "Registration number found but name does not match regulatory records.",
            data: { status: "name_mismatch", registration_number }
          });
          clearTimeout(timer);
          return;
        }

        resolve({
          success: false,
          message: "Registration number not found in regulatory records. Please check again or upload your license document for manual review.",
          data: { status: "not_found", registration_number }
        });
        clearTimeout(timer);
      } catch (err) {
        log("error", "PC Ghana Puppeteer error", { error: err.message, stack: err.stack?.substring(0, 500) });
        resolve(null);
      } finally {
        try { if (page) await page.close(); } catch (_) {}
        clearTimeout(timer);
      }
    })();
  });

  // After Puppeteer (or timeout), handle result
  if (puppeteerTimedOut) {
    log("warn", "PC Ghana Puppeteer timed out — falling back to manual review");
  }

  if (puppeteerResult) {
    return res.json(puppeteerResult);
  }

  return res.json({
    success: false,
    message: "Auto-verification is temporarily unavailable. Upload your license document for manual review by our team.",
    data: { status: "manual_review", registration_number }
  });
}

app.post("/verify-identity", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 10)) return;

  const email = sanitize(req.body.email);
  const selfie_url = req.body.selfie_url;
  const id_document_url = req.body.id_document_url;

  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required." });
  }

  if (user.email.toLowerCase() !== email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "Email does not match your authenticated account." });
  }

  const { data: existing } = await supabase
    .from("workers")
    .select("id")
    .eq("email", email)
    .maybeSingle();

  if (!existing) {
    return res.status(404).json({ success: false, message: "Worker profile not found for this email." });
  }

  // The face-match check that led to this call ran entirely in the caller's
  // browser, so we cannot trust it as proof of identity — anyone can call this
  // endpoint directly. We only store the submitted evidence here; an admin
  // must confirm it via /admin/toggle-identity before identity_verified flips.
  const updateData = {};
  if (selfie_url) updateData.selfie_url = selfie_url;
  if (id_document_url) updateData.id_document_url = id_document_url;

  if (Object.keys(updateData).length > 0) {
    const { error } = await supabase.from("workers").update(updateData).eq("email", email);
    if (error) {
      log("error", "Identity update error", { error: error.message });
      return res.status(500).json({ success: false, message: "Failed to save verification documents." });
    }
  }

  log("info", "Identity documents submitted for review", { email });
  return res.json({ success: true, message: "Documents submitted. Your identity is pending review by our team." });
});

app.post("/payment/initialize", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;

  const email = sanitize(req.body.email);
  const amount = parseFloat(req.body.amount);
  const shift_data = req.body.shift_data;

  if (!email || !amount || amount <= 0) {
    return res.status(400).json({ success: false, message: "Valid email and amount are required." });
  }
  if (user.email.toLowerCase() !== email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "Email does not match your authenticated account." });
  }
  if (!shift_data) {
    return res.status(400).json({ success: false, message: "shift_data is required." });
  }

  const { facilityTotal } = computeShiftAmounts(shift_data);
  if (facilityTotal <= 0) {
    return res.status(400).json({ success: false, message: "Invalid shift pay details." });
  }
  if (Math.abs(amount - facilityTotal) > 0.02) {
    return res.status(400).json({ success: false, message: "Payment amount does not match shift total." });
  }

  // ── Check if facility is trusted and chose postpaid ──
  const wantsPostpaid = req.body.payment_method === "postpaid";

  let isTrusted = false;
  if (wantsPostpaid) {
    const { data: facility } = await supabase
      .from("facilities")
      .select("billing_model, trusted_by")
      .eq("email", email)
      .maybeSingle();
    isTrusted = facility?.billing_model === "postpaid" && facility?.trusted_by;
  }

  if (wantsPostpaid && isTrusted) {
    // Trusted facility chose postpaid — skip Paystack, create shift directly
    const shiftFields = pickShiftFields(shift_data);
    shiftFields.contact_email = user.email;
    shiftFields.payment_status = "postpaid";
    shiftFields.status = "open";
    const { workerTotal, facilityTotal: ft } = computeShiftAmounts(shiftFields);
    shiftFields.total_pay = `GHS ${workerTotal.toLocaleString()}`;

    const { error: insertError } = await supabase.from("shifts").insert([shiftFields]);
    if (insertError) {
      log("error", "Trusted facility shift insert error", { error: insertError.message, email });
      return res.status(500).json({ success: false, message: "Failed to create shift." });
    }

    log("info", "Shift posted (postpaid)", { email, facilityTotal: ft });
    return res.json({
      success: true,
      message: "Shift posted successfully. Your account will be billed at end of month.",
      postpaid: true,
      facility_total: ft
    });
  }

  // ── Check wallet balance for non-postpaid users ──
  const userType = await resolveUserType(email);
  if (userType) {
    const balance = await getWalletBalance(email, userType);
    if (balance >= facilityTotal) {
      // Sufficient wallet balance — deduct (atomically) and create shift directly
      let walletResult;
      try {
        walletResult = await updateWallet(email, userType, "deduction", facilityTotal, null, `Shift posting: ${shift_data.role_needed || ""} ${shift_data.shift_date || ""}`);
      } catch (walletErr) {
        if (walletErr.code === "INSUFFICIENT_BALANCE" || walletErr.code === "WALLET_CONTENTION") {
          return res.status(400).json({ success: false, message: "Wallet balance changed. Please try again." });
        }
        log("error", "Wallet deduction error", { error: walletErr.message, email });
        return res.status(500).json({ success: false, message: "Failed to charge wallet." });
      }

      const shiftFields = pickShiftFields(shift_data);
      shiftFields.contact_email = user.email;
      shiftFields.payment_status = "paid";
      shiftFields.status = "open";
      const { workerTotal, facilityTotal: ft } = computeShiftAmounts(shiftFields);
      shiftFields.total_pay = `GHS ${workerTotal.toLocaleString()}`;

      const { error: insertError } = await supabase.from("shifts").insert([shiftFields]);
      if (insertError) {
        // Refund wallet if shift insert fails
        await updateWallet(email, userType, "refund", facilityTotal, null, "Refund for failed shift creation");
        log("error", "Wallet shift insert error, refunded", { error: insertError.message, email });
        return res.status(500).json({ success: false, message: "Shift could not be created. Amount refunded to wallet." });
      }

      log("info", "Shift posted (wallet)", { email, facilityTotal: ft });
      return res.json({
        success: true,
        message: "Shift posted successfully. Amount deducted from wallet.",
        wallet_paid: true,
        facility_total: ft,
        wallet_balance: walletResult.balanceAfter
      });
    }
  }

  // ── Insufficient wallet or user type not found — use Paystack ──
  try {
    const response = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email,
        amount: Math.round(amount * 100),
        currency: "GHS",
        metadata: { shift_data: JSON.stringify(shift_data) }
      })
    });

    const data = await response.json();

    if (!data.status) {
      log("error", "Paystack init failed", { error: data.message });
      return res.status(400).json({ success: false, message: "Payment initialization failed." });
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
    return res.status(500).json({ success: false, message: "Payment service unavailable." });
  }
});

app.post("/payment/verify", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;

  const reference = sanitize(req.body.reference);
  if (!reference) {
    return res.status(400).json({ success: false, message: "Payment reference is required." });
  }

  try {
    const { data: existingShift } = await supabase
      .from("shifts")
      .select("id")
      .eq("payment_reference", reference)
      .maybeSingle();

    if (existingShift) {
      return res.json({ success: true, message: "Payment already verified and shift created.", reference, already_processed: true });
    }

    const response = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
    });

    const data = await response.json();

    if (!data.status || data.data.status !== "success") {
      log("error", "Payment verification failed", { reference });
      return res.status(400).json({ success: false, message: "Payment verification failed." });
    }

    const metadata = data.data.metadata;
    const rawShiftData = metadata.shift_data ? JSON.parse(metadata.shift_data) : null;

    if (!rawShiftData) {
      return res.status(400).json({ success: false, message: "Shift data missing from payment." });
    }

    const shiftFields = pickShiftFields(rawShiftData);
    shiftFields.contact_email = user.email;
    const { workerTotal, facilityTotal } = computeShiftAmounts(shiftFields);
    const paidAmount = data.data.amount / 100;

    if (Math.abs(paidAmount - facilityTotal) > 0.02) {
      log("error", "Payment amount mismatch", { reference, paidAmount, facilityTotal });
      return res.status(400).json({ success: false, message: "Paid amount does not match expected shift cost." });
    }

    shiftFields.total_pay = `GHS ${workerTotal.toLocaleString()}`;

    const { error } = await supabase.from("shifts").insert([{
      ...shiftFields, payment_reference: reference, payment_status: "paid", status: "open"
    }]);

    if (error) {
      log("error", "Shift save error after payment", { error: error.message, reference });
      return res.status(500).json({
        success: false,
        message: "Payment received but shift could not be saved. Contact support with your reference."
      });
    }

    log("info", "Payment verified", { reference, amount: paidAmount });
    return res.json({ success: true, message: "Payment verified successfully.", amount: paidAmount, reference });

  } catch (err) {
    log("error", "Payment verify error", { error: err.message });
    return res.status(500).json({ success: false, message: "Verification service unavailable." });
  }
});

app.post("/shift/accept", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const shiftId = sanitize(req.body.shift_id);
  const workerId = sanitize(req.body.worker_id);

  if (!shiftId || !workerId) {
    return res.status(400).json({ success: false, message: "shift_id and worker_id are required." });
  }

  const { data: worker, error: workerError } = await supabase
    .from("workers")
    .select("id, full_name, email, phone, role, license_verified, identity_verified")
    .eq("id", workerId)
    .single();

  if (workerError || !worker) {
    return res.status(404).json({ success: false, message: "Worker not found." });
  }

  const shift = await getShiftById(shiftId);
  if (!shift) {
    return res.status(404).json({ success: false, message: "Shift not found." });
  }

  if (shift.status !== "open") {
    if (shift.worker_id === workerId && ["accepted", "in_progress"].includes(shift.status)) {
      let qrToken = shift.qr_token;
      let shiftRecord = shift;

      if (!qrToken) {
        qrToken = generateQrToken();
        const { data: updated, error: updateError } = await supabase
          .from("shifts")
          .update({ qr_token: qrToken })
          .eq("id", shiftId)
          .select()
          .single();

        if (updateError) {
          log("error", "QR token regenerate error", { error: updateError.message });
          return res.status(500).json({ success: false, message: "Failed to generate QR code." });
        }
        shiftRecord = updated;
      }

      return res.json({
        success: true,
        message: "Shift already accepted.",
        qr_url: buildQrUrl(shiftId, workerId, qrToken),
        qr_token: qrToken,
        shift: shiftRecord
      });
    }

    return res.status(400).json({ success: false, message: "This shift is no longer available." });
  }

  if (shift.payment_status && shift.payment_status !== "paid") {
    return res.status(400).json({ success: false, message: "This shift has not been paid for yet." });
  }

  if (!worker.identity_verified) {
    return res.status(400).json({ success: false, message: "Complete identity verification before accepting shifts." });
  }

  if (isPharmacyRole(shift.role_needed) && !worker.license_verified) {
    return res.status(400).json({ success: false, message: "License verification is required for pharmacy shifts." });
  }

  const qrToken = generateQrToken();
  const qrUrl = buildQrUrl(shiftId, workerId, qrToken);

  const { data, error } = await supabase
    .from("shifts")
    .update({ worker_id: workerId, qr_token: qrToken, status: "accepted" })
    .eq("id", shiftId)
    .eq("status", "open")
    .select()
    .single();

  if (error || !data) {
    log("error", "Shift accept error", { error: error?.message });
    return res.status(409).json({ success: false, message: "This shift was just taken by another worker." });
  }

  log("info", "Shift accepted", { shiftId, workerId });
  return res.json({
    success: true,
    message: "Shift accepted. Show your QR code on arrival.",
    qr_url: qrUrl,
    qr_token: qrToken,
    shift: data
  });
});

app.get("/qr/validate", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { shift_id, worker_id, token } = req.query;
  if (!shift_id || !worker_id || !token) {
    return res.status(400).json({ success: false, message: "Missing shift_id, worker_id, or token." });
  }

  const validation = await validateQrCredentials(shift_id, worker_id, token);
  if (!validation.ok) {
    return res.status(validation.status).json({ success: false, message: validation.message });
  }

  const { shift } = validation;
  if (shift.contact_email?.toLowerCase() !== user.email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "This shift does not belong to your facility." });
  }

  const { data: worker } = await supabase
    .from("workers")
    .select("id, full_name, role, license_verified, identity_verified")
    .eq("id", worker_id)
    .single();

  return res.json({
    success: true,
    shift: { role_needed: shift.role_needed, shift_date: shift.shift_date, start_time: shift.start_time },
    worker
  });
});

app.post("/shift/arrive", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 30)) return;

  const shiftId = sanitize(req.body.shift_id);
  const workerId = sanitize(req.body.worker_id);
  const token = sanitize(req.body.token);
  const facilityEmail = sanitize(req.body.facility_email);

  if (!shiftId || !workerId || !token) {
    return res.status(400).json({ success: false, message: "shift_id, worker_id, and token are required." });
  }

  const validation = await validateQrCredentials(shiftId, workerId, token);
  if (!validation.ok) {
    return res.status(validation.status).json({ success: false, message: validation.message });
  }

  const { shift } = validation;

  if (isShiftWindowPassed(shift)) {
    return res.status(400).json({ success: false, message: "This shift has already ended. Check-in is no longer available." });
  }

  if (facilityEmail && shift.contact_email !== facilityEmail) {
    return res.status(403).json({ success: false, message: "This shift does not belong to your facility." });
  }

  if (shift.status === "in_progress") {
    return res.json({ success: true, message: "Worker already checked in.", already_arrived: true, arrival_time: shift.arrival_time, shift });
  }

  if (shift.status !== "accepted") {
    return res.status(400).json({ success: false, message: `Cannot check in — shift status is "${shift.status}".` });
  }

  const arrivalTime = new Date();
  const lateMinutes = calcLateMinutes(shift, arrivalTime);
  const durationHours = getShiftDurationHours(shift);
  const adjustedPay = lateMinutes > 0 ? calcAdjustedPay(shift.total_pay, durationHours, lateMinutes) : shift.total_pay;
  const facilityCredit = lateMinutes > 0
    ? Math.round((parsePayAmount(shift.total_pay) - parsePayAmount(adjustedPay)) * 100) / 100
    : 0;

  const updateFields = {
    arrival_time: arrivalTime.toISOString(),
    status: "in_progress",
    late_minutes: lateMinutes,
    facility_credit: facilityCredit
  };
  if (lateMinutes > 0) updateFields.adjusted_pay = adjustedPay;

  const { data, error } = await supabase
    .from("shifts")
    .update(updateFields)
    .eq("id", shiftId)
    .eq("status", "accepted")
    .select()
    .single();

  if (error || !data) {
    log("error", "Shift arrive error", { error: error?.message });
    return res.status(500).json({ success: false, message: "Failed to log arrival." });
  }

  const { data: worker } = await supabase
    .from("workers")
    .select("id, full_name, role, license_verified, identity_verified")
    .eq("id", workerId)
    .single();

  log("info", "Worker arrived", { shiftId, workerId, arrivalTime: arrivalTime.toISOString(), lateMinutes });
  return res.json({
    success: true,
    message: lateMinutes > 0
      ? `Arrival confirmed. You arrived ${lateMinutes} min late — pay adjusted to ${adjustedPay}.`
      : "Arrival confirmed. Shift is now in progress.",
    arrival_time: arrivalTime.toISOString(),
    late_minutes: lateMinutes,
    adjusted_pay: adjustedPay,
    facility_credit: facilityCredit,
    worker,
    shift: data
  });
});

app.post("/shift/complete", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;

  const shiftId = sanitize(req.body.shift_id);
  const workerId = sanitize(req.body.worker_id);
  const token = sanitize(req.body.token);

  if (!shiftId || !workerId || !token) {
    return res.status(400).json({ success: false, message: "shift_id, worker_id, and token are required." });
  }

  const validation = await validateQrCredentials(shiftId, workerId, token);
  if (!validation.ok) {
    return res.status(validation.status).json({ success: false, message: validation.message });
  }

  const { shift } = validation;

  if (shift.status === "completed") {
    return res.json({ success: true, message: "Shift already completed.", already_completed: true, completion_time: shift.completion_time, shift });
  }

  if (shift.status !== "in_progress") {
    return res.status(400).json({
      success: false,
      message: `Cannot complete — shift status is "${shift.status}". Worker must check in first.`
    });
  }

  const MIN_SHIFT_MINUTES = 30;
  if (shift.arrival_time) {
    const elapsedMins = (Date.now() - new Date(shift.arrival_time).getTime()) / 60000;
    if (elapsedMins < MIN_SHIFT_MINUTES) {
      return res.status(400).json({ success: false, message: `Shift must run at least ${MIN_SHIFT_MINUTES} minutes before checkout.` });
    }
  }

  const completionTime = new Date();
  const arrivalDate = shift.arrival_time ? new Date(shift.arrival_time) : null;
  const scheduledEnd = getShiftEndTime(shift);
  let finalPay = shift.total_pay;
  let madeUp = false;
  let actualMinutes = 0;

  if (arrivalDate && scheduledEnd) {
    actualMinutes = Math.round((completionTime.getTime() - arrivalDate.getTime()) / 60000);
    const durationHours = getShiftDurationHours(shift);
    const scheduledMinutes = durationHours * 60;

    // Check if worker stayed late enough to make up for late arrival
    if (shift.late_minutes > 0) {
      const extraMinutes = Math.max(0, actualMinutes - scheduledMinutes);
      if (extraMinutes >= shift.late_minutes) {
        madeUp = true;
        finalPay = shift.total_pay;
      } else {
        finalPay = shift.adjusted_pay || shift.total_pay;
      }
    }
  }

  const isWaived = shift.waived || false;
  const completeFields = {
    completion_time: completionTime.toISOString(),
    status: "completed",
    actual_hours: Math.round(actualMinutes / 6) / 10,
    made_up: madeUp || isWaived,
    facility_credit: (madeUp || isWaived) ? 0 : (shift.facility_credit || 0)
  };
  if (finalPay) completeFields.adjusted_pay = finalPay;

  const { data, error } = await supabase
    .from("shifts")
    .update(completeFields)
    .eq("id", shiftId)
    .eq("status", "in_progress")
    .select()
    .single();

  if (error || !data) {
    log("error", "Shift complete error", { error: error?.message });
    return res.status(500).json({ success: false, message: "Failed to complete shift." });
  }

  const { data: worker } = await supabase
    .from("workers")
    .select("id, full_name, email, phone, paystack_recipient_code")
    .eq("id", workerId)
    .single();

  let payout = null;
  let payoutFailed = false;

  if (!worker) {
    payoutFailed = true;
  } else {
    try {
      payout = await initiateWorkerPayout(worker, data);
      await supabase.from("shifts").update({ payout_status: "paid", payout_reference: payout.transfer_code }).eq("id", shiftId);
    } catch (err) {
      payoutFailed = true;
      log("error", "Payout failed", { shiftId, error: err.message });
      await supabase.from("shifts").update({ payout_status: "failed" }).eq("id", shiftId).catch(() => {});
    }
  }

  let completeMsg = "";
  if (madeUp) {
    completeMsg = `You stayed late and made up for the late arrival — full pay of ${finalPay} retained.`;
  } else if (isWaived) {
    completeMsg = `Shift completed. Facility waived the late arrival — full pay of ${finalPay} retained.`;
  } else if (shift.late_minutes > 0) {
    const credit = shift.facility_credit || 0;
    completeMsg = `Shift completed. Pay adjusted to ${finalPay} due to ${shift.late_minutes} min late arrival. Facility saved GHS ${credit}.`;
  } else {
    completeMsg = payout ? "Shift completed. Payout sent to worker's Mobile Money." : "Shift completed but payout failed — support will follow up.";
  }

  log("info", "Shift completed", { shiftId, workerId, completionTime: completionTime.toISOString(), payout: payout ? "sent" : "failed", lateMinutes: shift.late_minutes, madeUp });
  return res.json({
    success: true,
    message: completeMsg,
    completion_time: completionTime.toISOString(),
    late_minutes: shift.late_minutes || 0,
    made_up: madeUp,
    adjusted_pay: finalPay,
    facility_credit: (madeUp || isWaived) ? 0 : (shift.facility_credit || 0),
    actual_hours: Math.round(actualMinutes / 6) / 10,
    payout: payout ? { amount: payout.amount, transfer_code: payout.transfer_code } : null,
    shift: data
  });
});

app.post("/shifts/waive-deduction", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;

  const shiftId = sanitize(req.body.shift_id);
  if (!shiftId) {
    return res.status(400).json({ success: false, message: "shift_id is required." });
  }

  const shift = await getShiftById(shiftId);
  if (!shift) {
    return res.status(404).json({ success: false, message: "Shift not found." });
  }

  if (shift.contact_email !== user.email) {
    return res.status(403).json({ success: false, message: "This shift does not belong to your facility." });
  }

  if (!shift.late_minutes || shift.late_minutes <= 0) {
    return res.status(400).json({ success: false, message: "This shift had no late deduction to waive." });
  }

  const { error } = await supabase
    .from("shifts")
    .update({
      adjusted_pay: shift.total_pay,
      facility_credit: 0,
      waived: true
    })
    .eq("id", shiftId)
    .eq("contact_email", user.email);

  if (error) {
    log("error", "Waive deduction error", { error: error.message, shiftId });
    return res.status(500).json({ success: false, message: "Failed to waive deduction." });
  }

  log("info", "Deduction waived", { shiftId, facility: user.email });
  return res.json({ success: true, message: "Deduction waived. Worker will receive full pay." });
});

app.post("/applications/apply", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { worker_id, shift_id, cover_note } = req.body;

  if (!worker_id || !shift_id) {
    return res.status(400).json({ success: false, message: "worker_id and shift_id are required." });
  }

  const { data: worker } = await supabase
    .from("workers")
    .select("id, email")
    .eq("id", worker_id)
    .single();

  if (!worker || worker.email.toLowerCase() !== user.email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "You can only apply on behalf of your own worker profile." });
  }

  const { data: shift } = await supabase
    .from("shifts")
    .select("id, status, contact_email, role_needed, shift_date, assigned_to_worker_id")
    .eq("id", shift_id)
    .single();

  if (!shift || shift.status !== "open") {
    return res.status(400).json({ success: false, message: "This shift is no longer accepting applications." });
  }

  if (shift.assigned_to_worker_id && shift.assigned_to_worker_id !== parseInt(worker_id)) {
    return res.status(403).json({ success: false, message: "This shift is assigned to another worker." });
  }

  const { data: existing } = await supabase
    .from("applications")
    .select("id, status")
    .eq("worker_id", worker_id)
    .eq("shift_id", shift_id)
    .single();

  if (existing) {
    return res.status(400).json({ success: false, message: "You have already applied to this shift.", existing_status: existing.status });
  }

  const { data, error } = await supabase
    .from("applications")
    .insert([{ worker_id, shift_id, cover_note: sanitize(cover_note || ""), status: "pending" }])
    .select()
    .single();

  if (error) {
    log("error", "Application error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to submit application." });
  }

  await supabase.from("notifications").insert([{
    email: shift.contact_email?.toLowerCase(),
    title: "New application received",
    message: `A worker has applied for ${shift.role_needed} on ${shift.shift_date}`,
    type: "info",
    read: false,
    created_at: new Date().toISOString()
  }]).catch(() => {});

  // ── Auto-accept if worker is the preassigned worker ──
  if (shift.assigned_to_worker_id && parseInt(shift.assigned_to_worker_id) === parseInt(worker_id)) {
    const qrToken = require("crypto").randomBytes(32).toString("hex");
    const qrUrl = `${process.env.ARRIVE_BASE_URL || "https://covercare-africa.vercel.app"}/arrive?shift_id=${shift_id}&worker_id=${worker_id}&token=${qrToken}`;
    const { error: acceptError } = await supabase
      .from("shifts")
      .update({ worker_id, qr_token: qrToken, status: "accepted" })
      .eq("id", shift_id);
    if (!acceptError) {
      log("info", "Preassigned shift auto-accepted", { worker_id, shift_id });
      return res.json({
        success: true,
        message: "Assigned shift accepted! Show the QR code on arrival.",
        auto_accepted: true,
        qr_url: qrUrl,
        qr_token: qrToken
      });
    }
  }

  log("info", "Application submitted", { worker_id, shift_id });
  return res.json({ success: true, message: "Application submitted successfully.", data });
});

app.post("/applications/withdraw", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { application_id, worker_id } = req.body;

  if (!application_id || !worker_id) {
    return res.status(400).json({ success: false, message: "application_id and worker_id are required." });
  }

  const { data: worker } = await supabase
    .from("workers")
    .select("id, email")
    .eq("id", worker_id)
    .single();

  if (!worker || worker.email.toLowerCase() !== user.email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "You can only withdraw your own applications." });
  }

  const { data, error } = await supabase
    .from("applications")
    .update({ status: "withdrawn", responded_at: new Date().toISOString() })
    .eq("id", application_id)
    .eq("worker_id", worker_id)
    .eq("status", "pending")
    .select()
    .single();

  if (error || !data) {
    return res.status(400).json({ success: false, message: "Could not withdraw. Application may already be processed." });
  }

  log("info", "Application withdrawn", { application_id, worker_id });
  return res.json({ success: true, message: "Application withdrawn successfully.", data });
});

app.post("/applications/accept", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { application_id, facility_email } = req.body;

  if (!application_id || !facility_email) {
    return res.status(400).json({ success: false, message: "application_id and facility_email are required." });
  }

  const { data: application } = await supabase
    .from("applications")
    .select("*, shifts(*), workers(*)")
    .eq("id", application_id)
    .single();

  if (!application) {
    return res.status(404).json({ success: false, message: "Application not found." });
  }

  if (application.shifts?.contact_email?.toLowerCase() !== facility_email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "This shift does not belong to your facility." });
  }

  if (user.email.toLowerCase() !== facility_email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "You can only accept applications for your own shifts." });
  }

  const { data, error } = await supabase
    .from("applications")
    .update({ status: "accepted", responded_at: new Date().toISOString(), responded_by: facility_email })
    .eq("id", application_id)
    .select()
    .single();

  if (error) {
    return res.status(500).json({ success: false, message: "Failed to accept application." });
  }

  await supabase
    .from("applications")
    .update({ status: "rejected", responded_at: new Date().toISOString(), responded_by: "system" })
    .eq("shift_id", application.shift_id)
    .eq("status", "pending")
    .neq("id", application_id);

  const qrToken = generateQrToken();
  await supabase
    .from("shifts")
    .update({ status: "accepted", worker_id: application.worker_id, qr_token: qrToken })
    .eq("id", application.shift_id);

  log("info", "Application accepted", { application_id, facility_email });
  return res.json({ success: true, message: "Application accepted. Worker assigned to shift.", data, worker: application.workers });
});

app.post("/applications/reject", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { application_id, facility_email } = req.body;

  if (!application_id) {
    return res.status(400).json({ success: false, message: "application_id is required." });
  }

  const { data: application } = await supabase
    .from("applications")
    .select("id, shifts(contact_email)")
    .eq("id", application_id)
    .single();

  if (!application) {
    return res.status(404).json({ success: false, message: "Application not found." });
  }

  if (application.shifts?.contact_email?.toLowerCase() !== (facility_email || user.email).toLowerCase()) {
    return res.status(403).json({ success: false, message: "This application does not belong to your facility." });
  }

  const { data, error } = await supabase
    .from("applications")
    .update({ status: "rejected", responded_at: new Date().toISOString(), responded_by: facility_email || user.email })
    .eq("id", application_id)
    .eq("status", "pending")
    .select()
    .single();

  if (error || !data) {
    return res.status(400).json({ success: false, message: "Could not reject application." });
  }

  log("info", "Application rejected", { application_id });
  return res.json({ success: true, message: "Application rejected.", data });
});

app.get("/applications/shift/:shift_id", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { shift_id } = req.params;

  const { data: shift } = await supabase
    .from("shifts")
    .select("contact_email")
    .eq("id", shift_id)
    .single();

  if (!shift || shift.contact_email?.toLowerCase() !== user.email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "You can only view applications for your own shifts." });
  }

  const { data, error } = await supabase
    .from("applications")
    .select(`*, workers(id, full_name, email, role, city, experience, license_verified, identity_verified)`)
    .eq("shift_id", shift_id)
    .order("created_at", { ascending: false });

  if (error) {
    return res.status(500).json({ success: false, message: "Failed to load applications." });
  }

  return res.json({ success: true, data: data || [] });
});

app.get("/applications/worker/:worker_id", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { worker_id } = req.params;

  const { data: worker } = await supabase
    .from("workers")
    .select("id, email")
    .eq("id", worker_id)
    .single();

  if (!worker || worker.email?.toLowerCase() !== user.email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "You can only view your own applications." });
  }

  const { data, error } = await supabase
    .from("applications")
    .select(`*, shifts(id, facility_name, role_needed, city, shift_date, start_time, duration, pay_rate, status)`)
    .eq("worker_id", worker_id)
    .order("created_at", { ascending: false });

  if (error) {
    return res.status(500).json({ success: false, message: "Failed to load applications." });
  }

  return res.json({ success: true, data: data || [] });
});

app.post("/admin/verify", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const isAdmin = ADMINS.includes(user.email.toLowerCase());
  return res.json({ success: true, admin: isAdmin, email: user.email });
});

app.get("/admin/analytics", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  try {
    const now = new Date();
    const sixMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 5, 1);

    const months = [];
    for (let i = 5; i >= 0; i--) {
      const start = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const end = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);
      months.push({
        label: start.toLocaleString("default", { month: "short", year: "2-digit" }),
        start: start.toISOString(),
        end: end.toISOString()
      });
    }

    const { data: allWorkers } = await supabase.from("workers").select("created_at");
    const { data: allFacilities } = await supabase.from("facilities").select("created_at");
    const { data: allShifts } = await supabase.from("shifts").select("created_at, total_pay, payment_status, status");
    const { data: allRatings } = await supabase.from("ratings").select("rating");
    const { data: supportTickets } = await supabase.from("support_tickets").select("status");
    const { data: allApps } = await supabase.from("applications").select("status");

    const workerCountByMonth = months.map(m => ({
      month: m.label,
      count: (allWorkers || []).filter(w => w.created_at && w.created_at >= m.start && w.created_at < m.end).length
    }));

    const shiftCountByMonth = months.map(m => ({
      month: m.label,
      count: (allShifts || []).filter(s => s.created_at && s.created_at >= m.start && s.created_at < m.end).length
    }));

    const revenueByMonth = months.map(m => ({
      month: m.label,
      amount: (allShifts || []).filter(s => s.created_at && s.created_at >= m.start && s.created_at < m.end && s.payment_status === "paid").reduce((sum, s) => {
        return sum + (parseFloat((s.total_pay || "").replace(/[^0-9.]/g, "")) || 0) * 0.25;
      }, 0)
    }));

    const avgRating = allRatings && allRatings.length > 0
      ? (allRatings.reduce((s, r) => s + (r.rating || 0), 0) / allRatings.length).toFixed(1)
      : "—";

    const pendingApps = (allApps || []).filter(a => a.status === "pending").length;

    const openTickets = (supportTickets || []).filter(t => t.status === "open").length;

    const { count: verifiedCount } = await supabase.from("workers").select("id", { count: "exact", head: true }).eq("license_verified", true);
    const { count: identityVerifiedCount } = await supabase.from("workers").select("id", { count: "exact", head: true }).eq("identity_verified", true);
    const { count: unverifiedCount } = await supabase.from("workers").select("id", { count: "exact", head: true }).eq("license_verified", false);

    const activeShifts = (allShifts || []).filter(s => s.status === "in_progress" || s.status === "accepted").length;
    const inProgressShifts = (allShifts || []).filter(s => s.status === "in_progress").length;
    const unfilledShifts = (allShifts || []).filter(s => s.status === "open").length;
    const paidShiftsList = (allShifts || []).filter(s => s.payment_status === "paid");
    const paidShifts = paidShiftsList.length;
    const totalShifts = (allShifts || []).length;
    const filledShifts = (allShifts || []).filter(s => s.status === "completed" || s.status === "in_progress" || s.status === "accepted").length;
    const fillRate = totalShifts > 0 ? Math.round((filledShifts / totalShifts) * 100) : 0;

    const totalRevenue = paidShiftsList.reduce((sum, s) => {
      return sum + (parseFloat((s.total_pay || "").replace(/[^0-9.]/g, "")) || 0) * 0.25;
    }, 0);

    const workers = allWorkers || [];
    const facilities = allFacilities || [];
    const totalWorkersCount = workers.length;
    const totalFacilitiesCount = facilities.length;

    return res.json({
      success: true,
      workersByMonth: workerCountByMonth,
      shiftsByMonth: shiftCountByMonth,
      revenueByMonth,
      avgRating,
      pendingApplications: pendingApps,
      openSupportTickets: openTickets,
      verifiedWorkersCount: verifiedCount || 0,
      identityVerifiedCount: identityVerifiedCount || 0,
      unverifiedCount: unverifiedCount || 0,
      activeShifts,
      inProgressShifts,
      unfilledShifts,
      paidShifts,
      totalShifts,
      fillRate,
      totalRevenue,
      totalWorkers: totalWorkersCount,
      totalFacilities: totalFacilitiesCount
    });
  } catch (err) {
    log("error", "Admin analytics error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load analytics." });
  }
});

// ── Admin: performance dashboard ──
app.get("/admin/performance", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  try {
    const { data: allShifts } = await supabase
      .from("shifts")
      .select("*, workers(full_name, email, role, city, profile_photo_url)")
      .not("worker_id", "is", null);

    const { data: allFacilities } = await supabase
      .from("facilities")
      .select("*");

    const { data: allRatings } = await supabase
      .from("ratings")
      .select("*");

    const facilityMap = {};
    for (const f of allFacilities || []) {
      facilityMap[f.email?.toLowerCase()] = f;
    }

    // ── Aggregate worker performance ──
    const workerMap = {};
    for (const s of allShifts || []) {
      if (!s.worker_id) continue;
      const wid = s.worker_id;
      if (!workerMap[wid]) {
        const w = s.workers || {};
        workerMap[wid] = {
          worker_id: wid,
          full_name: w.full_name || "Unknown",
          email: w.email || "",
          role: w.role || "",
          city: w.city || "",
          photo_url: w.profile_photo_url || "",
          completed: 0,
          total_earnings: 0,
          late_count: 0,
          total_late_minutes: 0
        };
      }
      const earnings = parsePayAmount(s.total_pay);
      if (s.status === "completed") {
        workerMap[wid].completed++;
        workerMap[wid].total_earnings += earnings;
        if (s.late_minutes && s.late_minutes > 0) {
          workerMap[wid].late_count++;
          workerMap[wid].total_late_minutes += s.late_minutes;
        }
      }
    }

    // ── Aggregate facility performance ──
    // Need ALL shifts for facilities (including unfilled)
    const { data: allShiftsForFacilities } = await supabase
      .from("shifts")
      .select("*");

    const facilityPerf = {};
    for (const s of allShiftsForFacilities || []) {
      const email = s.contact_email?.toLowerCase();
      if (!email) continue;
      if (!facilityPerf[email]) {
        const f = facilityMap[email] || {};
        facilityPerf[email] = {
          email,
          facility_name: f.facility_name || s.facility_name || email,
          facility_type: f.facility_type || s.facility_type || "",
          city: f.city || s.city || "",
          total_posted: 0,
          completed: 0,
          total_spend: 0,
          credits_saved: 0
        };
      }
      facilityPerf[email].total_posted++;
      const facilityTotal = Math.round(parsePayAmount(s.total_pay) * 1.25 * 100) / 100;
      if (s.status === "completed") {
        facilityPerf[email].completed++;
        facilityPerf[email].total_spend += facilityTotal;
      }
      if (s.facility_credit) {
        facilityPerf[email].credits_saved += parseFloat(s.facility_credit) || 0;
      }
    }

    // Add fill rate
    for (const email of Object.keys(facilityPerf)) {
      const p = facilityPerf[email];
      p.fill_rate = p.total_posted > 0 ? Math.round((p.completed / p.total_posted) * 100) : 0;
    }

    // ── Ratings ──
    const ratingMap = {};
    for (const r of allRatings || []) {
      const target = r.target_email?.toLowerCase();
      if (!target) continue;
      if (!ratingMap[target]) ratingMap[target] = [];
      ratingMap[target].push(r.rating);
    }

    function avgRating(email) {
      const ratings = ratingMap[email?.toLowerCase()];
      if (!ratings || ratings.length === 0) return null;
      return Math.round((ratings.reduce((a, b) => a + b, 0) / ratings.length) * 10) / 10;
    }

    // ── Build response ──
    const allWorkers = Object.values(workerMap).map(w => ({
      ...w,
      avg_rating: avgRating(w.email),
      on_time_rate: w.completed > 0 ? Math.round(((w.completed - w.late_count) / w.completed) * 100) : 100
    }));

    const allFacilitiesPerf = Object.values(facilityPerf).map(f => ({
      ...f,
      avg_rating: avgRating(f.email)
    }));

    // Sort
    allWorkers.sort((a, b) => b.completed - a.completed || b.total_earnings - a.total_earnings);
    allFacilitiesPerf.sort((a, b) => b.completed - a.completed || b.total_spend - a.total_spend);

    return res.json({
      success: true,
      topWorkers: allWorkers.slice(0, 20),
      topFacilities: allFacilitiesPerf.slice(0, 20),
      workerCount: allWorkers.length,
      facilityCount: allFacilitiesPerf.length,
      totalCompleted: allShiftsForFacilities?.filter(s => s.status === "completed").length || 0
    });
  } catch (err) {
    log("error", "Admin performance error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load performance data." });
  }
});

// ── Admin: get full worker detail ──
app.get("/admin/worker/:id", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  try {
    const { data: worker, error } = await supabase
      .from("workers")
      .select("*")
      .eq("id", req.params.id)
      .single();

    if (error || !worker) {
      return res.status(404).json({ success: false, message: "Worker not found." });
    }

    // Get shift stats
    const { data: shifts } = await supabase
      .from("shifts")
      .select("*")
      .eq("worker_id", worker.id);

    const shiftStats = {
      total: (shifts || []).length,
      completed: (shifts || []).filter(s => s.status === "completed").length,
      in_progress: (shifts || []).filter(s => s.status === "in_progress").length,
      cancelled: (shifts || []).filter(s => s.status === "cancelled").length,
      total_earnings: (shifts || []).reduce((sum, s) => sum + parsePayAmount(s.total_pay), 0)
    };

    return res.json({ success: true, worker, shiftStats });
  } catch (err) {
    log("error", "Admin worker detail error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load worker details." });
  }
});

// ── Admin: get full facility detail ──
app.get("/admin/facility/:id", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  try {
    const { data: facility, error } = await supabase
      .from("facilities")
      .select("*")
      .eq("id", req.params.id)
      .single();

    if (error || !facility) {
      return res.status(404).json({ success: false, message: "Facility not found." });
    }

    // Get shift stats
    const { data: shifts } = await supabase
      .from("shifts")
      .select("*")
      .eq("contact_email", facility.email);

    const shiftStats = {
      total: (shifts || []).length,
      completed: (shifts || []).filter(s => s.status === "completed").length,
      in_progress: (shifts || []).filter(s => s.status === "in_progress").length,
      open: (shifts || []).filter(s => s.status === "open").length,
      cancelled: (shifts || []).filter(s => s.status === "cancelled").length,
      total_spend: (shifts || []).reduce((sum, s) => sum + parsePayAmount(s.total_pay) * 1.25, 0)
    };

    return res.json({ success: true, facility, shiftStats });
  } catch (err) {
    log("error", "Admin facility detail error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load facility details." });
  }
});

// ── Admin: list all clients ──
app.get("/admin/clients", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  try {
    const { data: clients, error } = await supabase
      .from("clients")
      .select("*")
      .order("id", { ascending: false });

    if (error) {
      log("error", "Admin list clients error", { error: error.message });
      return res.status(500).json({ success: false, message: "Failed to load clients." });
    }

    return res.json({ success: true, clients: clients || [] });
  } catch (err) {
    log("error", "Admin list clients error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load clients." });
  }
});

// ── Admin: get full client detail ──
app.get("/admin/client/:id", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  try {
    const { data: client, error } = await supabase
      .from("clients")
      .select("*")
      .eq("id", req.params.id)
      .single();

    if (error || !client) {
      return res.status(404).json({ success: false, message: "Client not found." });
    }

    // Get shift stats (shifts posted by this client via contact_email)
    const { data: shifts } = await supabase
      .from("shifts")
      .select("*")
      .eq("contact_email", client.email);

    const shiftStats = {
      total: (shifts || []).length,
      completed: (shifts || []).filter(s => s.status === "completed").length,
      in_progress: (shifts || []).filter(s => s.status === "in_progress").length,
      open: (shifts || []).filter(s => s.status === "open").length,
      cancelled: (shifts || []).filter(s => s.status === "cancelled").length,
      total_spend: (shifts || []).reduce((sum, s) => sum + parsePayAmount(s.total_pay) * 1.25, 0)
    };

    return res.json({ success: true, client, shiftStats });
  } catch (err) {
    log("error", "Admin client detail error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load client details." });
  }
});

// ── Admin: toggle facility billing model ──
app.post("/admin/toggle-billing", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  const rawId = req.body?.facility_id;
  const facility_id = (rawId || "").toString().trim();
  log("info", "Toggle billing request", { rawId, facility_id, bodyKeys: Object.keys(req.body || {}) });
  if (!facility_id) {
    return res.status(400).json({ success: false, message: "Facility ID is required." });
  }

  try {
    const { data: facility, error: fetchError } = await supabase
      .from("facilities")
      .select("id, billing_model, trusted_by, email")
      .eq("id", facility_id)
      .maybeSingle();

    log("info", "Toggle billing facility query result", { facility_id, found: !!facility, fetchError: fetchError?.message || null, fetchErrorCode: fetchError?.code || null });

    if (fetchError || !facility) {
      return res.status(404).json({
        success: false,
        message: "Facility not found.",
        detail: fetchError?.message || `No facility with id="${facility_id}"`,
        facility_id
      });
    }

    const isCurrentlyPostpaid = facility.billing_model === "postpaid";
    const newBillingModel = isCurrentlyPostpaid ? "prepaid" : "postpaid";
    const newTrustedBy = isCurrentlyPostpaid ? null : user.email;

    const { error: updateError } = await supabase
      .from("facilities")
      .update({
        billing_model: newBillingModel,
        trusted_by: newTrustedBy
      })
      .eq("id", facility_id);

    if (updateError) throw updateError;

    // Create notification for facility
    const notifMessage = isCurrentlyPostpaid
      ? "Your postpaid billing has been disabled. Please pay upfront for new shifts."
      : "Your facility has been approved for postpaid billing. You can now post shifts without upfront payment.";

    await supabase.from("notifications").insert({
      user_email: facility.email,
      title: "Billing model updated",
      message: notifMessage,
      type: "info"
    });

    return res.json({
      success: true,
      billing_model: newBillingModel,
      trusted_by: newTrustedBy || null,
      message: isCurrentlyPostpaid
        ? "Facility reverted to prepaid billing."
        : "Facility approved for postpaid billing."
    });
  } catch (err) {
    log("error", "Admin toggle billing error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to toggle billing model." });
  }
});

// ── Admin: reset account ──
app.post("/admin/reset-account", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  const { email, type } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required." });
  }

  try {
    if (type === "worker") {
      const { data: worker } = await supabase.from("workers").select("id, user_id").eq("email", email.toLowerCase()).maybeSingle();
      if (worker) {
        await supabase.from("workers").delete().eq("id", worker.id);
        if (worker.user_id) {
          await supabase.auth.admin.deleteUser(worker.user_id);
        }
      }
    } else if (type === "facility") {
      const { data: facility } = await supabase.from("facilities").select("id, user_id").eq("email", email.toLowerCase()).maybeSingle();
      if (facility) {
        await supabase.from("facilities").delete().eq("id", facility.id);
        if (facility.user_id) {
          await supabase.auth.admin.deleteUser(facility.user_id);
        }
      }
    } else if (type === "client") {
      const { data: client } = await supabase.from("clients").select("id, user_id").eq("email", email.toLowerCase()).maybeSingle();
      if (client) {
        await supabase.from("clients").delete().eq("id", client.id);
        if (client.user_id) {
          await supabase.auth.admin.deleteUser(client.user_id);
        }
      }
    } else {
      return res.status(400).json({ success: false, message: "Invalid type. Must be 'worker', 'facility', or 'client'." });
    }

    log("info", "Account reset by admin", { email, type, admin: user.email });
    return res.json({ success: true, message: `${type} account for ${email} has been reset.` });
  } catch (err) {
    log("error", "Admin reset account error", { error: err.message, email, type });
    return res.status(500).json({ success: false, message: "Failed to reset account." });
  }
});

app.post("/admin/toggle-license", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  const { worker_id, current_status } = req.body;
  if (!worker_id) {
    return res.status(400).json({ success: false, message: "worker_id is required." });
  }

  const { error } = await supabase
    .from("workers")
    .update({ license_verified: !current_status })
    .eq("id", worker_id);

  if (error) {
    return res.status(500).json({ success: false, message: "Failed to update worker." });
  }

  log("info", "License toggled", { worker_id, new_status: !current_status });
  return res.json({ success: true, message: "Worker updated." });
});

app.post("/admin/toggle-identity", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  const { worker_id, current_status } = req.body;
  if (!worker_id) {
    return res.status(400).json({ success: false, message: "worker_id is required." });
  }

  const newStatus = !current_status;
  const { error } = await supabase
    .from("workers")
    .update({ identity_verified: newStatus, identity_verified_at: newStatus ? new Date().toISOString() : null })
    .eq("id", worker_id);

  if (error) {
    return res.status(500).json({ success: false, message: "Failed to update worker." });
  }

  log("info", "Identity verification toggled", { worker_id, new_status: newStatus, admin: user.email });
  return res.json({ success: true, message: "Worker updated." });
});

// ── Admin: activate a worker account ──
app.post("/admin/activate-worker", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  const { worker_id } = req.body;
  if (!worker_id) {
    return res.status(400).json({ success: false, message: "worker_id is required." });
  }

  const { error } = await supabase
    .from("workers")
    .update({ activated: true, activated_at: new Date().toISOString() })
    .eq("id", worker_id);

  if (error) {
    log("error", "Admin activate worker error", { error: error.message, worker_id });
    return res.status(500).json({ success: false, message: "Failed to activate worker." });
  }

  // Notify the worker
  try {
    const { data: worker } = await supabase.from("workers").select("email, full_name").eq("id", worker_id).single();
    if (worker) {
      await supabase.from("notifications").insert({
        email: worker.email,
        title: "Account activated!",
        message: `Your account has been reviewed and activated. You can now accept shifts and start working.`,
        type: "account"
      });
    }
  } catch (_) {}

  log("info", "Worker activated by admin", { worker_id, admin: user.email });
  return res.json({ success: true, message: "Worker activated successfully." });
});

// ── Admin: approve facility for postpaid billing ──
app.post("/admin/approve-facility", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  const email = sanitize(req.body.email);
  if (!email) {
    return res.status(400).json({ success: false, message: "Facility email is required." });
  }

  const { data: facility, error: fetchError } = await supabase
    .from("facilities")
    .select("id, billing_model")
    .eq("email", email)
    .maybeSingle();

  if (fetchError || !facility) {
    return res.status(404).json({ success: false, message: "Facility not found." });
  }

  if (facility.billing_model === "postpaid") {
    return res.json({ success: true, message: "Facility is already approved for postpaid billing." });
  }

  const { error } = await supabase
    .from("facilities")
    .update({ billing_model: "postpaid", trusted_by: user.email })
    .eq("email", email);

  if (error) {
    log("error", "Approve facility error", { error: error.message, email });
    return res.status(500).json({ success: false, message: "Failed to approve facility." });
  }

  log("info", "Facility approved for postpaid", { email, approved_by: user.email });
  return res.json({ success: true, message: "Facility approved for postpaid billing." });
});

// ── Admin: revoke postpaid billing ──
app.post("/admin/revoke-facility", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  const email = sanitize(req.body.email);
  if (!email) {
    return res.status(400).json({ success: false, message: "Facility email is required." });
  }

  const { error } = await supabase
    .from("facilities")
    .update({ billing_model: "prepaid", trusted_by: null })
    .eq("email", email);

  if (error) {
    log("error", "Revoke facility error", { error: error.message, email });
    return res.status(500).json({ success: false, message: "Failed to revoke facility." });
  }

  log("info", "Facility postpaid revoked", { email });
  return res.json({ success: true, message: "Facility postpaid billing revoked." });
});

// ── Admin: list trusted facilities with monthly totals ──
app.get("/admin/trusted-facilities", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;

  const { data: facilities, error: facError } = await supabase
    .from("facilities")
    .select("id, facility_name, email, city, billing_model, trusted_by, created_at")
    .eq("billing_model", "postpaid")
    .order("created_at", { ascending: false });

  if (facError) {
    return res.status(500).json({ success: false, message: "Failed to load facilities." });
  }

  // Get monthly totals for each facility
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

  const result = await Promise.all((facilities || []).map(async (fac) => {
    const { data: shifts } = await supabase
      .from("shifts")
      .select("total_pay, created_at")
      .eq("contact_email", fac.email)
      .eq("payment_status", "postpaid")
      .gte("created_at", monthStart);

    const monthlyTotal = (shifts || []).reduce((sum, s) => {
      return sum + (parseFloat((s.total_pay || "").replace(/[^0-9.]/g, "")) || 0) * 1.25;
    }, 0);

    return {
      ...fac,
      monthly_charge: Math.round(monthlyTotal * 100) / 100,
      shift_count: (shifts || []).length
    };
  }));

  return res.json({ success: true, data: result });
});

// ── Admin: finance summary ──
app.get("/finance/admin/summary", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const { data: shifts } = await supabase.from("shifts").select("total_pay, payment_status, facility_credit, contact_email, created_at");
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
    let total_revenue = 0, pending_postpaid = 0, total_credits = 0, this_month_revenue = 0;
    const facilitySet = new Set();
    for (const s of shifts || []) {
      const facilityTotal = Math.round(parsePayAmount(s.total_pay) * 1.25 * 100) / 100;
      if (s.payment_status === "paid") {
        total_revenue += facilityTotal;
        if (s.created_at && s.created_at >= monthStart) {
          this_month_revenue += facilityTotal;
        }
      }
      if (s.payment_status === "postpaid") {
        pending_postpaid += facilityTotal;
      }
      if (s.facility_credit) {
        total_credits += parseFloat(s.facility_credit) || 0;
      }
      if (s.contact_email) facilitySet.add(s.contact_email);
    }
    return res.json({
      success: true,
      data: {
        total_revenue: Math.round(total_revenue * 100) / 100,
        pending_postpaid: Math.round(pending_postpaid * 100) / 100,
        total_credits: Math.round(total_credits * 100) / 100,
        total_shifts: (shifts || []).length,
        total_facilities: facilitySet.size,
        this_month_revenue: Math.round(this_month_revenue * 100) / 100
      }
    });
  } catch (err) {
    log("error", "Admin finance summary error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load finance summary." });
  }
});

// ── Admin: finance transactions ──
app.get("/finance/admin/transactions", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    const { count, error: countError } = await supabase.from("shifts").select("*", { count: "exact", head: true });
    if (countError) return res.status(500).json({ success: false, message: "Failed to count transactions." });
    const { data: shifts, error } = await supabase.from("shifts").select("*").order("created_at", { ascending: false }).range(offset, offset + limit - 1);
    if (error) return res.status(500).json({ success: false, message: "Failed to load transactions." });
    const transactions = (shifts || []).map(s => ({
      id: s.id,
      facility_name: s.facility_name,
      contact_email: s.contact_email,
      role_needed: s.role_needed,
      shift_date: s.shift_date,
      total_pay: parsePayAmount(s.total_pay),
      facility_total: Math.round(parsePayAmount(s.total_pay) * 1.25 * 100) / 100,
      payment_status: s.payment_status,
      facility_credit: s.facility_credit,
      waived: s.waived,
      paid_at: s.paid_at,
      created_at: s.created_at
    }));
    return res.json({
      success: true,
      data: {
        transactions,
        total: count,
        page,
        limit,
        total_pages: Math.ceil(count / limit)
      }
    });
  } catch (err) {
    log("error", "Admin finance transactions error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load transactions." });
  }
});

// ── Admin: payment mediation ──
async function updatePaymentStatus(shiftId, status, res) {
  if (!shiftId) return res.status(400).json({ success: false, message: "shift_id is required." });
  const { error } = await supabase.from("shifts").update({ payment_status: status, paid_at: status === "paid" ? new Date().toISOString() : status === "refunded" ? null : undefined }).eq("id", shiftId);
  if (error) return res.status(500).json({ success: false, message: "Failed to update payment status." });
  return res.json({ success: true, message: `Payment ${status}.` });
}

app.post("/admin/payment/hold", async (req, res) => {
  const user = await requireAuth(req, res); if (!user) return; if (!requireAdmin(req, res)) return;
  await updatePaymentStatus(req.body.shift_id, "held", res);
  log("info", "Payment held by admin", { shift_id: req.body.shift_id, admin: user.email });
});

app.post("/admin/payment/release", async (req, res) => {
  const user = await requireAuth(req, res); if (!user) return; if (!requireAdmin(req, res)) return;
  await updatePaymentStatus(req.body.shift_id, "paid", res);
  log("info", "Payment released by admin", { shift_id: req.body.shift_id, admin: user.email });
});

app.post("/admin/payment/refund", async (req, res) => {
  const user = await requireAuth(req, res); if (!user) return; if (!requireAdmin(req, res)) return;
  await updatePaymentStatus(req.body.shift_id, "refunded", res);
  log("info", "Payment refunded by admin", { shift_id: req.body.shift_id, admin: user.email });
});

app.post("/admin/payment/complete", async (req, res) => {
  const user = await requireAuth(req, res); if (!user) return; if (!requireAdmin(req, res)) return;
  await updatePaymentStatus(req.body.shift_id, "completed", res);
  log("info", "Payment completed by admin", { shift_id: req.body.shift_id, admin: user.email });
});

app.get("/admin/payments", async (req, res) => {
  const user = await requireAuth(req, res); if (!user) return; if (!requireAdmin(req, res)) return;
  try {
    const { data: shifts, error } = await supabase.from("shifts").select("*").order("created_at", { ascending: false });
    if (error) return res.status(500).json({ success: false, message: "Failed to load payments." });
    const payments = (shifts || []).map(s => ({
      id: s.id,
      facility_name: s.facility_name,
      contact_email: s.contact_email,
      role_needed: s.role_needed,
      worker_id: s.worker_id,
      shift_date: s.shift_date,
      start_time: s.start_time,
      duration: s.duration,
      total_pay: parsePayAmount(s.total_pay),
      facility_total: Math.round(parsePayAmount(s.total_pay) * 1.25 * 100) / 100,
      payment_status: s.payment_status,
      facility_credit: s.facility_credit,
      waived: s.waived,
      paid_at: s.paid_at,
      created_at: s.created_at
    }));
    return res.json({ success: true, data: payments });
  } catch (err) {
    log("error", "Admin payments list error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load payments." });
  }
});

const ALLOWED_UPLOAD_MIME_TYPES = ["image/jpeg", "image/png", "image/webp", "application/pdf"];

app.post("/api/upload", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;

  const { image, folder } = req.body;
  if (!image) {
    return res.status(400).json({ success: false, message: "Image data is required." });
  }

  const mimeMatch = /^data:([a-zA-Z0-9.+-]+\/[a-zA-Z0-9.+-]+);base64,/.exec(image);
  if (!mimeMatch || !ALLOWED_UPLOAD_MIME_TYPES.includes(mimeMatch[1].toLowerCase())) {
    return res.status(400).json({ success: false, message: "File must be a JPG, PNG, WEBP, or PDF." });
  }

  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const uploadPreset = process.env.CLOUDINARY_UPLOAD_PRESET;

  if (!cloudName || !uploadPreset) {
    return res.status(500).json({ success: false, message: "Upload service not configured." });
  }

  try {
    const formData = new FormData();
    formData.append("file", image);
    formData.append("upload_preset", uploadPreset);
    formData.append("folder", `covercare/${folder || "uploads"}`);

    const response = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/upload`, {
      method: "POST",
      body: formData
    });

    const data = await response.json();
    if (!data.secure_url) {
      throw new Error(data.error?.message || "Upload failed");
    }

    return res.json({ success: true, url: data.secure_url });
  } catch (err) {
    log("error", "Upload error", { error: err.message });
    return res.status(500).json({ success: false, message: "Upload failed." });
  }
});

app.put("/worker", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { full_name, phone, role, license_number, city, country, experience, profile_photo_url, bio, license_file_url } = req.body;

  const { data: existing } = await supabase
    .from("workers")
    .select("id")
    .eq("email", user.email)
    .maybeSingle();

  if (!existing) {
    return res.status(404).json({ success: false, message: "Worker profile not found." });
  }

  const updates = {};
  if (full_name) updates.full_name = sanitize(full_name);
  if (phone) updates.phone = sanitize(phone);
  if (role) updates.role = sanitize(role);
  if (license_number) updates.license_number = sanitize(license_number);
  if (city) updates.city = sanitize(city);
  if (country) updates.country = sanitize(country);
  if (experience) updates.experience = sanitize(experience);
  if (profile_photo_url) updates.profile_photo_url = profile_photo_url;
  if (bio !== undefined) updates.bio = sanitize(bio);
  if (license_file_url) updates.license_file_url = license_file_url;

  const { error } = await supabase.from("workers").update(updates).eq("id", existing.id);

  if (error) {
    log("error", "Worker update error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to update profile." });
  }

  log("info", "Worker updated", { email: user.email });
  return res.json({ success: true, message: "Profile updated successfully." });
});

app.put("/facility", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { facility_name, facility_type, city, country, contact_name, contact_role, phone, staff_needs, frequency, incorporation_doc_url, hefra_license_url, pharmacy_council_url } = req.body;

  const { data: existing } = await supabase
    .from("facilities")
    .select("id")
    .eq("email", user.email)
    .maybeSingle();

  if (!existing) {
    return res.status(404).json({ success: false, message: "Facility profile not found." });
  }

  const updates = {};
  if (facility_name) updates.facility_name = sanitize(facility_name);
  if (facility_type) updates.facility_type = sanitize(facility_type);
  if (city) updates.city = sanitize(city);
  if (country) updates.country = sanitize(country);
  if (contact_name) updates.contact_name = sanitize(contact_name);
  if (contact_role) updates.contact_role = sanitize(contact_role);
  if (phone) updates.phone = sanitize(phone);
  if (staff_needs) updates.staff_needs = sanitize(staff_needs);
  if (frequency) updates.frequency = sanitize(frequency);
  if (req.body.incorporation_doc_url) updates.incorporation_doc_url = req.body.incorporation_doc_url;
  if (req.body.hefra_license_url) updates.hefra_license_url = req.body.hefra_license_url;
  if (req.body.pharmacy_council_url) updates.pharmacy_council_url = req.body.pharmacy_council_url;

  const { error } = await supabase.from("facilities").update(updates).eq("id", existing.id);

  if (error) {
    log("error", "Facility update error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to update profile." });
  }

  log("info", "Facility updated", { email: user.email });
  return res.json({ success: true, message: "Profile updated successfully." });
});

app.post("/account/delete", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const email = req.body.email;
  if (!email || email.toLowerCase() !== user.email.toLowerCase()) {
    return res.status(400).json({ success: false, message: "Email must match your account." });
  }

  const { error: workerDel } = await supabase.from("workers").delete().eq("email", email);
  const { error: facilityDel } = await supabase.from("facilities").delete().eq("email", email);

  if (workerDel || facilityDel) {
    log("error", "Account delete error", { workerError: workerDel?.message, facilityError: facilityDel?.message });
  }

  const { error: authError } = await supabase.auth.admin.deleteUser(user.id);
  if (authError) {
    log("error", "Auth delete error", { error: authError.message });
    return res.status(500).json({ success: false, message: "Account data removed but auth deletion failed. Contact support." });
  }

  log("info", "Account deleted", { email });
  return res.json({ success: true, message: "Account permanently deleted." });
});

function normalizeWorkerRole(role) {
  const map = {
    "medical-doctor": "medical-doctor",
    "lab-technician": "lab-technician",
    "pharmacist": "pharmacist",
    "pharmacy-tech": "pharmacy-tech",
    "nurse": "nurse",
    "doctor": "medical-doctor",
    "lab-tech": "lab-technician",
    "caregiver": "caregiver",
    "midwife": "midwife",
    "community health worker": "community health worker",
    "other": null
  };
  if (!role) return null;
  const key = role.toLowerCase();
  return map[key] || null;
}

// Public open-shifts listing for workers. Does the poster/branch joins server-side
// so contact_email/contact_phone/address/qr_token/payment fields never reach the browser.
app.get("/shifts/open", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { data: worker } = await supabase
    .from("workers")
    .select("id, role")
    .eq("email", user.email)
    .maybeSingle();

  const workerRole = worker ? normalizeWorkerRole(worker.role) : null;
  const workerId = worker?.id || null;

  const SELECT_COLS = "id, facility_name, role_needed, city, shift_date, start_time, duration, duration_hours, pay_rate, urgency, status, branch_id, assigned_to_worker_id, contact_email, created_at";

  let openQuery = supabase.from("shifts").select(SELECT_COLS).eq("status", "open");
  if (workerRole) openQuery = openQuery.eq("role_needed", workerRole);
  const { data: openShifts, error: openError } = await openQuery.order("created_at", { ascending: false }).limit(20);
  if (openError) {
    log("error", "Open shifts fetch error", { error: openError.message });
    return res.status(500).json({ success: false, message: "Failed to load shifts." });
  }

  let assignedShifts = [];
  if (workerId) {
    const { data: as, error: asError } = await supabase
      .from("shifts")
      .select(SELECT_COLS)
      .eq("assigned_to_worker_id", workerId)
      .in("status", ["open", "accepted", "in_progress"])
      .order("created_at", { ascending: false });
    if (!asError && as) assignedShifts = as;
  }

  let allData = [...(openShifts || []), ...assignedShifts];
  const seen = new Set();
  allData = allData.filter(s => { if (seen.has(s.id)) return false; seen.add(s.id); return true; });

  const clientEmails = [...new Set(allData.map(s => s.contact_email?.toLowerCase()).filter(Boolean))];
  const posterMap = {};
  if (clientEmails.length > 0) {
    const { data: clients } = await supabase
      .from("clients")
      .select("email, full_name, profile_photo_url, city")
      .in("email", clientEmails);
    if (clients) clients.forEach(c => { posterMap[c.email.toLowerCase()] = c; });
  }

  const branchIds = [...new Set(allData.map(s => s.branch_id).filter(Boolean))];
  const branchMap = {};
  if (branchIds.length > 0) {
    const { data: branches } = await supabase
      .from("facility_branches")
      .select("id, name, address, latitude, longitude")
      .in("id", branchIds);
    if (branches) branches.forEach(b => { branchMap[b.id] = b; });
  }

  const assignedIds = new Set(assignedShifts.map(s => s.id));

  const data = allData.map(s => {
    const poster = posterMap[s.contact_email?.toLowerCase()];
    const branch = branchMap[s.branch_id];
    return {
      id: s.id,
      facility_name: s.facility_name,
      role_needed: s.role_needed,
      city: s.city,
      shift_date: s.shift_date,
      start_time: s.start_time,
      duration: s.duration,
      duration_hours: s.duration_hours,
      pay_rate: s.pay_rate,
      urgency: s.urgency,
      status: s.status,
      branch_id: s.branch_id,
      assigned_to_worker_id: s.assigned_to_worker_id,
      _poster_name: poster?.full_name || null,
      _poster_photo: poster?.profile_photo_url || null,
      _poster_city: poster?.city || null,
      _branch_name: branch?.name || null,
      _branch_address: branch?.address || null,
      _branch_lat: branch?.latitude || null,
      _branch_lng: branch?.longitude || null,
      _is_assigned: assignedIds.has(s.id)
    };
  });

  return res.json({ success: true, data });
});

app.get("/shifts/history", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { data: worker } = await supabase
    .from("workers")
    .select("id, email")
    .eq("email", user.email)
    .maybeSingle();

  if (worker) {
    const { data, error } = await supabase
      .from("shifts")
      .select("*")
      .eq("worker_id", worker.id)
      .eq("status", "completed")
      .order("completion_time", { ascending: false });

    if (error) return res.status(500).json({ success: false, message: "Failed to load history." });
    return res.json({ success: true, role: "worker", data: data || [] });
  }

  const { data: facility } = await supabase
    .from("facilities")
    .select("id, email")
    .eq("email", user.email)
    .maybeSingle();

  if (facility) {
    const { data, error } = await supabase
      .from("shifts")
      .select("*")
      .eq("contact_email", user.email)
      .eq("status", "completed")
      .order("completion_time", { ascending: false });

    if (error) return res.status(500).json({ success: false, message: "Failed to load history." });
    return res.json({ success: true, role: "facility", data: data || [] });
  }

  return res.json({ success: true, role: "unknown", data: [] });
});

function getExperienceBand(exp) {
  const s = (exp || "").toString().toLowerCase();
  if (s.includes("entry") || s.includes("0") || s.includes("fresh") || s.includes("trainee")) return 1;
  if (s.includes("1") || s.includes("junior") || s.includes("2")) return 2;
  if (s.includes("3") || s.includes("mid") || s.includes("4") || s.includes("5")) return 3;
  if (s.includes("5+") || s.includes("senior") || s.includes("lead") || s.includes("principal") || s.includes("6") || s.includes("7") || s.includes("8") || s.includes("9") || s.includes("10")) return 4;
  return 2;
}

function calculateMatchScore(worker, shift) {
  const breakdown = { role: 0, city: 0, experience: 0, license: 0, identity: 0 };

  if ((worker.role || "").toLowerCase() !== (shift.role_needed || "").toLowerCase()) {
    return { score: 0, breakdown, maxScore: 100 };
  }
  breakdown.role = 40;

  if ((worker.city || "").toLowerCase() !== (shift.city || "").toLowerCase()) {
    return { score: 0, breakdown, maxScore: 100 };
  }
  breakdown.city = 30;

  const wBand = getExperienceBand(worker.experience);
  const sBand = getExperienceBand(shift.experience_required);
  const diff = Math.abs(wBand - sBand);
  if (diff <= 1) breakdown.experience = 15;
  else if (diff <= 2) breakdown.experience = 10;
  else breakdown.experience = 5;

  breakdown.license = worker.license_verified ? 10 : 0;
  breakdown.identity = worker.identity_verified ? 5 : 0;

  const score = breakdown.role + breakdown.city + breakdown.experience + breakdown.license + breakdown.identity;
  return { score, breakdown, maxScore: 100 };
}

app.get("/matches/worker", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { data: worker } = await supabase
      .from("workers")
      .select("*")
      .eq("email", user.email)
      .maybeSingle();

    if (!worker) {
      return res.status(404).json({ success: false, message: "Worker profile not found." });
    }

    const { data: openShifts } = await supabase
      .from("shifts")
      .select("*")
      .eq("status", "open")
      .eq("payment_status", "paid");

    if (!openShifts || openShifts.length === 0) {
      return res.json({ success: true, matches: [] });
    }

    const { data: applications } = await supabase
      .from("applications")
      .select("shift_id")
      .eq("worker_id", worker.id);

    const appliedShiftIds = new Set((applications || []).map(a => a.shift_id));

    const matches = openShifts
      .filter(s => !appliedShiftIds.has(s.id))
      .map(shift => {
        const { score, breakdown } = calculateMatchScore(worker, shift);
        return { shift, score, breakdown };
      })
      .sort((a, b) => b.score - a.score);

    return res.json({ success: true, matches });
  } catch (err) {
    log("error", "Matches worker error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to compute matches." });
  }
});

app.get("/matches/facility", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { data: facility } = await supabase
      .from("facilities")
      .select("*")
      .eq("email", user.email)
      .maybeSingle();

    if (!facility) {
      return res.status(404).json({ success: false, message: "Facility profile not found." });
    }

    const { data: facilityShifts } = await supabase
      .from("shifts")
      .select("*")
      .eq("contact_email", user.email)
      .eq("status", "open");

    if (!facilityShifts || facilityShifts.length === 0) {
      return res.json({ success: true, matches: {} });
    }

    const { data: allWorkers } = await supabase
      .from("workers")
      .select("*");

    const matches = {};
    for (const shift of facilityShifts) {
      const { data: applications } = await supabase
        .from("applications")
        .select("worker_id")
        .eq("shift_id", shift.id);

      const appliedWorkerIds = new Set((applications || []).map(a => a.worker_id));

      const matchedWorkers = (allWorkers || [])
        .filter(w => {
          if (appliedWorkerIds.has(w.id)) return false;
          if ((w.role || "").toLowerCase() !== (shift.role_needed || "").toLowerCase()) return false;
          if ((w.city || "").toLowerCase() !== (shift.city || "").toLowerCase()) return false;
          return true;
        })
        .map(worker => {
          const { score, breakdown } = calculateMatchScore(worker, shift);
          return { worker, score, breakdown };
        })
        .sort((a, b) => b.score - a.score);

      matches[shift.id] = matchedWorkers.map(m => ({
        ...m,
        role_needed: shift.role_needed,
        shift_date: shift.shift_date
      }));
    }

    return res.json({ success: true, matches });
  } catch (err) {
    log("error", "Matches facility error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to compute matches." });
  }
});

app.get("/payroll/summary", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { data: worker } = await supabase
      .from("workers")
      .select("*")
      .eq("email", user.email)
      .maybeSingle();

    if (worker) {
      const { data: completed } = await supabase
        .from("shifts")
        .select("total_pay, completion_time")
        .eq("worker_id", worker.id)
        .eq("status", "completed")
        .order("completion_time", { ascending: false });

      const shifts = completed || [];
      const totalEarnings = shifts.reduce((sum, s) => sum + parsePayAmount(s.total_pay), 0);
      const shiftCount = shifts.length;
      const lastPayout = shifts.length > 0 ? shifts[0].completion_time : null;

      return res.json({
        success: true,
        role: "worker",
        summary: { totalEarnings, shiftCount, lastPayout }
      });
    }

    const { data: facility } = await supabase
      .from("facilities")
      .select("*")
      .eq("email", user.email)
      .maybeSingle();

    if (facility) {
      const { data: completed } = await supabase
        .from("shifts")
        .select("total_pay, completion_time")
        .eq("contact_email", user.email)
        .eq("status", "completed")
        .order("completion_time", { ascending: false });

      const shifts = completed || [];
      const totalSpend = shifts.reduce((sum, s) => sum + parsePayAmount(s.total_pay) * 1.25, 0);
      const shiftCount = shifts.length;
      const lastPayout = shifts.length > 0 ? shifts[0].completion_time : null;

      return res.json({
        success: true,
        role: "facility",
        summary: { totalSpend, shiftCount, lastPayout }
      });
    }

    return res.status(404).json({ success: false, message: "User profile not found." });
  } catch (err) {
    log("error", "Payroll summary error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load payroll summary." });
  }
});

app.get("/payroll/earnings", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { data: worker } = await supabase
      .from("workers")
      .select("*")
      .eq("email", user.email)
      .maybeSingle();

    if (!worker) {
      return res.status(404).json({ success: false, message: "Worker profile not found." });
    }

    const { data, error } = await supabase
      .from("shifts")
      .select("*")
      .eq("worker_id", worker.id)
      .eq("status", "completed")
      .order("completion_time", { ascending: false });

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to load earnings." });
    }

    const result = (data || []).map(s => ({
      shift: s,
      payout_status: s.payout_status || null,
      payout_reference: s.payout_reference || null
    }));

    return res.json({ success: true, data: result });
  } catch (err) {
    log("error", "Payroll earnings error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load earnings." });
  }
});

app.get("/payroll/transactions", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { data: facility } = await supabase
      .from("facilities")
      .select("*")
      .eq("email", user.email)
      .maybeSingle();

    if (!facility) {
      return res.status(404).json({ success: false, message: "Facility profile not found." });
    }

    const { data, error } = await supabase
      .from("shifts")
      .select("*")
      .eq("contact_email", user.email)
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to load transactions." });
    }

    const result = (data || []).map(s => ({
      shift: s,
      payment_reference: s.payment_reference || null,
      payment_status: s.payment_status || null
    }));

    return res.json({ success: true, data: result });
  } catch (err) {
    log("error", "Payroll transactions error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load transactions." });
  }
});

app.get("/payroll/payslip/:shift_id", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const shiftId = sanitize(req.params.shift_id);
    const shift = await getShiftById(shiftId);

    if (!shift) {
      return res.status(404).json({ success: false, message: "Shift not found." });
    }

    if (shift.status !== "completed") {
      return res.status(400).json({ success: false, message: "Shift is not yet completed." });
    }

    let isWorker = false;
    if (shift.worker_id) {
      const { data: w } = await supabase.from("workers").select("email").eq("id", shift.worker_id).single();
      isWorker = !!(w && w.email.toLowerCase() === user.email.toLowerCase());
    }

    const isFacility = shift.contact_email && shift.contact_email.toLowerCase() === user.email.toLowerCase();

    if (!isWorker && !isFacility) {
      return res.status(403).json({ success: false, message: "You are not part of this shift." });
    }

    let workerName = "";
    if (shift.worker_id) {
      const { data: w } = await supabase.from("workers").select("full_name").eq("id", shift.worker_id).single();
      if (w) workerName = w.full_name;
    }

    const facilityName = shift.facility_name || "";
    const shiftDate = shift.shift_date || null;

    let hoursWorked = 0;
    if (shift.arrival_time && shift.completion_time) {
      hoursWorked = Math.round((new Date(shift.completion_time) - new Date(shift.arrival_time)) / 3600000 * 100) / 100;
    }

    const { hours, rate, workerTotal, facilityTotal } = computeShiftAmounts(shift);
    const grossPay = workerTotal;
    const platformFee = Math.round(workerTotal * 0.25 * 100) / 100;
    const netPay = Math.round((grossPay - platformFee) * 100) / 100;

    return res.json({
      success: true,
      payslip: {
        shift,
        workerName,
        facilityName,
        date: shiftDate,
        hoursWorked: hoursWorked || hours,
        hourlyRate: rate,
        grossPay,
        platformFee,
        netPay
      }
    });
  } catch (err) {
    log("error", "Payslip error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to generate payslip." });
  }
});

// ── Finance / facility summary ──
app.get("/finance/facility/summary", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: shifts } = await supabase.from("shifts").select("total_pay, payment_status, facility_credit, created_at").eq("contact_email", user.email.toLowerCase());
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
    let total_spent = 0, this_month = 0, pending_postpaid = 0, credits_saved = 0;
    for (const s of shifts || []) {
      const totalPay = parsePayAmount(s.total_pay);
      const facilityTotal = Math.round(totalPay * 1.25 * 100) / 100;
      if (s.payment_status === "paid" || s.payment_status === "postpaid") {
        total_spent += facilityTotal;
        if (s.created_at && s.created_at >= monthStart) {
          this_month += facilityTotal;
        }
      }
      if (s.payment_status === "postpaid") {
        pending_postpaid += facilityTotal;
      }
      if (s.facility_credit) {
        credits_saved += parseFloat(s.facility_credit) || 0;
      }
    }
    return res.json({
      success: true,
      data: {
        total_spent: Math.round(total_spent * 100) / 100,
        this_month: Math.round(this_month * 100) / 100,
        pending_postpaid: Math.round(pending_postpaid * 100) / 100,
        credits_saved: Math.round(credits_saved * 100) / 100
      }
    });
  } catch (err) {
    log("error", "Facility finance summary error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load finance summary." });
  }
});

// ── Finance / facility transactions ──
app.get("/finance/facility/transactions", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    const email = user.email.toLowerCase();
    const { count, error: countError } = await supabase.from("shifts").select("*", { count: "exact", head: true }).eq("contact_email", email);
    if (countError) return res.status(500).json({ success: false, message: "Failed to count transactions." });
    const { data: shifts, error } = await supabase.from("shifts").select("*").eq("contact_email", email).order("created_at", { ascending: false }).range(offset, offset + limit - 1);
    if (error) return res.status(500).json({ success: false, message: "Failed to load transactions." });
    const transactions = await Promise.all((shifts || []).map(async (s) => {
      let workerName = null, workerEmail = null;
      const { data: app } = await supabase.from("applications").select("worker_id").eq("shift_id", s.id).eq("status", "accepted").maybeSingle();
      if (app) {
        const { data: worker } = await supabase.from("workers").select("full_name, email").eq("id", app.worker_id).maybeSingle();
        if (worker) {
          workerName = worker.full_name;
          workerEmail = worker.email;
        }
      }
      return {
        id: s.id,
        role_needed: s.role_needed,
        shift_date: s.shift_date,
        start_time: s.start_time,
        duration_hours: s.duration_hours,
        days_needed: s.days_needed,
        workers_needed: s.workers_needed,
        pay_rate: s.pay_rate,
        total_pay: parsePayAmount(s.total_pay),
        facility_total: Math.round(parsePayAmount(s.total_pay) * 1.25 * 100) / 100,
        payment_status: s.payment_status,
        facility_credit: s.facility_credit,
        waived: s.waived,
        paid_at: s.paid_at,
        created_at: s.created_at,
        worker_name: workerName,
        worker_email: workerEmail
      };
    }));
    return res.json({
      success: true,
      data: {
        transactions,
        total: count,
        page,
        limit,
        total_pages: Math.ceil(count / limit)
      }
    });
  } catch (err) {
    log("error", "Facility finance transactions error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load transactions." });
  }
});

// ── Invoice generation ──
app.post("/admin/invoices/generate", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const now = new Date();
    const targetMonth = req.body.month || (now.getMonth() === 0 ? 12 : now.getMonth());
    const targetYear = req.body.month === 1 && now.getMonth() === 0 ? now.getFullYear() - 1 : (req.body.year || now.getFullYear());
    const periodStart = new Date(targetYear, targetMonth - 1, 1);
    const periodEnd = new Date(targetYear, targetMonth, 0, 23, 59, 59);
    const dueDate = new Date(targetYear, targetMonth, 15);

    const { data: facilities } = await supabase
      .from("facilities")
      .select("id, email, facility_name")
      .eq("billing_model", "postpaid");

    if (!facilities || facilities.length === 0) {
      return res.json({ success: true, message: "No postpaid facilities found.", invoices: [] });
    }

    const invoices = [];
    for (const f of facilities) {
      const { data: shifts } = await supabase
        .from("shifts")
        .select("total_pay, payment_status")
        .eq("contact_email", f.email)
        .eq("payment_status", "postpaid")
        .gte("created_at", periodStart.toISOString())
        .lte("created_at", periodEnd.toISOString());

      if (!shifts || shifts.length === 0) continue;

      const totalAmount = shifts.reduce((sum, s) => sum + (parsePayAmount(s.total_pay) * 1.25), 0);

      const { data: existing } = await supabase
        .from("invoices")
        .select("id")
        .eq("facility_id", f.id)
        .eq("month", targetMonth)
        .eq("year", targetYear)
        .maybeSingle();

      if (existing) {
        await supabase.from("invoices").update({
          total_amount: Math.round(totalAmount * 100) / 100,
          shift_count: shifts.length,
          status: "pending",
          notes: "Regenerated"
        }).eq("id", existing.id);
        invoices.push({ id: existing.id, facility: f.facility_name, amount: Math.round(totalAmount * 100) / 100, shifts: shifts.length });
      } else {
        const { data: ins } = await supabase.from("invoices").insert({
          facility_id: f.id,
          facility_email: f.email,
          facility_name: f.facility_name,
          month: targetMonth,
          year: targetYear,
          total_amount: Math.round(totalAmount * 100) / 100,
          shift_count: shifts.length,
          period_start: periodStart.toISOString().split("T")[0],
          period_end: periodEnd.toISOString().split("T")[0],
          due_date: dueDate.toISOString().split("T")[0]
        }).select().single();
        if (ins) invoices.push({ id: ins.id, facility: f.facility_name, amount: ins.total_amount, shifts: ins.shift_count });
      }

      await supabase.from("notifications").insert({
        user_email: f.email,
        title: "Invoice ready",
        message: `Your invoice for ${periodStart.toLocaleString("default", { month: "long" })} ${targetYear} (GHS ${Math.round(totalAmount * 100) / 100}) is ready. Due: ${dueDate.toISOString().split("T")[0]}.`,
        type: "info"
      });
    }

    log("info", "Invoices generated", { month: targetMonth, year: targetYear, count: invoices.length });
    return res.json({ success: true, message: `${invoices.length} invoice(s) generated.`, invoices });
  } catch (err) {
    log("error", "Invoice generation error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to generate invoices." });
  }
});

// ── Facility: list invoices ──
app.get("/finance/facility/invoices", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: invoices } = await supabase
      .from("invoices")
      .select("*")
      .eq("facility_email", user.email.toLowerCase())
      .order("year", { ascending: false })
      .order("month", { ascending: false });

    return res.json({ success: true, data: invoices || [] });
  } catch (err) {
    log("error", "Facility invoices error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load invoices." });
  }
});

// ── Admin: list all invoices ──
app.get("/finance/admin/invoices", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const { data: invoices } = await supabase
      .from("invoices")
      .select("*")
      .order("year", { ascending: false })
      .order("month", { ascending: false });

    return res.json({ success: true, data: invoices || [] });
  } catch (err) {
    log("error", "Admin invoices error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load invoices." });
  }
});

// ── Admin: mark invoice as paid ──
app.post("/finance/admin/invoice/:id/pay", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const invoiceId = parseInt(req.params.id);
    if (isNaN(invoiceId)) return res.status(400).json({ success: false, message: "Invalid invoice ID." });

    const { data: invoice, error: fetchError } = await supabase
      .from("invoices")
      .select("*")
      .eq("id", invoiceId)
      .maybeSingle();

    if (fetchError || !invoice) return res.status(404).json({ success: false, message: "Invoice not found." });
    if (invoice.status === "paid") return res.json({ success: true, message: "Invoice already marked as paid." });

    const { error: updateError } = await supabase
      .from("invoices")
      .update({
        status: "paid",
        paid_at: new Date().toISOString(),
        paid_by: user.email
      })
      .eq("id", invoiceId);

    if (updateError) throw updateError;

    await supabase.from("notifications").insert({
      user_email: invoice.facility_email,
      title: "Invoice paid",
      message: `Your invoice for ${invoice.month}/${invoice.year} (GHS ${invoice.total_amount}) has been marked as paid.`,
      type: "success"
    });

    log("info", "Invoice marked paid", { invoice_id: invoiceId, admin: user.email });
    return res.json({ success: true, message: "Invoice marked as paid." });
  } catch (err) {
    log("error", "Invoice pay error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to mark invoice as paid." });
  }
});

// ─────────────────────────────────────────────
// Wallet system (facility & client)
// ─────────────────────────────────────────────

// Helper: get wallet table + balance column for a user type
function walletTable(userType) {
  return userType === "client" ? "clients" : "facilities";
}

// Helper: find user type by email
async function resolveUserType(email) {
  const { data: fac } = await supabase.from("facilities").select("id").eq("email", email).maybeSingle();
  if (fac) return "facility";
  const { data: cli } = await supabase.from("clients").select("id").eq("email", email).maybeSingle();
  if (cli) return "client";
  return null;
}

// Route: check if email belongs to a worker (used by login.js routing)
app.post("/worker/by-email", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;
  try {
    const { email } = req.body;
    if (!email || user.email.toLowerCase() !== email.toLowerCase()) {
      return res.json({ success: false, message: "Email required" });
    }
    const { data } = await supabase.from("workers").select("id").eq("email", email).maybeSingle();
    res.json({ success: !!data });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Route: check if email belongs to a facility (used by login.js routing)
app.post("/facility/by-email", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;
  try {
    const { email } = req.body;
    if (!email || user.email.toLowerCase() !== email.toLowerCase()) {
      return res.json({ success: false, message: "Email required" });
    }
    const { data } = await supabase.from("facilities").select("id").eq("email", email).maybeSingle();
    res.json({ success: !!data });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Route: check if email belongs to a client (used by login.js routing)
app.post("/client/by-email", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;
  try {
    const { email } = req.body;
    if (!email || user.email.toLowerCase() !== email.toLowerCase()) {
      return res.json({ success: false, message: "Email required" });
    }
    const { data } = await supabase.from("clients").select("id").eq("email", email).maybeSingle();
    res.json({ success: !!data });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Helper: get wallet balance
async function getWalletBalance(email, userType) {
  const table = walletTable(userType);
  const { data } = await supabase.from(table).select("wallet_balance").eq("email", email).maybeSingle();
  return data ? parseFloat(data.wallet_balance) || 0 : 0;
}

// Helper: update wallet balance and log transaction.
// Uses compare-and-swap (conditional update on the balance we read) with a
// bounded retry loop so concurrent requests against the same wallet can't
// race past each other and corrupt the balance.
async function updateWallet(email, userType, type, amount, reference, description) {
  const table = walletTable(userType);
  const delta = ["deposit", "refund", "admin_credit"].includes(type) ? amount : -amount;

  for (let attempt = 0; attempt < 5; attempt++) {
    const balanceBefore = await getWalletBalance(email, userType);
    const balanceAfter = Math.round((balanceBefore + delta) * 100) / 100;

    if (balanceAfter < 0) {
      const err = new Error("Insufficient wallet balance.");
      err.code = "INSUFFICIENT_BALANCE";
      throw err;
    }

    const { data: updated, error: updateError } = await supabase
      .from(table)
      .update({ wallet_balance: balanceAfter })
      .eq("email", email)
      .eq("wallet_balance", balanceBefore)
      .select("wallet_balance");

    if (updateError) throw updateError;

    if (updated && updated.length > 0) {
      const { error: logError } = await supabase.from("wallet_transactions").insert({
        user_email: email,
        user_type: userType,
        type,
        amount: Math.abs(amount),
        balance_before: balanceBefore,
        balance_after: balanceAfter,
        reference: reference || null,
        description: description || ""
      });

      if (logError) throw logError;
      return { balanceBefore, balanceAfter };
    }
    // Balance changed under us since we read it — retry with a fresh read.
  }

  const err = new Error("Could not update wallet balance due to a concurrent update. Please try again.");
  err.code = "WALLET_CONTENTION";
  throw err;
}

// ── GET /wallet/balance ──
app.get("/wallet/balance", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const email = user.email.toLowerCase();
    const userType = await resolveUserType(email);
    if (!userType) return res.status(404).json({ success: false, message: "User not found." });
    const balance = await getWalletBalance(email, userType);
    return res.json({ success: true, data: { balance, user_type: userType } });
  } catch (err) {
    log("error", "Wallet balance error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to fetch balance." });
  }
});

// ── GET /wallet/transactions ──
app.get("/wallet/transactions", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const email = user.email.toLowerCase();
    const { data: txns } = await supabase
      .from("wallet_transactions")
      .select("*")
      .eq("user_email", email)
      .order("created_at", { ascending: false })
      .limit(50);

    return res.json({ success: true, data: txns || [] });
  } catch (err) {
    log("error", "Wallet transactions error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load transactions." });
  }
});

// ── POST /wallet/deposit ── Initiate Paystack deposit
app.post("/wallet/deposit", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;

  try {
    const email = user.email.toLowerCase();
    const amount = parseFloat(req.body.amount);
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: "Valid amount is required." });
    }
    if (amount < 10) {
      return res.status(400).json({ success: false, message: "Minimum deposit is GHS 10." });
    }

    const response = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email,
        amount: Math.round(amount * 100),
        currency: "GHS",
        metadata: { wallet_deposit: true, user_email: email }
      })
    });

    const data = await response.json();
    if (!data.status) {
      return res.status(400).json({ success: false, message: "Deposit initialization failed." });
    }

    return res.json({
      success: true,
      authorization_url: data.data.authorization_url,
      reference: data.data.reference
    });
  } catch (err) {
    log("error", "Wallet deposit error", { error: err.message });
    return res.status(500).json({ success: false, message: "Deposit service unavailable." });
  }
});

// ── POST /wallet/deposit/verify ── Verify Paystack deposit and credit wallet
app.post("/wallet/deposit/verify", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!rateLimitRoute(req, res, 20)) return;

  try {
    const reference = sanitize(req.body.reference);
    if (!reference) return res.status(400).json({ success: false, message: "Reference required." });

    // Check if already processed
    const { data: existing } = await supabase
      .from("wallet_transactions")
      .select("id")
      .eq("reference", reference)
      .maybeSingle();

    if (existing) {
      return res.json({ success: true, message: "Deposit already verified.", already_processed: true });
    }

    const response = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
    });

    const data = await response.json();
    if (!data.status || data.data.status !== "success") {
      return res.status(400).json({ success: false, message: "Deposit verification failed." });
    }

    const email = user.email.toLowerCase();
    const amount = data.data.amount / 100;
    const userType = await resolveUserType(email);
    if (!userType) return res.status(404).json({ success: false, message: "User not found." });

    await updateWallet(email, userType, "deposit", amount, reference, "Paystack deposit");

    log("info", "Wallet deposit verified", { email, amount, reference });
    return res.json({ success: true, message: `GHS ${amount.toLocaleString()} deposited successfully.`, amount });
  } catch (err) {
    log("error", "Wallet deposit verify error", { error: err.message });
    return res.status(500).json({ success: false, message: "Verification failed." });
  }
});

// ── POST /wallet/withdraw ── Request withdrawal
app.post("/wallet/withdraw", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const email = user.email.toLowerCase();
    const amount = parseFloat(req.body.amount);
    if (!amount || amount <= 0) return res.status(400).json({ success: false, message: "Valid amount required." });

    const userType = await resolveUserType(email);
    if (!userType) return res.status(404).json({ success: false, message: "User not found." });

    if (amount < 10) return res.status(400).json({ success: false, message: "Minimum withdrawal is GHS 10." });

    // Reserve the funds immediately (atomic deduct) so multiple pending
    // requests can't jointly overdraw the wallet before an admin gets to
    // approve them. Rejection refunds this amount back.
    let walletResult;
    try {
      walletResult = await updateWallet(email, userType, "withdrawal_hold", amount, null, "Withdrawal request submitted");
    } catch (walletErr) {
      if (walletErr.code === "INSUFFICIENT_BALANCE") {
        return res.status(400).json({ success: false, message: "Insufficient balance." });
      }
      if (walletErr.code === "WALLET_CONTENTION") {
        return res.status(400).json({ success: false, message: "Wallet balance changed. Please try again." });
      }
      throw walletErr;
    }

    // Create withdrawal request (funds are already held from the wallet balance above)
    const { data: request, error } = await supabase.from("withdrawal_requests").insert({
      user_email: email,
      user_type: userType,
      amount,
      bank_name: sanitize(req.body.bank_name || ""),
      bank_account_number: sanitize(req.body.bank_account_number || ""),
      bank_account_name: sanitize(req.body.bank_account_name || ""),
      momo_provider: req.body.momo_provider || "",
      momo_number: sanitize(req.body.momo_number || ""),
      status: "pending"
    }).select().single();

    if (error) {
      // Refund the hold since the request record failed to save
      await updateWallet(email, userType, "refund", amount, null, "Refund: withdrawal request failed to save");
      throw error;
    }

    // Notify admin
    const adminEmails = ADMINS.join(",");
    await supabase.from("notifications").insert({
      user_email: adminEmails,
      title: "Withdrawal request",
      message: `${userType} ${email} requested GHS ${amount} withdrawal.`,
      type: "info"
    });

    log("info", "Withdrawal requested", { email, amount, id: request.id });
    return res.json({ success: true, message: "Withdrawal request submitted for admin approval.", id: request.id });
  } catch (err) {
    log("error", "Withdrawal request error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to submit withdrawal request." });
  }
});

// ── GET /admin/wallet/withdrawals ── Admin lists withdrawal requests
app.get("/admin/wallet/withdrawals", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const { data: requests } = await supabase
      .from("withdrawal_requests")
      .select("*")
      .order("created_at", { ascending: false });

    return res.json({ success: true, data: requests || [] });
  } catch (err) {
    log("error", "Admin withdrawals error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load withdrawals." });
  }
});

// ── POST /admin/wallet/withdraw/:id/approve ── Admin approves/rejects withdrawal
app.post("/admin/wallet/withdraw/:id/:action", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const id = parseInt(req.params.id);
    const action = req.params.action; // 'approve' or 'reject'
    if (!["approve", "reject"].includes(action)) return res.status(400).json({ success: false, message: "Invalid action." });

    const { data: wd } = await supabase
      .from("withdrawal_requests")
      .select("*")
      .eq("id", id)
      .maybeSingle();

    if (!wd) return res.status(404).json({ success: false, message: "Request not found." });
    if (wd.status !== "pending") return res.json({ success: true, message: `Already ${wd.status}.` });

    if (action === "approve") {
      // Funds were already deducted (held) when the request was created — just mark it processed.
      await supabase.from("withdrawal_requests").update({
        status: "approved", processed_at: new Date().toISOString(), processed_by: user.email
      }).eq("id", id);
    } else {
      // Refund the held amount back to the wallet
      await updateWallet(wd.user_email, wd.user_type, "refund", wd.amount, null, "Withdrawal rejected — refunded");
      await supabase.from("withdrawal_requests").update({
        status: "rejected", processed_at: new Date().toISOString(), processed_by: user.email
      }).eq("id", id);
    }

    await supabase.from("notifications").insert({
      user_email: wd.user_email,
      title: `Withdrawal ${action === "approve" ? "approved" : "rejected"}`,
      message: action === "approve"
        ? `Your withdrawal of GHS ${wd.amount} has been approved and will be paid out.`
        : `Your withdrawal of GHS ${wd.amount} has been rejected and refunded to your wallet.`,
      type: action === "approve" ? "success" : "info"
    });

    return res.json({ success: true, message: `Withdrawal ${action === "approve" ? "approved" : "rejected"}.` });
  } catch (err) {
    log("error", "Withdrawal action error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to process withdrawal." });
  }
});

// ── POST /admin/wallet/credit ── Admin manually credits a wallet
app.post("/admin/wallet/credit", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const email = sanitize(req.body.email);
    const amount = parseFloat(req.body.amount);
    const description = sanitize(req.body.description || "Manual credit");
    if (!email || !amount || amount <= 0) return res.status(400).json({ success: false, message: "Valid email and amount required." });

    const userType = await resolveUserType(email);
    if (!userType) return res.status(404).json({ success: false, message: "User not found." });

    await updateWallet(email, userType, "admin_credit", amount, null, description);

    await supabase.from("notifications").insert({
      user_email: email,
      title: "Wallet credited",
      message: `GHS ${amount.toLocaleString()} has been added to your wallet. ${description ? "Reason: " + description : ""}`,
      type: "success"
    });

    log("info", "Admin wallet credit", { email, amount, admin: user.email });
    return res.json({ success: true, message: `GHS ${amount.toLocaleString()} credited to ${email}.` });
  } catch (err) {
    log("error", "Admin wallet credit error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to credit wallet." });
  }
});

// ── POST /admin/wallet/debit ── Admin manually debits a wallet
app.post("/admin/wallet/debit", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const email = sanitize(req.body.email);
    const amount = parseFloat(req.body.amount);
    const description = sanitize(req.body.description || "Manual debit");
    if (!email || !amount || amount <= 0) return res.status(400).json({ success: false, message: "Valid email and amount required." });

    const userType = await resolveUserType(email);
    if (!userType) return res.status(404).json({ success: false, message: "User not found." });

    const balance = await getWalletBalance(email, userType);
    if (amount > balance) return res.status(400).json({ success: false, message: "Insufficient balance." });

    await updateWallet(email, userType, "admin_debit", amount, null, description);

    log("info", "Admin wallet debit", { email, amount, admin: user.email });
    return res.json({ success: true, message: `GHS ${amount.toLocaleString()} debited from ${email}.` });
  } catch (err) {
    log("error", "Admin wallet debit error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to debit wallet." });
  }
});

// ── Finance / payout profile ──
app.get("/finance/worker/profile", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: worker } = await supabase.from("workers").select("id, full_name, phone, bank_name, bank_account_number, bank_account_name, momo_provider, momo_number, paystack_recipient_code").eq("email", user.email).maybeSingle();
    if (!worker) return res.status(404).json({ success: false, message: "Worker not found." });
    return res.json({ success: true, data: worker });
  } catch (err) {
    log("error", "Finance profile error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load finance profile." });
  }
});

app.post("/finance/worker/profile", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { bank_name, bank_account_number, bank_account_name, momo_provider, momo_number } = req.body;
    const { data: worker } = await supabase.from("workers").select("id").eq("email", user.email).maybeSingle();
    if (!worker) return res.status(404).json({ success: false, message: "Worker not found." });
    const updates = {};
    if (bank_name !== undefined) updates.bank_name = sanitize(bank_name);
    if (bank_account_number !== undefined) updates.bank_account_number = sanitize(bank_account_number);
    if (bank_account_name !== undefined) updates.bank_account_name = sanitize(bank_account_name);
    if (momo_provider !== undefined) updates.momo_provider = sanitize(momo_provider);
    if (momo_number !== undefined) updates.momo_number = sanitize(momo_number);
    const { error } = await supabase.from("workers").update(updates).eq("id", worker.id);
    if (error) return res.status(500).json({ success: false, message: "Failed to save payout profile." });
    return res.json({ success: true, message: "Payout profile saved." });
  } catch (err) {
    log("error", "Finance profile save error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to save payout profile." });
  }
});

app.get("/finance/worker/transactions", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: worker } = await supabase.from("workers").select("id").eq("email", user.email).maybeSingle();
    if (!worker) return res.status(404).json({ success: false, message: "Worker not found." });
    const { data: shifts } = await supabase.from("shifts").select("*").eq("worker_id", worker.id).eq("status", "completed").order("completion_time", { ascending: false });
    const now = new Date();
    const monthly = {};
    for (let i = 5; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const key = d.toISOString().substring(0, 7);
      monthly[key] = 0;
    }
    const transactions = (shifts || []).map(s => {
      const amt = parsePayAmount(s.total_pay);
      const mKey = s.completion_time ? s.completion_time.substring(0, 7) : null;
      if (mKey && monthly[mKey] !== undefined) monthly[mKey] += amt;
      return {
        id: s.id,
        facility_name: s.facility_name,
        role_needed: s.role_needed,
        shift_date: s.shift_date,
        completion_time: s.completion_time,
        amount: amt,
        payout_status: s.payout_status || "pending",
        payout_reference: s.payout_reference
      };
    });
    return res.json({ success: true, data: { transactions, monthly, total: transactions.reduce((sum, t) => sum + t.amount, 0) } });
  } catch (err) {
    log("error", "Finance transactions error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load transactions." });
  }
});

// ── Finance / wallet ──
app.get("/finance/wallet", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: worker } = await supabase.from("workers").select("id").eq("email", user.email).maybeSingle();
    if (!worker) return res.status(404).json({ success: false, message: "Worker not found." });

    const { data: shifts } = await supabase.from("shifts").select("total_pay, payout_status").eq("worker_id", worker.id).eq("status", "completed");
    let totalEarned = 0, autoPaid = 0;
    for (const s of shifts || []) {
      const amt = parsePayAmount(s.total_pay);
      totalEarned += amt;
      if (s.payout_status === "paid" || s.payout_status === "instant_paid") autoPaid += amt;
    }

    const { data: payouts } = await supabase.from("payout_requests").select("amount, status").eq("worker_id", worker.id);
    let requested = 0, completedPayouts = 0;
    for (const p of payouts || []) {
      if (p.status === "completed") completedPayouts += p.amount;
      if (p.status === "pending" || p.status === "processing") requested += p.amount;
    }

    const totalPaidOut = autoPaid + completedPayouts;
    return res.json({
      success: true,
      data: {
        total_earned: totalEarned,
        auto_paid: autoPaid,
        payout_requests_paid: completedPayouts,
        pending_requests: requested,
        available_balance: Math.max(0, totalEarned - totalPaidOut - requested)
      }
    });
  } catch (err) {
    log("error", "Wallet error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load wallet." });
  }
});

// ── Finance / payout request ──
app.post("/finance/payout/request", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { amount, method } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ success: false, message: "Invalid amount." });
    if (!method || !["bank", "momo"].includes(method)) return res.status(400).json({ success: false, message: "Invalid payment method." });

    const { data: worker } = await supabase.from("workers").select("*").eq("email", user.email).maybeSingle();
    if (!worker) return res.status(404).json({ success: false, message: "Worker not found." });

    // Compute available balance
    const { data: shifts } = await supabase.from("shifts").select("total_pay, payout_status").eq("worker_id", worker.id).eq("status", "completed");
    let totalEarned = 0, autoPaid = 0;
    for (const s of shifts || []) {
      const amt = parsePayAmount(s.total_pay);
      totalEarned += amt;
      if (s.payout_status === "paid" || s.payout_status === "instant_paid") autoPaid += amt;
    }
    const { data: payouts } = await supabase.from("payout_requests").select("amount, status").eq("worker_id", worker.id);
    let paidOut = 0, pendingReq = 0;
    for (const p of payouts || []) {
      if (p.status === "completed") paidOut += p.amount;
      if (p.status === "pending" || p.status === "processing") pendingReq += p.amount;
    }
    const available = Math.max(0, totalEarned - autoPaid - paidOut - pendingReq);

    if (amount > available) return res.status(400).json({ success: false, message: "Insufficient available balance." });

    const fee = 0;
    const netAmount = amount;

    const payoutData = {
      worker_id: worker.id,
      amount,
      fee,
      net_amount: netAmount,
      method,
      status: "pending"
    };
    if (method === "bank") {
      if (!worker.bank_name || !worker.bank_account_number || !worker.bank_account_name) return res.status(400).json({ success: false, message: "Bank account details not set. Go to Payment Methods first." });
      payoutData.bank_name = worker.bank_name;
      payoutData.bank_account_number = worker.bank_account_number;
      payoutData.bank_account_name = worker.bank_account_name;
    } else {
      if (!worker.momo_provider || !worker.momo_number) return res.status(400).json({ success: false, message: "Mobile Money details not set. Go to Payment Methods first." });
      payoutData.momo_provider = worker.momo_provider;
      payoutData.momo_number = worker.momo_number;
    }

    const { data: created, error } = await supabase.from("payout_requests").insert(payoutData).select().single();
    if (error) { log("error", "Payout request insert error", { error: error.message }); return res.status(500).json({ success: false, message: "Failed to create payout request." }); }

    return res.json({ success: true, message: "Payout request submitted. It will be processed within 24 hours.", data: created });
  } catch (err) {
    log("error", "Payout request error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to create payout request." });
  }
});

// ── Finance / payout history ──
app.get("/finance/payout/history", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: worker } = await supabase.from("workers").select("id").eq("email", user.email).maybeSingle();
    if (!worker) return res.status(404).json({ success: false, message: "Worker not found." });
    const { data: requests, error } = await supabase.from("payout_requests").select("*").eq("worker_id", worker.id).order("created_at", { ascending: false });
    if (error) return res.status(500).json({ success: false, message: "Failed to load payout history." });
    return res.json({ success: true, data: requests || [] });
  } catch (err) {
    log("error", "Payout history error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load payout history." });
  }
});

app.post("/ratings", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { shift_id, rating, review, target_email } = req.body;

    if (!shift_id || !rating || !target_email) {
      return res.status(400).json({ success: false, message: "shift_id, rating, and target_email are required." });
    }

    const ratingNum = parseInt(rating, 10);
    if (ratingNum < 1 || ratingNum > 5) {
      return res.status(400).json({ success: false, message: "Rating must be between 1 and 5." });
    }

    const shift = await getShiftById(shift_id);
    if (!shift) {
      return res.status(404).json({ success: false, message: "Shift not found." });
    }

    if (shift.status !== "completed") {
      return res.status(400).json({ success: false, message: "Can only rate completed shifts." });
    }

    const { data: callerWorker } = await supabase
      .from("workers")
      .select("id, email")
      .eq("email", user.email)
      .maybeSingle();

    const { data: callerFacility } = await supabase
      .from("facilities")
      .select("id, email")
      .eq("email", user.email)
      .maybeSingle();

    const callerEmail = user.email.toLowerCase();
    const shiftWorkerEmail = shift.worker_id
      ? (await supabase.from("workers").select("email").eq("id", shift.worker_id).single()).data?.email
      : null;

    const isPartOfShift =
      (callerWorker && shift.worker_id === callerWorker.id) ||
      (shift.contact_email && shift.contact_email.toLowerCase() === callerEmail);

    if (!isPartOfShift) {
      return res.status(403).json({ success: false, message: "You are not part of this shift." });
    }

    const raterEmail = user.email;

    const { data: existing } = await supabase
      .from("ratings")
      .select("id")
      .eq("shift_id", shift_id)
      .eq("rater_email", raterEmail)
      .maybeSingle();

    if (existing) {
      const { data, error } = await supabase
        .from("ratings")
        .update({ rating: ratingNum, review: sanitize(review || ""), updated_at: new Date().toISOString() })
        .eq("id", existing.id)
        .select()
        .single();

      if (error) {
        return res.status(500).json({ success: false, message: "Failed to update rating." });
      }

      log("info", "Rating updated", { shift_id, rater: raterEmail, target: target_email });
      return res.json({ success: true, data });
    }

    const { data, error } = await supabase
      .from("ratings")
      .insert([{
        shift_id,
        rater_email: raterEmail,
        target_email: target_email.toLowerCase(),
        rating: ratingNum,
        review: sanitize(review || ""),
        created_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to submit rating." });
    }

    await supabase.from("notifications").insert([{
      email: target_email.toLowerCase(),
      title: "New rating received",
      message: `You received a ${ratingNum}/5 rating for your shift at ${shift.facility_name}.`,
      type: "info",
      read: false,
      created_at: new Date().toISOString()
    }]).catch(() => {});

    log("info", "Rating created", { shift_id, rater: raterEmail, target: target_email });
    return res.json({ success: true, data });
  } catch (err) {
    log("error", "Rating error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to submit rating." });
  }
});

app.get("/ratings/mine", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const email = user.email.toLowerCase();

    const { data: ratings, error } = await supabase
      .from("ratings")
      .select("*")
      .eq("target_email", email)
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to load ratings." });
    }

    const enriched = await Promise.all((ratings || []).map(async (r) => {
      let raterName = null;
      const { data: worker } = await supabase
        .from("workers")
        .select("full_name")
        .eq("email", r.rater_email)
        .maybeSingle();
      if (worker) {
        raterName = worker.full_name;
      } else {
        const { data: facility } = await supabase
          .from("facilities")
          .select("facility_name")
          .eq("email", r.rater_email)
          .maybeSingle();
        if (facility) raterName = facility.facility_name;
      }
      return { ...r, rater_name: raterName };
    }));

    return res.json({ success: true, data: enriched });
  } catch (err) {
    log("error", "Ratings mine error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load ratings." });
  }
});

app.get("/ratings/given", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const email = user.email.toLowerCase();

    const { data, error } = await supabase
      .from("ratings")
      .select("*")
      .eq("rater_email", email)
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to load ratings." });
    }

    return res.json({ success: true, data: data || [] });
  } catch (err) {
    log("error", "Ratings given error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load ratings." });
  }
});

app.post("/notifications", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { title, message, type, related_link } = req.body;

    if (!title || !message) {
      return res.status(400).json({ success: false, message: "title and message are required." });
    }

    const validTypes = ["info", "success", "warning", "error"];
    const notifType = validTypes.includes(type) ? type : "info";

    const { data, error } = await supabase
      .from("notifications")
      .insert([{
        email: user.email.toLowerCase(),
        title: sanitize(title),
        message: sanitize(message),
        type: notifType,
        related_link: related_link ? sanitize(related_link) : null,
        read: false,
        created_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to create notification." });
    }

    log("info", "Notification created", { email: user.email, title });
    return res.json({ success: true, data });
  } catch (err) {
    log("error", "Notification create error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to create notification." });
  }
});

app.get("/notifications", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const email = user.email.toLowerCase();

    const { data, error } = await supabase
      .from("notifications")
      .select("*")
      .eq("email", email)
      .order("created_at", { ascending: false })
      .limit(50);

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to load notifications." });
    }

    const unread_count = (data || []).filter(n => !n.read).length;

    return res.json({ success: true, data: data || [], unread_count });
  } catch (err) {
    log("error", "Notifications fetch error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load notifications." });
  }
});

app.put("/notifications/:id/read", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const notifId = sanitize(req.params.id);
    const email = user.email.toLowerCase();

    const { data: existing } = await supabase
      .from("notifications")
      .select("id")
      .eq("id", notifId)
      .eq("email", email)
      .maybeSingle();

    if (!existing) {
      return res.status(404).json({ success: false, message: "Notification not found." });
    }

    const { error } = await supabase
      .from("notifications")
      .update({ read: true })
      .eq("id", notifId);

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to mark as read." });
    }

    return res.json({ success: true });
  } catch (err) {
    log("error", "Notification read error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to mark as read." });
  }
});

app.post("/notifications/read-all", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const email = user.email.toLowerCase();

    const { error } = await supabase
      .from("notifications")
      .update({ read: true })
      .eq("email", email)
      .eq("read", false);

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to mark all as read." });
    }

    return res.json({ success: true });
  } catch (err) {
    log("error", "Notifications read-all error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to mark all as read." });
  }
});

app.post("/worker/availability", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { available } = req.body;

    if (typeof available !== "boolean") {
      return res.status(400).json({ success: false, message: "available must be a boolean." });
    }

    const { data: worker } = await supabase
      .from("workers")
      .select("id")
      .eq("email", user.email)
      .maybeSingle();

    if (!worker) {
      return res.status(404).json({ success: false, message: "Worker profile not found." });
    }

    const { error } = await supabase
      .from("workers")
      .update({ available_for_work: available })
      .eq("id", worker.id);

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to update availability." });
    }

    log("info", "Worker availability updated", { email: user.email, available });
    return res.json({ success: true, available });
  } catch (err) {
    log("error", "Worker availability error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to update availability." });
  }
});

app.get("/worker/availability", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { data: worker } = await supabase
      .from("workers")
      .select("available_for_work")
      .eq("email", user.email)
      .maybeSingle();

    if (!worker) {
      return res.status(404).json({ success: false, message: "Worker profile not found." });
    }

    return res.json({ success: true, available: worker.available_for_work || false });
  } catch (err) {
    log("error", "Worker availability get error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to get availability." });
  }
});

app.post("/shift/cancel", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const shift_id = sanitize(req.body.shift_id);
    const worker_id = sanitize(req.body.worker_id);
    const reason = sanitize(req.body.reason);

    if (!shift_id || !worker_id) {
      return res.status(400).json({ success: false, message: "shift_id and worker_id are required." });
    }

    const { data: shift } = await supabase
      .from("shifts")
      .select("*")
      .eq("id", shift_id)
      .single();

    if (!shift) {
      return res.status(404).json({ success: false, message: "Shift not found." });
    }

    if (shift.status !== "accepted" && shift.status !== "in_progress") {
      return res.status(400).json({ success: false, message: `Cannot cancel shift with status "${shift.status}".` });
    }

    if (shift.worker_id !== worker_id) {
      return res.status(403).json({ success: false, message: "This worker is not assigned to this shift." });
    }

    const { data: worker } = await supabase
      .from("workers")
      .select("id, email")
      .eq("id", worker_id)
      .single();

    if (!worker || worker.email.toLowerCase() !== user.email.toLowerCase()) {
      return res.status(403).json({ success: false, message: "You do not own this worker profile." });
    }

    const { error: cancelError } = await supabase
      .from("shifts")
      .update({ status: "open", worker_id: null, qr_token: null })
      .eq("id", shift_id);

    if (cancelError) {
      return res.status(500).json({ success: false, message: "Failed to cancel shift." });
    }

    await supabase.from("notifications").insert([{
    email: shift.contact_email?.toLowerCase(),
    title: "Shift cancelled by worker",
    message: `A worker cancelled for ${shift.role_needed} on ${shift.shift_date}. Reason: ${reason || "Not provided"}.`,
    type: "warning",
    read: false,
    created_at: new Date().toISOString()
  }]).catch(() => {});

  log("info", "Shift cancelled", { shift_id, worker_id, reason: reason || "No reason provided" });

    let replacement = null;

    const matchConditions = { role: shift.role_needed, city: shift.city, available_for_work: true, identity_verified: true };
    if (isPharmacyRole(shift.role_needed)) {
      matchConditions.license_verified = true;
    }

    let query = supabase
      .from("workers")
      .select("id, full_name, email, role, city")
      .eq("role", shift.role_needed)
      .eq("city", shift.city)
      .eq("available_for_work", true)
      .eq("identity_verified", true);

    if (isPharmacyRole(shift.role_needed)) {
      query = query.eq("license_verified", true);
    }

    const { data: availableWorkers } = await query.limit(5);

    if (availableWorkers && availableWorkers.length > 0) {
      const candidate = availableWorkers[0];
      const newQrToken = generateQrToken();

      const { data: assignedShift, error: assignError } = await supabase
        .from("shifts")
        .update({ worker_id: candidate.id, qr_token: newQrToken, status: "accepted" })
        .eq("id", shift_id)
        .select()
        .single();

      if (!assignError && assignedShift) {
        replacement = { worker_name: candidate.full_name };

        await supabase.from("notifications").insert([{
          email: candidate.email.toLowerCase(),
          title: "Shift assigned",
          message: `You've been auto-assigned to a shift at ${shift.facility_name} on ${shift.shift_date}`,
          type: "info",
          read: false,
          created_at: new Date().toISOString()
        }]);

        const { data: updatedShift } = await supabase
          .from("shifts")
          .select("*")
          .eq("id", shift_id)
          .single();

        return res.json({ success: true, message: "Shift cancelled. Replacement worker assigned.", replacement, shift: updatedShift });
      }
    }

    const { data: updatedShift } = await supabase
      .from("shifts")
      .select("*")
      .eq("id", shift_id)
      .single();

    return res.json({ success: true, message: "Shift cancelled. No replacement found. Shift returned to open.", replacement: null, shift: updatedShift });
  } catch (err) {
    log("error", "Shift cancel error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to cancel shift." });
  }
});

app.post("/invitations", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { worker_email, shift_id, message } = req.body;
    const cleanWorkerEmail = sanitize(worker_email);
    const cleanShiftId = sanitize(shift_id);
    const cleanMessage = sanitize(message || "");

    if (!cleanWorkerEmail || !cleanShiftId) {
      return res.status(400).json({ success: false, message: "worker_email and shift_id are required." });
    }

    const { data: facility } = await supabase
      .from("facilities")
      .select("id, facility_name")
      .eq("email", user.email)
      .maybeSingle();

    if (!facility) {
      return res.status(403).json({ success: false, message: "Facility profile not found." });
    }

    const { data: shift } = await supabase
      .from("shifts")
      .select("id, contact_email, shift_date, facility_name")
      .eq("id", cleanShiftId)
      .single();

    if (!shift) {
      return res.status(404).json({ success: false, message: "Shift not found." });
    }

    if (shift.contact_email.toLowerCase() !== user.email.toLowerCase()) {
      return res.status(403).json({ success: false, message: "This shift does not belong to your facility." });
    }

    const { data: worker } = await supabase
      .from("workers")
      .select("id")
      .eq("email", cleanWorkerEmail)
      .maybeSingle();

    if (!worker) {
      return res.status(404).json({ success: false, message: "Worker not found with that email." });
    }

    const { data: existingApp } = await supabase
      .from("applications")
      .select("id")
      .eq("worker_id", worker.id)
      .eq("shift_id", cleanShiftId)
      .maybeSingle();

    if (existingApp) {
      return res.status(400).json({ success: false, message: "Worker has already applied or been invited to this shift." });
    }

    const { data, error } = await supabase
      .from("applications")
      .insert([{ worker_id: worker.id, shift_id: cleanShiftId, status: "invited", cover_note: cleanMessage }])
      .select()
      .single();

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to create invitation." });
    }

    await supabase.from("notifications").insert([{
      email: cleanWorkerEmail.toLowerCase(),
      title: "You've been invited!",
      message: `${facility.facility_name} has invited you to a shift on ${shift.shift_date}`,
      type: "info",
      read: false,
      created_at: new Date().toISOString()
    }]);

    log("info", "Invitation sent", { worker_email: cleanWorkerEmail, shift_id: cleanShiftId });
    return res.json({ success: true, data });
  } catch (err) {
    log("error", "Create invitation error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to send invitation." });
  }
});

app.get("/invitations", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { data: worker } = await supabase
      .from("workers")
      .select("id")
      .eq("email", user.email)
      .maybeSingle();

    if (!worker) {
      return res.status(404).json({ success: false, message: "Worker profile not found." });
    }

    const { data, error } = await supabase
      .from("applications")
      .select(`*, shifts(id, facility_name, city, role_needed, shift_date, start_time, duration, pay_rate)`)
      .eq("worker_id", worker.id)
      .eq("status", "invited")
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to load invitations." });
    }

    return res.json({ success: true, data: data || [] });
  } catch (err) {
    log("error", "Get invitations error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load invitations." });
  }
});

app.post("/invitations/respond", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const application_id = sanitize(req.body.application_id);
    const response = sanitize(req.body.response);

    if (!application_id || !response || !["accepted", "rejected"].includes(response)) {
      return res.status(400).json({ success: false, message: "application_id and response (accepted/rejected) are required." });
    }

    const { data: worker } = await supabase
      .from("workers")
      .select("id, full_name")
      .eq("email", user.email)
      .maybeSingle();

    if (!worker) {
      return res.status(404).json({ success: false, message: "Worker profile not found." });
    }

    const { data: application } = await supabase
      .from("applications")
      .select(`*, shifts(*)`)
      .eq("id", application_id)
      .single();

    if (!application) {
      return res.status(404).json({ success: false, message: "Application not found." });
    }

    if (application.worker_id !== worker.id) {
      return res.status(403).json({ success: false, message: "This invitation does not belong to you." });
    }

    if (application.status !== "invited") {
      return res.status(400).json({ success: false, message: `This invitation is no longer valid (status: ${application.status}).` });
    }

    if (response === "accepted") {
      const qrToken = generateQrToken();

      await supabase
        .from("applications")
        .update({ status: "accepted", responded_at: new Date().toISOString() })
        .eq("id", application_id);

      await supabase
        .from("shifts")
        .update({ worker_id: worker.id, qr_token: qrToken, status: "accepted" })
        .eq("id", application.shift_id);

      await supabase
        .from("applications")
        .update({ status: "rejected", responded_at: new Date().toISOString() })
        .eq("shift_id", application.shift_id)
        .eq("status", "invited")
        .neq("id", application_id);

      await supabase.from("notifications").insert([{
        email: application.shifts.contact_email.toLowerCase(),
        title: "Invitation accepted",
        message: `${worker.full_name} has accepted your invitation for ${application.shifts.shift_date}`,
        type: "success",
        read: false,
        created_at: new Date().toISOString()
      }]);

      log("info", "Invitation accepted", { application_id, worker_id: worker.id });
      return res.json({ success: true, data: { ...application, status: "accepted" } });
    }

    await supabase
      .from("applications")
      .update({ status: "rejected", responded_at: new Date().toISOString() })
      .eq("id", application_id);

    await supabase.from("notifications").insert([{
      email: application.shifts.contact_email.toLowerCase(),
      title: "Invitation rejected",
      message: `${worker.full_name} has rejected your invitation for ${application.shifts.shift_date}`,
      type: "warning",
      read: false,
      created_at: new Date().toISOString()
    }]);

    log("info", "Invitation rejected", { application_id, worker_id: worker.id });
    return res.json({ success: true, data: { ...application, status: "rejected" } });
  } catch (err) {
    log("error", "Invitation respond error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to respond to invitation." });
  }
});

app.get("/roles/rates", (req, res) => {
  return res.json({
    success: true,
    rates: {
      pharmacist: 80,
      "pharmacy-tech": 45,
      nurse: 60,
      "medical-doctor": 120,
      "lab-technician": 40,
      caregiver: 25,
      other: 35
    },
    currency: "GHS"
  });
});

app.post("/support/ticket", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const subject = sanitize(req.body.subject);
    const message = sanitize(req.body.message);
    const category = sanitize(req.body.category || "general");

    const validCategories = ["general", "payment", "shift", "account", "technical"];
    const cleanCategory = validCategories.includes(category) ? category : "general";

    if (!subject || !message) {
      return res.status(400).json({ success: false, message: "subject and message are required." });
    }

    const { data, error } = await supabase
      .from("support_tickets")
      .insert([{
        email: user.email.toLowerCase(),
        subject,
        message,
        category: cleanCategory,
        status: "open",
        created_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to create support ticket." });
    }

    await supabase.from("notifications").insert([{
      email: user.email.toLowerCase(),
      title: "Support ticket received",
      message: "We've received your request and will respond within 24 hours.",
      type: "info",
      read: false,
      created_at: new Date().toISOString()
    }]);

    log("info", "Support ticket created", { email: user.email, subject });
    return res.json({ success: true, data });
  } catch (err) {
    log("error", "Support ticket error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to create support ticket." });
  }
});

app.get("/support/tickets", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const { data, error } = await supabase
      .from("support_tickets")
      .select("*")
      .eq("email", user.email.toLowerCase())
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(500).json({ success: false, message: "Failed to load support tickets." });
    }

    return res.json({ success: true, data: data || [] });
  } catch (err) {
    log("error", "Support tickets fetch error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load support tickets." });
  }
});

app.post("/shift/instant-pay", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  try {
    const shift_id = sanitize(req.body.shift_id);
    const fee_accepted = req.body.fee_accepted === true;

    if (!shift_id) {
      return res.status(400).json({ success: false, message: "shift_id is required." });
    }

    if (!fee_accepted) {
      return res.status(400).json({ success: false, message: "Please accept the instant pay fee, or use the standard free payout (2-3 business days)." });
    }

    const { data: worker } = await supabase
      .from("workers")
      .select("id, full_name, email, phone, paystack_recipient_code")
      .eq("email", user.email)
      .maybeSingle();

    if (!worker) {
      return res.status(404).json({ success: false, message: "Worker profile not found." });
    }

    const { data: shift } = await supabase
      .from("shifts")
      .select("*")
      .eq("id", shift_id)
      .single();

    if (!shift) {
      return res.status(404).json({ success: false, message: "Shift not found." });
    }

    if (shift.worker_id !== worker.id) {
      return res.status(403).json({ success: false, message: "This shift does not belong to you." });
    }

    if (shift.status !== "completed") {
      return res.status(400).json({ success: false, message: "Shift must be completed before payout." });
    }

    if (shift.payout_status === "paid" || shift.payout_status === "instant_paid") {
      return res.status(400).json({ success: false, message: "This shift has already been paid out." });
    }

    const totalPay = parsePayAmount(shift.total_pay);
    const fee = Math.max(Math.round(totalPay * 0.025 * 100) / 100, 1);
    const net = Math.round((totalPay - fee) * 100) / 100;

    const { transfer_code } = await initiateWorkerPayout({ ...worker, id: worker.id }, { ...shift, total_pay: `GHS ${net}` });

    await supabase
      .from("shifts")
      .update({ payout_status: "instant_paid", payout_reference: transfer_code, payout_fee: fee, payout_instant: true })
      .eq("id", shift_id);

    await supabase.from("notifications").insert([{
      email: user.email.toLowerCase(),
      title: "Instant payout sent!",
      message: `GHS ${net} sent to your Mobile Money. Fee: GHS ${fee}`,
      type: "success",
      read: false,
      created_at: new Date().toISOString()
    }]);

    log("info", "Instant payout processed", { shift_id, worker_id: worker.id, amount: totalPay, fee, net });
    return res.json({ success: true, message: `GHS ${net} sent to your Mobile Money.`, amount: totalPay, fee, net });
  } catch (err) {
    log("error", "Instant payout error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to process instant payout." });
  }
});

// ── Settings / facility ──
app.get("/settings/facility", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: facility, error } = await supabase.from("facilities").select("id, facility_name, facility_type, city, contact_name, contact_phone, staff_needs, billing_model, trusted_by, created_at, updated_at").eq("email", user.email.toLowerCase()).maybeSingle();
    if (error || !facility) return res.status(404).json({ success: false, message: "Facility not found." });
    return res.json({ success: true, data: facility });
  } catch (err) {
    log("error", "Settings facility error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load facility settings." });
  }
});

app.put("/settings/facility", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { facility_name, facility_type, city, contact_name, contact_phone, staff_needs } = req.body;
    const updates = {};
    if (facility_name) updates.facility_name = sanitize(facility_name);
    if (facility_type) updates.facility_type = sanitize(facility_type);
    if (city) updates.city = sanitize(city);
    if (contact_name) updates.contact_name = sanitize(contact_name);
    if (contact_phone) updates.contact_phone = sanitize(contact_phone);
    if (staff_needs) updates.staff_needs = sanitize(staff_needs);
    const { data: facility, error } = await supabase.from("facilities").update(updates).eq("email", user.email.toLowerCase()).select().single();
    if (error) return res.status(500).json({ success: false, message: "Failed to update facility." });
    return res.json({ success: true, data: facility });
  } catch (err) {
    log("error", "Settings facility update error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to update facility." });
  }
});

// ── Facility branches ──
app.get("/facility/branches", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data, error } = await supabase.from("facility_branches").select("*").eq("facility_email", user.email.toLowerCase()).order("name");
    if (error) return res.status(500).json({ success: false, message: "Failed to load branches." });
    return res.json({ success: true, data: data || [] });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/facility/branches", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const { name, city, address, latitude, longitude, phone } = req.body;
  if (!name || !city) return res.status(400).json({ success: false, message: "Branch name and city are required." });
  try {
    const { data, error } = await supabase.from("facility_branches").insert([{
      facility_email: user.email.toLowerCase(), name: sanitize(name),
      city: sanitize(city), address: address ? sanitize(address) : null,
      latitude: latitude || null, longitude: longitude || null,
      phone: phone ? sanitize(phone) : null
    }]).select().single();
    if (error) return res.status(500).json({ success: false, message: "Failed to create branch." });
    return res.json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.put("/facility/branches/:id", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const { id } = req.params;
  const { name, city, address, latitude, longitude, phone } = req.body;
  try {
    const { data: existing } = await supabase.from("facility_branches").select("id").eq("id", id).eq("facility_email", user.email.toLowerCase()).maybeSingle();
    if (!existing) return res.status(404).json({ success: false, message: "Branch not found." });
    const updates = {};
    if (name) updates.name = sanitize(name);
    if (city) updates.city = sanitize(city);
    if (address !== undefined) updates.address = sanitize(address);
    if (latitude !== undefined) updates.latitude = latitude;
    if (longitude !== undefined) updates.longitude = longitude;
    if (phone !== undefined) updates.phone = sanitize(phone);
    const { data, error } = await supabase.from("facility_branches").update(updates).eq("id", id).select().single();
    if (error) return res.status(500).json({ success: false, message: "Failed to update branch." });
    return res.json({ success: true, data });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.delete("/facility/branches/:id", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const { id } = req.params;
  try {
    const { data: existing } = await supabase.from("facility_branches").select("id").eq("id", id).eq("facility_email", user.email.toLowerCase()).maybeSingle();
    if (!existing) return res.status(404).json({ success: false, message: "Branch not found." });
    const { error } = await supabase.from("facility_branches").delete().eq("id", id);
    if (error) return res.status(500).json({ success: false, message: "Failed to delete branch." });
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ── Worker search for pre-assignment ──
app.get("/workers/search", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const { role, city, q } = req.query;
  try {
    let query = supabase.from("workers").select("id, full_name, email, phone, role, city, experience, profile_photo_url, license_verified, identity_verified");
    if (role) query = query.eq("role", role);
    if (city) query = query.eq("city", city);
    if (q) query = query.or(`full_name.ilike.%${q}%,email.ilike.%${q}%`);
    const { data, error } = await query.limit(30);
    if (error) return res.status(500).json({ success: false, message: "Search failed." });
    return res.json({ success: true, data: data || [] });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ── Settings / admin ──
app.get("/settings/admin", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const { data: rows, error } = await supabase.from("platform_settings").select("*");
    if (error || !rows || rows.length === 0) {
      return res.json({
        success: true,
        data: {
          covercare_fee_percent: 25,
          min_pay_rate: 20,
          suggested_rates: { pharmacist: 80, "pharmacy-tech": 40, "medical-doctor": 120, nurse: 60, "lab-technician": 50 }
        }
      });
    }
    const settings = {};
    for (const row of rows) {
      settings[row.key] = row.value;
    }
    return res.json({ success: true, data: settings });
  } catch (err) {
    return res.json({
      success: true,
      data: {
        covercare_fee_percent: 25,
        min_pay_rate: 20,
        suggested_rates: { pharmacist: 80, "pharmacy-tech": 40, "medical-doctor": 120, nurse: 60, "lab-technician": 50 }
      }
    });
  }
});

app.put("/settings/admin", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  try {
    const { key, value } = req.body;
    if (!key) return res.status(400).json({ success: false, message: "key is required." });
    const { error } = await supabase.from("platform_settings").upsert({ key, value }, { onConflict: "key" });
    if (error) return res.status(500).json({ success: false, message: "Failed to save setting." });
    log("info", "Admin setting updated", { key, value });
    return res.json({ success: true, message: "Setting saved." });
  } catch (err) {
    log("error", "Settings admin update error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to save setting." });
  }
});

// ── Send email notification (admin-only: relays arbitrary HTML from our verified sending domain) ──
app.post("/notifications/send-email", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!requireAdmin(req, res)) return;
  if (!rateLimitRoute(req, res, 20)) return;
  try {
    const { to, subject, body } = req.body;
    if (!to || !subject || !body) {
      return res.status(400).json({ success: false, message: "to, subject, and body are required." });
    }

    if (!process.env.RESEND_API_KEY) {
      log("warn", "RESEND_API_KEY not set — storing email notification in DB");
      await supabase.from("notifications").insert([{
        email: to.toLowerCase(),
        title: subject,
        message: body,
        type: "email",
        read: false,
        created_at: new Date().toISOString()
      }]).catch(() => {});
      return res.json({ success: true, message: "Notification stored (email not sent — no Resend key)." });
    }

    const emailRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "CoverCare Africa <notifications@covercareafrica.com>",
        to: [to],
        subject,
        html: body
      })
    });

    const emailData = await emailRes.json();
    if (!emailRes.ok) {
      log("error", "Resend email failed", { error: emailData });
      return res.status(500).json({ success: false, message: "Failed to send email." });
    }

    log("info", "Email sent via Resend", { to, subject });
    return res.json({ success: true, message: "Email sent." });
  } catch (err) {
    log("error", "Send email error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to send email." });
  }
});

process.on("SIGTERM", async () => {
  await browserPool.close();
  process.exit(0);
});

// ── Client settings ──
app.get("/client", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: client, error } = await supabase.from("clients")
      .select("*").eq("email", user.email.toLowerCase()).maybeSingle();
    if (error || !client) return res.status(404).json({ success: false, message: "Client not found." });
    return res.json({ success: true, data: client });
  } catch (err) {
    log("error", "Get client error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load profile." });
  }
});

app.put("/client", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const { full_name, phone, city, country, address, gps_code, gender, profile_photo_url } = req.body;
  if (!full_name || !phone || !city) {
    return res.status(400).json({ success: false, message: "Name, phone, and city are required." });
  }
  try {
    const { data: existing } = await supabase.from("clients")
      .select("id").eq("email", user.email.toLowerCase()).maybeSingle();
    if (!existing) return res.status(404).json({ success: false, message: "Client not found." });

    // Build updates — try all fields first; if it fails, retry with only basic fields
    const updates = { full_name: sanitize(full_name), phone: sanitize(phone), city: sanitize(city) };
    if (country) updates.country = sanitize(country);
    if (gender) updates.gender = sanitize(gender);
    if (address !== undefined) updates.address = sanitize(address);
    if (gps_code !== undefined) updates.gps_code = sanitize(gps_code);
    if (profile_photo_url) updates.profile_photo_url = profile_photo_url;

    let { error } = await supabase.from("clients").update(updates).eq("id", existing.id);
    // If update failed, retry with only basic fields (newer columns may not exist yet)
    if (error) {
      log("warn", "Full client update failed, retrying with basics", { error: error.message });
      const basic = { full_name: sanitize(full_name), phone: sanitize(phone), city: sanitize(city) };
      if (country) basic.country = sanitize(country);
      if (gender) basic.gender = sanitize(gender);
      const { error: e2 } = await supabase.from("clients").update(basic).eq("id", existing.id);
      if (e2) {
        log("error", "Basic client update also failed", { error: e2.message });
        return res.status(500).json({ success: false, message: "Failed to update profile." });
      }
      return res.json({ success: true, message: "Profile updated (basic fields)." });
    }
    return res.json({ success: true, message: "Profile updated successfully." });
  } catch (err) {
    log("error", "Update client error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to update profile." });
  }
});

app.delete("/client", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  const email = req.body.email;
  if (!email || email.toLowerCase() !== user.email.toLowerCase()) {
    return res.status(400).json({ success: false, message: "Email must match your account." });
  }
  await supabase.from("clients").delete().eq("email", email);
  const { error: authError } = await supabase.auth.admin.deleteUser(user.id);
  if (authError) {
    log("error", "Client auth delete error", { error: authError.message });
    return res.status(500).json({ success: false, message: "Account data removed but auth deletion failed. Contact support." });
  }
  log("info", "Client account deleted", { email });
  return res.json({ success: true, message: "Account permanently deleted." });
});

// ── Client finance ──
app.get("/finance/client/summary", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: shifts } = await supabase.from("shifts")
      .select("total_pay, payment_status, created_at")
      .eq("contact_email", user.email.toLowerCase());
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
    let total_spent = 0, this_month = 0, pending = 0;
    for (const s of shifts || []) {
      const pay = parseFloat(s.total_pay) || 0;
      if (s.payment_status === "paid") {
        total_spent += pay;
        if (s.created_at && s.created_at >= monthStart) this_month += pay;
      }
      if (s.payment_status === "pending" || s.payment_status === "postpaid") pending += pay;
    }
    return res.json({ success: true, data: {
      total_spent: Math.round(total_spent * 100) / 100,
      this_month: Math.round(this_month * 100) / 100,
      pending: Math.round(pending * 100) / 100
    }});
  } catch (err) {
    log("error", "Client finance summary error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load finance summary." });
  }
});

app.get("/finance/client/transactions", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const email = user.email.toLowerCase();
    const { count, error: countError } = await supabase.from("shifts")
      .select("*", { count: "exact", head: true }).eq("contact_email", email);
    if (countError) return res.status(500).json({ success: false, message: "Failed to count transactions." });
    const { data: shifts, error } = await supabase.from("shifts")
      .select("*").eq("contact_email", email).order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);
    if (error) return res.status(500).json({ success: false, message: "Failed to load transactions." });
    const transactions = (shifts || []).map(s => ({
      id: s.id, role_needed: s.role_needed, shift_date: s.shift_date,
      start_time: s.start_time, duration_hours: s.duration_hours,
      pay_rate: s.pay_rate, total_pay: parseFloat(s.total_pay) || 0,
      payment_status: s.payment_status, payment_reference: s.payment_reference,
      facility_type: s.facility_type, facility_name: s.facility_name,
      created_at: s.created_at, status: s.status
    }));
    return res.json({ success: true, data: {
      transactions, total: count, page, limit,
      total_pages: Math.ceil(count / limit)
    }});
  } catch (err) {
    log("error", "Client finance transactions error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load transactions." });
  }
});

// ── Client finance profile (momo / bank / card) ──
app.get("/finance/client/profile", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { data: client } = await supabase
      .from("clients")
      .select("id, full_name, phone, bank_name, bank_account_number, bank_account_name, momo_provider, momo_number, card_last4, card_brand")
      .eq("email", user.email.toLowerCase())
      .maybeSingle();
    if (!client) return res.status(404).json({ success: false, message: "Client not found." });
    return res.json({ success: true, data: client });
  } catch (err) {
    log("error", "Client finance profile error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load finance profile." });
  }
});

app.post("/finance/client/profile", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const { bank_name, bank_account_number, bank_account_name, momo_provider, momo_number } = req.body;
    const { data: client } = await supabase.from("clients").select("id").eq("email", user.email.toLowerCase()).maybeSingle();
    if (!client) return res.status(404).json({ success: false, message: "Client not found." });
    const updates = {};
    if (bank_name !== undefined) updates.bank_name = sanitize(bank_name);
    if (bank_account_number !== undefined) updates.bank_account_number = sanitize(bank_account_number);
    if (bank_account_name !== undefined) updates.bank_account_name = sanitize(bank_account_name);
    if (momo_provider !== undefined) updates.momo_provider = sanitize(momo_provider);
    if (momo_number !== undefined) updates.momo_number = sanitize(momo_number);
    const { error } = await supabase.from("clients").update(updates).eq("id", client.id);
    if (error) return res.status(500).json({ success: false, message: "Failed to save payment profile." });
    return res.json({ success: true, message: "Payment profile saved." });
  } catch (err) {
    log("error", "Client finance profile save error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to save payment profile." });
  }
});

// ── Workers hired by this client ──
app.get("/client/workers-history", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const email = user.email.toLowerCase();
    const { data: shifts } = await supabase
      .from("shifts")
      .select("id, role_needed, shift_date, status, total_pay, created_at")
      .eq("contact_email", email)
      .in("status", ["accepted", "completed", "in_progress"])
      .order("created_at", { ascending: false });
    const history = [];
    for (const shift of shifts || []) {
      const { data: app } = await supabase
        .from("applications")
        .select("worker_id")
        .eq("shift_id", shift.id)
        .eq("status", "accepted")
        .maybeSingle();
      if (!app) continue;
      const { data: worker } = await supabase
        .from("workers")
        .select("id, full_name, role, phone, email, profile_photo_url, city, experience")
        .eq("id", app.worker_id)
        .maybeSingle();
      if (!worker) continue;
      history.push({
        shift_id: shift.id,
        role_needed: shift.role_needed,
        shift_date: shift.shift_date,
        shift_status: shift.status,
        total_pay: parseFloat(shift.total_pay) || 0,
        shift_created: shift.created_at,
        worker_id: worker.id,
        worker_name: worker.full_name,
        worker_role: worker.role,
        worker_phone: worker.phone,
        worker_email: worker.email,
        worker_photo: worker.profile_photo_url,
        worker_city: worker.city,
        worker_experience: worker.experience
      });
    }
    return res.json({ success: true, data: history });
  } catch (err) {
    log("error", "Client workers history error", { error: err.message });
    return res.status(500).json({ success: false, message: "Failed to load workers history." });
  }
});

app.listen(PORT, () => {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    log("warn", "Supabase env vars missing — database calls will fail");
  }
  if (!process.env.PAYSTACK_SECRET_KEY) {
    log("warn", "PAYSTACK_SECRET_KEY not set — payments disabled");
  }
  log("info", "Server started", { port: PORT });
});
