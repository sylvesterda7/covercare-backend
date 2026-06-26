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

app.use(cors({
  origin: [
    "https://covercare-africa.vercel.app",
    "http://localhost:5500",
    "http://127.0.0.1:5500"
  ],
  methods: ["GET", "POST"],
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

function sanitize(str) {
  if (!str) return "";
  return str.toString().replace(/[<>'";&]/g, "").trim().substring(0, 200);
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
    if (!this.instance || !this.instance.isConnected()) {
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
  "experience_required", "urgency", "notes"
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
  const hours = parseFloat(String(shiftData.duration || "").replace(/[^0-9.]/g, "")) || 0;
  const rate = parseFloat(String(shiftData.pay_rate || "").replace(/[^0-9.]/g, "")) || 0;
  const workerTotal = Math.round(rate * hours * 100) / 100;
  const facilityTotal = Math.round(workerTotal * 1.25 * 100) / 100;
  return { hours, rate, workerTotal, facilityTotal };
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

  const { full_name, email, phone, role, license_number, city, experience } = body;

  if (!full_name || !email || !phone || !role || !city) {
    return res.status(400).json({ success: false, message: "full_name, email, phone, role, and city are required." });
  }

  if (user.email.toLowerCase() !== email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "Email does not match your authenticated account." });
  }

  const { error } = await supabase.from("workers").insert([{
    full_name, email, phone, role, license_number, license_verified: false, city, experience
  }]);

  if (error) {
    log("error", "Worker save error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to save worker.", error: error.message });
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

  const { facility_name, facility_type, city, contact_name, contact_role, email, phone, staff_needs, frequency } = body;

  if (user.email.toLowerCase() !== email.toLowerCase()) {
    return res.status(403).json({ success: false, message: "Email does not match your authenticated account." });
  }

  const { error } = await supabase.from("facilities").insert([{
    facility_name, facility_type, city, contact_name, contact_role, email, phone, staff_needs, frequency
  }]);

  if (error) {
    log("error", "Facility save error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to save facility.", error: error.message });
  }

  log("info", "Facility saved", { facility_name });
  return res.json({ success: true, message: "Facility saved successfully." });
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

  if (!registration_number) {
    return res.status(400).json({ success: false, message: "Registration number is required." });
  }
  if (!name) {
    return res.status(400).json({ success: false, message: "Name is required for verification." });
  }

  log("info", "Verifying license", { registration_number, name });

  const nameParts = name.toLowerCase().trim().split(" ");
  const firstName = nameParts[0] || "";
  const lastName = nameParts[nameParts.length - 1] || "";

  let page;
  try {
    const browser = await browserPool.getBrowser();
    page = await browser.newPage();

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

    const pharmacistOption = options.find(o => o.text.toLowerCase().includes("pharmacist"));
    if (pharmacistOption) {
      await page.select("select", pharmacistOption.value);
    }

    await new Promise(resolve => setTimeout(resolve, 1500));
    await page.waitForSelector("input[type='text']", { timeout: 10000 });
    await page.click("input[type='text']", { clickCount: 3 });
    await page.type("input[type='text']", registration_number);
    await page.keyboard.press("Enter");
    await new Promise(resolve => setTimeout(resolve, 6000));

    const resultText = await page.evaluate(() => document.body.innerText.toLowerCase());

    const hasResultRow = resultText.includes("no results") === false && /\d+\s+\w+\s+\w+/.test(resultText);
    const nameMatches = resultText.includes(firstName) || resultText.includes(lastName);
    const hasResults = hasResultRow && nameMatches;

    log("info", "Verification result", { registration_number, hasResultRow, nameMatches });

    if (hasResults) {
      return res.json({
        success: true,
        message: "License verified in good standing with the Pharmacy Council.",
        data: { status: "verified_good", registration_number, name_verified: name, source: "Pharmacy Council Ghana" }
      });
    } else if (hasResultRow && !nameMatches) {
      return res.json({
        success: false,
        message: "Registration number found but name does not match Council records.",
        data: { status: "name_mismatch", registration_number, source: "Pharmacy Council Ghana" }
      });
    } else {
      return res.json({
        success: false,
        message: "Registration number not found in Pharmacy Council records.",
        data: { status: "not_found", registration_number, source: "Pharmacy Council Ghana" }
      });
    }

  } catch (err) {
    log("error", "Verification error", { error: err.message });
    return res.status(500).json({ success: false, message: "Verification service temporarily unavailable." });
  } finally {
    if (page) await page.close();
  }
});

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

  const updateData = { identity_verified: true, identity_verified_at: new Date().toISOString() };
  if (selfie_url) updateData.selfie_url = selfie_url;
  if (id_document_url) updateData.id_document_url = id_document_url;

  const { error } = await supabase.from("workers").update(updateData).eq("email", email);

  if (error) {
    log("error", "Identity update error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to update identity status." });
  }

  log("info", "Identity verified", { email });
  return res.json({ success: true, message: "Identity verified successfully." });
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

  if (facilityEmail && shift.contact_email !== facilityEmail) {
    return res.status(403).json({ success: false, message: "This shift does not belong to your facility." });
  }

  if (shift.status === "in_progress") {
    return res.json({ success: true, message: "Worker already checked in.", already_arrived: true, arrival_time: shift.arrival_time, shift });
  }

  if (shift.status !== "accepted") {
    return res.status(400).json({ success: false, message: `Cannot check in — shift status is "${shift.status}".` });
  }

  const arrivalTime = new Date().toISOString();

  const { data, error } = await supabase
    .from("shifts")
    .update({ arrival_time: arrivalTime, status: "in_progress" })
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

  log("info", "Worker arrived", { shiftId, workerId, arrivalTime });
  return res.json({
    success: true,
    message: "Arrival confirmed. Shift is now in progress.",
    arrival_time: arrivalTime,
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

  const completionTime = new Date().toISOString();

  const { data, error } = await supabase
    .from("shifts")
    .update({ completion_time: completionTime, status: "completed" })
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

  log("info", "Shift completed", { shiftId, workerId, completionTime, payout: payout ? "sent" : "failed" });
  return res.json({
    success: true,
    message: payout ? "Shift completed. Payout sent to worker's Mobile Money." : "Shift completed but payout failed — support will follow up.",
    completion_time: completionTime,
    payout: payout ? { amount: payout.amount, transfer_code: payout.transfer_code } : null,
    shift: data
  });
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
    .select("id, status")
    .eq("id", shift_id)
    .single();

  if (!shift || shift.status !== "open") {
    return res.status(400).json({ success: false, message: "This shift is no longer accepting applications." });
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

  await supabase
    .from("shifts")
    .update({ status: "accepted", worker_id: application.worker_id })
    .eq("id", application.shift_id);

  log("info", "Application accepted", { application_id, facility_email });
  return res.json({ success: true, message: "Application accepted. Worker assigned to shift.", data });
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

app.post("/api/upload", async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { image, folder } = req.body;
  if (!image) {
    return res.status(400).json({ success: false, message: "Image data is required." });
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

  const { full_name, phone, role, license_number, city, experience } = req.body;

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
  if (experience) updates.experience = sanitize(experience);

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

  const { facility_name, facility_type, city, contact_name, contact_role, phone, staff_needs, frequency } = req.body;

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
  if (contact_name) updates.contact_name = sanitize(contact_name);
  if (contact_role) updates.contact_role = sanitize(contact_role);
  if (phone) updates.phone = sanitize(phone);
  if (staff_needs) updates.staff_needs = sanitize(staff_needs);
  if (frequency) updates.frequency = sanitize(frequency);

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

process.on("SIGTERM", async () => {
  await browserPool.close();
  process.exit(0);
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
