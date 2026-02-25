// server.js
// HuntBase backend + static file server
// Run: node server.js
// Open: http://localhost:5173

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = 5173;
const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "app-data.json");
const TEMPLATE_DIR = path.join(__dirname, "templates");
const USER_TEMPLATE_FILE = path.join(TEMPLATE_DIR, "user-account-template.html");
const AUTH_SECRET = process.env.AUTH_SECRET || "change-this-secret-in-production";
const ADMIN_EXPORT_KEY = process.env.ADMIN_EXPORT_KEY || "";
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const RESET_TOKEN_TTL_MS = 1000 * 60 * 30;
const VERIFY_TOKEN_TTL_MS = 1000 * 60 * 60 * 24;
const NODE_ENV = process.env.NODE_ENV || "development";
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "onboarding@resend.dev";
const FEEDBACK_TO_EMAIL = process.env.FEEDBACK_TO_EMAIL || "ethanprebleco@gmail.com";
const EMAIL_OUTBOX_FILE = path.join(DATA_DIR, "email-outbox.log");
const AUTH_RATE_LIMIT_MAX = Number(process.env.AUTH_RATE_LIMIT_MAX || 25);
const AUTH_RATE_LIMIT_WINDOW_MS = Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);

// Base URL for iSportsman
const ISPORTSMAN_BASE = "https://ftleonardwood.isportsman.net";
const authRateLimitStore = new Map();

function ensureDataStore() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DATA_FILE)) {
    const initial = {
      users: [],
      syncByUserId: {}
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2), "utf8");
  }
}

function readDataStore() {
  ensureDataStore();
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed.users || !parsed.syncByUserId) {
      return { users: [], syncByUserId: {} };
    }
    parsed.users.forEach(normalizeUserRecord);
    return parsed;
  } catch {
    return { users: [], syncByUserId: {} };
  }
}

function writeDataStore(data) {
  ensureDataStore();
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function createOneTimeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "");
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

function consumeRateLimit(key, maxAttempts, windowMs) {
  const now = Date.now();
  const existing = authRateLimitStore.get(key);
  if (!existing || now > existing.resetAt) {
    authRateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
    return { blocked: false, remaining: maxAttempts - 1 };
  }

  existing.count += 1;
  authRateLimitStore.set(key, existing);
  if (existing.count > maxAttempts) {
    return { blocked: true, remaining: 0, retryAfterMs: Math.max(0, existing.resetAt - now) };
  }
  return { blocked: false, remaining: Math.max(0, maxAttempts - existing.count) };
}

async function sendTransactionalEmail({ to, subject, html, text = "" }) {
  if (RESEND_API_KEY) {
    try {
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${RESEND_API_KEY}`
        },
        body: JSON.stringify({ from: EMAIL_FROM, to, subject, html, text })
      });

      if (!response.ok) {
        const body = await response.text();
        throw new Error(`Resend API error ${response.status}: ${body}`);
      }
      return { provider: "resend" };
    } catch (err) {
      ensureDataStore();
      const entry = {
        at: new Date().toISOString(),
        to,
        subject,
        html,
        text,
        note: `Resend failed, wrote fallback outbox entry: ${String(err.message || err)}`
      };
      fs.appendFileSync(EMAIL_OUTBOX_FILE, JSON.stringify(entry) + "\n", "utf8");
      return { provider: "outbox-fallback" };
    }
  }

  ensureDataStore();
  const entry = {
    at: new Date().toISOString(),
    to,
    subject,
    html,
    text,
    note: "RESEND_API_KEY not set; email written to outbox log"
  };
  fs.appendFileSync(EMAIL_OUTBOX_FILE, JSON.stringify(entry) + "\n", "utf8");
  return { provider: "outbox" };
}

function getConfigStatus() {
  const usingDefaultAuthSecret = AUTH_SECRET === "change-this-secret-in-production";
  const corsIsWildcard = CORS_ORIGIN === "*";
  const appBaseIsLocalhost = /localhost|127\.0\.0\.1/i.test(APP_BASE_URL);
  const hasAdminKey = Boolean(ADMIN_EXPORT_KEY);
  const hasResendKey = Boolean(RESEND_API_KEY);

  return {
    nodeEnv: NODE_ENV,
    appBaseUrl: APP_BASE_URL,
    corsOrigin: CORS_ORIGIN,
    usingDefaultAuthSecret,
    hasAdminKey,
    hasResendKey,
    appBaseIsLocalhost,
    corsIsWildcard
  };
}

function getProductionConfigErrors() {
  const status = getConfigStatus();
  const errors = [];

  if (status.usingDefaultAuthSecret) {
    errors.push("AUTH_SECRET must be set to a strong random value.");
  }
  if (!status.hasAdminKey) {
    errors.push("ADMIN_EXPORT_KEY must be set.");
  }
  if (status.corsIsWildcard) {
    errors.push("CORS_ORIGIN cannot be '*'. Set it to your domain URL.");
  }
  if (status.appBaseIsLocalhost) {
    errors.push("APP_BASE_URL must be your public https URL, not localhost.");
  }
  if (!status.hasResendKey) {
    errors.push("RESEND_API_KEY must be set for live email verification/reset/report delivery.");
  }

  return errors;
}

function buildVerifyEmailLink(email, token) {
  return `${APP_BASE_URL}/api/auth/verify-email?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
}

function buildResetPasswordLink(email, token) {
  return `${APP_BASE_URL}/?email=${encodeURIComponent(email)}&resetToken=${encodeURIComponent(token)}`;
}

function ensureTemplateStore() {
  if (!fs.existsSync(TEMPLATE_DIR)) {
    fs.mkdirSync(TEMPLATE_DIR, { recursive: true });
  }
}

function ensureDefaultTemplateFile() {
  ensureTemplateStore();
  if (fs.existsSync(USER_TEMPLATE_FILE)) {
    return;
  }

  const defaultTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>User Account Record</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #111; }
    h1 { margin-bottom: 4px; }
    .muted { color: #666; margin-bottom: 16px; }
    table { border-collapse: collapse; width: 100%; max-width: 720px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }
    th { width: 220px; background: #f6f6f6; }
  </style>
</head>
<body>
  <h1>User Account Record</h1>
  <div class="muted">Generated at {{export_generated_at}}</div>

  <table>
    <tr><th>User ID</th><td>{{user_id}}</td></tr>
    <tr><th>Email</th><td>{{email}}</td></tr>
    <tr><th>Full Name</th><td>{{full_name}}</td></tr>
    <tr><th>Created At</th><td>{{created_at}}</td></tr>
    <tr><th>Last Login</th><td>{{last_login_at}}</td></tr>
    <tr><th>Phone</th><td>{{phone}}</td></tr>
    <tr><th>Vehicle</th><td>{{vehicle}}</td></tr>
    <tr><th>Emergency Contact</th><td>{{emergency_contact}}</td></tr>
    <tr><th>Notes</th><td>{{notes}}</td></tr>
    <tr><th>Waypoint Count</th><td>{{waypoint_count}}</td></tr>
    <tr><th>Track Count</th><td>{{track_count}}</td></tr>
  </table>
</body>
</html>`;

  fs.writeFileSync(USER_TEMPLATE_FILE, defaultTemplate, "utf8");
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 2 * 1024 * 1024) {
        reject(new Error("Payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": CORS_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS"
  });
  res.end(JSON.stringify(payload));
}

function base64urlEncode(text) {
  return Buffer.from(text)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64urlDecode(value) {
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64, "base64").toString("utf8");
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function timingSafeEqual(a, b) {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function createToken(payload) {
  const encoded = base64urlEncode(JSON.stringify(payload));
  const signature = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(encoded)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `${encoded}.${signature}`;
}

function verifyToken(token) {
  if (!token || !token.includes(".")) return null;
  const [encoded, signature] = token.split(".");
  const expected = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(encoded)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  if (!timingSafeEqual(signature, expected)) return null;
  try {
    const payload = JSON.parse(base64urlDecode(encoded));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function getAuthUser(req) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return null;
  return verifyToken(token);
}

function toRad(value) {
  return (value * Math.PI) / 180;
}

function distanceMeters(a, b) {
  const earthRadius = 6371000;
  const dLat = toRad(b[0] - a[0]);
  const dLng = toRad(b[1] - a[1]);
  const x =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(a[0])) * Math.cos(toRad(b[0])) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1 - x));
  return earthRadius * c;
}

function calculateTrackDistanceMeters(points) {
  if (!Array.isArray(points) || points.length < 2) return 0;
  let total = 0;
  for (let i = 1; i < points.length; i++) {
    total += distanceMeters(points[i - 1], points[i]);
  }
  return total;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeCsv(value) {
  const text = String(value || "");
  return `"${text.replace(/"/g, '""')}"`;
}

function buildUsersCsv(users = []) {
  const header = [
    "user_id",
    "email",
    "full_name",
    "created_at",
    "last_login_at"
  ].join(",");

  const rows = users.map(u =>
    [
      escapeCsv(u.id),
      escapeCsv(u.email),
      escapeCsv(u.fullName || ""),
      escapeCsv(u.createdAt || ""),
      escapeCsv(u.lastLoginAt || "")
    ].join(",")
  );

  return [header, ...rows].join("\n");
}

function buildUsersOverviewHtml(store) {
  const users = Array.isArray(store?.users) ? store.users : [];
  const rows = users
    .map(user => {
      const sync = store.syncByUserId?.[user.id] || {};
      const profile = sync.profile || {};
      const waypoints = Array.isArray(sync.waypoints) ? sync.waypoints : [];
      const tracks = Array.isArray(sync.tracks) ? sync.tracks : [];

      return `<tr>
        <td>${escapeHtml(user.id || "")}</td>
        <td>${escapeHtml(user.email || "")}</td>
        <td>${escapeHtml(profile.fullName || user.fullName || "")}</td>
        <td>${escapeHtml(user.createdAt || "")}</td>
        <td>${escapeHtml(user.lastLoginAt || "")}</td>
        <td>${escapeHtml(profile.phone || "")}</td>
        <td>${escapeHtml(profile.vehicle || "")}</td>
        <td>${escapeHtml(profile.emergencyContact || "")}</td>
        <td>${escapeHtml(profile.notes || "")}</td>
        <td>${waypoints.length}</td>
        <td>${tracks.length}</td>
      </tr>`;
    })
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>HuntAO Admin Users Overview</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; color: #111; }
    h1 { margin: 0 0 8px 0; }
    .muted { color: #666; margin-bottom: 14px; }
    .wrap { overflow-x: auto; border: 1px solid #ddd; border-radius: 6px; }
    table { border-collapse: collapse; width: 100%; min-width: 1200px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px; vertical-align: top; }
    th { background: #f6f6f6; position: sticky; top: 0; z-index: 1; }
    .empty { padding: 20px; color: #666; }
  </style>
</head>
<body>
  <h1>HuntAO Admin Users Overview</h1>
  <div class="muted">Generated: ${escapeHtml(new Date().toISOString())} • Total users: ${users.length}</div>
  <div class="wrap">
    <table>
      <thead>
        <tr>
          <th>User ID</th>
          <th>Email</th>
          <th>Full Name</th>
          <th>Created At</th>
          <th>Last Login</th>
          <th>Phone</th>
          <th>Vehicle</th>
          <th>Emergency Contact</th>
          <th>Notes</th>
          <th>Waypoints</th>
          <th>Tracks</th>
        </tr>
      </thead>
      <tbody>
        ${rows || '<tr><td class="empty" colspan="11">No users found.</td></tr>'}
      </tbody>
    </table>
  </div>
</body>
</html>`;
}

function fillTemplate(template, fields) {
  return template.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, key) => {
    return escapeHtml(fields[key] ?? "");
  });
}

function getAdminKeyFromRequest(req, url) {
  const keyFromQuery = NODE_ENV === "production" ? "" : String(url.searchParams.get("key") || "");
  const keyFromHeader = String(req.headers["x-admin-key"] || "");
  return keyFromHeader || keyFromQuery;
}

function validateAdminExportKey(req, url) {
  const suppliedKey = getAdminKeyFromRequest(req, url);

  if (!ADMIN_EXPORT_KEY) {
    return { ok: false, status: 503, message: "Admin export is disabled. Set ADMIN_EXPORT_KEY environment variable first." };
  }

  if (!suppliedKey || suppliedKey !== ADMIN_EXPORT_KEY) {
    return { ok: false, status: 403, message: "Forbidden" };
  }

  return { ok: true };
}

function normalizeUserRecord(user) {
  if (typeof user.emailVerified !== "boolean") {
    user.emailVerified = true;
  }
  if (!Object.prototype.hasOwnProperty.call(user, "emailVerificationTokenHash")) {
    user.emailVerificationTokenHash = "";
  }
  if (!Object.prototype.hasOwnProperty.call(user, "emailVerificationExpiresAt")) {
    user.emailVerificationExpiresAt = "";
  }
  if (!Object.prototype.hasOwnProperty.call(user, "passwordResetTokenHash")) {
    user.passwordResetTokenHash = "";
  }
  if (!Object.prototype.hasOwnProperty.call(user, "passwordResetExpiresAt")) {
    user.passwordResetExpiresAt = "";
  }
}

// Helper: serve static files
function serveFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }
    const headers = { 
      "Content-Type": contentType,
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Pragma": "no-cache",
      "Expires": "0"
    };
    res.writeHead(200, headers);
    res.end(data);
  });
}

function isPublicStaticPath(relativePath, absolutePath) {
  const normalizedRelative = relativePath.replace(/\\/g, "/").replace(/^\/+/, "");
  const rootPath = path.resolve(__dirname);
  const targetPath = path.resolve(absolutePath);

  if (!targetPath.startsWith(rootPath + path.sep) && targetPath !== rootPath) {
    return false;
  }

  const blockedPrefixes = ["data/", "templates/"];
  if (blockedPrefixes.some(prefix => normalizedRelative.startsWith(prefix))) {
    return false;
  }

  const blockedFiles = new Set([
    "server.js",
    "package.json",
    "remove_bg.py",
    "Open Admin Users Overview.url"
  ]);
  if (blockedFiles.has(normalizedRelative)) {
    return false;
  }

  return true;
}

// Helper: today's date YYYY-MM-DD
function todayISO() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate()
  ).padStart(2, "0")}`;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  if (req.method === "GET" && pathname === "/api/health") {
    const config = getConfigStatus();
    const productionErrors = NODE_ENV === "production" ? getProductionConfigErrors() : [];
    sendJson(res, 200, {
      ok: productionErrors.length === 0,
      env: NODE_ENV,
      emailDeliveryMode: config.hasResendKey ? "resend" : "outbox-fallback",
      config,
      productionErrors
    });
    return;
  }

  if (pathname.startsWith("/api/") && req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": CORS_ORIGIN,
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS"
    });
    res.end();
    return;
  }

  if (req.method === "POST" && pathname === "/api/auth/signup") {
    try {
      const { email, password, fullName = "" } = await parseBody(req);
      const normalizedEmail = String(email || "").trim().toLowerCase();
      const ip = getClientIp(req);
      const signupLimiter = consumeRateLimit(`signup:${ip}`, AUTH_RATE_LIMIT_MAX, AUTH_RATE_LIMIT_WINDOW_MS);
      if (signupLimiter.blocked) {
        sendJson(res, 429, { error: "Too many attempts. Please try again shortly." });
        return;
      }

      if (!normalizedEmail || !normalizedEmail.includes("@")) {
        sendJson(res, 400, { error: "Valid email is required." });
        return;
      }
      if (!password || String(password).length < 8) {
        sendJson(res, 400, { error: "Password must be at least 8 characters." });
        return;
      }

      const store = readDataStore();
      const existing = store.users.find(u => u.email === normalizedEmail);
      if (existing) {
        sendJson(res, 409, { error: "Account already exists." });
        return;
      }

      const salt = crypto.randomBytes(16).toString("hex");
      const passwordHash = hashPassword(String(password), salt);
      const user = {
        id: crypto.randomUUID(),
        email: normalizedEmail,
        fullName: String(fullName || "").trim(),
        salt,
        passwordHash,
        createdAt: new Date().toISOString(),
        lastLoginAt: new Date().toISOString(),
        emailVerified: false,
        emailVerificationTokenHash: "",
        emailVerificationExpiresAt: "",
        passwordResetTokenHash: "",
        passwordResetExpiresAt: ""
      };

      const verificationToken = createOneTimeToken();
      user.emailVerificationTokenHash = hashToken(verificationToken);
      user.emailVerificationExpiresAt = new Date(Date.now() + VERIFY_TOKEN_TTL_MS).toISOString();

      store.users.push(user);
      store.syncByUserId[user.id] = {
        waypoints: [],
        tracks: [],
        profile: {
          fullName: user.fullName,
          phone: "",
          vehicle: "",
          emergencyContact: "",
          notes: ""
        },
        updatedAt: new Date().toISOString()
      };
      writeDataStore(store);

      const verificationLink = buildVerifyEmailLink(user.email, verificationToken);
      let emailDelivery = "sent";
      try {
        await sendTransactionalEmail({
          to: user.email,
          subject: "Verify your HuntAO account",
          html:
            `<p>Welcome to HuntAO.</p><p>Please verify your email to activate login:</p>` +
            `<p><a href=\"${verificationLink}\">Verify Email</a></p>` +
            `<p>If you did not create this account, you can ignore this email.</p>`,
          text: `Verify your HuntAO email: ${verificationLink}`
        });
      } catch {
        emailDelivery = "failed";
      }

      const token = createToken({
        uid: user.id,
        email: user.email,
        exp: Date.now() + TOKEN_TTL_MS
      });

      sendJson(res, 201, {
        token,
        user: { id: user.id, email: user.email, fullName: user.fullName, emailVerified: user.emailVerified },
        verificationRequired: true,
        emailDelivery,
        ...(NODE_ENV === "production" ? {} : { verificationLink })
      });
    } catch (err) {
      sendJson(res, 400, { error: String(err.message || err) });
    }
    return;
  }

  if (req.method === "POST" && pathname === "/api/auth/login") {
    try {
      const { email, password } = await parseBody(req);
      const normalizedEmail = String(email || "").trim().toLowerCase();
      const ip = getClientIp(req);
      const loginLimiter = consumeRateLimit(`login:${ip}:${normalizedEmail}`, AUTH_RATE_LIMIT_MAX, AUTH_RATE_LIMIT_WINDOW_MS);
      if (loginLimiter.blocked) {
        sendJson(res, 429, { error: "Too many login attempts. Please try again shortly." });
        return;
      }

      const store = readDataStore();
      const user = store.users.find(u => u.email === normalizedEmail);
      if (!user) {
        sendJson(res, 401, { error: "Invalid email or password." });
        return;
      }

      const suppliedHash = hashPassword(String(password || ""), user.salt);
      if (!timingSafeEqual(suppliedHash, user.passwordHash)) {
        sendJson(res, 401, { error: "Invalid email or password." });
        return;
      }

      if (user.emailVerified === false) {
        sendJson(res, 403, { error: "Email not verified. Please verify your email before logging in.", code: "EMAIL_NOT_VERIFIED" });
        return;
      }

      user.lastLoginAt = new Date().toISOString();
      writeDataStore(store);

      const token = createToken({ uid: user.id, email: user.email, exp: Date.now() + TOKEN_TTL_MS });
      sendJson(res, 200, {
        token,
        user: { id: user.id, email: user.email, fullName: user.fullName || "", emailVerified: user.emailVerified !== false }
      });
    } catch (err) {
      sendJson(res, 400, { error: String(err.message || err) });
    }
    return;
  }

  if (req.method === "GET" && pathname === "/api/auth/me") {
    const auth = getAuthUser(req);
    if (!auth) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }

    const store = readDataStore();
    const user = store.users.find(u => u.id === auth.uid);
    if (!user) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }

    sendJson(res, 200, {
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName || "",
        emailVerified: user.emailVerified !== false
      }
    });
    return;
  }

  if (req.method === "POST" && pathname === "/api/auth/request-verification") {
    try {
      const auth = getAuthUser(req);
      const body = await parseBody(req);
      const normalizedEmail = String(body.email || "").trim().toLowerCase();
      const store = readDataStore();

      let user = null;
      if (auth) {
        user = store.users.find(u => u.id === auth.uid) || null;
      } else if (normalizedEmail) {
        user = store.users.find(u => u.email === normalizedEmail) || null;
      }

      if (!user) {
        sendJson(res, 200, { ok: true, message: "If this email exists, a verification message has been sent." });
        return;
      }

      if (user.emailVerified === true) {
        sendJson(res, 200, { ok: true, message: "Email is already verified." });
        return;
      }

      const token = createOneTimeToken();
      user.emailVerificationTokenHash = hashToken(token);
      user.emailVerificationExpiresAt = new Date(Date.now() + VERIFY_TOKEN_TTL_MS).toISOString();
      writeDataStore(store);

      const verificationLink = buildVerifyEmailLink(user.email, token);
      let emailDelivery = "sent";
      try {
        await sendTransactionalEmail({
          to: user.email,
          subject: "Verify your HuntAO account",
          html: `<p>Please verify your email:</p><p><a href=\"${verificationLink}\">Verify Email</a></p>`,
          text: `Verify your HuntAO email: ${verificationLink}`
        });
      } catch {
        emailDelivery = "failed";
      }

      sendJson(res, 200, {
        ok: true,
        message: "Verification email sent.",
        emailDelivery,
        ...(NODE_ENV === "production" ? {} : { verificationLink })
      });
    } catch (err) {
      sendJson(res, 400, { error: String(err.message || err) });
    }
    return;
  }

  if (req.method === "GET" && pathname === "/api/auth/verify-email") {
    const email = String(url.searchParams.get("email") || "").trim().toLowerCase();
    const token = String(url.searchParams.get("token") || "").trim();

    if (!email || !token) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      res.end("<h2>Invalid verification link.</h2>");
      return;
    }

    const store = readDataStore();
    const user = store.users.find(u => u.email === email);
    if (!user || !user.emailVerificationTokenHash) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      res.end("<h2>Verification link is invalid or expired.</h2>");
      return;
    }

    const tokenHash = hashToken(token);
    const expiresAt = Date.parse(user.emailVerificationExpiresAt || "");
    if (!timingSafeEqual(tokenHash, user.emailVerificationTokenHash) || Number.isNaN(expiresAt) || Date.now() > expiresAt) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
      res.end("<h2>Verification link is invalid or expired.</h2>");
      return;
    }

    user.emailVerified = true;
    user.emailVerificationTokenHash = "";
    user.emailVerificationExpiresAt = "";
    writeDataStore(store);

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end("<h2>Email verified successfully.</h2><p>You can return to HuntAO and log in.</p>");
    return;
  }

  if (req.method === "POST" && pathname === "/api/auth/request-password-reset") {
    try {
      const ip = getClientIp(req);
      const limiter = consumeRateLimit(`reset:${ip}`, AUTH_RATE_LIMIT_MAX, AUTH_RATE_LIMIT_WINDOW_MS);
      if (limiter.blocked) {
        sendJson(res, 429, { error: "Too many attempts. Please try again shortly." });
        return;
      }

      const { email } = await parseBody(req);
      const normalizedEmail = String(email || "").trim().toLowerCase();
      const store = readDataStore();
      const user = store.users.find(u => u.email === normalizedEmail);

      if (!user) {
        sendJson(res, 200, { ok: true, message: "If this email exists, a reset link has been sent." });
        return;
      }

      const token = createOneTimeToken();
      user.passwordResetTokenHash = hashToken(token);
      user.passwordResetExpiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString();
      writeDataStore(store);

      const resetLink = buildResetPasswordLink(user.email, token);
      let emailDelivery = "sent";
      try {
        await sendTransactionalEmail({
          to: user.email,
          subject: "Reset your HuntAO password",
          html: `<p>You requested a password reset.</p><p><a href=\"${resetLink}\">Reset Password</a></p>`,
          text: `Reset your HuntAO password: ${resetLink}`
        });
      } catch {
        emailDelivery = "failed";
      }

      sendJson(res, 200, {
        ok: true,
        message: "If this email exists, a reset link has been sent.",
        emailDelivery,
        ...(NODE_ENV === "production" ? {} : { resetLink })
      });
    } catch (err) {
      sendJson(res, 400, { error: String(err.message || err) });
    }
    return;
  }

  if (req.method === "POST" && pathname === "/api/auth/reset-password") {
    try {
      const { email, token, newPassword } = await parseBody(req);
      const normalizedEmail = String(email || "").trim().toLowerCase();

      if (!normalizedEmail || !token) {
        sendJson(res, 400, { error: "Email and reset token are required." });
        return;
      }
      if (!newPassword || String(newPassword).length < 8) {
        sendJson(res, 400, { error: "New password must be at least 8 characters." });
        return;
      }

      const store = readDataStore();
      const user = store.users.find(u => u.email === normalizedEmail);
      if (!user || !user.passwordResetTokenHash) {
        sendJson(res, 400, { error: "Invalid or expired reset token." });
        return;
      }

      const tokenHash = hashToken(token);
      const expiresAt = Date.parse(user.passwordResetExpiresAt || "");
      if (!timingSafeEqual(tokenHash, user.passwordResetTokenHash) || Number.isNaN(expiresAt) || Date.now() > expiresAt) {
        sendJson(res, 400, { error: "Invalid or expired reset token." });
        return;
      }

      const salt = crypto.randomBytes(16).toString("hex");
      user.salt = salt;
      user.passwordHash = hashPassword(String(newPassword), salt);
      user.passwordResetTokenHash = "";
      user.passwordResetExpiresAt = "";
      writeDataStore(store);

      sendJson(res, 200, { ok: true, message: "Password has been reset. You can now log in." });
    } catch (err) {
      sendJson(res, 400, { error: String(err.message || err) });
    }
    return;
  }

  if (req.method === "POST" && pathname === "/api/feedback") {
    try {
      const ip = getClientIp(req);
      const limiter = consumeRateLimit(`feedback:${ip}`, 20, 15 * 60 * 1000);
      if (limiter.blocked) {
        sendJson(res, 429, { error: "Too many feedback submissions. Please try again later." });
        return;
      }

      const { message, contactEmail = "", pageUrl = "", userAgent = "" } = await parseBody(req);
      const cleanMessage = String(message || "").trim();
      const cleanContact = String(contactEmail || "").trim();

      if (!cleanMessage || cleanMessage.length < 5) {
        sendJson(res, 400, { error: "Please provide a short description of the problem." });
        return;
      }

      const html = `
        <h2>HuntAO Beta Problem Report</h2>
        <p><strong>Submitted:</strong> ${escapeHtml(new Date().toISOString())}</p>
        <p><strong>Contact Email:</strong> ${escapeHtml(cleanContact || "Not provided")}</p>
        <p><strong>Page URL:</strong> ${escapeHtml(String(pageUrl || ""))}</p>
        <p><strong>User Agent:</strong> ${escapeHtml(String(userAgent || ""))}</p>
        <hr />
        <p><strong>Report:</strong></p>
        <pre style="white-space: pre-wrap; font-family: Arial, sans-serif;">${escapeHtml(cleanMessage)}</pre>
      `;

      const text = [
        "HuntAO Beta Problem Report",
        `Submitted: ${new Date().toISOString()}`,
        `Contact Email: ${cleanContact || "Not provided"}`,
        `Page URL: ${String(pageUrl || "")}`,
        `User Agent: ${String(userAgent || "")}`,
        "",
        "Report:",
        cleanMessage
      ].join("\n");

      const delivery = await sendTransactionalEmail({
        to: FEEDBACK_TO_EMAIL,
        subject: "[HuntAO] Beta Problem Report",
        html,
        text
      });

      sendJson(res, 200, {
        ok: true,
        message: "Report submitted. Thank you!",
        delivery: delivery.provider
      });
    } catch (err) {
      sendJson(res, 500, { error: "Could not submit report. Please try again." });
    }
    return;
  }

  if (req.method === "GET" && pathname === "/api/admin/users.csv") {
    const keyValidation = validateAdminExportKey(req, url);
    if (!keyValidation.ok) {
      sendJson(res, keyValidation.status, { error: keyValidation.message });
      return;
    }

    const store = readDataStore();
    const csv = buildUsersCsv(store.users || []);

    res.writeHead(200, {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename=users-${new Date().toISOString().slice(0, 10)}.csv`,
      "Cache-Control": "no-store"
    });
    res.end(csv);
    return;
  }

  if (req.method === "GET" && pathname === "/api/admin/users-overview") {
    const keyValidation = validateAdminExportKey(req, url);
    if (!keyValidation.ok) {
      sendJson(res, keyValidation.status, { error: keyValidation.message });
      return;
    }

    const store = readDataStore();
    const html = buildUsersOverviewHtml(store);

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    });
    res.end(html);
    return;
  }

  if (req.method === "GET" && pathname === "/api/admin/user-document") {
    const keyValidation = validateAdminExportKey(req, url);
    if (!keyValidation.ok) {
      sendJson(res, keyValidation.status, { error: keyValidation.message });
      return;
    }

    const userId = String(url.searchParams.get("userId") || "").trim();
    const email = String(url.searchParams.get("email") || "").trim().toLowerCase();

    if (!userId && !email) {
      sendJson(res, 400, { error: "Provide userId or email query parameter." });
      return;
    }

    const store = readDataStore();
    const user = userId
      ? store.users.find(u => u.id === userId)
      : store.users.find(u => String(u.email || "").toLowerCase() === email);

    if (!user) {
      sendJson(res, 404, { error: "User not found." });
      return;
    }

    ensureDefaultTemplateFile();
    let template;
    try {
      template = fs.readFileSync(USER_TEMPLATE_FILE, "utf8");
    } catch {
      sendJson(res, 500, { error: "Could not read template file." });
      return;
    }

    const sync = store.syncByUserId[user.id] || {};
    const profile = sync.profile || {};
    const waypoints = Array.isArray(sync.waypoints) ? sync.waypoints : [];
    const tracks = Array.isArray(sync.tracks) ? sync.tracks : [];

    const fields = {
      export_generated_at: new Date().toISOString(),
      user_id: user.id,
      email: user.email || "",
      full_name: profile.fullName || user.fullName || "",
      created_at: user.createdAt || "",
      last_login_at: user.lastLoginAt || "",
      phone: profile.phone || "",
      vehicle: profile.vehicle || "",
      emergency_contact: profile.emergencyContact || "",
      notes: profile.notes || "",
      waypoint_count: String(waypoints.length),
      track_count: String(tracks.length)
    };

    const content = fillTemplate(template, fields);
    const safeEmail = String(user.email || "user").replace(/[^a-zA-Z0-9._-]/g, "_");

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Disposition": `attachment; filename=user-record-${safeEmail}-${new Date().toISOString().slice(0, 10)}.html`,
      "Cache-Control": "no-store"
    });
    res.end(content);
    return;
  }

  if (req.method === "GET" && pathname === "/api/sync") {
    const auth = getAuthUser(req);
    if (!auth) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }

    const store = readDataStore();
    const userSync = store.syncByUserId[auth.uid] || {
      waypoints: [],
      tracks: [],
      profile: {},
      updatedAt: new Date().toISOString()
    };
    sendJson(res, 200, userSync);
    return;
  }

  if (req.method === "PUT" && pathname === "/api/sync") {
    const auth = getAuthUser(req);
    if (!auth) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }

    try {
      const { waypoints = [], tracks = [], profile = {} } = await parseBody(req);
      const safeWaypoints = Array.isArray(waypoints)
        ? waypoints.slice(0, 2000).map(wp => ({
            id: String(wp.id || crypto.randomUUID()),
            lat: Number(wp.lat),
            lng: Number(wp.lng),
            type: String(wp.type || "generic"),
            name: String(wp.name || ""),
            createdAt: String(wp.createdAt || new Date().toISOString())
          }))
        : [];

      const safeTracks = Array.isArray(tracks)
        ? tracks.slice(0, 500).map(track => ({
            id: String(track.id || crypto.randomUUID()),
            name: String(track.name || "Track"),
            points: Array.isArray(track.points)
              ? track.points.slice(0, 5000).map(p => [Number(p[0]), Number(p[1])])
              : [],
            createdAt: String(track.createdAt || new Date().toISOString())
          }))
        : [];

      const safeProfile = {
        fullName: String(profile.fullName || "").slice(0, 120),
        phone: String(profile.phone || "").slice(0, 60),
        vehicle: String(profile.vehicle || "").slice(0, 120),
        emergencyContact: String(profile.emergencyContact || "").slice(0, 120),
        notes: String(profile.notes || "").slice(0, 1000)
      };

      const store = readDataStore();
      store.syncByUserId[auth.uid] = {
        waypoints: safeWaypoints,
        tracks: safeTracks,
        profile: safeProfile,
        updatedAt: new Date().toISOString()
      };
      writeDataStore(store);

      sendJson(res, 200, { ok: true, updatedAt: store.syncByUserId[auth.uid].updatedAt });
    } catch (err) {
      sendJson(res, 400, { error: String(err.message || err) });
    }
    return;
  }

  if (req.method === "GET" && pathname === "/api/tracking-document") {
    const auth = getAuthUser(req);
    if (!auth) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }

    const store = readDataStore();
    const user = store.users.find(u => u.id === auth.uid);
    const sync = store.syncByUserId[auth.uid] || { waypoints: [], tracks: [], profile: {} };
    const profile = sync.profile || {};
    const waypoints = Array.isArray(sync.waypoints) ? sync.waypoints : [];
    const tracks = Array.isArray(sync.tracks) ? sync.tracks : [];

    const totalDistanceMeters = tracks.reduce(
      (sum, t) => sum + calculateTrackDistanceMeters(Array.isArray(t.points) ? t.points : []),
      0
    );

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>HuntAO Tracking Document</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #111; }
    h1 { margin-bottom: 8px; }
    h2 { margin-top: 24px; border-bottom: 1px solid #ddd; padding-bottom: 6px; }
    .muted { color: #555; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { border: 1px solid #ddd; padding: 8px; font-size: 13px; text-align: left; }
    th { background: #f5f5f5; }
  </style>
</head>
<body>
  <h1>HuntAO Tracking Document</h1>
  <div class="muted">Generated: ${escapeHtml(new Date().toLocaleString())}</div>

  <h2>User</h2>
  <table>
    <tr><th>Account Email</th><td>${escapeHtml(user?.email || auth.email || "")}</td></tr>
    <tr><th>Full Name</th><td>${escapeHtml(profile.fullName || user?.fullName || "")}</td></tr>
    <tr><th>Phone</th><td>${escapeHtml(profile.phone || "")}</td></tr>
    <tr><th>Vehicle</th><td>${escapeHtml(profile.vehicle || "")}</td></tr>
    <tr><th>Emergency Contact</th><td>${escapeHtml(profile.emergencyContact || "")}</td></tr>
    <tr><th>Notes</th><td>${escapeHtml(profile.notes || "")}</td></tr>
  </table>

  <h2>Summary</h2>
  <table>
    <tr><th>Waypoint Count</th><td>${waypoints.length}</td></tr>
    <tr><th>Track Count</th><td>${tracks.length}</td></tr>
    <tr><th>Total Tracked Distance</th><td>${(totalDistanceMeters / 1609.344).toFixed(2)} miles</td></tr>
  </table>

  <h2>Waypoints</h2>
  <table>
    <thead>
      <tr><th>Name</th><th>Type</th><th>Latitude</th><th>Longitude</th><th>Created</th></tr>
    </thead>
    <tbody>
      ${
        waypoints.length
          ? waypoints
              .map(
                wp =>
                  `<tr><td>${escapeHtml(wp.name || "")}</td><td>${escapeHtml(wp.type || "")}</td><td>${Number(wp.lat).toFixed(5)}</td><td>${Number(wp.lng).toFixed(5)}</td><td>${escapeHtml(wp.createdAt || "")}</td></tr>`
              )
              .join("")
          : '<tr><td colspan="5">No waypoints available.</td></tr>'
      }
    </tbody>
  </table>
</body>
</html>`;

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Disposition": `attachment; filename=tracking-document-${new Date().toISOString().slice(0, 10)}.html`,
      "Access-Control-Allow-Origin": CORS_ORIGIN,
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS"
    });
    res.end(html);
    return;
  }

  // ----------------------------------------------------
  // API: Proxy iSportsman area status (normalized format)
  // ----------------------------------------------------
  if (req.method === "GET" && pathname === "/api/areas") {
    try {
      const payload = {
        activity: "",
        area: "",
        category: "",
        date: todayISO(),
        end_date: "",
        parent_area: "",
        status: ""
      };

      const apiUrl = `${ISPORTSMAN_BASE}/api/area/query?cacheBuster=${Date.now()}`;

      const r = await fetch(apiUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json, text/plain, */*",
          "Origin": ISPORTSMAN_BASE,
          "Referer": `${ISPORTSMAN_BASE}/areas.aspx`,
          "User-Agent": "Mozilla/5.0"
        },
        body: JSON.stringify(payload)
      });

      const text = await r.text();

      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch (e) {
        parsed = null;
      }

      let raw = [];
      if (parsed && Array.isArray(parsed.data)) {
        raw = parsed.data;
      }

      // ⭐ Normalize to the format your gpkg + frontend expect
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
      });

      const response = { data: raw };
      res.end(JSON.stringify(response));
    } catch (err) {
      console.error("Proxy error:", err);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: String(err) }));
    }
    return;
  }

  // ----------------------------------------------------
  // Serve index.html
  // ----------------------------------------------------
  if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
    return serveFile(res, path.join(__dirname, "index.html"), "text/html; charset=utf-8");
  }

  // ----------------------------------------------------
  // Serve static files
  // ----------------------------------------------------
  const relativePath = pathname.replace(/^\/+/, "");
  const filePath = path.join(__dirname, relativePath);
  if (isPublicStaticPath(relativePath, filePath) && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath).toLowerCase();
    const types = {
      ".html": "text/html",
      ".js": "application/javascript",
      ".css": "text/css",
      ".json": "application/json",
      ".geojson": "application/geo+json",
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".svg": "image/svg+xml",
      ".webmanifest": "application/manifest+json"
    };
    return serveFile(res, filePath, types[ext] || "application/octet-stream");
  }

  // 404 fallback
  res.writeHead(404);
  res.end("Not found");
});

// Start server
server.listen(PORT, () => {
  ensureDataStore();
  ensureDefaultTemplateFile();
  if (NODE_ENV === "production") {
    const errors = getProductionConfigErrors();
    if (errors.length) {
      throw new Error(`Production configuration invalid:\n- ${errors.join("\n- ")}`);
    }
  }
  console.log(`HuntBase server running at http://localhost:${PORT}`);
});