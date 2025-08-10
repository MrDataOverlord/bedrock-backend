import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";

import { prisma } from "./db.js";
import {
  signJwt, verifyJwt, createUserWithOrg, authenticate,
  newTotpSecret, verifyTotp
} from "./auth.js";

const app = express();

// IMPORTANT: trust Render's proxy BEFORE any middleware (fixes express-rate-limit IP warning)
app.set("trust proxy", 1);

// ---- middleware ----
app.use(helmet());
app.use(express.json({ limit: "256kb" }));

// CORS allowlist via env (empty = allow any origin; tighten later)
const ALLOWED = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED.length === 0 || ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  }
}));

// basic rate limit
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

// ---- health ----
app.get("/healthz", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ---- friendly root page ----
app.get("/", (_req, res) => {
  res.type("html").send(`
    <h1>Bedrock Backend</h1>
    <p>Status: <a href="/healthz">/healthz</a></p>
    <p>POST <code>/devices/register</code> with JSON:</p>
    <pre>{
  "platform": "android",
  "push_token": "TEST-TOKEN-123"
}</pre>
    <p>Auth:</p>
    <ul>
      <li>POST <code>/auth/signup</code> {"email","password"}</li>
      <li>POST <code>/auth/login</code> {"email","password"}</li>
      <li>POST <code>/auth/totp/enable</code> (Bearer token)</li>
      <li>POST <code>/auth/totp/verify</code> {"code"}</li>
      <li>GET  <code>/entitlements</code> (Bearer token)</li>
    </ul>
  `);
});

// ---- devices ----
app.post("/devices/register", async (req, res) => {
  try {
    const { platform, push_token, user_id, org_id } = req.body || {};
    if (!platform || !push_token) {
      return res.status(400).json({ error: "platform and push_token required" });
    }
    const device = await prisma.device.create({
      data: {
        platform,
        pushToken: push_token,
        userId: user_id || null,
        orgId: org_id || null
      }
    });
    res.json({ ok: true, id: device.id });
  } catch (e) {
    console.error("devices/register error", e);
    res.status(500).json({ error: "failed to register device" });
  }
});

// ---- auth: signup ----
app.post("/auth/signup", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });
  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: "email already in use" });

    const { user, org } = await createUserWithOrg(email, password);
    const access  = signJwt({ uid: user.id, orgId: org.id, role: "owner" }, "15m");
    const refresh = signJwt({ uid: user.id, orgId: org.id, type: "refresh" }, "30d");
    res.json({ ok: true, access, refresh });
  } catch (e) {
    console.error("signup error", e);
    res.status(500).json({ error: "signup failed" });
  }
});

// ---- auth: login ----
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });

  const user = await authenticate(email, password);
  if (!user) return res.status(401).json({ error: "invalid credentials" });

  const member = await prisma.member.findFirst({ where: { userId: user.id } });
  const orgId  = member?.orgId || null;

  const access  = signJwt({ uid: user.id, orgId, role: member?.role || "owner" }, "15m");
  const refresh = signJwt({ uid: user.id, orgId, type: "refresh" }, "30d");
  res.json({ ok: true, access, refresh, has2fa: !!user.totpSecret });
});

// ---- 2FA: enable ----
app.post("/auth/totp/enable", async (req, res) => {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    const payload = verifyJwt(token);
    const { secret, otpauth } = newTotpSecret();
    await prisma.user.update({ where: { id: payload.uid }, data: { totpSecret: secret } });
    res.json({ ok: true, otpauth });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

// ---- 2FA: verify ----
app.post("/auth/totp/verify", async (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: "code required" });
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    const payload = verifyJwt(token);
    const user = await prisma.user.findUnique({ where: { id: payload.uid } });
    if (!user?.totpSecret) return res.status(400).json({ error: "no totp pending" });

    const ok = verifyTotp(user.totpSecret, code);
    if (!ok) return res.status(401).json({ error: "invalid code" });
    res.json({ ok: true });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

// ---- entitlements (72h grace; premium=false for now) ----
app.get("/entitlements", async (req, res) => {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    const payload = verifyJwt(token);

    const entitlement = {
      uid: payload.uid,
      orgId: payload.orgId,
      features: ["basic"], // flip to ["premium"] after Stripe/PayPal hook
      expiry: Date.now() + 72 * 60 * 60 * 1000
    };
    const signed = signJwt({ ent: entitlement }, "72h");
    res.json({ ok: true, entitlement: signed });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`API up on :${port}`));
