
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { prisma } from "./db.js";
import { signJwt, verifyJwt, createUserWithOrg, authenticate, newTotpSecret, verifyTotp } from "./auth.js";


const app = express();
app.use(helmet());
app.use(express.json({ limit: "256kb" }));

const ALLOWED = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED.length === 0 || ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  }
}));
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

app.get("/healthz", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

app.post("/devices/register", async (req, res) => {
  const { platform, push_token, user_id, org_id } = req.body || {};
  if (!platform || !push_token) return res.status(400).json({ error: "platform and push_token required" });
  const device = await prisma.device.create({
    data: {
      platform,
      pushToken: push_token,
      userId: user_id || null,
      orgId: org_id || null
    }
  });
  res.json({ ok: true, id: device.id });
});

const port = process.env.PORT || 8080;

app.get("/", (_req, res) => {
  res.type("html").send(`
    <h1>Bedrock Backend</h1>
    <p>Status: <a href="/healthz">/healthz</a></p>
    <p>POST <code>/devices/register</code> with JSON:
    <pre>{
  "platform": "android",
  "push_token": "TEST-TOKEN-123"
}</pre>
  `);
});

// Auth: signup
app.post("/auth/signup", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });
  try {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: "email already in use" });

    const { user, org } = await createUserWithOrg(email, password);
    const access = signJwt({ uid: user.id, orgId: org.id, role: "owner" }, "15m");
    const refresh = signJwt({ uid: user.id, orgId: org.id, type: "refresh" }, "30d");
    res.json({ ok: true, access, refresh });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "signup failed" });
  }
});

// Auth: login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });

  const user = await authenticate(email, password);
  if (!user) return res.status(401).json({ error: "invalid credentials" });

  // Find owner org via membership (simplified)
  const member = await prisma.member.findFirst({ where: { userId: user.id } });
  const orgId = member?.orgId || null;

  const access = signJwt({ uid: user.id, orgId, role: member?.role || "owner" }, "15m");
  const refresh = signJwt({ uid: user.id, orgId, type: "refresh" }, "30d");
  res.json({ ok: true, access, refresh, has2fa: !!user.totpSecret });
});

// TOTP: enable (returns secret + otpauth URL)
app.post("/auth/totp/enable", async (req, res) => {
  try {
    const { authorization } = req.headers;
    if (!authorization) return res.status(401).json({ error: "no auth" });
    const token = authorization.replace("Bearer ", "");
    const payload = verifyJwt(token);

    const { secret, otpauth } = newTotpSecret();
    await prisma.user.update({ where: { id: payload.uid }, data: { totpSecret: secret } });
    res.json({ ok: true, otpauth });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

// TOTP: verify (user submits 6-digit code from app)
app.post("/auth/totp/verify", async (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: "code required" });

  try {
    const { authorization } = req.headers;
    const token = authorization?.replace("Bearer ", "");
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

// Entitlements (72h grace token for premium gating)
app.get("/entitlements", async (req, res) => {
  try {
    const { authorization } = req.headers;
    const token = authorization?.replace("Bearer ", "");
    const payload = verifyJwt(token);

    // TODO: look up subscription status later; for now premium=false
    const entitlement = {
      uid: payload.uid,
      orgId: payload.orgId,
      features: ["basic"],  // later push ["premium"]
      expiry: Date.now() + 72 * 60 * 60 * 1000
    };

    // Sign as a compact token (reuse JWT for simplicity)
    const signed = signJwt({ ent: entitlement }, "72h");
    res.json({ ok: true, entitlement: signed });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

app.listen(port, () => console.log(`API up on :${port}`));
