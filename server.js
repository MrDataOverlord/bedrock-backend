import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import bodyParser from "body-parser";
import Stripe from "stripe";

import { prisma } from "./db.js";
import {
  signJwt, verifyJwt, createUserWithOrg, authenticate,
  newTotpSecret, verifyTotp
} from "./auth.js";

const app = express();

// ---------- helpers ----------
const getToken = (req) =>
  String(req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "") // case-insensitive, trims extra spaces
    .trim();

// ---------- proxy & security ----------
app.set("trust proxy", 1);
app.use(helmet());

// ---------- stripe webhook must get RAW body BEFORE express.json ----------
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "", { apiVersion: "2024-06-20" });
app.post("/webhooks/stripe", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  try {
    const sig = req.headers["stripe-signature"];
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);

    if (event.type === "checkout.session.completed" || event.type === "invoice.payment_succeeded") {
      const obj = event.data.object;
      const orgId = obj.metadata?.orgId;
      if (orgId) {
        const subId = `stripe_${obj.subscription || obj.id}`;
        const unix = (obj.current_period_end || obj.period_end || Math.floor(Date.now() / 1000));
        await prisma.subscription.upsert({
          where: { id: subId },
          update: { status: "active", currentPeriodEnd: new Date(unix * 1000) },
          create: { id: subId, orgId, provider: "stripe", status: "active", currentPeriodEnd: new Date(unix * 1000) }
        });
      }
    }

    if (event.type === "customer.subscription.updated" || event.type === "customer.subscription.deleted") {
      const sub = event.data.object;
      await prisma.subscription.updateMany({
        where: { id: `stripe_${sub.id}` },
        data: { status: sub.status, currentPeriodEnd: new Date(sub.current_period_end * 1000) }
      });
    }

    res.json({ received: true });
  } catch (e) {
    console.error("stripe webhook error:", e?.message || e);
    res.status(400).send("Webhook Error");
  }
});

// ---------- normal JSON, CORS, rate limit ----------
app.use(express.json({ limit: "256kb" }));

const ALLOWED = (process.env.CORS_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED.length === 0 || ALLOWED.includes(origin)) return cb(null, true);
    cb(new Error("Not allowed by CORS"));
  }
}));

app.use(rateLimit({ windowMs: 60_000, max: 60 }));

// ---------- health & root ----------
app.get("/healthz", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));
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
    <p>Billing (test/dev):</p>
    <ul>
      <li>POST <code>/billing/force-active</code> (Bearer token) → marks org premium</li>
      <li>POST <code>/webhooks/stripe</code> (Stripe) → updates subscription</li>
    </ul>
  `);
});

// ---------- devices ----------
app.post("/devices/register", async (req, res) => {
  try {
    const { platform, push_token, user_id, org_id } = req.body || {};
    if (!platform || !push_token) return res.status(400).json({ error: "platform and push_token required" });
    const device = await prisma.device.create({
      data: { platform, pushToken: push_token, userId: user_id || null, orgId: org_id || null }
    });
    res.json({ ok: true, id: device.id });
  } catch (e) {
    console.error("devices/register error", e);
    res.status(500).json({ error: "failed to register device" });
  }
});

// ---------- auth: signup ----------
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

// ---------- auth: login ----------
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

// ---------- 2FA TOTP ----------
app.post("/auth/totp/enable", async (req, res) => {
  try {
    const token = getToken(req);
    const payload = verifyJwt(token);
    const { secret, otpauth } = newTotpSecret();
    await prisma.user.update({ where: { id: payload.uid }, data: { totpSecret: secret } });
    res.json({ ok: true, otpauth });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

app.post("/auth/totp/verify", async (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: "code required" });
  try {
    const token = getToken(req);
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

// ---------- billing: manual toggle (dev/testing) ----------
app.post("/billing/force-active", async (req, res) => {
  try {
    const token = getToken(req);
    const { orgId } = verifyJwt(token);
    await prisma.subscription.upsert({
      where: { id: `manual_${orgId}` },
      update: { status: "active" },
      create: { id: `manual_${orgId}`, orgId, provider: "manual", status: "active" }
    });
    res.json({ ok: true });
  } catch (e) {
    console.error("force-active error", e);
    res.status(401).json({ error: "invalid token" });
  }
});

// ---------- entitlements (premium-aware) ----------
app.get("/entitlements", async (req, res) => {
  try {
    const token = getToken(req);
    const payload = verifyJwt(token);

    const subs = await prisma.subscription.findMany({
      where: { orgId: payload.orgId, status: "active" }
    });
    const isPremium = subs.length > 0;

    const entitlement = {
      uid: payload.uid,
      orgId: payload.orgId,
      features: isPremium ? ["premium"] : ["basic"],
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
