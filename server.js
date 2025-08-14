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
app.set("trust proxy", 1);
app.use(helmet());

// ---------- Stripe webhook (raw body) BEFORE express.json ----------
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "", { apiVersion: "2024-06-20" });

app.post("/webhooks/stripe", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  let event;
  try {
    const sig = req.headers["stripe-signature"];
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error("stripe webhook error (verify):", e?.message || e);
    return res.status(400).send("Webhook Error");
  }

  try {
    const upsertActive = async ({ subId, orgId, periodEndSec }) => {
      if (!orgId || !subId || !periodEndSec) return;
      const when = new Date(periodEndSec * 1000);
      await prisma.subscription.upsert({
        where: { id: subId },
        update: { status: "active", currentPeriodEnd: when },
        create: { id: subId, orgId, provider: "stripe", status: "active", currentPeriodEnd: when }
      });
    };

    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const orgId = session.metadata?.orgId;
        if (orgId && session.subscription) {
          const sub = await stripe.subscriptions.retrieve(session.subscription);
          await upsertActive({
            subId: `stripe_${sub.id}`,
            orgId,
            periodEndSec: sub.current_period_end
          });
        }
        break;
      }
      case "invoice.payment_succeeded": {
        const invoice = event.data.object;
        const orgId = invoice.metadata?.orgId || invoice.customer;
        const line = invoice.lines?.data?.[0];
        const periodEndSec = line?.period?.end || null;
        if (orgId && invoice.subscription && periodEndSec) {
          await upsertActive({
            subId: `stripe_${invoice.subscription}`,
            orgId,
            periodEndSec
          });
        }
        break;
      }
      case "customer.subscription.updated":
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        await prisma.subscription.updateMany({
          where: { id: `stripe_${sub.id}` },
          data: {
            status: sub.status,
            currentPeriodEnd: new Date((sub.current_period_end || Date.now() / 1000) * 1000)
          }
        });
        break;
      }
    }
    res.json({ received: true });
  } catch (e) {
    console.error("stripe webhook error (handler):", e?.message || e);
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

// ---------- Stripe Checkout (subscription) ----------
app.post("/billing/checkout", async (req, res) => {
  try {
    const token = getToken(req);
    const { orgId } = verifyJwt(token);

    const price = process.env.STRIPE_PRICE_PREMIUM;
    if (!price) throw new Error("Missing STRIPE_PRICE_PREMIUM env var");

    const base = (process.env.APP_DOMAIN?.match(/^https?:\/\//)
      ? process.env.APP_DOMAIN
      : `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price, quantity: 1 }],
      success_url: `${base}/?billing=success`,
      cancel_url: `${base}/?billing=canceled`,
      metadata: { orgId },
      subscription_data: { metadata: { orgId } },
    });

    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("checkout error", e.message || e);
    res.status(400).json({ error: "checkout failed", detail: e.message || String(e) });
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
