// server.js
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// ---------- env ----------
const {
  PORT = 8080,
  CORS_ORIGINS = "",
  JWT_SECRET = "dev_jwt_secret_change_me",
  APP_DOMAIN = "",                      // e.g. https://bedrock-backend-xxxx.onrender.com
  STRIPE_SECRET_KEY = "",
  STRIPE_PRICE_PREMIUM = "",            // e.g. price_xxx
  STRIPE_WEBHOOK_SECRET = "",           // from Stripe endpoint “Signing secret”
} = process.env;

// If APP_DOMAIN not provided, guess from Render request at runtime (safe fallback below)
const appBase = APP_DOMAIN || "";

// ---------- helpers ----------
function signJwt(payload, expiresIn = "15m") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}
function verifyJwt(token) {
  return jwt.verify(token, JWT_SECRET);
}
function unixToDate(unix) {
  if (!unix || Number.isNaN(Number(unix))) return undefined;
  const d = new Date(Number(unix) * 1000);
  return isNaN(d.getTime()) ? undefined : d;
}
function pickDefined(obj) {
  // remove undefined keys before passing to Prisma
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined));
}

app.post(
  "/webhooks/stripe",
  bodyParser.raw({ type: "*/*" }),   // ⟵ catch any json content-type
  async (req, res) => {
    try {
      const sig = req.headers["stripe-signature"];
      if (!sig) throw new Error("Missing Stripe-Signature header");
      // req.body MUST be a Buffer
      if (!Buffer.isBuffer(req.body)) throw new Error("Webhook body is not a Buffer");

      const event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        STRIPE_WEBHOOK_SECRET
      );

      // … (rest of your event handling stays the same)
      res.json({ received: true });
    } catch (e) {
      console.error("stripe webhook error (verify):", e?.message || e);
      res.status(400).send("Webhook Error");
    }
  }
);

// ---------- app ----------
const app = express();
app.set("trust proxy", 1); // avoids express-rate-limit proxy warning on Render
app.use(helmet());

// CORS
const ALLOWED = CORS_ORIGINS.split(",").map(s => s.trim()).filter(Boolean);
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || ALLOWED.length === 0 || ALLOWED.includes(origin)) return cb(null, true);
      cb(new Error("Not allowed by CORS"));
    },
  })
);

// Rate limit
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

// ------ STRIPE: webhook MUST be declared BEFORE express.json() ------
const stripe = new Stripe(STRIPE_SECRET_KEY || "", { apiVersion: "2024-06-20" });

app.post(
  "/webhooks/stripe",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const sig = req.headers["stripe-signature"];
      const event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);

      // 1) Checkout completed → activate/record subscription
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const orgId = session?.metadata?.orgId;
        const subId = session?.subscription; // string
        const end = unixToDate(session?.current_period_end);

        if (orgId && subId) {
          await prisma.subscription.upsert({
            where: { id: `stripe_${subId}` },
            update: pickDefined({ status: "active", currentPeriodEnd: end }),
            create: pickDefined({
              id: `stripe_${subId}`,
              orgId,
              provider: "stripe",
              status: "active",
              currentPeriodEnd: end,
            }),
          });
        }
      }

      // 2) Subscription lifecycle updates
      if (event.type === "customer.subscription.updated" || event.type === "customer.subscription.deleted") {
        const sub = event.data.object;
        const end = unixToDate(sub?.current_period_end);
        await prisma.subscription.updateMany({
          where: { id: `stripe_${sub.id}` },
          data: pickDefined({ status: sub.status, currentPeriodEnd: end }),
        });
      }

      // 3) Invoice paid → ensure active & extend period
      if (event.type === "invoice.payment_succeeded") {
        const inv = event.data.object;
        const subId = inv?.subscription;
        const maybeEnd =
          inv?.lines?.data?.[0]?.period?.end ??
          inv?.period_end ??
          inv?.current_period_end;

        const end = unixToDate(maybeEnd);

        if (subId) {
          await prisma.subscription.upsert({
            where: { id: `stripe_${subId}` },
            update: pickDefined({ status: "active", currentPeriodEnd: end }),
            create: pickDefined({
              id: `stripe_${subId}`,
              orgId: inv?.metadata?.orgId || "",
              provider: "stripe",
              status: "active",
              currentPeriodEnd: end,
            }),
          });
        }
      }

      res.json({ received: true });
    } catch (e) {
      console.error("stripe webhook error (verify):", e?.message || e);
      res.status(400).send("Webhook Error");
    }
  }
);

// ---------- JSON body AFTER webhook ----------
app.use(express.json({ limit: "256kb" }));

// ---------- tiny homepage ----------
app.get("/", (req, res) => {
  const html = `
  <h1>Bedrock Backend</h1>
  <p>Status: <a href="/healthz">/healthz</a></p>

  <p>POST /devices/register with JSON:</p>
  <pre>{
  "platform": "android",
  "push_token": "TEST-TOKEN-123"
}</pre>

  <h3>Auth:</h3>
  <ul>
    <li>POST /auth/signup {"email","password"}</li>
    <li>POST /auth/login {"email","password"}</li>
    <li>POST /auth/totp/enable (Bearer token)</li>
    <li>POST /auth/totp/verify {"code"}</li>
    <li>GET /entitlements (Bearer token)</li>
  </ul>

  <h3>Billing (test/dev):</h3>
  <ul>
    <li>POST /billing/checkout (Bearer token) → Stripe Checkout (subscription)</li>
    <li>POST /webhooks/stripe (Stripe) → updates subscription</li>
  </ul>
  `;
  res.type("html").send(html);
});

// ---------- health ----------
app.get("/healthz", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ---------- devices/register (simple) ----------
app.post("/devices/register", async (req, res) => {
  const { platform, push_token, user_id, org_id } = req.body || {};
  if (!platform || !push_token) return res.status(400).json({ error: "platform and push_token required" });

  const device = await prisma.device.create({
    data: {
      platform,
      pushToken: push_token,
      userId: user_id || null,
      orgId: org_id || null,
    },
  });

  res.json({ ok: true, id: device.id });
});

// ---------- auth (email/pass) ----------
app.post("/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password required" });

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: "email already in use" });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await prisma.user.create({ data: { email, passwordHash } });
    const org = await prisma.org.create({ data: { ownerUserId: user.id, name: "My Server" } });
    await prisma.member.create({ data: { orgId: org.id, userId: user.id, role: "owner" } });

    const access = signJwt({ uid: user.id, orgId: org.id, role: "owner" }, "15m");
    const refresh = signJwt({ uid: user.id, orgId: org.id, type: "refresh" }, "30d");
    res.json({ ok: true, access, refresh });
  } catch (e) {
    console.error("signup error:", e);
    res.status(500).json({ error: "signup failed" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: "invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });

  const member = await prisma.member.findFirst({ where: { userId: user.id } });
  const orgId = member?.orgId || null;

  const access = signJwt({ uid: user.id, orgId, role: member?.role || "owner" }, "15m");
  const refresh = signJwt({ uid: user.id, orgId, type: "refresh" }, "30d");
  res.json({ ok: true, access, refresh });
});

// ---------- billing: start checkout ----------
app.post("/billing/checkout", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.replace(/^Bearer\s+/i, "");
    const payload = verifyJwt(token);
    const orgId = payload?.orgId;
    if (!orgId) return res.status(401).json({ error: "invalid token" });

    if (!STRIPE_SECRET_KEY || !STRIPE_PRICE_PREMIUM) {
      return res.status(400).json({ error: "stripe not configured" });
    }

    // Build success/cancel URLs
    const base = appBase || `${req.protocol}://${req.get("host")}`;

    // Create a Stripe Checkout Session (subscription)
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      success_url: `${base}/billing/success`,
      cancel_url: `${base}/billing/cancelled`,
      metadata: { orgId },
      allow_promotion_codes: true,
      automatic_tax: { enabled: false },
    });

    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("checkout error:", e?.message || e);
    res.status(400).json({ error: "checkout failed" });
  }
});

// ---------- tiny success/cancel pages ----------
app.get("/billing/success", (_req, res) => {
  res.type("html").send(`
<!doctype html>
<meta charset="utf-8" />
<title>Payment success</title>
<h2>✅ Payment success</h2>
<p>You can close this tab and return to the app.</p>
<script>
  try { window.opener && window.opener.postMessage({billing:"success"}, "*"); } catch (e) {}
</script>
`);
});
app.get("/billing/cancelled", (_req, res) => {
  res.type("html").send(`
<!doctype html>
<meta charset="utf-8" />
<title>Payment cancelled</title>
<h2>❌ Payment cancelled</h2>
<p>You can close this tab and return to the app.</p>
`);
});

// ---------- entitlements ----------
app.get("/entitlements", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.replace(/^Bearer\s+/i, "");
    const payload = verifyJwt(token);
    if (!payload?.orgId) return res.status(401).json({ error: "invalid token" });

    const subs = await prisma.subscription.findMany({
      where: {
        orgId: payload.orgId,
        status: { in: ["active", "trialing"] },
      },
    });

    const now = Date.now();
    const hasPremium = subs.some(
      (s) => !s.currentPeriodEnd || new Date(s.currentPeriodEnd).getTime() > now
    );

    const entitlement = {
      uid: payload.uid,
      orgId: payload.orgId,
      features: hasPremium ? ["premium"] : ["basic"],
      expiry: Date.now() + 72 * 60 * 60 * 1000, // 72h cache window
    };
    const signed = signJwt({ ent: entitlement }, "72h");
    res.json({ ok: true, entitlement: signed });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

// ---------- start ----------
app.listen(PORT, () => {
  console.log(`API up on :${PORT}`);
});
