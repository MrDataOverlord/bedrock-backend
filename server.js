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

/* =========================
   Env
========================= */
const {
  PORT = 10000,
  CORS_ORIGINS = "",
  JWT_SECRET = "dev_jwt_secret_change_me",
  APP_DOMAIN = "", // e.g. https://bedrock-backend-xxxxx.onrender.com
  STRIPE_SECRET_KEY = "",
  STRIPE_PRICE_PREMIUM = "",
  STRIPE_WEBHOOK_SECRET = "",
  SUCCESS_URL, // optional override
  CANCEL_URL,  // optional override
} = process.env;

const stripe = new Stripe(STRIPE_SECRET_KEY || "", { apiVersion: "2024-06-20" });

/* =========================
   Helpers
========================= */
const signJwt  = (payload, expiresIn = "72h") => jwt.sign(payload, JWT_SECRET, { expiresIn });
const verifyJwt = (token) => jwt.verify(token, JWT_SECRET);

const unixToDate = (unix) => {
  if (!unix || Number.isNaN(Number(unix))) return undefined;
  const d = new Date(Number(unix) * 1000);
  return isNaN(d.getTime()) ? undefined : d;
};
const defined = (obj) => Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined));

/** Persist one subscription snapshot into DB */
async function writeSubFromStripe(sub, orgIdMaybe) {
  // prefer orgId from subscription metadata; fall back to provided orgId
  const orgId = sub?.metadata?.orgId || orgIdMaybe;
  const end = unixToDate(sub?.current_period_end);
  if (!orgId) {
    // If orgId is missing, try to keep status only (row may already exist with orgId)
    await prisma.subscription.upsert({
      where: { id: `stripe_${sub.id}` },
      update: defined({ status: sub.status, currentPeriodEnd: end }),
      create: defined({
        id: `stripe_${sub.id}`,
        orgId: "", // unknown; will be backfilled when known
        provider: "stripe",
        status: sub.status,
        currentPeriodEnd: end,
      }),
    });
    return;
  }

  await prisma.subscription.upsert({
    where: { id: `stripe_${sub.id}` },
    update: defined({ orgId, provider: "stripe", status: sub.status, currentPeriodEnd: end }),
    create: defined({
      id: `stripe_${sub.id}`,
      orgId,
      provider: "stripe",
      status: sub.status,
      currentPeriodEnd: end,
    }),
  });
}

/* =========================
   App
========================= */
const app = express();
app.set("trust proxy", 1);
app.use(helmet());

// CORS
const ALLOWED = CORS_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean);
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || ALLOWED.length === 0 || ALLOWED.includes(origin)) return cb(null, true);
      cb(new Error("Not allowed by CORS"));
    },
  })
);

// Basic rate limit
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

/* =========================================================
   STRIPE WEBHOOK — must come BEFORE express.json middleware
========================================================= */
app.post(
  "/webhooks/stripe",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    let event;
    try {
      const sig = req.headers["stripe-signature"];
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error("stripe webhook error (verify):", err?.message || err);
      return res.status(400).send("Webhook Error");
    }

    try {
      // Helpful breadcrumb in logs
      console.log("stripe webhook:", event.type);

      switch (event.type) {
        /** User just completed checkout */
        case "checkout.session.completed": {
          const session = event.data.object;
          const orgId = session?.metadata?.orgId;
          const subId = session?.subscription;

          if (subId) {
            // Ensure the subscription permanently carries orgId in its metadata
            try {
              await stripe.subscriptions.update(subId, { metadata: { orgId } });
            } catch (e) {
              // ignore; might already be set or not allowed in some states
              console.warn("sub metadata update skipped:", e?.message || e);
            }

            const sub = await stripe.subscriptions.retrieve(subId);
            await writeSubFromStripe(sub, orgId);
          }
          break;
        }

        /** Recurring invoice succeeded (period extended) */
        case "invoice.payment_succeeded": {
          const inv = event.data.object;
          const subId = inv?.subscription;
          if (subId) {
            const sub = await stripe.subscriptions.retrieve(subId);
            await writeSubFromStripe(sub /* orgId from metadata */);
          }
          break;
        }

        /** Any subscription state change (trialing->active, canceled, etc.) */
        case "customer.subscription.updated":
        case "customer.subscription.deleted": {
          const sub = event.data.object;
          await writeSubFromStripe(sub /* orgId from metadata */);
          break;
        }

        default:
          // No-op for other events
          break;
      }

      res.json({ received: true });
    } catch (err) {
      console.error("stripe webhook handler error:", err?.message || err);
      res.status(500).send("webhook_handler_error");
    }
  }
);

/* =========================================================
   All other routes use JSON body — after the webhook
========================================================= */
app.use(express.json({ limit: "256kb" }));

/* =========================
   Health & Home
========================= */
app.get("/healthz", (_req, res) => res.json({ ok: true }));
app.get("/", (_req, res) => {
  res.type("text/plain").send(
`Bedrock Backend

Status: /healthz

Auth:
• POST /auth/signup {"email","password"}
• POST /auth/login  {"email","password"}

Billing:
• POST /billing/checkout    (Bearer token) → returns Stripe URL
• POST /billing/force-active (test/dev; Bearer token) → mark premium
• GET  /billing/status       (Bearer token) → debug view
• GET  /billing/success
• POST /webhooks/stripe     (Stripe)

Entitlements:
• GET  /entitlements  (Bearer token)
`
  );
});

/* =========================
   Auth (minimal)
========================= */
app.post("/auth/signup", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  const hash = await bcrypt.hash(password, 10);

  // create user + org
  const user = await prisma.user.create({ data: { email, passwordHash: hash } });
  const org = await prisma.org.create({ data: { ownerUserId: user.id, name: "My Org" } });
  await prisma.member.create({ data: { orgId: org.id, userId: user.id, role: "owner" } });

  const token = signJwt({ uid: user.id, orgId: org.id });
  res.json({ ok: true, token });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash || "");
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const member = await prisma.member.findFirst({ where: { userId: user.id } });
  const orgId = member?.orgId;

  const token = signJwt({ uid: user.id, orgId });
  res.json({ ok: true, access: token });
});

/* =========================
   Billing
========================= */
app.get("/billing/success", (_req, res) =>
  res.type("html").send(`<h2>Payment success</h2><p>You can close this tab.</p>`)
);

// Create a checkout session
app.post("/billing/checkout", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.replace("Bearer ", "");
    const payload = verifyJwt(token);
    const orgId = payload.orgId;
    if (!orgId) return res.status(400).json({ error: "No orgId on token" });

    const successUrl = SUCCESS_URL || `${APP_DOMAIN}/billing/success`;
    const cancelUrl  = CANCEL_URL  || `${APP_DOMAIN}/billing/success`;

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      success_url: successUrl,
      cancel_url: cancelUrl,
      // put orgId on the SUBSCRIPTION so all future events carry it
      subscription_data: { metadata: { orgId } },
      // keep also on session for immediate use in the webhook
      metadata: { orgId },
    });

    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("checkout error", e?.message || e);
    res.status(400).json({ error: "checkout_failed" });
  }
});

// Dev helper — mark premium active manually
app.post("/billing/force-active", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.replace("Bearer ", "");
    const payload = verifyJwt(token);
    await prisma.subscription.upsert({
      where: { id: `manual_${payload.orgId}` },
      update: { status: "active" },
      create: { id: `manual_${payload.orgId}`, orgId: payload.orgId, provider: "manual", status: "active" },
    });
    res.json({ ok: true });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

// Debug helper — see what the server thinks your latest sub is
app.get("/billing/status", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.replace("Bearer ", "");
    const { orgId } = verifyJwt(token);
    const sub = await prisma.subscription.findFirst({
      where: { orgId },
      orderBy: { updatedAt: "desc" },
    });
    res.json({ ok: true, subscription: sub });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

/* =========================
   Entitlements
========================= */
const PREMIUM_STATES = new Set(["active", "trialing"]);

app.get("/entitlements", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.replace("Bearer ", "");
    const payload = verifyJwt(token);

    const subs = await prisma.subscription.findMany({
      where: { orgId: payload.orgId },
      orderBy: { updatedAt: "desc" },
      take: 3,
    });

    const latest = subs.find((s) => PREMIUM_STATES.has(s.status));
    const isPremium = Boolean(latest);

    const entitlement = {
      uid: payload.uid,
      orgId: payload.orgId,
      features: isPremium ? ["premium"] : ["basic"],
      expiry: Date.now() + 72 * 60 * 60 * 1000,
    };

    const signed = signJwt({ ent: entitlement }, "72h");
    res.json({ ok: true, entitlement: signed });
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
});

/* =========================
   Start
========================= */
app.listen(PORT, () => {
  console.log(`API up on :${PORT}`);
});
