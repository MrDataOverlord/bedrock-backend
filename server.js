// server.js  (ESM - "type":"module" in package.json)

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Stripe from "stripe";
import { PrismaClient } from "@prisma/client";

const app = express();
const prisma = new PrismaClient();

const {
  NODE_ENV,
  PORT,
  JWT_SECRET,
  STRIPE_SECRET_KEY,
  STRIPE_PRICE_ID,
  STRIPE_WEBHOOK_SECRET,
  CORS_ORIGINS,
  PUBLIC_BASE_URL,
  RENDER_EXTERNAL_URL,
} = process.env;

if (!JWT_SECRET) throw new Error("JWT_SECRET is required");
if (!STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is required");
if (!STRIPE_PRICE_ID) throw new Error("STRIPE_PRICE_ID is required");
if (!STRIPE_WEBHOOK_SECRET) throw new Error("STRIPE_WEBHOOK_SECRET is required");

const stripe = new Stripe(STRIPE_SECRET_KEY, {
  apiVersion: "2024-06-20",
});

// ---------- CORS (browser only) ----------
const allowList = (CORS_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, cb) {
    // If no origin header -> non-browser caller (PowerShell, curl, backend); allow it
    if (!origin) return cb(null, true);
    if (allowList.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  },
  credentials: false,
};

// Mount the Stripe webhook FIRST and use express.raw for signature verification.
app.post(
  "/webhooks/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    let event;
    try {
      const signature = req.headers["stripe-signature"];
      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("⚠️  Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      switch (event.type) {
        case "checkout.session.completed":
          await handleCheckoutCompleted(event.data.object);
          break;

        case "customer.subscription.created":
        case "customer.subscription.updated":
        case "customer.subscription.deleted":
          await syncSubscriptionFromStripe(event.data.object.id);
          break;

        case "invoice.payment_succeeded":
          // Keep period_end/status fresh
          if (event.data.object.subscription) {
            await syncSubscriptionFromStripe(event.data.object.subscription);
          }
          break;

        default:
          // quiet for unhandled events
          break;
      }
      res.json({ received: true });
    } catch (err) {
      console.error("Webhook handling error:", err);
      res.status(500).json({ error: "Webhook handler failed" });
    }
  }
);

// Common middleware for the rest of the routes
app.use(helmet());
app.use(morgan("dev"));
app.use(cors(corsOptions));
app.use(express.json());

// Optional rate limiting for public POSTs
app.use(
  ["/auth/login", "/billing/checkout_public"],
  rateLimit({ windowMs: 60_000, max: 60 })
);

// ---------- Helpers ----------
const baseUrl =
  PUBLIC_BASE_URL ||
  RENDER_EXTERNAL_URL ||
  "https://bedrock-backend-ipj6.onrender.com";

function signEntitlement(payload, expiresIn = "30m") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifyJwtFromHeader(req) {
  const auth = req.headers.authorization || "";
  const [, token] = auth.split(" ");
  if (!token) throw new Error("Missing token");
  return jwt.verify(token, JWT_SECRET);
}

async function getOrCreateUserByEmail(email) {
  let user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    user = await prisma.user.create({
      data: { email },
    });
  }
  return user;
}

async function ensureOwnedOrg(userId) {
  let org = await prisma.org.findFirst({ where: { ownerUserId: userId } });
  if (!org) {
    org = await prisma.org.create({
      data: { ownerUserId: userId, name: "My Org" },
    });
  }
  return org;
}

async function userHasActiveEntitlement(userId) {
  // Check subscriptions for owned org (simple, clean).
  const sub = await prisma.subscription.findFirst({
    where: {
      org: { ownerUserId: userId },
      status: { in: ["active", "trialing"] },
      OR: [{ currentPeriodEnd: null }, { currentPeriodEnd: { gt: new Date() } }],
    },
  });
  return Boolean(sub);
}

async function syncSubscriptionFromStripe(subscriptionId) {
  const sub = await stripe.subscriptions.retrieve(subscriptionId, {
    expand: ["items.data.price.product"],
  });

  // We expect a user for this customer (set during checkout)
  const customerId = sub.customer;
  const user = await prisma.user.findFirst({
    where: { stripeCustomerId: String(customerId) },
  });

  // If user isn't found by customerId, we can't map; skip safely.
  if (!user) {
    console.warn(
      "Stripe subscription references unknown customer; skipping upsert:",
      customerId
    );
    return;
  }

  const org = await ensureOwnedOrg(user.id);

  const priceId = sub.items?.data?.[0]?.price?.id ?? STRIPE_PRICE_ID;
  const currentPeriodEnd = sub.current_period_end
    ? new Date(sub.current_period_end * 1000)
    : null;

  await prisma.subscription.upsert({
    where: { id: sub.id }, // store Stripe sub id
    update: {
      orgId: org.id,
      provider: "stripe",
      status: sub.status,
      customerId: String(customerId),
      currentPeriodEnd,
      updatedAt: new Date(),
    },
    create: {
      id: sub.id,
      orgId: org.id,
      provider: "stripe",
      status: sub.status,
      currentPeriodEnd,
      customerId: String(customerId),
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  });
}

async function handleCheckoutCompleted(session) {
  // session.subscription & session.customer exist here
  const email =
    session.customer_details?.email || session.customer_email || session.metadata?.email;
  const customerId = session.customer;
  const subscriptionId = session.subscription;

  if (!email || !customerId || !subscriptionId) return;

  const user = await getOrCreateUserByEmail(email);

  // Attach customerId to user if missing
  if (!user.stripeCustomerId) {
    await prisma.user.update({
      where: { id: user.id },
      data: { stripeCustomerId: String(customerId) },
    });
  }

  // Pull full subscription to populate DB
  await syncSubscriptionFromStripe(subscriptionId);
}

// ---------- Routes ----------

app.get("/healthz", (_req, res) => {
  res.json({ ok: true, env: NODE_ENV || "dev" });
});

// PUBLIC: create a checkout session by email (no auth)
// Your Windows app (or your website) can call this with { email }
app.post("/billing/checkout_public", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "email is required" });

    const user = await getOrCreateUserByEmail(email);

    // ensure stripe customer
    let customerId = user.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({ email });
      customerId = customer.id;
      await prisma.user.update({
        where: { id: user.id },
        data: { stripeCustomerId: String(customerId) },
      });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${baseUrl}/billing/success`,
      cancel_url: `${baseUrl}/billing/cancel`,
      metadata: { userId: user.id, email },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("checkout_public error:", err);
    res.status(500).json({ error: "failed_to_create_checkout_session" });
  }
});

// (Optional) Authenticated checkout if you want it
app.post("/billing/checkout", async (req, res) => {
  try {
    const payload = verifyJwtFromHeader(req);
    const user = await prisma.user.findUnique({ where: { id: payload.uid } });
    if (!user) return res.status(401).json({ error: "invalid_user" });

    let customerId = user.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await prisma.user.update({
        where: { id: user.id },
        data: { stripeCustomerId: String(customerId) },
      });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      success_url: `${baseUrl}/billing/success`,
      cancel_url: `${baseUrl}/billing/cancel`,
      metadata: { userId: user.id, email: user.email },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("checkout error:", err);
    res.status(401).json({ error: "unauthorized" });
  }
});

// Basic success/cancel pages for Stripe redirects
app.get("/billing/success", (_req, res) => {
  res.type("html").send("<h1>Payment success</h1><p>You can close this tab.</p>");
});
app.get("/billing/cancel", (_req, res) => {
  res.type("html").send("<h1>Payment canceled</h1><p>You can close this tab.</p>");
});

// LOGIN (no CORS/Origin requirement for non-browser callers)
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "missing_fields" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: "invalid_credentials" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "invalid_credentials" });

    const token = jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "12h",
    });
    res.json({ access: token });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ error: "login_failed" });
  }
});

// ENTITLEMENTS (Windows app calls this with Bearer token)
app.get("/entitlements", async (req, res) => {
  try {
    const payload = verifyJwtFromHeader(req);
    const active = await userHasActiveEntitlement(payload.uid);

    if (!active) {
      // return empty/default entitlement
      const token = signEntitlement({
        uid: payload.uid,
        features: [],
        expiry: Math.floor(Date.now() / 1000) + 60 * 15, // 15 min
      }, "15m");
      return res.json({ entitlement: token });
    }

    // include an expiry (days remaining visible on client after decode)
    const sub = await prisma.subscription.findFirst({
      where: {
        org: { ownerUserId: payload.uid },
        status: { in: ["active", "trialing"] },
      },
      orderBy: { updatedAt: "desc" },
    });

    const expiryUnix =
      sub?.currentPeriodEnd
        ? Math.floor(sub.currentPeriodEnd.getTime() / 1000)
        : Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30;

    const token = signEntitlement({
      uid: payload.uid,
      features: ["premium"],
      expiry: expiryUnix,
    }, "30m");

    res.json({ entitlement: token });
  } catch (err) {
    console.error("entitlements error:", err);
    res.status(401).json({ error: "unauthorized" });
  }
});

// ---------- Startup ----------
const listenPort = Number(PORT) || 10000;
app.listen(listenPort, () => {
  console.log(`API up on :${listenPort}`);
});
