// server.js
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
import Stripe from "stripe";

const app = express();
const prisma = new PrismaClient();

// ---------- config ----------
const PORT = process.env.PORT || 10000;
const APP_DOMAIN = process.env.APP_DOMAIN || "https://bedrock-backend-ipj6.onrender.com";
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_PRICE_PREMIUM = process.env.STRIPE_PRICE_PREMIUM || "";
const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: "2024-06-20" });

// Allow comma-separated webhook secrets to make rotation easy
const WEBHOOK_SECRETS = (process.env.STRIPE_WEBHOOK_SECRET || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

// ---------- middleware (global, but NOT for the webhook) ----------
app.use(cors());
app.use(morgan("tiny"));
app.use(bodyParser.json());

// ---------- helpers ----------
function signJwt(payload, exp = "7d") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: exp });
}
function verifyJwt(token) {
  return jwt.verify(token, JWT_SECRET);
}
function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    req.user = verifyJwt(token);
    next();
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
}

// ---------- demo home ----------
app.get("/", (_, res) => {
  res.type("text/plain").send(
`Bedrock Backend

Status: /healthz

Auth:
• POST /auth/signup {"email","password"}
• POST /auth/login  {"email","password"}

Billing (test/dev):
• POST /billing/checkout (Bearer token) → Stripe Checkout
• POST /webhooks/stripe (Stripe) → updates subscription

Entitlements:
• GET /entitlements (Bearer token)
`);
});
app.get("/healthz", (_, res) => res.json({ ok: true }));

// ---------- auth ----------
app.post("/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) throw new Error("missing fields");

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({ data: { email, passwordHash } });

    // also create an org owned by this user
    const org = await prisma.org.create({
      data: { ownerUserId: user.id, name: `${email.split("@")[0]}'s Org` }
    });

    const token = signJwt({ uid: user.id, orgId: org.id, role: "owner" }, "72h");
    res.json({ ok: true, access: token });
  } catch (e) {
    res.status(400).json({ error: e.message || "signup failed" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.passwordHash || ""))) {
      throw new Error("bad credentials");
    }

    const org = await prisma.org.findFirst({ where: { ownerUserId: user.id } });
    const token = signJwt({ uid: user.id, orgId: org?.id, role: "owner" }, "72h");
    res.json({ ok: true, access: token });
  } catch (e) {
    res.status(401).json({ error: e.message || "login failed" });
  }
});

// ---------- entitlements ----------
app.get("/entitlements", auth, async (req, res) => {
  try {
    const subs = await prisma.subscription.findMany({
      where: { orgId: req.user.orgId, status: "active" }
    });
    const isPremium = subs.length > 0;
    const entitlement = {
      uid: req.user.uid,
      orgId: req.user.orgId,
      features: isPremium ? ["premium"] : ["basic"],
      expiry: Date.now() + 72 * 60 * 60 * 1000
    };
    const signed = signJwt(entitlement, "72h");
    res.json({ ok: true, entitlement: signed });
  } catch (e) {
    res.status(400).json({ error: e.message || "failed" });
  }
});

// ---------- billing: create Stripe checkout ----------
app.post("/billing/checkout", auth, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      success_url: `${APP_DOMAIN}/billing/success`,
      cancel_url: `${APP_DOMAIN}/billing/cancel`,
      metadata: { orgId: req.user.orgId },
      subscription_data: { metadata: { orgId: req.user.orgId } }
    });
    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("checkout error:", e?.message || e);
    res.status(400).json({ error: "checkout failed" });
  }
});

app.get("/billing/success", (_, res) =>
  res.type("html").send("<h2>✅ Payment success</h2><p>You can close this tab and return to the app.</p>")
);
app.get("/billing/cancel", (_, res) =>
  res.type("html").send("<h2>❌ Payment canceled</h2>")
);

// ---------- webhook: MUST be raw body ----------
app.post("/webhooks/stripe", bodyParser.raw({ type: "*/*" }), async (req, res) => {
  const signature = req.headers["stripe-signature"];
  let event;

  // Try each secret until one verifies
  let verified = false, usedSecret = null, errLast;
  for (const secret of WEBHOOK_SECRETS) {
    try {
      event = stripe.webhooks.constructEvent(req.body, signature, secret);
      verified = true;
      usedSecret = secret;
      break;
    } catch (e) {
      errLast = e;
    }
  }

  if (!verified) {
    console.error("stripe webhook error (verify):", errLast?.message || errLast);
    return res.status(400).send("Webhook signature verification failed");
  }

  try {
    const type = event.type;
    const obj = event.data.object;

    // Create/activate subscription on successful checkout or payment
    if (type === "checkout.session.completed" || type === "invoice.payment_succeeded") {
      const orgId = obj.metadata?.orgId || obj.subscription_details?.metadata?.orgId;
      if (orgId) {
        const subId = `stripe_${obj.subscription || obj.id}`;
        const unix = obj.current_period_end || obj.period_end || Math.floor(Date.now() / 1000);
        await prisma.subscription.upsert({
          where: { id: subId },
          update: { orgId, provider: "stripe", status: "active", currentPeriodEnd: new Date(unix * 1000) },
          create: { id: subId, orgId, provider: "stripe", status: "active", currentPeriodEnd: new Date(unix * 1000) }
        });
      }
    }

    // Keep status up to date if Stripe changes it later
    if (type === "customer.subscription.updated" || type === "customer.subscription.deleted") {
      const sub = obj;
      await prisma.subscription.updateMany({
        where: { id: `stripe_${sub.id}` },
        data: {
          status: sub.status,
          currentPeriodEnd: sub.current_period_end ? new Date(sub.current_period_end * 1000) : undefined
        }
      });
    }

    console.log(`✅ webhook verified with secret: ${usedSecret?.slice(0, 8)}… type=${type}`);
    res.json({ received: true });
  } catch (e) {
    console.error("stripe webhook handler error:", e?.message || e);
    res.status(500).send("Webhook handler error");
  }
});

// ---------- start ----------
app.listen(PORT, () => console.log(`API up on :${PORT}`));
