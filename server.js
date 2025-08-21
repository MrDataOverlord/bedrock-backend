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
import crypto from "crypto";

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

  // Email (Resend) + password link bases
  MAIL_FROM = "NerdHerd Utilities <no-reply@nerdherdutilities.com>",
  RESEND_API_KEY = "", // if blank, emails are logged to console for dev
  REG_URL_BASE = "https://www.nerdherdutilities.com/account",
  RESET_URL_BASE = "https://www.nerdherdutilities.com/account",
} = process.env;

const stripe = new Stripe(STRIPE_SECRET_KEY || "", { apiVersion: "2024-06-20" });

/* =========================
   Helpers
========================= */
const signJwt  = (payload, expiresIn = "24h") => jwt.sign(payload, JWT_SECRET, { expiresIn });
const verifyJwt = (token) => jwt.verify(token, JWT_SECRET);

const unixToDate = (unix) => {
  if (!unix || Number.isNaN(Number(unix))) return undefined;
  const d = new Date(Number(unix) * 1000);
  return isNaN(d.getTime()) ? undefined : d;
};
const defined = (obj) => Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined));

async function sendEmail({ to, subject, html }) {
  if (RESEND_API_KEY) {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, html })
    });
    if (!r.ok) throw new Error(`Resend error: ${await r.text()}`);
    return;
  }
  console.log("[DEV EMAIL]", { to, subject, html }); // dev fallback
}

const makeRawToken = () => crypto.randomBytes(32).toString("base64url");
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

async function issuePasswordToken(userId, purpose) {
  const raw = makeRawToken();
  const tokenHash = sha256(raw);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
  await prisma.passwordToken.create({ data: { userId, purpose, tokenHash, expiresAt } });
  return raw;
}

async function sendRegistrationEmail(email, userId) {
  const raw = await issuePasswordToken(userId, "register");
  const url = `${REG_URL_BASE.replace(/\/$/, "")}/set-password?token=${encodeURIComponent(raw)}`;
  await sendEmail({
    to: email,
    subject: "Complete your NerdHerd Utilities account",
    html: `<p>Thanks for your purchase! Create your password:</p><p><a href="${url}">Set your password</a></p><p>This link expires in 24 hours.</p>`
  });
}

async function sendResetEmail(email, userId) {
  const raw = await issuePasswordToken(userId, "reset");
  const url = `${RESET_URL_BASE.replace(/\/$/, "")}/reset-password?token=${encodeURIComponent(raw)}`;
  await sendEmail({
    to: email,
    subject: "Reset your NerdHerd Utilities password",
    html: `<p>Reset with the link below:</p><p><a href="${url}">Reset password</a></p><p>This link expires in 24 hours.</p>`
  });
}

/** Persist one subscription snapshot into DB */
async function writeSubFromStripe(sub, orgIdMaybe) {
  const orgId = sub?.metadata?.orgId || orgIdMaybe;
  const end = unixToDate(sub?.current_period_end);
  const customerId = typeof sub.customer === "string" ? sub.customer : sub.customer?.id;

  await prisma.subscription.upsert({
    where: { id: `stripe_${sub.id}` },
    update: defined({ orgId, provider: "stripe", status: sub.status, currentPeriodEnd: end, customerId }),
    create: defined({ id: `stripe_${sub.id}`, orgId, provider: "stripe", status: sub.status, currentPeriodEnd: end, customerId }),
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
      switch (event.type) {
        case "checkout.session.completed": {
          const session = event.data.object;
          const subId = session?.subscription;
          let orgId = session?.metadata?.orgId || null;

          // Extract purchaser email for “public” checkout
          let purchaserEmail = session?.customer_details?.email || session?.customer_email || null;
          if (!purchaserEmail && session?.customer) {
            try {
              const cust = await stripe.customers.retrieve(session.customer);
              purchaserEmail = typeof cust.email === "string" ? cust.email : null;
            } catch {}
          }

          // If no orgId (public checkout), create user/org and email registration link
          if (!orgId && purchaserEmail) {
            let user = await prisma.user.findUnique({ where: { email: purchaserEmail } });
            if (!user) {
              user = await prisma.user.create({ data: { email: purchaserEmail } }); // passwordHash null for now
              const org = await prisma.org.create({ data: { ownerUserId: user.id, name: "My Org" } });
              await prisma.member.create({ data: { orgId: org.id, userId: user.id, role: "owner" } });
              orgId = org.id;
              try { await sendRegistrationEmail(purchaserEmail, user.id); } catch (e) { console.warn("registration email fail:", e?.message || e); }
            } else {
              const membership = await prisma.member.findFirst({ where: { userId: user.id } });
              if (!membership) {
                const org = await prisma.org.create({ data: { ownerUserId: user.id, name: "My Org" } });
                await prisma.member.create({ data: { orgId: org.id, userId: user.id, role: "owner" } });
                orgId = org.id;
              } else {
                orgId = membership.orgId;
              }
              const hasPassword = !!(await prisma.user.findUnique({ where: { email: purchaserEmail }, select: { passwordHash: true } }))?.passwordHash;
              if (!hasPassword) { try { await sendRegistrationEmail(purchaserEmail, user.id); } catch {} }
            }
          }

          if (subId) {
            try { await stripe.subscriptions.update(subId, { metadata: { orgId } }); } catch {}
            const sub = await stripe.subscriptions.retrieve(subId);
            await writeSubFromStripe(sub, orgId);
          }
          break;
        }

        case "invoice.payment_succeeded": {
          const inv = event.data.object;
          const subId = inv?.subscription;
          if (subId) {
            const sub = await stripe.subscriptions.retrieve(subId);
            await writeSubFromStripe(sub);
          }
          break;
        }

        case "customer.subscription.updated":
        case "customer.subscription.deleted": {
          const sub = event.data.object;
          await writeSubFromStripe(sub);
          break;
        }

        default:
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
• POST /auth/login  {"email","password"}
• POST /auth/request-reset {"email"}
• POST /auth/set-password {"token","password"}

Billing:
• POST /billing/checkout            (Bearer token) → Stripe URL
• POST /billing/checkout_public     {"email"}     → Stripe URL (no login)
• GET  /billing/success
• POST /webhooks/stripe

Entitlements:
• GET  /entitlements  (Bearer token)
`
  );
});

/* =========================
   Auth  (signup disabled: pay first, then set password via email)
========================= */
app.post("/auth/signup", (_req, res) => {
  res.status(403).json({ error: "signup_disabled", message: "Create your account from the email link after payment." });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user?.passwordHash) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  // Find user's org
  const member = await prisma.member.findFirst({ where: { userId: user.id } });
  const orgId = member?.orgId;
  if (!orgId) return res.status(403).json({ error: "no_org" });

  // Enforce ACTIVE & not expired (30-day windows via Stripe current_period_end)
  const now = new Date();
  const sub = await prisma.subscription.findFirst({ where: { orgId }, orderBy: { updatedAt: "desc" } });
  const active = !!(sub && sub.status === "active" && sub.currentPeriodEnd && sub.currentPeriodEnd > now);
  if (!active) return res.status(402).json({ error: "inactive_subscription" });

  const token = signJwt({ uid: user.id, orgId });
  res.json({ ok: true, access: token });
});

// Forgot password (no user enumeration)
app.post("/auth/request-reset", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "missing_email" });
  const user = await prisma.user.findUnique({ where: { email } });
  if (user) { try { await sendResetEmail(email, user.id); } catch (e) { console.warn("reset email:", e?.message || e); } }
  res.json({ ok: true });
});

// Set/Reset password with single-use token
app.post("/auth/set-password", async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: "missing_fields" });

  const tokenHash = sha256(token);
  const t = await prisma.passwordToken.findUnique({ where: { tokenHash } }).catch(() => null);
  if (!t || t.usedAt || new Date(t.expiresAt).getTime() < Date.now()) {
    return res.status(400).json({ error: "invalid_or_expired_token" });
  }
  if (t.purpose !== "register" && t.purpose !== "reset") {
    return res.status(400).json({ error: "invalid_token_purpose" });
  }

  const hash = await bcrypt.hash(password, 10);

  await prisma.$transaction([
    prisma.user.update({ where: { id: t.userId }, data: { passwordHash: hash } }),
    prisma.passwordToken.update({ where: { tokenHash }, data: { usedAt: new Date() } }),
  ]);

  // Optional: return an access token (still requires ACTIVE sub to be useful)
  const m = await prisma.member.findFirst({ where: { userId: t.userId } });
  const access = signJwt({ uid: t.userId, orgId: m?.orgId });
  res.json({ ok: true, access });
});

/* =========================
   Billing
========================= */
app.get("/billing/success", (_req, res) =>
  res.type("html").send(`<h2>Payment success</h2><p>You can close this tab.</p>`)
);

// Logged-in checkout
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
      success_url: successUrl, cancel_url: cancelUrl,
      subscription_data: { metadata: { orgId } },
      metadata: { orgId },
    });

    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("checkout error", e?.message || e);
    res.status(400).json({ error: "checkout_failed" });
  }
});

// Public checkout (email only)
app.post("/billing/checkout_public", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "missing_email" });

    // Ensure user/org
    let user = await prisma.user.findUnique({ where: { email } });
    let orgId;
    if (!user) {
      user = await prisma.user.create({ data: { email } });
      const org = await prisma.org.create({ data: { ownerUserId: user.id, name: "My Org" } });
      await prisma.member.create({ data: { orgId: org.id, userId: user.id, role: "owner" } });
      orgId = org.id;
    } else {
      const m = await prisma.member.findFirst({ where: { userId: user.id } });
      if (m) orgId = m.orgId;
      else {
        const org = await prisma.org.create({ data: { ownerUserId: user.id, name: "My Org" } });
        await prisma.member.create({ data: { orgId: org.id, userId: user.id, role: "owner" } });
        orgId = org.id;
      }
    }

    const successUrl = SUCCESS_URL || `${APP_DOMAIN}/billing/success`;
    const cancelUrl  = CANCEL_URL  || `${APP_DOMAIN}/billing/success`;

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      success_url: successUrl, cancel_url: cancelUrl,
      customer_email: email,
      subscription_data: { metadata: { orgId } },
      metadata: { orgId },
    });

    // Pre-issue registration email (webhook also handles it)
    try { await sendRegistrationEmail(email, user.id); } catch {}

    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("checkout_public error", e?.message || e);
    res.status(400).json({ error: "checkout_public_failed" });
  }
});

/* =========================
   Entitlements (ACTIVE only) + days remaining
========================= */
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

    const now = new Date();
    const s = subs.find((x) => x.status === "active" && x.currentPeriodEnd && x.currentPeriodEnd > now);

    const isPremium = !!s;
    const periodEnd = s?.currentPeriodEnd ?? null;
    const daysRemaining = periodEnd ? Math.max(0, Math.ceil((periodEnd.getTime() - Date.now()) / 86400000)) : 0;

    const entitlement = {
      uid: payload.uid,
      orgId: payload.orgId,
      features: isPremium ? ["premium"] : ["basic"],
      periodEnd: periodEnd ? periodEnd.getTime() : null, // epoch ms
      daysRemaining,
      issuedAt: Date.now(),
    };

    const signed = signJwt({ ent: entitlement }, "24h");
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
