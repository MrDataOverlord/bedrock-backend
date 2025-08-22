// server.js
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import bodyParser from "body-parser";           // raw body for Stripe webhooks
import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import nodemailer from "nodemailer";
import { PrismaClient } from "@prisma/client";

/* =========================
   Env
========================= */
const {
  NODE_ENV = "production",
  PORT = 10000,

  // Auth / App
  JWT_SECRET,
  CORS_ORIGINS = "", // comma-separated list: https://nerdherdmc.net,https://www.nerdherdmc.net,http://localhost:3000,http://localhost:5173
  APP_DOMAIN = "https://bedrock-backend-ipj6.onrender.com",

  // Stripe
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
  STRIPE_PRICE_PREMIUM,

  // Registration: Wix page that handles ?token=...&email=...
  // (If you changed the slug to /account/set-password keep this in ENV.)
  REG_URL_BASE = "https://www.nerdherdmc.net/account/set-password",

  // SMTP (Namescheap PrivateEmail)
  SMTP_HOST = "mail.privateemail.com",
  SMTP_PORT = "465",
  SMTP_SECURE = "true",  // "true" => port 465, "false" => port 587
  SMTP_USER,             // support@nerdherdmc.com
  SMTP_PASS,
  EMAIL_FROM             // optional (defaults to SMTP_USER)
} = process.env;

function must(name, val) {
  if (!val) throw new Error(`${name} is required`);
}
must("JWT_SECRET", JWT_SECRET);
must("STRIPE_SECRET_KEY", STRIPE_SECRET_KEY);
must("STRIPE_WEBHOOK_SECRET", STRIPE_WEBHOOK_SECRET);
must("STRIPE_PRICE_PREMIUM", STRIPE_PRICE_PREMIUM);
must("SMTP_USER", SMTP_USER);
must("SMTP_PASS", SMTP_PASS);

const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: "2024-06-20" });
const prisma = new PrismaClient();

/* =========================
   App + middleware
========================= */
const app = express();

// Render/Proxies: remove rate-limit warning and get real client IPs
app.set("trust proxy", 1);

// Security / rate-limit / CORS / logging
app.use(helmet());
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

const corsOrigins = CORS_ORIGINS.split(",").map(s => s.trim()).filter(Boolean);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);           // allow curl/Postman
      if (corsOrigins.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    credentials: true,
  })
);
app.options("*", cors()); // preflight

app.use(morgan("dev"));

// DO NOT put express.json() before Stripe webhook.
// We add it after the webhook route.

/* =========================
   Helpers
========================= */
const signJwt = (payload, exp = "72h") =>
  jwt.sign(payload, JWT_SECRET, { expiresIn: exp });

function setPasswordLink(rawToken, email) {
  const q = new URLSearchParams({ token: rawToken, email }).toString();
  return `${REG_URL_BASE}?${q}`;
}

/* =========================
   Email (Nodemailer)
========================= */
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT),
  secure: String(SMTP_SECURE).toLowerCase() === "true",
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

async function verifyTransporter() {
  try {
    const ok = await transporter.verify();
    console.log("[mail] transporter verified:", ok);
  } catch (e) {
    console.error("[mail] transporter verify FAILED:", e.message);
  }
}

async function sendMail({ to, subject, html, text }) {
  const from = EMAIL_FROM || SMTP_USER;
  const info = await transporter.sendMail({ from, to, subject, html, text });
  console.log("[mail] sent:", { to, subject, messageId: info.messageId });
  return info;
}

/* =========================
   Password tokens
========================= */
async function issuePasswordToken(userId, purpose = "register", ttlMinutes = 120) {
  const raw = crypto.randomBytes(32).toString("hex");
  const tokenHash = await bcrypt.hash(raw, 10);
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);

  await prisma.passwordToken.create({
    data: { userId, purpose, tokenHash, expiresAt },
  });

  return raw; // send this via email
}

/* =========================
   Stripe: Checkout (public)
========================= */
app.post("/billing/checkout_public", express.json(), async (req, res) => {
  try {
    const { email, returnUrl } = req.body || {};
    if (!email) return res.status(400).json({ error: "email is required" });

    console.log("[checkout_public] start { email }", { email });

    // Ensure a user row exists
    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      user = await prisma.user.create({ data: { email } });
      console.log("[checkout_public] created user", { id: user.id, email });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer_email: email,
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      allow_promotion_codes: true,
      success_url: returnUrl ? String(returnUrl) : `${APP_DOMAIN}/billing/success`,
      cancel_url: `${APP_DOMAIN}/billing/cancelled`,
    });

    console.log("[checkout_public] session created", { id: session.id, url: session.url });
    res.json({ url: session.url });
  } catch (e) {
    console.error("[checkout_public] ERROR", e);
    res.status(500).json({ error: "checkout failed" });
  }
});

/* =========================
   Stripe Webhook (raw body)
========================= */
app.post(
  "/webhooks/stripe",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error("[webhook] signature verify FAILED:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      console.log("[webhook] event:", event.type);

      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const email = session?.customer_details?.email || session?.customer_email;
        console.log("[webhook] checkout.session.completed", { session: session.id, email });

        if (email) {
          let user = await prisma.user.findUnique({ where: { email } });
          if (!user) {
            user = await prisma.user.create({ data: { email } });
            console.log("[webhook] created user", { id: user.id });
          }

          // If no password yet, send registration link
          if (!user.passwordHash) {
            const rawToken = await issuePasswordToken(user.id, "register", 120);
            const url = setPasswordLink(rawToken, email);
            await sendMail({
              to: email,
              subject: "Set your Bedrock Utilities password",
              text: `Welcome! Click this link to set your password: ${url}`,
              html: `
                <p>Welcome to Bedrock Utilities!</p>
                <p><a href="${url}" target="_blank" rel="noopener">Click here to set your password</a></p>
                <p>This link expires in 2 hours.</p>
              `,
            });
          } else {
            console.log("[webhook] user already has a password; no email sent");
          }
        }
      }

      if (event.type === "invoice.payment_failed") {
        const invoice = event.data.object;
        const email = invoice?.customer_email || invoice?.customer_details?.email;
        if (email) {
          await sendMail({
            to: email,
            subject: "Payment failed — subscription on hold",
            text: "Your recent payment failed and your premium access is on hold. Please update your payment method.",
            html: `
              <p>Your recent payment failed and your premium access is on hold.</p>
              <p>Please update your payment method to restore access.</p>
            `,
          });
        }
      }

      if (event.type === "invoice.payment_succeeded") {
        const invoice = event.data.object;
        console.log("[webhook] invoice.payment_succeeded", { invoice: invoice.id });
        // Optional: update your DB's Subscription table nextPeriodEnd, etc.
      }

      return res.json({ received: true });
    } catch (err) {
      console.error("[webhook] handler ERROR:", err);
      // Still return 200 to avoid endless retries
      return res.json({ received: true });
    }
  }
);

// JSON parser for everything after the webhook
app.use(express.json());

/* =========================
   Auth: complete registration (set password)
========================= */
app.post("/auth/register/complete", async (req, res) => {
  try {
    const { email, token, password } = req.body || {};
    if (!email || !token || !password) {
      return res.status(400).json({ error: "email, token and password are required" });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: "password must be at least 8 characters" });
    }

    const user = await prisma.user.findUnique({
      where: { email },
      include: {
        passwordTokens: {
          where: {
            purpose: "register",
            usedAt: null,
            expiresAt: { gt: new Date() },
          },
          orderBy: { createdAt: "desc" },
        },
      },
    });
    if (!user) return res.status(404).json({ error: "user not found" });

    // Find matching token by bcrypt compare
    let matching = null;
    for (const t of user.passwordTokens) {
      if (await bcrypt.compare(token, t.tokenHash)) {
        matching = t;
        break;
      }
    }
    if (!matching) return res.status(400).json({ error: "invalid or expired token" });

    const hash = await bcrypt.hash(password, 10);
    await prisma.$transaction([
      prisma.user.update({ where: { id: user.id }, data: { passwordHash: hash } }),
      prisma.passwordToken.update({ where: { id: matching.id }, data: { usedAt: new Date() } }),
      prisma.passwordToken.deleteMany({
        where: { userId: user.id, purpose: "register", usedAt: null, NOT: { id: matching.id } },
      }),
    ]);

    // Ensure the user has an Org + owner membership (best-effort)
    const existingOrg = await prisma.org.findFirst({ where: { ownerUserId: user.id } });
    if (!existingOrg) {
      const org = await prisma.org.create({
        data: { ownerUserId: user.id, name: `Org ${user.email}` },
      });
      await prisma.member.create({ data: { userId: user.id, orgId: org.id, role: "owner" } }).catch(() => {});
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error("[register/complete] ERROR", e);
    return res.status(500).json({ error: "failed to complete registration" });
  }
});

/* =========================
   Auth: login (email + password)
========================= */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password are required" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash) return res.status(401).json({ error: "invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });

    const access = signJwt({ uid: user.id, email: user.email });
    res.json({ access, user: { id: user.id, email: user.email } });
  } catch (e) {
    console.error("[auth/login] ERROR", e);
    res.status(500).json({ error: "login failed" });
  }
});

/* =========================
   Me / entitlements (JWT required)
========================= */
function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing token" });
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}

// Resolve “premium” by looking up the Stripe subscription for the email
async function resolvePremiumByStripe(email) {
  const customers = await stripe.customers.list({ email, limit: 1 });
  if (!customers.data.length) return { premium: false };

  const customer = customers.data[0];
  const subs = await stripe.subscriptions.list({
    customer: customer.id,
    status: "all",
    limit: 10,
  });

  // active/trialing counts as premium
  const active = subs.data.find(s => ["active", "trialing"].includes(s.status));
  if (!active) return { premium: false };

  return {
    premium: true,
    currentPeriodEnd: active.current_period_end ? new Date(active.current_period_end * 1000) : null,
    status: active.status,
    subscriptionId: active.id,
  };
}

app.get("/account/me", requireAuth, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.auth.uid } });
    if (!user) return res.status(404).json({ error: "user not found" });

    const ent = await resolvePremiumByStripe(user.email);
    res.json({
      user: { id: user.id, email: user.email, createdAt: user.createdAt },
      entitlements: ent,
    });
  } catch (e) {
    console.error("[account/me] ERROR", e);
    res.status(500).json({ error: "failed to fetch account" });
  }
});

/* =========================
   Health + quick mail test
========================= */
app.get("/health", (_req, res) => {
  res.json({ ok: true, env: NODE_ENV, ts: new Date().toISOString() });
});

// GET /dev/send-test?to=email@domain.com
app.get("/dev/send-test", async (req, res) => {
  try {
    const to = req.query.to;
    if (!to) return res.status(400).json({ error: "missing ?to=" });
    await sendMail({
      to,
      subject: "Bedrock Utilities — test email",
      text: "This is a test email from your backend.",
      html: "<p>This is a <b>test email</b> from your backend.</p>",
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* =========================
   Simple success pages
========================= */
app.get("/billing/success", (_req, res) => {
  res.type("html").send("<h1>Payment success</h1><p>You can close this tab.</p>");
});
app.get("/billing/cancelled", (_req, res) => {
  res.type("html").send("<h1>Checkout cancelled</h1>");
});

/* =========================
   Start
========================= */
app.listen(Number(PORT), async () => {
  console.log(`API up on :${PORT}`);
  console.log("[env] allowed CORS:", corsOrigins);
  await verifyTransporter();
});
