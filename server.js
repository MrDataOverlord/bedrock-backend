// server.js
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import bodyParser from "body-parser"; // needed for Stripe raw body
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
  CORS_ORIGINS = "",            // comma-separated
  APP_DOMAIN = "https://bedrock-backend-ipj6.onrender.com",

  // Stripe
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
  STRIPE_PRICE_PREMIUM,

  // Registration
  // The page on your Wix site that accepts ?token=... (e.g. https://www.nerdherdmc.net/account/set-password)
  REG_URL_BASE = "https://www.nerdherdmc.net/set-password",

  // SMTP for Namescheap PrivateEmail
  SMTP_HOST = "mail.privateemail.com",
  SMTP_PORT = "465",
  SMTP_SECURE = "true", // "true" for 465, "false" for 587
  SMTP_USER,            // support@nerdherdmc.com
  SMTP_PASS,
  EMAIL_FROM            // optional, defaults to SMTP_USER
} = process.env;

// Basic env checks (fail fast, with readable errors)
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

// Security / rate-limit / CORS / logs
app.use(helmet());
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Allow your site + localhost dev
const corsOrigins = CORS_ORIGINS
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // allow curl/postman
      if (corsOrigins.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    credentials: true,
  })
);

app.use(morgan("dev"));

// IMPORTANT: Do NOT put express.json() before Stripe webhook.
// We’ll add json() after the webhook route.

// Small helpers
const signJwt = (payload, exp = "72h") =>
  jwt.sign(payload, JWT_SECRET, { expiresIn: exp });

/* =========================
   Email (Nodemailer)
========================= */
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT),
  secure: String(SMTP_SECURE).toLowerCase() === "true", // 465 -> true, 587 -> false
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

async function verifyTransporter() {
  try {
    const res = await transporter.verify();
    console.log("[mail] transporter verified:", res);
  } catch (e) {
    console.error("[mail] transporter verify FAILED:", e.message);
  }
}

async function sendMail({ to, subject, html, text }) {
  const from = EMAIL_FROM || SMTP_USER;
  try {
    const info = await transporter.sendMail({ from, to, subject, html, text });
    console.log("[mail] sent:", { to, subject, messageId: info.messageId });
    return info;
  } catch (e) {
    console.error("[mail] send FAILED:", { to, subject, error: e.message });
    throw e;
  }
}

/* =========================
   Token helpers
========================= */
async function issuePasswordToken(userId, purpose = "register", ttlMinutes = 60) {
  const raw = crypto.randomBytes(32).toString("hex");
  const tokenHash = await bcrypt.hash(raw, 10);

  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000);
  await prisma.passwordToken.create({
    data: {
      userId,
      purpose,
      tokenHash,
      expiresAt,
    },
  });

  return raw; // raw goes to email
}
 function setPasswordLink(rawToken, email) {
   // Wix page can read both query params
   const q = new URLSearchParams({
     token: rawToken,
     email
   }).toString();
   return `${REG_URL_BASE}?${q}`;
 }

/* =========================
   Stripe: Checkout
========================= */
app.post("/billing/checkout_public", express.json(), async (req, res) => {
  try {
    const { email, returnUrl } = req.body || {};
    if (!email) return res.status(400).json({ error: "email is required" });

    console.log("[checkout_public] start", { email });

    // Create or fetch user
    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      user = await prisma.user.create({
        data: { email },
      });
      console.log("[checkout_public] created user", { id: user.id, email });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer_email: email,
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      success_url:
        (returnUrl && `${returnUrl}`) || `${APP_DOMAIN}/billing/success`,
      cancel_url: `${APP_DOMAIN}/billing/cancelled`,
      allow_promotion_codes: true,
      // optional: automatic_tax, trial, etc.
    });

    console.log("[checkout_public] session created", {
      id: session.id,
      url: session.url,
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error("[checkout_public] ERROR", e);
    res.status(500).json({ error: "checkout failed" });
  }
});

/* =========================
   Stripe Webhook
========================= */
// Use raw body so we can verify Stripe signature
app.post(
  "/webhooks/stripe",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("[webhook] signature verify FAILED:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      console.log("[webhook] event:", event.type);

      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const email =
          session?.customer_details?.email || session?.customer_email;

        console.log("[webhook] checkout.session.completed", {
          session: session.id,
          email,
        });

        if (email) {
          let user = await prisma.user.findUnique({ where: { email } });
          if (!user) {
            // Very rare: we didn't pre-create in checkout_public
            user = await prisma.user.create({ data: { email } });
            console.log("[webhook] created user for email", { id: user.id });
          }

          // If no password yet, issue token + email the user
          if (!user.passwordHash) {
            const rawToken = await issuePasswordToken(user.id, "register", 120); // 2h TTL
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

        console.log("[webhook] invoice.payment_failed", {
          invoice: invoice.id,
          email,
        });

        if (email) {
          await sendMail({
            to: email,
            subject: "Payment failed — subscription on hold",
            text:
              "Your recent payment failed and your premium access is on hold. " +
              "Please update your payment method in the Billing Portal to restore access.",
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
        // (Optional) update your Subscription table with next period end using invoice.lines/subscription info.
      }

      // Always 200 so Stripe doesn't retry unless we truly had a bad signature above
      return res.json({ received: true });
    } catch (err) {
      console.error("[webhook] handler ERROR:", err);
      // Still return 200 to stop endless retries; everything important is logged.
      return res.json({ received: true });
    }
  }
);

// JSON parser for the rest of routes (after webhook)
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

    // Find a matching token (bcrypt compare)
    let matching = null;
    for (const t of user.passwordTokens) {
      const ok = await bcrypt.compare(token, t.tokenHash);
      if (ok) {
        matching = t;
        break;
      }
    }
    if (!matching) return res.status(400).json({ error: "invalid or expired token" });

    // Set password
    const hash = await bcrypt.hash(password, 10);
    await prisma.$transaction([
      prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: hash },
      }),
      prisma.passwordToken.update({
        where: { id: matching.id },
        data: { usedAt: new Date() },
      }),
      // Optional: invalidate any other outstanding register tokens
      prisma.passwordToken.deleteMany({
        where: {
          userId: user.id,
          purpose: "register",
          usedAt: null,
          NOT: { id: matching.id },
        },
      }),
    ]);

    // Optional: ensure they have an Org + owner membership
    const existingOrg = await prisma.org.findFirst({ where: { ownerUserId: user.id } });
    if (!existingOrg) {
      const org = await prisma.org.create({
        data: {
          ownerUserId: user.id,
          name: `Org ${user.email}`,
        },
      });
      // best-effort create membership (ignore unique dup)
      await prisma.member.create({
        data: { userId: user.id, orgId: org.id, role: "owner" },
      }).catch(() => {});
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error("[register/complete] ERROR", e);
    return res.status(500).json({ error: "failed to complete registration" });
  }
});


/* =========================
   Health + Debug mail
========================= */
app.get("/health", (_req, res) => {
  res.json({ ok: true, env: NODE_ENV, ts: new Date().toISOString() });
});

// Quick functional test for the mailer without Stripe
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
   Success pages (basic)
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
app.listen(PORT, async () => {
  console.log(`API up on :${PORT}`);
  console.log("[env] allowed CORS:", corsOrigins);
  await verifyTransporter();
});
