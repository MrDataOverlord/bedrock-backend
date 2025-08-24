// server.js
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import Stripe from 'stripe';
import rateLimit from 'express-rate-limit';
import { PrismaClient } from '@prisma/client';

// ---------- env ----------
const {
  DATABASE_URL,
  JWT_SECRET,
  CORS_ORIGINS,
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
  STRIPE_PRICE_PREMIUM,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASS,
  REG_URL_BASE, // e.g. https://www.nerdherdmc.net/set-password
  PORT = 10000,
  NODE_ENV = 'production',
} = process.env;

if (!JWT_SECRET) throw new Error('JWT_SECRET is required');
if (!STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY is required');
if (!STRIPE_WEBHOOK_SECRET) throw new Error('STRIPE_WEBHOOK_SECRET is required');
if (!STRIPE_PRICE_PREMIUM) throw new Error('STRIPE_PRICE_PREMIUM is required');

// ---------- init ----------
const app = express();
app.set('trust proxy', 1); // behind Render; silences rate-limit warning re: x-forwarded-for

const prisma = new PrismaClient();
const stripe = new Stripe(STRIPE_SECRET_KEY);

// Health is plain
app.use('/health', (req, res, next) => next());

// CORS
const allowed = (CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin || allowed.length === 0 || allowed.includes(origin)) return cb(null, true);
      return cb(new Error('Not allowed by CORS: ' + origin));
    },
    credentials: true,
  })
);

// Rate‑limit (skip health & webhooks)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health' || req.path.startsWith('/webhooks/'),
});
app.use(limiter);

// ---------- utilities ----------
function log(...args) { console.log(...args); }

function signAccess(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '12h' });
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const [, token] = h.split(' ');
    if (!token) return res.status(401).json({ error: 'Missing bearer token' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// --- SMTP transporter ---
let transporter = null;
(async () => {
  if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT || 465),
      secure: String(SMTP_SECURE || 'true') === 'true',
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
    try { await transporter.verify(); log('[mail] transporter verified: true'); }
    catch (e) { log('[mail] transporter verify failed:', e?.message); }
  } else {
    log('[mail] SMTP_* env not fully configured; email will be disabled.');
  }
})();

async function issueRegistrationToken(userId) {
  const raw = crypto.randomBytes(32).toString('hex');
  const tokenHash = await bcrypt.hash(raw, 10);
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24); // 24h

  await prisma.passwordToken.create({
    data: { userId, tokenHash, purpose: 'register', expiresAt },
  });
  return raw;
}

async function sendRegistrationEmail(email, rawToken) {
  if (!transporter) { log('[mail] transporter missing, cannot send'); return; }
  const base = (REG_URL_BASE || '').replace(/\/+$/, '');
  const url = `${base}?token=${encodeURIComponent(rawToken)}&email=${encodeURIComponent(email)}`;
  const info = await transporter.sendMail({
    from: SMTP_USER,
    to: email,
    subject: 'Set your Bedrock Utilities password',
    html: `<p>Click to set your password:</p><p><a href="${url}">${url}</a></p>`,
  });
  log('[mail] sent:', email, 'messageId:', info.messageId);
}

// ---------- Stripe raw body handling ----------
// Keep global JSON parsing, but preserve the raw payload for Stripe signature verification.
app.use(express.json({
  verify: (req, _res, buf) => {
    if (req.originalUrl === '/webhooks/stripe') {
      // @ts-ignore
      req.rawBody = buf; // Buffer
    }
  }
}));

// ---------- Org / Member / Subscription helpers ----------

function isPremium(status, end) {
  const s = String(status || '').toLowerCase();
  return (s === 'active' || s === 'trialing') && end instanceof Date && end.getTime() > Date.now();
}

async function ensureOrgAndMember({ userId, customerId, customerName, email }) {
  // Find or create Org by Stripe customer
  let org = await prisma.org.findFirst({ where: { stripeCustomerId: customerId } });
  if (!org) {
    const fallbackName = customerName || (email ? `${email.split('@')[0]}'s Org` : 'Account');
    org = await prisma.org.create({
      data: { name: fallbackName, stripeCustomerId: customerId, ownerUserId: userId || null }
    });
  }

  // Ensure membership (owner if first)
  if (userId) {
    try {
      await prisma.member.upsert({
        where: { orgId_userId: { orgId: org.id, userId } },
        update: {},
        create: { orgId: org.id, userId, role: 'owner' }
      });
    } catch {
      const exists = await prisma.member.findFirst({ where: { orgId: org.id, userId } });
      if (!exists) await prisma.member.create({ data: { orgId: org.id, userId, role: 'owner' } });
    }
  }
  return org;
}

async function upsertSubscription({ orgId, sub }) {
  const end = sub.current_period_end ? new Date(sub.current_period_end * 1000) : null;
  const id = `stripe_${sub.id}`;
  await prisma.subscription.upsert({
    where: { id },
    create: {
      id,
      orgId,
      provider: 'stripe',        // ignore if your schema doesn’t have this field
      status: sub.status,
      currentPeriodEnd: end,
      customerId: typeof sub.customer === 'string' ? sub.customer : sub.customer?.id
    },
    update: { status: sub.status, currentPeriodEnd: end }
  });
}

async function getStripeCustomer(customerId) {
  try { return await stripe.customers.retrieve(customerId); }
  catch { return null; }
}

// ---------- public endpoints ----------

// Basic health
app.get('/health', (req, res) => {
  res.json({ ok: true, env: NODE_ENV, ts: new Date().toISOString() });
});

// Login: { email, password } -> { access }
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !user.passwordHash) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const access = signAccess(user);
  res.json({ access });
});

// Complete registration: { email, token, password }
app.post('/auth/register/complete', async (req, res) => {
  const { email, token, password } = req.body || {};
  if (!email || !token || !password) return res.status(400).json({ error: 'Missing fields' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(400).json({ error: 'User not found' });
  if (user.passwordHash) return res.status(400).json({ error: 'Password already set' });

  const tok = await prisma.passwordToken.findFirst({
    where: {
      userId: user.id,
      purpose: 'register',
      usedAt: null,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
  });
  if (!tok) return res.status(400).json({ error: 'Token not found or expired' });

  const ok = await bcrypt.compare(token, tok.tokenHash);
  if (!ok) return res.status(400).json({ error: 'Invalid token' });

  const hash = await bcrypt.hash(password, 10);
  await prisma.$transaction([
    prisma.user.update({ where: { id: user.id }, data: { passwordHash: hash } }),
    prisma.passwordToken.update({ where: { id: tok.id }, data: { usedAt: new Date() } }),
  ]);

  res.json({ ok: true });
});

// Manual re-send registration email (only if password is not set yet)
app.post('/auth/register/resend', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Missing email' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(200).json({ ok: true }); // do not reveal
  if (user.passwordHash) return res.status(200).json({ ok: true, note: 'already_has_password' });

  const raw = await issueRegistrationToken(user.id);
  await sendRegistrationEmail(user.email, raw);
  res.json({ ok: true });
});

// ---------- Entitlements (user + orgs + premium) ----------
async function getEntitlementsPayload(userId) {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  const orgsRaw = await prisma.org.findMany({
    where: {
      OR: [
        { ownerUserId: userId },
        { members: { some: { userId } } },
      ],
    },
    select: {
      id: true, name: true,
      subscriptions: {
        orderBy: { updatedAt: 'desc' },
        take: 1,
        select: { status: true, currentPeriodEnd: true }
      }
    },
  });

  const orgs = orgsRaw.map(o => {
    const sub = o.subscriptions[0];
    const premium = sub ? isPremium(sub.status, sub.currentPeriodEnd) : false;
    return {
      id: o.id,
      name: o.name,
      premium,
      status: sub?.status || 'none',
      currentPeriodEnd: sub?.currentPeriodEnd ? sub.currentPeriodEnd.toISOString() : null,
    };
  });

  return { user: { id: user.id, email: user.email }, orgs };
}

app.get('/account/me', auth, async (req, res) => {
  const payload = await getEntitlementsPayload(req.user.sub);
  res.json(payload);
});
app.get('/entitlements', auth, async (req, res) => {
  const payload = await getEntitlementsPayload(req.user.sub);
  res.json(payload);
});

// ---------- Public checkout (Wix -> backend -> Stripe) ----------
app.post('/billing/checkout_public', async (req, res) => {
  try {
    const { email, returnUrl } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: email,
      success_url: returnUrl || 'https://bedrock-backend-ipj6.onrender.com/billing/success',
      cancel_url: returnUrl || 'https://bedrock-backend-ipj6.onrender.com/billing/cancel',
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      allow_promotion_codes: true,
    });

    res.json({ url: session.url, id: session.id });
  } catch (e) {
    log('[checkout_public] error:', e?.message);
    res.status(500).json({ error: 'Checkout failed' });
  }
});

app.get('/billing/success', (req, res) => res.send('Payment success\nYou can close this tab.'));
app.get('/billing/cancel', (req, res) => res.send('Payment canceled'));

// ---------- Stripe webhooks ----------
// NOTE: We rely on req.rawBody set by the global express.json { verify } above.
app.post('/webhooks/stripe', async (req, res) => {
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    // @ts-ignore
    const raw = req.rawBody;
    event = stripe.webhooks.constructEvent(raw, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    log('[webhook] signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const s = event.data.object;
        const email = s.customer_details?.email || s.customer_email;
        if (!email) break;

        // Ensure user exists
        let user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
          user = await prisma.user.create({ data: { email } });
          log('[webhook] created user:', email);
        }

        // Send registration email if password not set
        if (!user.passwordHash) {
          const raw = await issueRegistrationToken(user.id);
          await sendRegistrationEmail(email, raw);
          log('[webhook] sent registration email:', email);
        } else {
          log('[webhook] user already has a password; no email sent');
        }

        // Ensure Org + Member, then upsert Subscription (if present)
        const customerId = s.customer;
        if (customerId) {
          const cust = await getStripeCustomer(customerId);
          const org = await ensureOrgAndMember({
            userId: user.id, customerId, customerName: cust?.name, email
          });

          if (s.subscription) {
            const subId = typeof s.subscription === 'string' ? s.subscription : s.subscription.id;
            const sub = await stripe.subscriptions.retrieve(subId);
            await upsertSubscription({ orgId: org.id, sub });
          }
        }
        break;
      }

      case 'customer.subscription.created':
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const customerId = sub.customer;
        if (!customerId) break;

        const cust = await getStripeCustomer(customerId);
        const email = cust?.email;

        // user may not exist yet (guest checkout)
        let user = email ? await prisma.user.findUnique({ where: { email } }) : null;
        if (!user && email) user = await prisma.user.create({ data: { email } });

        const org = await ensureOrgAndMember({
          userId: user?.id ?? undefined,
          customerId,
          customerName: cust?.name,
          email
        });

        await upsertSubscription({ orgId: org.id, sub });
        break;
      }

      case 'invoice.payment_succeeded':
      case 'invoice.payment_failed': {
        // Optional: could refresh Subscription from sub id on the invoice.
        break;
      }

      default:
        break;
    }
  } catch (e) {
    log('[webhook] handler error:', e);
  }

  res.json({ received: true });
});

// ---------- start ----------
app.listen(PORT, () => {
  log(`API up on :${PORT}`);
  log('[env] allowed CORS:', allowed);
});
