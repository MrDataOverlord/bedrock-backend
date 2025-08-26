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
app.set('trust proxy', 1);

const prisma = new PrismaClient();
const stripe = new Stripe(STRIPE_SECRET_KEY);

// Health is plain (skip body parsing & rate limits here)
app.use('/health', (_req, _res, next) => next());

// CORS
const allowed = (CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowed.length === 0 || allowed.includes(origin)) return cb(null, true);
      cb(new Error('Not allowed by CORS: ' + origin));
    },
    credentials: true,
  })
);

// Rate-limit (skip health & webhooks)
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 120,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/health' || req.path.startsWith('/webhooks/'),
  })
);

// ---------- utilities ----------
const log = (...a) => console.log(...a);

const signAccess = (user) =>
  jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '12h' });

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

// ---------- SMTP ----------
let transporter = null;
(async () => {
  if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: Number(SMTP_PORT || 465),
      secure: String(SMTP_SECURE || 'true') === 'true',
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
    try {
      await transporter.verify();
      log('[mail] transporter verified: true');
    } catch (e) {
      log('[mail] transporter verify failed:', e?.message);
    }
  } else {
    log('[mail] SMTP_* not fully configured; email disabled.');
  }
})();

// ---------- one-time token helpers ----------
async function invalidateTokensFor(userId, purpose) {
  await prisma.passwordToken.updateMany({
    where: { userId, purpose, usedAt: null },
    data: { usedAt: new Date() },
  });
}

async function issueRegistrationToken(userId) {
  await invalidateTokensFor(userId, 'register');
  const raw = crypto.randomBytes(32).toString('hex');
  const tokenHash = await bcrypt.hash(raw, 10);
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24); // 24h
  await prisma.passwordToken.create({
    data: { userId, tokenHash, purpose: 'register', expiresAt },
  });
  return raw;
}

async function sendRegistrationEmail(email, rawToken) {
  if (!transporter) {
    log('[mail] transporter missing, cannot send');
    return;
  }
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

// ---------- Stripe raw-body ----------
// Keep JSON for everything but also retain raw buffer for the webhook signature check.
app.use(
  express.json({
    verify: (req, _res, buf) => {
      if (req.originalUrl === '/webhooks/stripe') {
        // @ts-ignore
        req.rawBody = buf;
      }
    },
  })
);

// ---------- Org / Member / Subscription ----------
function isPremium(status, end) {
  const s = String(status || '').toLowerCase();
  return (s === 'active' || s === 'trialing') && end instanceof Date && end.getTime() > Date.now();
}

// fetch a customer but never throw (simplifies webhook logic)
async function getStripeCustomer(customerId) {
  try {
    return await stripe.customers.retrieve(customerId);
  } catch (_e) {
    return null;
  }
}

async function ensureOrgAndMember({ userId, customerId, customerName, email }) {
  if (!customerId) throw new Error('ensureOrgAndMember: missing customerId');

  let org = await prisma.org.findFirst({ where: { stripeCustomerId: customerId } });

  if (!org) {
    const fallbackName = customerName || (email ? `${String(email).split('@')[0]}'s Org` : 'Account');
    org = await prisma.org.create({
      data: {
        name: fallbackName,
        stripeCustomerId: customerId,
        ownerUserId: userId ?? null,
      },
    });
    console.log('[org] created', org.id, 'cust:', customerId);
  } else if (userId && !org.ownerUserId) {
    org = await prisma.org.update({ where: { id: org.id }, data: { ownerUserId: userId } });
    console.log('[org] repaired owner', org.id, '->', userId);
  }

  if (userId) {
    await prisma.member.upsert({
      where: { orgId_userId: { orgId: org.id, userId } },
      update: {},
      create: { orgId: org.id, userId, role: 'owner' },
    });
    console.log('[member] ensured link user', userId, 'org', org.id);
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
      provider: 'stripe',
      status: sub.status,
      currentPeriodEnd: end,
      customerId: typeof sub.customer === 'string' ? sub.customer : sub.customer?.id,
    },
    update: { status: sub.status, currentPeriodEnd: end },
  });
}

// ---------- public endpoints ----------
app.get('/health', (_req, res) => {
  res.json({ ok: true, env: NODE_ENV, ts: new Date().toISOString() });
});

// Auth
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !user.passwordHash) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ access: signAccess(user) });
});

// Registration complete
app.post('/auth/register/complete', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Missing fields' });

  const tok = await prisma.passwordToken.findFirst({
    where: { purpose: 'register', usedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: 'desc' },
  });
  if (!tok) return res.status(400).json({ error: 'Token not found or expired' });

  const ok = await bcrypt.compare(token, tok.tokenHash);
  if (!ok) return res.status(400).json({ error: 'Invalid token' });

  const user = await prisma.user.findUnique({ where: { id: tok.userId } });
  if (!user) return res.status(400).json({ error: 'User not found' });
  if (user.passwordHash) return res.status(400).json({ error: 'Password already set' });

  const hash = await bcrypt.hash(password, 10);
  await prisma.$transaction([
    prisma.user.update({ where: { id: user.id }, data: { passwordHash: hash } }),
    prisma.passwordToken.update({ where: { id: tok.id }, data: { usedAt: new Date() } }),
  ]);

  res.json({ ok: true });
});

// Registration resend / start
app.post('/auth/register/resend', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Missing email' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(200).json({ ok: true });
  if (user.passwordHash) return res.status(200).json({ ok: true, note: 'already_has_password' });

  const raw = await issueRegistrationToken(user.id);
  await sendRegistrationEmail(user.email, raw);
  res.json({ ok: true });
});

app.post('/auth/register/start', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });

    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) user = await prisma.user.create({ data: { email } });

    if (user.passwordHash) return res.json({ ok: true, note: 'already_has_password' });

    const raw = await issueRegistrationToken(user.id);
    await sendRegistrationEmail(user.email, raw);
    res.json({ ok: true });
  } catch (e) {
    console.error('[register/start] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to start registration', detail: e?.message });
  }
});

// Reset start / complete
app.post('/auth/reset/start', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Missing email' });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.json({ ok: true });

  await invalidateTokensFor(user.id, 'reset');

  const raw = crypto.randomBytes(32).toString('hex');
  const tokenHash = await bcrypt.hash(raw, 10);
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24);
  await prisma.passwordToken.create({
    data: { userId: user.id, tokenHash, purpose: 'reset', expiresAt },
  });

  if (transporter) {
    const base = (REG_URL_BASE || '').replace(/\/+$/, '');
    const url = `${base}?token=${encodeURIComponent(raw)}&email=${encodeURIComponent(
      email
    )}&mode=reset`;
    await transporter.sendMail({
      from: SMTP_USER,
      to: email,
      subject: 'Reset your Bedrock Utilities password',
      html: `<p>Click to reset your password:</p><p><a href="${url}">${url}</a></p>`,
    });
  } else {
    log('[mail] reset requested but SMTP not configured');
  }

  res.json({ ok: true });
});

app.post('/auth/reset/complete', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).json({ error: 'Missing fields' });

  const tok = await prisma.passwordToken.findFirst({
    where: { purpose: 'reset', usedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: 'desc' },
  });
  if (!tok) return res.status(400).json({ error: 'Token not found or expired' });

  const ok = await bcrypt.compare(token, tok.tokenHash);
  if (!ok) return res.status(400).json({ error: 'Invalid token' });

  const hash = await bcrypt.hash(newPassword, 10);
  await prisma.$transaction([
    prisma.user.update({ where: { id: tok.userId }, data: { passwordHash: hash } }),
    prisma.passwordToken.update({ where: { id: tok.id }, data: { usedAt: new Date() } }),
  ]);

  res.json({ ok: true });
});
// ----- Entitlements (robust) -----
async function getEntitlementsPayload(userId) {
  const now = new Date();

  // Pull the orgs the user owns or belongs to, and *only* the subs that are truly active
  const orgsRaw = await prisma.org.findMany({
    where: {
      OR: [
        { ownerUserId: userId },
        { members: { some: { userId } } },
      ],
    },
    select: {
      id: true,
      name: true,
      subscriptions: {
        where: {
          status: { in: ['active', 'trialing'] },
          currentPeriodEnd: { gt: now },
        },
        orderBy: { currentPeriodEnd: 'desc' },
        take: 1, // the best/farthest-valid one is enough
        select: {
          status: true,
          currentPeriodEnd: true,
        },
      },
    },
  });

  const orgs = orgsRaw.map(o => {
    const sub = o.subscriptions[0] || null;
    const premium = !!sub; // by construction, sub implies active/trialing & future end
    return {
      id: o.id,
      name: o.name,
      premium,
      status: sub?.status || 'none',
      currentPeriodEnd: sub?.currentPeriodEnd ? sub.currentPeriodEnd.toISOString() : null,
    };
  });

  return { user: { id: userId }, orgs };
}

// DEBUG: GET /__debug/entitlements?email=...&key=...
app.get('/__debug/entitlements', async (req, res) => {
  try {
    if (process.env.DEBUG_KEY && req.query.key !== process.env.DEBUG_KEY) {
      return res.status(403).json({ error: 'forbidden' });
    }
    const email = String(req.query.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'missing email' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'user not found' });

    const payload = await getEntitlementsPayload(user.id);
    res.json(payload);
  } catch (e) {
    console.error('[__debug/entitlements] error:', e);
    res.status(500).json({ error: 'debug failed', detail: e?.message });
  }
});


app.get('/account/me', auth, async (req, res) => {
  res.json(await getEntitlementsPayload(req.user.sub));
});
app.get('/entitlements', auth, async (req, res) => {
  res.json(await getEntitlementsPayload(req.user.sub));
});

// ----- Checkout (subscription) -----
app.post('/billing/checkout_public', async (req, res) => {
  try {
    const { email, returnUrl } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email required' });

    const successUrl =
      (returnUrl && String(returnUrl)) || 'https://www.nerdherdmc.net/new-account';
    const cancelUrl = 'https://www.nerdherdmc.net/accounts';

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: email, // (auto-creates a Customer if needed)
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      success_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancelUrl,
      allow_promotion_codes: true,
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error('[checkout_public] stripe error:', e);
    res.status(500).json({ error: 'stripe_error' });
  }
});

// ----- Price sanity check -----
app.get('/billing/price_check', async (_req, res) => {
  try {
    const p = await stripe.prices.retrieve(STRIPE_PRICE_PREMIUM);
    res.json({
      id: p.id,
      active: p.active,
      currency: p.currency,
      type: p.type,
      recurring: p.recurring || null,
      product: typeof p.product === 'string' ? p.product : p.product?.id,
    });
  } catch (e) {
    console.error('[price_check] error:', e?.message);
    res.status(500).json({ error: e?.message || 'price check failed' });
  }
});

app.get('/billing/success', (_req, res) => res.send('Payment success\nYou can close this tab.'));
app.get('/billing/cancel', (_req, res) => res.send('Payment canceled'));

// ---------- Stripe webhooks ----------
app.post('/webhooks/stripe', async (req, res) => {
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    // @ts-ignore
    const raw = req.rawBody;
    event = stripe.webhooks.constructEvent(raw, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('[webhook] signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    console.log('[webhook] received:', event.type, event.id);

    switch (event.type) {
      case 'checkout.session.completed': {
        const s = event.data.object;
        const email = s.customer_details?.email || s.customer_email;
        console.log('[webhook] session.completed for email:', email, 'sub:', s.subscription);

        if (!email) break;

        // Ensure user
        let user = await prisma.user.findUnique({ where: { email } });
        if (!user) user = await prisma.user.create({ data: { email } });

        // Registration email if they don't have a password yet
        if (!user.passwordHash) {
          try {
            const rawTok = await issueRegistrationToken(user.id);
            await sendRegistrationEmail(email, rawTok);
            console.log('[webhook] registration email queued to:', email);
          } catch (mailErr) {
            console.error('[webhook] email send failed:', mailErr?.message || mailErr);
          }
        }

        // Sync org + subscription
        const customerId = s.customer;
        if (customerId) {
          const cust = await getStripeCustomer(customerId);
          const org = await ensureOrgAndMember({
            userId: user.id,
            customerId,
            customerName: cust?.name,
            email,
          });

          if (s.subscription) {
            const subId = typeof s.subscription === 'string' ? s.subscription : s.subscription.id;
            const sub = await stripe.subscriptions.retrieve(subId);
            await upsertSubscription({ orgId: org.id, sub });
            console.log('[webhook] sub upserted:', subId, 'status:', sub.status);
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

        let user = email ? await prisma.user.findUnique({ where: { email } }) : null;
        if (!user && email) user = await prisma.user.create({ data: { email } });

        const org = await ensureOrgAndMember({
          userId: user?.id ?? undefined,
          customerId,
          customerName: cust?.name,
          email,
        });

        await upsertSubscription({ orgId: org.id, sub });
        console.log('[webhook] sub sync:', sub.id, 'status:', sub.status);
        break;
      }

      default:
        break;
    }
  } catch (e) {
    console.error('[webhook] handler error:', e);
  }

  res.json({ received: true });
});

// ---------- start ----------
app.listen(PORT, () => {
  log(`API up on :${PORT}`);
  log('[env] allowed CORS:', allowed);
});
