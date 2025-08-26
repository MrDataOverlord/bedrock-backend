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

// Health is plain
app.use('/health', (req, res, next) => next());

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

// Rate‑limit (skip health & webhooks)
app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health' || req.path.startsWith('/webhooks/'),
}));

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
    try { await transporter.verify(); log('[mail] transporter verified: true'); }
    catch (e) { log('[mail] transporter verify failed:', e?.message); }
  } else {
    log('[mail] SMTP_* not fully configured; email disabled.');
  }
})();

// ---------- one-time token helpers ----------
async function invalidateTokensFor(userId, purpose) {
  await prisma.passwordToken.updateMany({
    where: { userId, purpose, usedAt: null },
    data:  { usedAt: new Date() }
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

// ---------- Stripe raw-body ----------
app.use(express.json({
  verify: (req, _res, buf) => {
    if (req.originalUrl === '/webhooks/stripe') {
      // @ts-ignore
      req.rawBody = buf;
    }
  }
}));

// ---------- Org / Member / Subscription ----------
function isPremium(status, end) {
  const s = String(status || '').toLowerCase();
  return (s === 'active' || s === 'trialing') && end instanceof Date && end.getTime() > Date.now();
}
async function ensureOrgAndMember({ userId, customerId, customerName, email }) {
  if (!customerId) throw new Error('ensureOrgAndMember: missing customerId');

  // Find/create org by Stripe Customer
  let org = await prisma.org.findFirst({ where: { stripeCustomerId: customerId } });

  if (!org) {
    const fallbackName =
      customerName || (email ? `${String(email).split('@')[0]}'s Org` : 'Account');

    org = await prisma.org.create({
      data: {
        name: fallbackName,
        stripeCustomerId: customerId,
        // ownerUserId may be null here; we’ll fix just below if we have a userId
        ownerUserId: userId ?? null,
      },
    });
    console.log('[org] created', org.id, 'cust:', customerId);
  } else if (userId && !org.ownerUserId) {
    // Repair: latch owner if missing
    org = await prisma.org.update({
      where: { id: org.id },
      data: { ownerUserId: userId },
    });
    console.log('[org] repaired owner', org.id, '->', userId);
  }

  // If we know the user, be sure they’re a member
  if (userId) {
    // This relies on the composite unique on (orgId, userId) in your schema
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
      customerId: typeof sub.customer === 'string' ? sub.customer : sub.customer?.id
    },
    update: { status: sub.status, currentPeriodEnd: end }
  });
}

// ---------- public endpoints ----------
app.get('/health', (req, res) => {
  res.json({ ok: true, env: NODE_ENV, ts: new Date().toISOString() });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !user.passwordHash) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ access: signAccess(user) });
});

// ----- Registration completion (token-anchored, ignores email) -----
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

// ----- Resend registration email (if no password yet) -----
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

// ----- Manual start registration (recovery path / resend button) -----
app.post('/auth/register/start', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });

    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) user = await prisma.user.create({ data: { email } });

    if (user.passwordHash) {
      return res.json({ ok: true, note: 'already_has_password' });
    }

    const raw = await issueRegistrationToken(user.id);
    await sendRegistrationEmail(user.email, raw);
    res.json({ ok: true });
  } catch (e) {
    console.error('[register/start] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to start registration', detail: e?.message });
  }
});

// ----- Forgot password (start) -----
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
    const url = `${base}?token=${encodeURIComponent(raw)}&email=${encodeURIComponent(email)}&mode=reset`;
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

// ----- Forgot password (complete) – token-anchored -----
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

// ----- Entitlements -----
async function getEntitlementsPayload(userId) {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  // current read
  let orgsRaw = await prisma.org.findMany({
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

  // --- NEW: self-heal if the user has no orgs but Stripe has a customer for their email ---
  if (!orgsRaw.length && user?.email) {
    try {
      const list = await stripe.customers.list({ email: user.email, limit: 1 });
      const cust = list.data?.[0];
      if (cust?.id) {
        // create/link an org, and upsert the active sub if present
        const org = await ensureOrgAndMember({
          userId,
          customerId: cust.id,
          customerName: cust.name,
          email: user.email
        });

        // If a subscription exists, upsert it too (best-effort)
        if (cust.subscriptions?.data?.length) {
          const activeSub = cust.subscriptions.data[0];
          await upsertSubscription({ orgId: org.id, sub: activeSub });
        }

        // re-read orgs after linking
        orgsRaw = await prisma.org.findMany({
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
      }
    } catch (e) {
      console.error('[entitlements self-heal] failed:', e?.message || e);
    }
  }
  // --- END NEW ---

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
  res.json(await getEntitlementsPayload(req.user.sub));
});
app.get('/entitlements', auth, async (req, res) => {
  res.json(await getEntitlementsPayload(req.user.sub));
});

// POST /billing/checkout_public
app.post('/billing/checkout_public', async (req, res) => {
  try {
    const { email, returnUrl } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email required' });

    const successUrl = (returnUrl && String(returnUrl)) || 'https://www.nerdherdmc.net/new-account';
    const cancelUrl  = 'https://www.nerdherdmc.net/accounts';

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: email,   // Stripe will auto-create a customer if one doesn't exist
      line_items: [
        {
          price: process.env.STRIPE_PRICE_PREMIUM, // must be a valid recurring price ID
          quantity: 1,
        },
      ],
      success_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancelUrl,
      allow_promotion_codes: true,
    });

    return res.json({ url: session.url });
  } catch (e) {
    console.error('[checkout_public] error:', e);
    return res.status(500).json({ error: 'Checkout failed' });
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
      product: typeof p.product === 'string' ? p.product : p.product?.id
    });
  } catch (e) {
    console.error('[price_check] error:', e?.message);
    res.status(500).json({ error: e?.message || 'price check failed' });
  }
});

app.get('/billing/success', (_req, res) => res.send('Payment success\nYou can close this tab.'));
app.get('/billing/cancel',  (_req, res) => res.send('Payment canceled'));

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

  try { console.log('[webhook] received:', event.type, event.id); } catch {}

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const s = event.data.object;
        const email = s.customer_details?.email || s.customer_email;
        console.log('[webhook] session.completed for email:', email, 'sub:', s.subscription);

        if (!email) break;

        // Ensure user
        let user = await prisma.user.findUnique({ where: { email } });
        if (!user) user = await prisma.user.create({ data: { email } });

        // Registration mail if needed (one-time token behavior)
        if (!user.passwordHash) {
          try {
            const rawTok = await issueRegistrationToken(user.id);
            await sendRegistrationEmail(email, rawTok);
            console.log('[webhook] registration email queued to:', email);
          } catch (mailErr) {
            console.error('[webhook] email send failed:', mailErr?.message || mailErr);
          }
        }

        // Org/Member/Subscription sync
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
          email
        });

        await upsertSubscription({ orgId: org.id, sub });
        console.log('[webhook] sub sync:', sub.id, 'status:', sub.status);
        break;
      }

      case 'invoice.payment_succeeded':
      case 'invoice.payment_failed':
        // Optional: refresh via invoice.subscription
        break;

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
