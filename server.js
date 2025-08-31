// server.js
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
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
  CORS_ORIGINS,                 // comma-separated (use your wix origins)
  STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET,
  STRIPE_PRICE_PREMIUM,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASS,
  REG_URL_BASE,                 // e.g. https://www.nerdherdmc.net/set-password
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

// security headers
app.use(helmet({
  contentSecurityPolicy: false, // wix + external assets; keep CSP off here
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// Health must be reachable without body parsing
app.get('/health', (_req, res) => res.json({ ok: true, env: NODE_ENV, ts: new Date().toISOString() }));

// CORS
const allowed = (CORS_ORIGINS || 'https://nerdherdmc.net,https://www.nerdherdmc.net')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowed.length === 0 || allowed.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS: ' + origin));
  },
  credentials: true,
}));

// JSON (note: raw body for stripe is handled below)
app.use(express.json());

// Rate-limit (skip webhooks)
app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/webhooks/stripe',
}));

// ---------- utilities ----------
const log = (...a) => console.log(...a);
const normEmail = (s) => String(s || '').trim().toLowerCase();
const isEmail = (s) => !!normEmail(s).match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);

const signAccess = (user) =>
  jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '12h' });

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const [, token] = h.split(' ');
    if (!token) return res.status(401).json({ error: 'missing_token' });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'invalid_token' });
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

async function emailLink(to, subject, url) {
  if (!transporter) { log('[mail] not configured'); return; }
  await transporter.sendMail({
    from: SMTP_USER,
    to,
    subject,
    html: `<p><a href="${url}">${url}</a></p>`,
  });
}

// ---------- token helpers (selector + verifier) ----------
/*
  We store:
    selector: random 16 bytes (hex), unique, NOT secret
    tokenHash: bcrypt( verifier ) where verifier is random 32 bytes (hex)
  Link contains both as "t=<selector>.<verifier>"
*/
function parseSelectorToken(raw) {
  // raw = "selector.verifier"
  if (!raw || typeof raw !== 'string' || !raw.includes('.')) return null;
  const [selector, verifier] = raw.split('.', 2);
  if (!selector || !verifier) return null;
  return { selector, verifier };
}

async function invalidateTokensFor(userId, purpose) {
  await prisma.passwordToken.updateMany({
    where: { userId, purpose, usedAt: null },
    data:  { usedAt: new Date() }
  });
}

async function issueToken(userId, purpose) {
  await invalidateTokensFor(userId, purpose);
  const selector = crypto.randomBytes(16).toString('hex');
  const verifier = crypto.randomBytes(32).toString('hex');
  const tokenHash = await bcrypt.hash(verifier, 10);
  const expiresAt = new Date(Date.now() + 24 * 3600 * 1000);
  await prisma.passwordToken.create({
    data: { userId, selector, tokenHash, purpose, expiresAt }
  });
  return `${selector}.${verifier}`;
}

async function findAndConsumeToken(raw, purpose) {
  const st = parseSelectorToken(raw);
  if (!st) return null;
  const tok = await prisma.passwordToken.findUnique({ where: { selector: st.selector } });
  if (!tok || tok.purpose !== purpose || tok.usedAt || tok.expiresAt < new Date()) return null;
  const ok = await bcrypt.compare(st.verifier, tok.tokenHash);
  if (!ok) return null;
  await prisma.passwordToken.update({ where: { id: tok.id }, data: { usedAt: new Date() } });
  return tok;
}

// ---------- Stripe raw-body for webhook ----------
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('[webhook] signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try { console.log('[webhook] received:', event.type, event.id); } catch {}

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const s = event.data.object;
        const email = normEmail(s.customer_details?.email || s.customer_email);
        if (!email) break;

        // user (create if missing)
        let user = await prisma.user.findUnique({ where: { email } });
        if (!user) user = await prisma.user.create({ data: { email } });

        // invite to set password if needed
        if (!user.passwordHash) {
          try {
            const token = await issueToken(user.id, 'register');
            const base = (REG_URL_BASE || '').replace(/\/+$/, '');
            const url  = `${base}?t=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
            await emailLink(email, 'Set your Bedrock Utilities password', url);
            console.log('[webhook] registration email queued to:', email);
          } catch (mailErr) {
            console.error('[webhook] email send failed:', mailErr?.message || mailErr);
          }
        }

        // sync org + sub
        const customerId = s.customer;
        if (customerId) {
          const cust = await safeGetCustomer(customerId);
          const org  = await ensureOrgAndMember({ userId: user.id, customerId, customerName: cust?.name, email });
          if (s.subscription) {
            const subId = typeof s.subscription === 'string' ? s.subscription : s.subscription.id;
            const sub   = await stripe.subscriptions.retrieve(subId);
            await upsertSubscription({ orgId: org.id, sub });
            console.log('[webhook] upsert sub', subId, 'status', sub.status);
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

        const cust  = await safeGetCustomer(customerId);
        const email = cust?.email ? normEmail(cust.email) : null;

        let user = email ? await prisma.user.findUnique({ where: { email } }) : null;
        if (!user && email) user = await prisma.user.create({ data: { email } });

        const org = await ensureOrgAndMember({
          userId: user?.id ?? undefined,
          customerId,
          customerName: cust?.name,
          email
        });

        await upsertSubscription({ orgId: org.id, sub });
        console.log('[webhook] sub sync', sub.id, sub.status);
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

// ---------- helpers for org/sub ----------
const isPremium = (status, end) => {
  const s = String(status || '').toLowerCase();
  return (s === 'active' || s === 'trialing') && end instanceof Date && end.getTime() > Date.now();
};

async function userHasActivePremium(userId) {
  const orgs = await prisma.org.findMany({
    where: { OR: [{ ownerUserId: userId }, { members: { some: { userId } } }] },
    select: {
      id: true,
      subscriptions: { orderBy: { updatedAt: 'desc' }, take: 1, select: { status: true, currentPeriodEnd: true } }
    },
  });
  return orgs.some(o => {
    const s = o.subscriptions?.[0];
    return s && isPremium(s.status, s.currentPeriodEnd);
  });
}

async function ensureOrgAndMember({ userId, customerId, customerName, email }) {
  let org = await prisma.org.findFirst({ where: { stripeCustomerId: customerId } });

  if (!org) {
    const fallback = customerName || (email ? `${email.split('@')[0]}'s Org` : 'Account');
    org = await prisma.org.create({
      data: { name: fallback, stripeCustomerId: customerId, ownerUserId: userId || null }
    });
  } else if (userId && !org.ownerUserId) {
    org = await prisma.org.update({ where: { id: org.id }, data: { ownerUserId: userId } });
  }

  if (userId) {
    await prisma.member.upsert({
      where: { orgId_userId: { orgId: org.id, userId } },
      update: {},
      create: { orgId: org.id, userId, role: 'owner' }
    });
  }
  return org;
}

async function upsertSubscription({ orgId, sub }) {
  const end = sub.current_period_end ? new Date(sub.current_period_end * 1000) : null;
  const id  = `stripe_${sub.id}`;
  await prisma.subscription.upsert({
    where: { id },
    create: {
      id, orgId, provider: 'stripe',
      status: sub.status,
      currentPeriodEnd: end,
      customerId: typeof sub.customer === 'string' ? sub.customer : sub.customer?.id
    },
    update: { status: sub.status, currentPeriodEnd: end }
  });
}

async function safeGetCustomer(customerId) {
  try { return await stripe.customers.retrieve(customerId); }
  catch { return null; }
}

// ---------- auth ----------
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const em = normEmail(email);
  if (!isEmail(em) || !password) return res.status(400).json({ error: 'missing_fields' });

  const user = await prisma.user.findUnique({ where: { email: em } });
  if (!user || !user.passwordHash) return res.status(401).json({ error: 'invalid_creds' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid_creds' });

  res.json({ access: signAccess(user) });
});

// start/register (idempotent – queues a new token if no password yet)
app.post('/auth/register/start', async (req, res) => {
  try {
    const em = normEmail(req.body?.email);
    if (!isEmail(em)) return res.status(400).json({ error: 'bad_email' });

    let user = await prisma.user.findUnique({ where: { email: em } });
    if (!user) user = await prisma.user.create({ data: { email: em } });
    if (user.passwordHash) return res.json({ ok: true, note: 'already_has_password' });

    const t   = await issueToken(user.id, 'register');          // selector.verifier
    const base = (REG_URL_BASE || '').replace(/\/+$/, '');
    const url  = `${base}?t=${encodeURIComponent(t)}&email=${encodeURIComponent(em)}`;
    await emailLink(em, 'Set your Bedrock Utilities password', url);

    res.json({ ok: true });
  } catch (e) {
    console.error('[register/start] error:', e?.message || e);
    res.status(500).json({ error: 'register_start_failed' });
  }
});

// complete registration (token-anchored)
app.post('/auth/register/complete', async (req, res) => {
  const { t, password } = req.body || {};
  if (!t || !password) return res.status(400).json({ error: 'missing_fields' });

  const tok = await findAndConsumeToken(t, 'register');
  if (!tok) return res.status(400).json({ error: 'bad_or_expired_token' });

  const hash = await bcrypt.hash(password, 10);
  await prisma.user.update({ where: { id: tok.userId }, data: { passwordHash: hash } });

  res.json({ ok: true });
});

// forgot password start
app.post('/auth/reset/start', async (req, res) => {
  const em = normEmail(req.body?.email);
  if (!isEmail(em)) return res.status(400).json({ error: 'bad_email' });

  const user = await prisma.user.findUnique({ where: { email: em } });
  if (!user) return res.json({ ok: true });

  const t   = await issueToken(user.id, 'reset');
  const base = (REG_URL_BASE || '').replace(/\/+$/, '');
  const url  = `${base}?t=${encodeURIComponent(t)}&email=${encodeURIComponent(em)}&mode=reset`;
  await emailLink(em, 'Reset your Bedrock Utilities password', url);

  res.json({ ok: true });
});

// forgot password complete
app.post('/auth/reset/complete', async (req, res) => {
  const { t, newPassword } = req.body || {};
  if (!t || !newPassword) return res.status(400).json({ error: 'missing_fields' });

  const tok = await findAndConsumeToken(t, 'reset');
  if (!tok) return res.status(400).json({ error: 'bad_or_expired_token' });

  const hash = await bcrypt.hash(newPassword, 10);
  await prisma.user.update({ where: { id: tok.userId }, data: { passwordHash: hash } });

  res.json({ ok: true });
});

// ---------- entitlements (with cautious self-heal) ----------
async function getEntitlementsPayload(userId) {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  const pull = async () => prisma.org.findMany({
    where: { OR: [{ ownerUserId: userId }, { members: { some: { userId } } }] },
    select: {
      id: true, name: true, stripeCustomerId: true,
      subscriptions: { orderBy: { updatedAt: 'desc' }, take: 1, select: { status: true, currentPeriodEnd: true } }
    },
  });

  let orgsRaw = await pull();
  const hasPremiumNow = orgsRaw.some(o => {
    const s = o.subscriptions?.[0];
    return s && isPremium(s.status, s.currentPeriodEnd);
  });

  // self-heal only if no premium and we know email
  if (!hasPremiumNow && user?.email) {
    try {
      const search = await stripe.customers.search({ query: `email:"${user.email}"` });
      const cust   = search?.data?.[0];
      if (cust) {
        const org = await ensureOrgAndMember({
          userId,
          customerId: cust.id,
          customerName: cust.name,
          email: user.email
        });
        const subs = await stripe.subscriptions.list({ customer: cust.id, limit: 1 });
        const sub  = subs?.data?.[0];
        if (sub) await upsertSubscription({ orgId: org.id, sub });
        orgsRaw = await pull();
      }
    } catch (e) {
      console.error('[entitlements self-heal] error:', e?.message || e);
    }
  }

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

app.get('/entitlements', auth, async (req, res) => {
  res.json(await getEntitlementsPayload(req.user.sub));
});

// ---------- Billing ----------

// Public checkout (block if account already exists)
app.post('/billing/checkout_public', async (req, res) => {
  try {
    const em = normEmail(req.body?.email);
    const returnUrl = String(req.body?.returnUrl || '');
    if (!isEmail(em)) return res.status(400).json({ error: 'bad_email' });

    const existing = await prisma.user.findUnique({ where: { email: em } });
    if (existing) return res.status(400).json({ error: 'account_exists' });

    const successUrl = returnUrl || 'https://www.nerdherdmc.net/new-account';
    const cancelUrl  = 'https://www.nerdherdmc.net/accounts';

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_creation: 'always',
      customer_email: em,
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      success_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  cancelUrl,
      allow_promotion_codes: true,
    });

    return res.json({ url: session.url });
  } catch (e) {
    console.error('[checkout_public] error:', e);
    return res.status(500).json({ error: 'checkout_failed' });
  }
});

// Auth’d renew (only when not currently premium). Never use a stale customer id.
app.post('/billing/checkout_renew', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const user   = await prisma.user.findUnique({ where: { id: userId } });
    if (!user?.email) return res.status(400).json({ error: 'missing_email' });

    if (await userHasActivePremium(userId)) {
      return res.status(400).json({ error: 'already_active' });
    }

    // try to reuse existing org.customer if it still exists in Stripe
    let customerId = null;
    const org = await prisma.org.findFirst({
      where: { OR: [{ ownerUserId: userId }, { members: { some: { userId } } }], stripeCustomerId: { not: null } },
      select: { stripeCustomerId: true }
    });
    if (org?.stripeCustomerId) {
      const exists = await safeGetCustomer(org.stripeCustomerId);
      if (exists) customerId = org.stripeCustomerId;
    }

    const successUrl = 'https://www.nerdherdmc.net/new-account';
    const cancelUrl  = 'https://www.nerdherdmc.net/accounts';

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      ...(customerId
        ? { customer: customerId }
        : { customer_creation: 'always', customer_email: user.email }),
      success_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancelUrl,
      allow_promotion_codes: true,
    });

    return res.json({ url: session.url });
  } catch (e) {
    console.error('[checkout_renew] error:', e);
    return res.status(500).json({ error: 'checkout_failed' });
  }
});

// Client-side finalizer that you call after Stripe returns (idempotent)
app.post('/billing/checkout_sync', auth, async (req, res) => {
  try {
    const { session_id } = req.body || {};
    if (!session_id) return res.status(400).json({ error: 'missing_session_id' });

    const session = await stripe.checkout.sessions.retrieve(session_id);
    const email   = normEmail(session.customer_details?.email || session.customer_email);
    const customerId = session.customer;
    const subId   = typeof session.subscription === 'string'
      ? session.subscription
      : session.subscription?.id;

    if (!email || !customerId || !subId) return res.json({ ok: true, note: 'nothing_to_sync' });

    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) user = await prisma.user.create({ data: { email } });

    const cust = await safeGetCustomer(customerId);
    const org  = await ensureOrgAndMember({
      userId: user.id, customerId, customerName: cust?.name, email
    });

    const sub = await stripe.subscriptions.retrieve(subId);
    await upsertSubscription({ orgId: org.id, sub });

    res.json({ ok: true });
  } catch (e) {
    console.error('[checkout_sync] error:', e?.message || e);
    res.status(500).json({ error: 'sync_failed' });
  }
});

// Optional: sanity endpoint to check your price id quickly
app.get('/billing/price_check', async (_req, res) => {
  try {
    const p = await stripe.prices.retrieve(STRIPE_PRICE_PREMIUM);
    res.json({ id: p.id, active: p.active, currency: p.currency, recurring: p.recurring || null });
  } catch (e) {
    res.status(500).json({ error: e?.message || 'price_check_failed' });
  }
});

// ---------- start ----------
app.listen(PORT, () => {
  log(`API up on :${PORT}`);
  log('[env] allowed CORS:', allowed);
});
