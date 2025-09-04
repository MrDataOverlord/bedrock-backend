// server.js
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import Stripe from 'stripe';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import path from 'path';
import { PrismaClient } from '@prisma/client';
import fs from 'fs';

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

// Add security headers
app.use(helmet({
  contentSecurityPolicy: false, // Allow for flexibility with Wix integration
  crossOriginEmbedderPolicy: false
}));

const prisma = new PrismaClient();
const stripe = new Stripe(STRIPE_SECRET_KEY);

// CORS
const allowed = (CORS_ORIGINS || 'https://nerdherdmc.net,https://www.nerdherdmc.net')
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
app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health' || req.path.startsWith('/webhooks/'),
}));

// ---------- utilities ----------
const log = (...a) => console.log(...a);
const isEmail = (s) => typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.trim());

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

// helper: return a valid Stripe customer id for this user (or null)
async function getValidCustomerIdForUser(userId, email) {
  // Find any org with a stored customer id
  const org = await prisma.org.findFirst({
    where: {
      OR: [{ ownerUserId: userId }, { members: { some: { userId } } }],
      stripeCustomerId: { not: null }
    },
    select: { id: true, stripeCustomerId: true }
  });

  if (!org?.stripeCustomerId) return null;

  // Verify the id still exists in Stripe (it may have been deleted during tests)
  const cust = await getStripeCustomer(org.stripeCustomerId);
  if (cust && !cust.deleted) return org.stripeCustomerId;

  // Stale id -> clean it up to avoid future failures
  try {
    await prisma.org.update({
      where: { id: org.id },
      data: { stripeCustomerId: null }
    });
    console.warn('[renew] cleared stale stripeCustomerId on org', org.id, 'for', email);
  } catch (e) {
    console.warn('[renew] failed to clear stale stripeCustomerId:', e?.message || e);
  }
  return null;
}

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
const isPremium = (status, end) => {
  const s = String(status || '').toLowerCase();
  return (s === 'active' || s === 'trialing') && end instanceof Date && end.getTime() > Date.now();
};

async function userHasActivePremium(userId) {
  const orgs = await prisma.org.findMany({
    where: { OR: [{ ownerUserId: userId }, { members: { some: { userId } } }] },
    select: {
      id: true,
      subscriptions: {
        orderBy: { updatedAt: 'desc' },
        take: 1,
        select: { status: true, currentPeriodEnd: true }
      }
    },
  });
  for (const o of orgs) {
    const sub = o.subscriptions?.[0];
    if (sub && isPremium(sub.status, sub.currentPeriodEnd)) return true;
  }
  return false;
}

async function ensureOrgAndMember({ userId, customerId, customerName, email }) {
  let org = await prisma.org.findFirst({ where: { stripeCustomerId: customerId } });

  if (!org) {
    const fallbackName = customerName || (email ? `${email.split('@')[0]}'s Org` : 'Account');
    org = await prisma.org.create({
      data: { name: fallbackName, stripeCustomerId: customerId, ownerUserId: userId || null }
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

const getStripeCustomer = async (customerId) => {
  try { return await stripe.customers.retrieve(customerId); }
  catch { return null; }
};

// ---------- public endpoints ----------
app.get('/health', (req, res) => {
  res.json({ ok: true, env: NODE_ENV, ts: new Date().toISOString() });
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
    const user = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
    if (!user || !user.passwordHash) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ access: signAccess(user) });
  } catch (e) {
    console.error('[login] error:', e?.message || e);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ----- Registration completion (FIXED token validation) -----
app.post('/auth/register/complete', async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password) return res.status(400).json({ error: 'Missing fields' });

    // Get all unused registration tokens and find the matching one
    const tokens = await prisma.passwordToken.findMany({
      where: { purpose: 'register', usedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
    });

    let validToken = null;
    for (const tok of tokens) {
      if (await bcrypt.compare(token, tok.tokenHash)) {
        validToken = tok;
        break;
      }
    }

    if (!validToken) return res.status(400).json({ error: 'Token not found or expired' });

    const user = await prisma.user.findUnique({ where: { id: validToken.userId } });
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (user.passwordHash) return res.status(400).json({ error: 'Password already set' });

    const hash = await bcrypt.hash(password, 10);
    await prisma.$transaction([
      prisma.user.update({ where: { id: user.id }, data: { passwordHash: hash } }),
      prisma.passwordToken.update({ where: { id: validToken.id }, data: { usedAt: new Date() } }),
    ]);

    res.json({ ok: true });
  } catch (e) {
    console.error('[register/complete] error:', e?.message || e);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ----- Resend registration email (if no password yet) -----
app.post('/auth/register/resend', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });

    const cleanEmail = email.toLowerCase().trim();
    const user = await prisma.user.findUnique({ where: { email: cleanEmail } });
    if (!user) return res.status(200).json({ ok: true });
    if (user.passwordHash) return res.status(200).json({ ok: true, note: 'already_has_password' });

    const raw = await issueRegistrationToken(user.id);
    await sendRegistrationEmail(user.email, raw);
    res.json({ ok: true });
  } catch (e) {
    console.error('[register/resend] error:', e?.message || e);
    res.status(500).json({ error: 'Resend failed' });
  }
});

// ----- Manual start registration (recovery path / resend button) -----
app.post('/auth/register/start', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });

    const cleanEmail = email.toLowerCase().trim();
    let user = await prisma.user.findUnique({ where: { email: cleanEmail } });
    if (!user) user = await prisma.user.create({ data: { email: cleanEmail } });

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
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });

    const cleanEmail = email.toLowerCase().trim();
    const user = await prisma.user.findUnique({ where: { email: cleanEmail } });
    if (!user) return res.json({ ok: true }); // Don't reveal if email exists

    await invalidateTokensFor(user.id, 'reset');

    const raw = crypto.randomBytes(32).toString('hex');
    const tokenHash = await bcrypt.hash(raw, 10);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24);
    await prisma.passwordToken.create({
      data: { userId: user.id, tokenHash, purpose: 'reset', expiresAt },
    });

    if (transporter) {
      const base = (REG_URL_BASE || '').replace(/\/+$/, '');
      const url = `${base}?token=${encodeURIComponent(raw)}&email=${encodeURIComponent(cleanEmail)}&mode=reset`;
      await transporter.sendMail({
        from: SMTP_USER,
        to: cleanEmail,
        subject: 'Reset your Bedrock Utilities password',
        html: `<p>Click to reset your password:</p><p><a href="${url}">${url}</a></p>`,
      });
    } else {
      log('[mail] reset requested but SMTP not configured');
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('[reset/start] error:', e?.message || e);
    res.status(500).json({ error: 'Reset failed' });
  }
});

// ----- Forgot password (complete) – FIXED token validation -----
app.post('/auth/reset/complete', async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ error: 'Missing fields' });

    // Get all unused reset tokens and find the matching one
    const tokens = await prisma.passwordToken.findMany({
      where: { purpose: 'reset', usedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
    });

    let validToken = null;
    for (const tok of tokens) {
      if (await bcrypt.compare(token, tok.tokenHash)) {
        validToken = tok;
        break;
      }
    }

    if (!validToken) return res.status(400).json({ error: 'Token not found or expired' });

    const hash = await bcrypt.hash(newPassword, 10);
    await prisma.$transaction([
      prisma.user.update({ where: { id: validToken.userId }, data: { passwordHash: hash } }),
      prisma.passwordToken.update({ where: { id: validToken.id }, data: { usedAt: new Date() } }),
    ]);

    res.json({ ok: true });
  } catch (e) {
    console.error('[reset/complete] error:', e?.message || e);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// ----- Entitlements (with broadened self-heal) -----
async function getEntitlementsPayload(userId) {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  // Grab all orgs this user touches
  let orgsRaw = await prisma.org.findMany({
    where: { OR: [{ ownerUserId: userId }, { members: { some: { userId } } }] },
    select: {
      id: true, name: true, stripeCustomerId: true,
      subscriptions: {
        orderBy: { updatedAt: 'desc' },
        take: 1,
        select: { status: true, currentPeriodEnd: true }
      }
    },
  });

  // Determine if we currently have any premium
  const hasPremiumNow = orgsRaw.some(o => {
    const s = o.subscriptions?.[0];
    return s && isPremium(s.status, s.currentPeriodEnd);
  });

  // BROADENED SELF-HEAL: if no premium seen, try Stripe by email, and sync
  if (!hasPremiumNow && user?.email) {
    try {
      const search = await stripe.customers.search({ query: `email:"${user.email}"` });
      const cust = search?.data?.[0];
      if (cust) {
        const org = await ensureOrgAndMember({
          userId,
          customerId: cust.id,
          customerName: cust.name,
          email: user.email
        });
        const subs = await stripe.subscriptions.list({ customer: cust.id, limit: 1 });
        const sub = subs?.data?.[0];
        if (sub) await upsertSubscription({ orgId: org.id, sub });

        // Refresh local snapshot
        orgsRaw = await prisma.org.findMany({
          where: { OR: [{ ownerUserId: userId }, { members: { some: { userId } } }] },
          select: {
            id: true, name: true, stripeCustomerId: true,
            subscriptions: {
              orderBy: { updatedAt: 'desc' },
              take: 1,
              select: { status: true, currentPeriodEnd: true }
            }
          },
        });
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

app.get('/account/me', auth, async (req, res) => {
  try {
    res.json(await getEntitlementsPayload(req.user.sub));
  } catch (e) {
    console.error('[account/me] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to get account info' });
  }
});

app.get('/entitlements', auth, async (req, res) => {
  try {
    res.json(await getEntitlementsPayload(req.user.sub));
  } catch (e) {
    console.error('[entitlements] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to get entitlements' });
  }
});

// ---------- Billing ----------

// PUBLIC CHECKOUT (NEW-ACCOUNT ONLY) – blocks if a user already exists
app.post('/billing/checkout_public', async (req, res) => {
  try {
    const { email, returnUrl } = req.body || {};
    if (!isEmail(email)) return res.status(400).json({ error: 'email required' });

    const cleanEmail = email.toLowerCase().trim();
    const existing = await prisma.user.findUnique({ where: { email: cleanEmail } });
    if (existing) return res.status(400).json({ error: 'account_exists' });

    const successUrl = (returnUrl && String(returnUrl)) || 'https://www.nerdherdmc.net/new-account';
    const cancelUrl  = 'https://www.nerdherdmc.net/accounts';

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: cleanEmail,
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
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

// AUTH'D RENEW CHECKOUT (ONLY WHEN NO ACTIVE PREMIUM)
app.post('/billing/checkout_renew', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user?.email) return res.status(400).json({ error: 'missing_email' });

    // If already premium, block renew
    if (await userHasActivePremium(userId)) {
      return res.status(400).json({ error: 'already_active' });
    }

    // Get a *verified* existing customer id if we have one
    const verifiedCustomerId = await getValidCustomerIdForUser(userId, user.email);

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      ...(verifiedCustomerId
        ? { customer: verifiedCustomerId }
        : { customer_creation: 'always', customer_email: user.email }),
      success_url: 'https://www.nerdherdmc.net/accounts?renew=success&session_id={CHECKOUT_SESSION_ID}',
      cancel_url: 'https://www.nerdherdmc.net/accounts?renew=cancel',
      allow_promotion_codes: true,
    });

    return res.json({ url: session.url });
  } catch (e) {
    console.error('[checkout_renew] error:', e);
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

        const cleanEmail = email.toLowerCase().trim();

        // Ensure user
        let user = await prisma.user.findUnique({ where: { email: cleanEmail } });
        if (!user) user = await prisma.user.create({ data: { email: cleanEmail } });

        // Registration mail if needed
        if (!user.passwordHash) {
          try {
            const rawTok = await issueRegistrationToken(user.id);
            await sendRegistrationEmail(cleanEmail, rawTok);
            console.log('[webhook] registration email queued to:', cleanEmail);
          } catch (mailErr) {
            console.error('[webhook] email send failed:', mailErr?.message || mailErr);
          }
        }

        // Org/Member/Subscription sync
        const customerId = s.customer;
        if (customerId) {
          const cust = await getStripeCustomer(customerId);
          const org = await ensureOrgAndMember({
            userId: user.id, customerId, customerName: cust?.name, email: cleanEmail
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
        const email = cust?.email?.toLowerCase()?.trim();

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

// ---------- Premium Features (Server-Side Validation) ----------

// Get user's notification settings
app.get('/premium/notifications/settings', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    
    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Get or create default notification settings
    let settings = await prisma.notificationSettings.findUnique({
      where: { userId },
      include: { rules: true }
    });

    if (!settings) {
      // Create default settings with common notification rules
      settings = await prisma.notificationSettings.create({
        data: {
          userId,
          soundEnabled: false,
          rules: {
            create: [
              {
                name: 'Player Join',
                type: 'contains',
                pattern: 'joined the game',
                soundFile: 'player_join.wav',
                enabled: true
              },
              {
                name: 'Player Leave', 
                type: 'contains',
                pattern: 'left the game',
                soundFile: 'player_leave.wav',
                enabled: true
              },
              {
                name: 'Error Alert',
                type: 'regex',
                pattern: '\\b(ERROR|FATAL)\\b',
                soundFile: 'error_alert.wav',
                enabled: true
              },
              {
                name: 'Warning Alert',
                type: 'contains',
                pattern: 'WARN',
                soundFile: 'warning.wav',
                enabled: true
              },
              {
                name: 'Server Crash',
                type: 'contains',
                pattern: 'FAIL',
                soundFile: 'critical_alert.wav',
                enabled: true
              }
            ]
          }
        },
        include: { rules: true }
      });
    }

    res.json({
      soundEnabled: settings.soundEnabled,
      rules: {
        rules: settings.rules.map(rule => ({
          name: rule.name,
          type: rule.type,
          pattern: rule.pattern,
          soundFile: rule.soundFile,
          enabled: rule.enabled
        }))
      }
    });
  } catch (e) {
    console.error('[premium/notifications/settings] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to get notification settings' });
  }
});

// Update a specific notification rule
app.post('/premium/notifications/rule', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { name, type, pattern, soundFile, enabled } = req.body || {};

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Get user's notification settings
    const settings = await prisma.notificationSettings.findUnique({
      where: { userId },
      include: { rules: true }
    });

    if (!settings) {
      return res.status(404).json({ error: 'Notification settings not found' });
    }

    // Find and update the rule
    const rule = settings.rules.find(r => r.name === name);
    if (!rule) {
      return res.status(404).json({ error: 'Notification rule not found' });
    }

    await prisma.notificationRule.update({
      where: { id: rule.id },
      data: {
        type: type || rule.type,
        pattern: pattern || rule.pattern,
        soundFile: soundFile || rule.soundFile,
        enabled: enabled !== undefined ? enabled : rule.enabled
      }
    });

    res.json({ ok: true });
  } catch (e) {
    console.error('[premium/notifications/rule] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to update notification rule' });
  }
});

// Reset notification rules to defaults
app.post('/premium/notifications/reset', auth, async (req, res) => {
  try {
    const userId = req.user.sub;

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Delete existing settings and recreate with defaults
    await prisma.notificationSettings.deleteMany({
      where: { userId }
    });

    // Create default settings
    await prisma.notificationSettings.create({
      data: {
        userId,
        soundEnabled: false,
        rules: {
          create: [
            {
              name: 'Player Join',
              type: 'contains',
              pattern: 'joined the game',
              soundFile: 'player_join.wav',
              enabled: true
            },
            {
              name: 'Player Leave', 
              type: 'contains',
              pattern: 'left the game',
              soundFile: 'player_leave.wav',
              enabled: true
            },
            {
              name: 'Error Alert',
              type: 'regex',
              pattern: '\\b(ERROR|FATAL)\\b',
              soundFile: 'error_alert.wav',
              enabled: true
            },
            {
              name: 'Warning Alert',
              type: 'contains',
              pattern: 'WARN',
              soundFile: 'warning.wav',
              enabled: true
            },
            {
              name: 'Server Crash',
              type: 'contains',
              pattern: 'FAIL',
              soundFile: 'critical_alert.wav',
              enabled: true
            },
            {
              name: 'Server Stop',
              type: 'contains',
              pattern: 'Stopping server',
              soundFile: 'server_stop.wav',
              enabled: true
            }
          ]
        }
      }
    });

    res.json({ ok: true });
  } catch (e) {
    console.error('[premium/notifications/reset] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to reset notification rules' });
  }
});

// Enable/disable sound notifications
app.post('/premium/notifications/sound', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { enabled } = req.body || {};

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    await prisma.notificationSettings.upsert({
      where: { userId },
      create: { userId, soundEnabled: Boolean(enabled) },
      update: { soundEnabled: Boolean(enabled) }
    });

    res.json({ ok: true, enabled: Boolean(enabled) });
  } catch (e) {
    console.error('[premium/notifications/sound] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to update notification settings' });
  }
});

// Serve sound files (premium only)
app.get('/premium/sounds/:filename', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { filename } = req.params;

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Validate filename for security
    if (!/^[a-zA-Z0-9_-]+\.(wav|mp3)$/.test(filename)) {
      return res.status(400).json({ error: 'Invalid filename' });
    }

    // Serve from sounds directory
    const soundPath = path.join(process.cwd(), 'sounds', filename);
    
    // Check if file exists
    if (!fs.existsSync(soundPath)) {
      // If sound file doesn't exist, create a minimal default sound
      console.log(`[premium/sounds] Sound file not found: ${filename}, creating default`);
      return res.status(404).json({ error: 'Sound file not found' });
    }

    // Set proper headers for audio files
    const ext = path.extname(filename).toLowerCase();
    const mimeType = ext === '.wav' ? 'audio/wav' : 'audio/mpeg';
    
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
    
    // Stream the file
    const stream = fs.createReadStream(soundPath);
    stream.pipe(res);
    
  } catch (e) {
    console.error('[premium/sounds] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to serve sound file' });
  }
});

// Report notification trigger (analytics)
app.post('/premium/notifications/trigger', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { rule, timestamp, lineLength } = req.body || {};

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Store trigger event for analytics (optional)
    await prisma.notificationTrigger.create({
      data: {
        userId,
        ruleName: String(rule || 'unknown'),
        triggeredAt: timestamp ? new Date(timestamp) : new Date(),
        lineLength: Number(lineLength || 0)
      }
    });

    res.json({ ok: true });
  } catch (e) {
    console.error('[premium/notifications/trigger] error:', e?.message || e);
    // Don't return error - this is fire-and-forget analytics
    res.json({ ok: true });
  }
});

// ---------- start ----------
app.listen(PORT, () => {
  log(`API up on :${PORT}`);
  log('[env] allowed CORS:', allowed);
});
