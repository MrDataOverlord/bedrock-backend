/* =========================================================================
   Bedrock Backend — Express + Stripe + Prisma (no cookie-parser required)
   ========================================================================= */

/* Optional .env loader (safe to skip on Render) */
if (process.env.NODE_ENV !== 'production') {
  try { await import('dotenv/config'); console.log('[env] .env loaded'); } catch {}
}

import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';
import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';

/* ====== Environment ===================================================== */

const {
  NODE_ENV = 'development',
  PORT = '3001',
  JWT_SECRET = '',
  FRONTEND_URL = 'http://localhost:5173',
  CORS_ORIGINS = '',
  STRIPE_SECRET_KEY = '',
  STRIPE_WEBHOOK_SECRET = '',
  STRIPE_PRICE_PREMIUM = '',                  // preferred
  RESEND_API_KEY = '',                        // optional
  RESEND_FROM = 'no-reply@yourdomain.com',
  APP_NAME = 'Bedrock',
} = process.env;

// Accept legacy STRIPE_PRICE_ID too
const PRICE_ID = STRIPE_PRICE_PREMIUM || process.env.STRIPE_PRICE_ID || '';
if (!PRICE_ID) { console.error('Missing Stripe price id (STRIPE_PRICE_PREMIUM or STRIPE_PRICE_ID).'); process.exit(1); }
if (!JWT_SECRET) { console.error('JWT_SECRET is required'); process.exit(1); }
if (!STRIPE_SECRET_KEY) { console.error('STRIPE_SECRET_KEY is required'); process.exit(1); }

const prisma = new PrismaClient();
const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

/* ====== Email (Resend optional) ========================================= */
async function sendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) { console.log('[email:mock]', { to, subject }); return; }
  const { Resend } = await import('resend');
  const resend = new Resend(RESEND_API_KEY);
  await resend.emails.send({ from: RESEND_FROM, to, subject, html });
}
function buildRegistrationEmail({ email, token }) {
  const url = `${FRONTEND_URL.replace(/\/$/, '')}/register/complete?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
  return {
    subject: `${APP_NAME}: Set your password`,
    html: `
      <div style="font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif">
        <h2>Welcome to ${APP_NAME}</h2>
        <p>Payment received. Click below to set your password and finish creating your account.</p>
        <p style="margin:24px 0"><a href="${url}" style="background:#111;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none">Set Password</a></p>
        <p>This link is single-use and expires in 24 hours.</p>
      </div>
    `,
  };
}
async function issuePasswordToken(userId) {
  const raw = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await prisma.passwordToken.create({ data: { userId, purpose: 'register', tokenHash, expiresAt } });
  return raw;
}
async function sendRegistrationEmail(email, userId) {
  const raw = await issuePasswordToken(userId);
  const { subject, html } = buildRegistrationEmail({ email, token: raw });
  await sendEmail({ to: email, subject, html });
}

/* ====== Auth helpers ===================================================== */
function signAccessToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' }); }
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}

/* ====== App ============================================================= */
const app = express();

/* CORS */
const allow = (CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
if (FRONTEND_URL && !allow.includes(FRONTEND_URL)) allow.push(FRONTEND_URL);
console.log('[CORS allowlist]', allow);
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    cb(null, allow.includes(origin));
  },
  credentials: true,
}));
app.use((req, res, next) => { res.header('Vary', 'Origin'); next(); });

/* ----------------- VERY IMPORTANT: Stripe webhook FIRST ------------------ */
/* Use raw body for signature verification before any global JSON parser. */
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('[webhook] signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const email = (session.customer_details?.email || session.customer_email || session.metadata?.email || '').toLowerCase().trim();
        if (!email) break;

        let user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
          user = await prisma.user.create({
            data: {
              email,
              ownedOrgs: {
                create: {
                  name: `${email}'s Org`,
                  members: { create: { role: 'owner', user: { connect: { email } } } },
                },
              },
            },
          });
        } else {
          const hasMember = await prisma.member.findFirst({ where: { userId: user.id } });
          if (!hasMember) {
            const org = await prisma.org.create({ data: { ownerUserId: user.id, name: `${email}'s Org` } });
            await prisma.member.create({ data: { orgId: org.id, userId: user.id, role: 'owner' } });
          }
        }

        if (session.subscription) {
          const sub = await stripe.subscriptions.retrieve(session.subscription);
          const m = await prisma.member.findFirst({ where: { userId: user.id }, include: { org: true } });
          if (m?.org) {
            await prisma.subscription.upsert({
              where: { id: `stripe_${sub.id}` },
              create: {
                id: `stripe_${sub.id}`,
                orgId: m.org.id,
                provider: 'stripe',
                status: sub.status,
                currentPeriodEnd: sub.current_period_end ? new Date(sub.current_period_end * 1000) : null,
                customerId: sub.customer?.toString(),
              },
              update: {
                status: sub.status,
                currentPeriodEnd: sub.current_period_end ? new Date(sub.current_period_end * 1000) : null,
                customerId: sub.customer?.toString(),
              },
            });
          }
        }

        if (user && !user.passwordHash) await sendRegistrationEmail(email, user.id);
        break;
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        if (invoice.subscription) {
          const sub = await stripe.subscriptions.retrieve(invoice.subscription);
          await prisma.subscription.upsert({
            where: { id: `stripe_${sub.id}` },
            create: {
              id: `stripe_${sub.id}`,
              orgId: await (async () => {
                const cust = typeof sub.customer === 'string'
                  ? await stripe.customers.retrieve(sub.customer)
                  : sub.customer;
                const email = (cust?.email || '').toLowerCase();
                const u = email ? await prisma.user.findUnique({ where: { email } }) : null;
                const m = u ? await prisma.member.findFirst({ where: { userId: u.id } }) : null;
                if (m?.orgId) return m.orgId;
                const ownerId = u?.id ?? (await prisma.user.create({ data: { email: email || `user_${crypto.randomBytes(6).toString('hex')}@example.com` } })).id;
                const org = await prisma.org.create({ data: { ownerUserId: ownerId, name: `${email || 'Customer'}'s Org` } });
                await prisma.member.create({ data: { orgId: org.id, userId: ownerId, role: 'owner' } });
                return org.id;
              })(),
              provider: 'stripe',
              status: sub.status,
              currentPeriodEnd: sub.current_period_end ? new Date(sub.current_period_end * 1000) : null,
              customerId: sub.customer?.toString(),
            },
            update: {
              status: sub.status,
              currentPeriodEnd: sub.current_period_end ? new Date(sub.current_period_end * 1000) : null,
              customerId: sub.customer?.toString(),
            },
          });
        }
        break;
      }

      default: break;
    }

    res.json({ received: true });
  } catch (err) {
    console.error('[webhook] handler error', err);
    res.status(500).send('Webhook handler error');
  }
});

/* ------------------------ Global parsers AFTER webhook ------------------- */
app.use(express.json({ limit: '1mb' })); // safe for all other routes

/* ====== Health =========================================================== */
app.get('/health', (_req, res) => res.json({ ok: true, env: NODE_ENV, ts: new Date().toISOString() }));

/* ====== Auth ============================================================= */
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = (req.body || {});
    if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    res.json({ access: signAccessToken({ sub: user.id, email: user.email }) });
  } catch (e) {
    console.error('/auth/login error', e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/auth/request-reset', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.json({ ok: true });

    const raw = await issuePasswordToken(user.id);
    const url = `${FRONTEND_URL.replace(/\/$/, '')}/reset/complete?token=${encodeURIComponent(raw)}&email=${encodeURIComponent(email)}`;
    await sendEmail({ to: email, subject: `${APP_NAME}: Reset your password`, html: `<p>Reset here: <a href="${url}">${url}</a></p>` });
    res.json({ ok: true });
  } catch (e) {
    console.error('/auth/request-reset error', e);
    res.status(500).json({ error: 'Failed' });
  }
});

app.post('/auth/set-password', async (req, res) => {
  try {
    const { email, token, password } = req.body || {};
    if (!email || !token || !password) return res.status(400).json({ error: 'Missing fields' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: 'Invalid token' });

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const found = await prisma.passwordToken.findFirst({
      where: { userId: user.id, tokenHash, usedAt: null, expiresAt: { gt: new Date() } },
    });
    if (!found) return res.status(400).json({ error: 'Invalid or expired token' });

    const passwordHash = await bcrypt.hash(password, 12);
    await prisma.$transaction([
      prisma.user.update({ where: { id: user.id }, data: { passwordHash } }),
      prisma.passwordToken.update({ where: { id: found.id }, data: { usedAt: new Date() } }),
    ]);

    res.json({ ok: true });
  } catch (e) {
    console.error('/auth/set-password error', e);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ====== Billing (public) ================================================= */
app.post('/billing/checkout_public', async (req, res) => {
  try {
    const { email, returnUrl } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });

    const successUrl = (returnUrl || `${FRONTEND_URL}/pay/success`).replace(/\/$/, '');
    const cancelUrl  = `${FRONTEND_URL}/pay/cancel`;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: email,
      line_items: [{ price: PRICE_ID, quantity: 1 }],
      success_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancelUrl,
      allow_promotion_codes: true,
      billing_address_collection: 'auto',
      subscription_data: { metadata: { email } },
      metadata: { email, flow: 'public' },
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error('/billing/checkout_public error', e);
    res.status(500).json({ error: 'Failed to start checkout' });
  }
});

/* ====== Billing (authenticated) ========================================= */
app.post('/billing/checkout', requireAuth, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.sub } });
    if (!user) return res.status(401).json({ error: 'Not found' });

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: user.email,
      line_items: [{ price: PRICE_ID, quantity: 1 }],
      success_url: `${FRONTEND_URL.replace(/\/$/, '')}/pay/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}/pay/cancel`,
      allow_promotion_codes: true,
      billing_address_collection: 'auto',
      subscription_data: { metadata: { email: user.email, appUserId: user.id } },
      metadata: { email: user.email, appUserId: user.id, flow: 'auth' },
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error('/billing/checkout error', e);
    res.status(500).json({ error: 'Failed to start checkout' });
  }
});

/* ====== Entitlements ===================================================== */
app.get('/entitlements', requireAuth, async (req, res) => {
  try {
    const member = await prisma.member.findFirst({
      where: { userId: req.user.sub },
      include: { org: { include: { subscriptions: { orderBy: { createdAt: 'desc' }, take: 1 } } } },
    });

    const sub = member?.org?.subscriptions?.[0] || null;
    let daysRemaining = 0;
    if (sub?.currentPeriodEnd) {
      const diff = +new Date(sub.currentPeriodEnd) - Date.now();
      daysRemaining = Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
    }

    res.json({
      status: sub?.status ?? 'none',
      currentPeriodEnd: sub?.currentPeriodEnd ?? null,
      daysRemaining,
    });
  } catch (e) {
    console.error('/entitlements error', e);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ====== Start ============================================================ */
app.listen(Number(PORT), () => {
  console.log(`Server listening on port ${PORT} (${NODE_ENV})`);
});
