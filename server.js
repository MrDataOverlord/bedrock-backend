/* =========================================================================
   Bedrock Backend — Express + Stripe + Prisma + Resend (optional)
   ========================================================================= */

/* Optional .env loader: only in non-production and only if installed */
if (process.env.NODE_ENV !== 'production') {
  try {
    // loads .env if the 'dotenv' package is present locally
    await import('dotenv/config');
    console.log('[env] .env loaded via dotenv');
  } catch {
    // safe to ignore on Render/production
  }
}

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
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
  STRIPE_PRICE_PREMIUM = '',      // preferred modern name
  RESEND_API_KEY = '',            // optional (emails); omit to log-only
  RESEND_FROM = 'no-reply@yourdomain.com',
  APP_NAME = 'Bedrock',
} = process.env;

// Accept legacy STRIPE_PRICE_ID as well
const PRICE_ID = STRIPE_PRICE_PREMIUM || process.env.STRIPE_PRICE_ID || '';
if (!PRICE_ID) {
  console.error('[CONFIG] Missing Stripe price id. Set STRIPE_PRICE_PREMIUM (preferred) or STRIPE_PRICE_ID.');
  process.exit(1);
} else {
  console.log(`[CONFIG] Using Stripe price id: ${PRICE_ID}`);
}

if (!JWT_SECRET) {
  console.error('JWT_SECRET is required'); process.exit(1);
}
if (!STRIPE_SECRET_KEY) {
  console.error('STRIPE_SECRET_KEY is required'); process.exit(1);
}
if (!STRIPE_WEBHOOK_SECRET) {
  console.warn('WARNING: STRIPE_WEBHOOK_SECRET is not set — webhooks will fail to verify.');
}

/* ====== Init ============================================================= */

const prisma = new PrismaClient();
const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

/* ====== Email (Resend optional) ========================================= */

async function sendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) {
    console.log('[email:mock]', { to, subject, html: html?.slice(0, 140) + '...' });
    return;
  }
  const { Resend } = await import('resend'); // only loaded when key is present
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
        <p>We’ve confirmed your payment. Click the button below to set your password and finish creating your account.</p>
        <p style="margin: 24px 0;">
          <a href="${url}" style="background:#111;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none;">Set Password</a>
        </p>
        <p>This link is single-use and expires in 24 hours.</p>
      </div>
    `,
  };
}

async function issuePasswordToken(userId) {
  const raw = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await prisma.passwordToken.create({
    data: { userId, purpose: 'register', tokenHash, expiresAt },
  });

  return raw;
}

async function sendRegistrationEmail(email, userId) {
  const raw = await issuePasswordToken(userId);
  const { subject, html } = buildRegistrationEmail({ email, token: raw });
  await sendEmail({ to: email, subject, html });
}

/* ====== Auth helpers ===================================================== */

function signAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}

/* ====== App ============================================================= */

const app = express();

// CORS
const allow = (CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
if (FRONTEND_URL) {
  const f = FRONTEND_URL.trim();
  if (f && !allow.includes(f)) allow.push(f);
}
console.log('[CORS allowlist]', allow);

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    const ok = allow.some(a => origin === a || origin.endsWith(a.replace(/^\*+/, '')));
    cb(null, ok);
  },
  credentials: true,
}));
app.use((req, res, next) => { res.header('Vary', 'Origin'); next(); });

// Body parsers (JSON everywhere except Stripe webhook)
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));

/* ====== Health =========================================================== */

app.get('/health', (_req, res) => {
  res.json({ ok: true, env: NODE_ENV, ts: new Date().toISOString() });
});

/* ====== Auth ============================================================= */

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = (req.body || {});
    if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    const token = signAccessToken({ sub: user.id, email: user.email });
    res.json({ access: token });
  } catch (err) {
    console.error('/auth/login error', err);
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
    await sendEmail({
      to: email,
      subject: `${APP_NAME}: Reset your password`,
      html: `<p>Click to reset your password: <a href="${url}">${url}</a></p>`,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('/auth/request-reset error', err);
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
      where: {
        userId: user.id,
        tokenHash,
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
    });
    if (!found) return res.status(400).json({ error: 'Invalid or expired token' });

    const passwordHash = await bcrypt.hash(password, 12);
    await prisma.$transaction([
      prisma.user.update({ where: { id: user.id }, data: { passwordHash } }),
      prisma.passwordToken.update({ where: { id: found.id }, data: { usedAt: new Date() } }),
    ]);

    res.json({ ok: true });
  } catch (err) {
    console.error('/auth/set-password error', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ====== Billing ========================================================== */

app.post('/billing/checkout_public', async (req, res) => {
  try {
    const { email, returnUrl } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });

    const successUrl = (returnUrl || `${FRONTEND_URL}/pay/success`).replace(/\/$/, '');
    const cancelUrl = `${FRONTEND_URL}/pay/cancel`;

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
  } catch (err) {
    console.error('/billing/checkout_public error', err);
    res.status(500).json({ error: 'Failed to start checkout' });
  }
});

app.post('/billing/checkout', requireAuth, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.sub } });
    if (!user) return res.status(401).json({ error: 'Not found' });

    const successUrl = `${FRONTEND_URL.replace(/\/$/, '')}/pay/success?session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl = `${FRONTEND_URL}/pay/cancel`;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: user.email,
      line_items: [{ price: PRICE_ID, quantity: 1 }],
      success_url: successUrl,
      cancel_url: cancelUrl,
      allow_promotion_codes: true,
      billing_address_collection: 'auto',
      subscription_data: { metadata: { email: user.email, appUserId: user.id } },
      metadata: { email: user.email, appUserId: user.id, flow: 'auth' },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('/billing/checkout error', err);
    res.status(500).json({ error: 'Failed to start checkout' });
  }
});

app.get('/entitlements', requireAuth, async (req, res) => {
  try {
    const member = await prisma.member.findFirst({
      where: { userId: req.user.sub },
      include: {
        org: {
          include: {
            subscriptions: { orderBy: { createdAt: 'desc' }, take: 1 },
          },
        },
      },
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
  } catch (err) {
    console.error('/entitlements error', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ====== Stripe Webhook =================================================== */

app.post(
  '/webhooks/stripe',
  express.raw({ type: 'application/json' }), // raw body for signature verification
  async (req, res) => {
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
                    members: {
                      create: {
                        user: { connect: { email } },
                        role: 'owner',
                      },
                    },
                  },
                },
              },
            });
          } else {
            const hasMember = await prisma.member.findFirst({ where: { userId: user.id } });
            if (!hasMember) {
              const org = await prisma.org.create({
                data: { ownerUserId: user.id, name: `${email}'s Org` },
              });
              await prisma.member.create({ data: { orgId: org.id, userId: user.id, role: 'owner' } });
            }
          }

          if (session.subscription) {
            const sub = await stripe.subscriptions.retrieve(session.subscription);
            const org = await prisma.member.findFirst({ where: { userId: user.id }, include: { org: true } });
            if (org?.org) {
              await prisma.subscription.upsert({
                where: { id: `stripe_${sub.id}` },
                create: {
                  id: `stripe_${sub.id}`,
                  orgId: org.org.id,
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

          if (user && !user.passwordHash) {
            await sendRegistrationEmail(email, user.id);
          }

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
                orgId: (await (async () => {
                  const cust = typeof sub.customer === 'string'
                    ? await stripe.customers.retrieve(sub.customer)
                    : sub.customer;
                  const email = (cust?.email || '').toLowerCase();
                  const u = email ? await prisma.user.findUnique({ where: { email } }) : null;
                  const m = u ? await prisma.member.findFirst({ where: { userId: u.id } }) : null;
                  return m?.orgId ?? (await prisma.org.create({
                    data: { ownerUserId: u?.id ?? (await prisma.user.create({ data: { email: email || `user_${crypto.randomBytes(6).toString('hex')}@example.com` } })).id },
                  })).id;
                })()),
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

        default:
          break;
      }

      res.json({ received: true });
    } catch (err) {
      console.error('[webhook] handler error', err);
      res.status(500).send('Webhook handler error');
    }
  }
);

// generic error handler (after routes)
app.use((err, _req, res, _next) => {
  console.error('Unhandled error', err);
  res.status(500).json({ error: 'Server error' });
});

/* ====== Start ============================================================ */

app.listen(Number(PORT), () => {
  console.log(`Server listening on port ${PORT} (${NODE_ENV})`);
});
