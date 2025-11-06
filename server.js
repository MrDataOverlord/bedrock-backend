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
import { promises as fsPromises } from 'fs';
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
  jwt.sign({ sub: user.id, email: user.email, type: 'access' }, JWT_SECRET, { expiresIn: '1h' });

const signRefresh = (user) =>
  jwt.sign({ sub: user.id, email: user.email, type: 'refresh' }, JWT_SECRET, { expiresIn: '30d' });

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const [, token] = h.split(' ');
    if (!token) return res.status(401).json({ error: 'Missing bearer token' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Ensure this is an access token, not a refresh token
    if (decoded.type !== 'access') {
      return res.status(401).json({ error: 'Invalid token type' });
    }
    
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Function to create default notification rules that match actual Bedrock server format
function createDefaultNotificationRules() {
  return [
    {
      name: 'Player Join',
      type: 'contains',
      pattern: 'Player connected:',
      soundFile: 'player_join.wav',
      enabled: true
    },
    {
      name: 'Player Spawn',
      type: 'contains', 
      pattern: 'Player Spawned:',
      soundFile: 'player_spawn.wav',
      enabled: false // Disabled by default to avoid double notifications
    },
    {
      name: 'Player Leave', 
      type: 'contains',
      pattern: 'Player disconnected:',
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
  ];
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

// ---------- password policy ----------
function validatePasswordPolicy(pw) {
  const issues = [];
  const s = String(pw || '');
  if (s.length < 8) issues.push('at least 8 characters');
  if (/\s/.test(s)) issues.push('no spaces');
  if (!(/[0-9]/.test(s) || /[~`!@#$%^&*()\-\_=+\[\]{}|\\;:'",.<>/?]/.test(s))) {
    issues.push('include a number or a symbol');
  }
  return { ok: issues.length === 0, issues };
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
// Updated to recognize canceled subscriptions that still have time left
const isPremium = (status, end) => {
  const s = String(status || '').toLowerCase();
  const hasValidPeriod = end instanceof Date && end.getTime() > Date.now();
  
  // Premium if:
  // - Status is active/trialing AND period hasn't ended
  // - OR status is canceled BUT period hasn't ended yet (user keeps access until end)
  return ((s === 'active' || s === 'trialing' || s === 'canceled') && hasValidPeriod);
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
    
    // Return both access and refresh tokens
    res.json({ 
      access: signAccess(user),
      refresh: signRefresh(user)
    });
  } catch (e) {
    console.error('[login] error:', e?.message || e);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ---------- REFRESH ENDPOINT ----------
app.post('/auth/refresh', async (req, res) => {
  try {
    const { refresh } = req.body || {};
    if (!refresh) {
      return res.status(400).json({ error: 'Missing refresh token' });
    }

    // Verify the refresh token
    let decoded;
    try {
      decoded = jwt.verify(refresh, JWT_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Refresh token expired', code: 'REFRESH_EXPIRED' });
      }
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Ensure this is a refresh token, not an access token
    if (decoded.type !== 'refresh') {
      return res.status(401).json({ error: 'Invalid token type' });
    }

    // Verify user still exists
    const user = await prisma.user.findUnique({ where: { id: decoded.sub } });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    // Issue new access token (and optionally a new refresh token)
    res.json({ 
      access: signAccess(user),
      refresh: signRefresh(user) // Issue new refresh token for extended sessions
    });
    
    log(`[refresh] issued new tokens for user ${user.email}`);
  } catch (e) {
    console.error('[refresh] error:', e?.message || e);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// ----- Registration completion (FIXED token validation) -----
app.post('/auth/register/complete', async (req, res) => {
  try {
    const { token, password, confirm } = req.body || {};
    if (!token || !password) return res.status(400).json({ error: 'Missing fields' });

    // Policy enforcement
    const v = validatePasswordPolicy(password);
    if (!v.ok) return res.status(400).json({ error: `Password requirements: ${v.issues.join(', ')}` });

    // Optional confirm check (harmless if client doesn’t send it)
    if (typeof confirm === 'string' && confirm !== password) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

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

// ----- Forgot password (complete) -----
app.post('/auth/reset/complete', async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ error: 'Missing fields' });

    // Policy enforcement
    const v = validatePasswordPolicy(newPassword);
    if (!v.ok) return res.status(400).json({ error: `Password requirements: ${v.issues.join(', ')}` });

    if (typeof confirmPassword === 'string' && confirmPassword !== newPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

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

app.post('/premium/notifications/migrate-patterns', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    console.log('[DEBUG] Pattern migration request for user:', userId);

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Get existing notification settings
    const settings = await prisma.notificationSettings.findUnique({
      where: { userId },
      include: { rules: true }
    });

    if (!settings) {
      console.log('[DEBUG] No existing settings found, creating new ones...');
      
      const defaultRules = createDefaultNotificationRules();
      await prisma.notificationSettings.create({
        data: {
          userId,
          soundEnabled: false,
          rules: {
            create: defaultRules
          }
        }
      });
      
      return res.json({ ok: true, message: 'Created new settings with correct patterns' });
    }

    console.log('[DEBUG] Found existing settings, updating rule patterns...');

    // Update existing rules to correct patterns
    const updates = [
      {
        oldPattern: 'joined the game',
        newPattern: 'Player connected:',
        name: 'Player Join'
      },
      {
        oldPattern: 'left the game', 
        newPattern: 'Player disconnected:',
        name: 'Player Leave'
      }
    ];

    let updatedCount = 0;

    for (const update of updates) {
      const rule = settings.rules.find(r => 
        r.pattern === update.oldPattern || r.name === update.name
      );
      
      if (rule) {
        await prisma.notificationRule.update({
          where: { id: rule.id },
          data: { 
            pattern: update.newPattern,
            type: 'contains' // Ensure it's set to contains
          }
        });
        
        console.log(`[DEBUG] Updated rule "${rule.name}": "${update.oldPattern}" -> "${update.newPattern}"`);
        updatedCount++;
      }
    }

    // Add new Player Spawn rule if it doesn't exist
    const spawnRule = settings.rules.find(r => r.name === 'Player Spawn');
    if (!spawnRule) {
      await prisma.notificationRule.create({
        data: {
          settingsId: settings.id,
          name: 'Player Spawn',
          type: 'contains',
          pattern: 'Player Spawned:',
          soundFile: 'player_join.wav',
          enabled: true
        }
      });
      
      console.log('[DEBUG] Added new Player Spawn rule');
      updatedCount++;
    }

    console.log(`[DEBUG] Migration completed, updated ${updatedCount} rules`);
    res.json({ ok: true, updated: updatedCount, message: 'Patterns updated successfully' });
    
  } catch (e) {
    console.error('[premium/notifications/migrate-patterns] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to migrate patterns', detail: e?.message });
  }
});

app.post('/premium/notifications/fix-patterns', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    console.log('[PATTERN_FIX] Fixing patterns for user:', userId);

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Update patterns directly in the database
    const results = await prisma.$transaction(async (tx) => {
      // Fix Player Join pattern
      const joinUpdate = await tx.notificationRule.updateMany({
        where: {
          pattern: 'joined the game'
        },
        data: {
          pattern: 'Player connected:'
        }
      });

      // Fix Player Leave pattern
      const leaveUpdate = await tx.notificationRule.updateMany({
        where: {
          pattern: 'left the game'
        },
        data: {
          pattern: 'Player disconnected:'
        }
      });

      return { joinUpdated: joinUpdate.count, leaveUpdated: leaveUpdate.count };
    });

    console.log('[PATTERN_FIX] Updated patterns:', results);
    res.json({ 
      ok: true, 
      message: 'Patterns fixed successfully',
      updated: results 
    });

  } catch (e) {
    console.error('[PATTERN_FIX] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to fix patterns', detail: e?.message });
  }
});

// Test endpoint to verify current patterns
app.get('/premium/notifications/debug-patterns', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    
    const settings = await prisma.notificationSettings.findUnique({
      where: { userId },
      include: { rules: true }
    });

    const patterns = settings?.rules.map(rule => ({
      name: rule.name,
      pattern: rule.pattern,
      type: rule.type
    })) || [];

    res.json({ patterns });
  } catch (e) {
    res.status(500).json({ error: e?.message });
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

app.get('/premium/sounds', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    
    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Ensure sounds directory exists
    const soundsDir = path.join(process.cwd(), 'sounds');
    if (!fs.existsSync(soundsDir)) {
      fs.mkdirSync(soundsDir, { recursive: true });
    }

    // Read all sound files from the directory
    const files = fs.readdirSync(soundsDir)
      .filter(file => /\.(wav|mp3|ogg)$/i.test(file))
      .map(file => ({
        filename: file,
        displayName: file.replace(/\.(wav|mp3|ogg)$/i, '').replace(/[_-]/g, ' '),
        size: fs.statSync(path.join(soundsDir, file)).size
      }))
      .sort((a, b) => a.displayName.localeCompare(b.displayName));

    console.log(`[premium/sounds] Found ${files.length} sound files`);

    // Add default files if directory is empty
    if (files.length === 0) {
      const defaultSounds = [
        'player_join.wav',
        'player_leave.wav', 
        'player_spawn.wav',
        'error_alert.wav',
        'warning.wav',
        'critical_alert.wav',
        'server_stop.wav',
        'default.wav'
      ];

      console.log('[premium/sounds] Creating default sound files...');

      // Create minimal WAV files for each default sound
      const wavHeader = Buffer.from([
        0x52, 0x49, 0x46, 0x46, // "RIFF"
        0x24, 0x00, 0x00, 0x00, // File size - 8
        0x57, 0x41, 0x56, 0x45, // "WAVE"
        0x66, 0x6D, 0x74, 0x20, // "fmt "
        0x10, 0x00, 0x00, 0x00, // Subchunk1Size (16 for PCM)
        0x01, 0x00,             // AudioFormat (1 for PCM)
        0x01, 0x00,             // NumChannels (1 = mono)
        0x44, 0xAC, 0x00, 0x00, // SampleRate (44100)
        0x44, 0xAC, 0x00, 0x00, // ByteRate
        0x01, 0x00,             // BlockAlign
        0x08, 0x00,             // BitsPerSample (8)
        0x64, 0x61, 0x74, 0x61, // "data"
        0x00, 0x00, 0x00, 0x00  // Subchunk2Size (0 = no audio data)
      ]);

      for (const soundFile of defaultSounds) {
        const soundPath = path.join(soundsDir, soundFile);
        if (!fs.existsSync(soundPath)) {
          fs.writeFileSync(soundPath, wavHeader);
        }
      }

      // Re-read the directory after creating defaults
      const newFiles = fs.readdirSync(soundsDir)
        .filter(file => /\.(wav|mp3|ogg)$/i.test(file))
        .map(file => ({
          filename: file,
          displayName: file.replace(/\.(wav|mp3|ogg)$/i, '').replace(/[_-]/g, ' '),
          size: fs.statSync(path.join(soundsDir, file)).size
        }))
        .sort((a, b) => a.displayName.localeCompare(b.displayName));

      return res.json({ sounds: newFiles });
    }

    res.json({ sounds: files });

  } catch (e) {
    console.error('[premium/sounds] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to list sound files' });
  }
});

// ---------- Billing ----------

// PUBLIC CHECKOUT (NEW-ACCOUNT ONLY) — blocks if a user already exists
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

    console.log('[checkout_renew] Processing renewal for:', user.email);

    // Get verified customer id if exists
    const verifiedCustomerId = await getValidCustomerIdForUser(userId, user.email);

    // Create checkout session
    const sessionConfig = {
      mode: 'subscription',
      line_items: [{ price: STRIPE_PRICE_PREMIUM, quantity: 1 }],
      success_url: 'https://www.nerdherdmc.net/accounts?renew=success&session_id={CHECKOUT_SESSION_ID}',
      cancel_url: 'https://www.nerdherdmc.net/accounts?renew=cancel',
      allow_promotion_codes: true,
    };

    // Add customer info - use existing customer OR just customer_email (NOT customer_creation)
    if (verifiedCustomerId) {
      sessionConfig.customer = verifiedCustomerId;
      console.log('[checkout_renew] Using existing customer:', verifiedCustomerId);
    } else {
      sessionConfig.customer_email = user.email;
      console.log('[checkout_renew] Creating new customer for:', user.email);
    }

    const session = await stripe.checkout.sessions.create(sessionConfig);

    console.log('[checkout_renew] Checkout session created:', session.id);
    return res.json({ url: session.url });
    
  } catch (e) {
    console.error('[checkout_renew] error:', e?.message || e);
    return res.status(500).json({ 
      error: 'Checkout failed', 
      detail: e?.message 
    });
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

// ============================================================================
// Device Management Endpoints
// ============================================================================


// ---------- Device Management Helper Functions ----------

async function canResetDevice(userId) {
  const tokens = await prisma.deviceResetToken.findUnique({
    where: { userId }
  });
  
  if (!tokens) return { canReset: true, tokensRemaining: 2 }; // New user
  
  // Check if they have tokens remaining
  if (tokens.tokensRemaining > 0) {
    return { canReset: true, tokensRemaining: tokens.tokensRemaining };
  }
  
  // Check if 30 days have passed since last reset
  if (tokens.lastResetAt) {
    const daysSinceReset = (Date.now() - tokens.lastResetAt.getTime()) / (1000 * 60 * 60 * 24);
    if (daysSinceReset >= 30) {
      // Grant new token
      await prisma.deviceResetToken.update({
        where: { userId },
        data: { tokensRemaining: 1, lastResetAt: null }
      });
      return { canReset: true, tokensRemaining: 1 };
    }
    
    const daysUntilReset = Math.ceil(30 - daysSinceReset);
    return { 
      canReset: false, 
      tokensRemaining: 0,
      daysUntilReset 
    };
  }
  
  return { canReset: false, tokensRemaining: 0 };
}

function getDeviceFingerprint(req) {
  // Get IP address and user agent for audit
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || 
             req.headers['x-real-ip'] || 
             req.connection.remoteAddress;
  return { ip };
}

// ============================================================================
// DEVICE VERIFICATION HELPER FUNCTION
// ============================================================================

async function verifyPremiumDevice(req, res) {
  const userId = req.user.userId;
  const deviceId = req.body.deviceId || req.query.deviceId || req.headers['x-device-id'];
  const appType = req.body.appType || req.query.appType || 'commander';

  console.log(`[DEVICE_CHECK] Verifying device for user ${userId}, deviceId: ${deviceId}, appType: ${appType}`);

  try {
    // Check if user has premium
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        orgs: {
          include: {
            subscriptions: {
              where: {
                status: 'active',
                currentPeriodEnd: { gt: new Date() }
              }
            }
          }
        }
      }
    });

    const hasPremium = user?.orgs?.some(org => org.subscriptions?.length > 0);
    if (!hasPremium) {
      console.log(`[DEVICE_CHECK] User ${userId} does not have premium`);
      return { authorized: false, error: 'Premium subscription required' };
    }

    // If no device ID provided, allow (backward compatibility during transition)
    if (!deviceId) {
      console.log(`[DEVICE_CHECK] No device ID provided, allowing access (backward compatibility)`);
      return { authorized: true };
    }

    // Check if device is authorized
    const device = await prisma.authorizedDevice.findFirst({
      where: {
        userId,
        deviceId,
        appType,
        active: true
      }
    });

    if (!device) {
      console.log(`[DEVICE_CHECK] Device not authorized for user ${userId}`);
      return { authorized: false, error: 'Device not authorized. Please manage your devices in the Premium menu.' };
    }

    // Update last seen
    await prisma.authorizedDevice.update({
      where: { id: device.id },
      data: { lastSeenAt: new Date() }
    });

    console.log(`[DEVICE_CHECK] Device ${device.deviceName} authorized for user ${userId}`);
    return { authorized: true };
  } catch (error) {
    console.error('[DEVICE_CHECK] Error:', error);
    return { authorized: false, error: 'Device verification failed' };
  }
}

// ---------- Device Registration Endpoint ----------
app.post('/devices/register', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { deviceId, deviceName, appType, platform } = req.body || {};
    
    // Validate inputs
    if (!deviceId || !appType || !platform) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (!['commander', 'server-manager'].includes(appType)) {
      return res.status(400).json({ error: 'Invalid appType' });
    }
    
    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }
    
    // Check if this device is already registered
    const existing = await prisma.authorizedDevice.findUnique({
      where: { 
        userId_deviceId_appType: { userId, deviceId, appType } 
      }
    });
    
    if (existing) {
      // Update last seen
      await prisma.authorizedDevice.update({
        where: { id: existing.id },
        data: { lastSeenAt: new Date(), active: true }
      });
      
      return res.json({ 
        ok: true, 
        device: existing,
        message: 'Device already registered' 
      });
    }
    
    // Check if another device is registered for this app type
    // Platform-specific device limit check
const isWindows = platform.toLowerCase().includes('windows');
const isLinux = platform.toLowerCase().includes('linux');

// Get user's device limits
const user = await prisma.user.findUnique({
  where: { id: userId },
  select: { 
    maxWindowsDevices: true, 
    maxLinuxDevices: true 
  }
});

const maxAllowed = isWindows 
  ? (user?.maxWindowsDevices || 1)
  : isLinux 
    ? (user?.maxLinuxDevices || 1)
    : 1; // Default for other platforms

// Count active devices for this platform + appType
const platformKey = isWindows ? 'windows' : isLinux ? 'linux' : platform.toLowerCase();

const activeDeviceCount = await prisma.authorizedDevice.count({
  where: {
    userId,
    appType,
    active: true,
    platform: {
      contains: platformKey,
      mode: 'insensitive'
    },
    id: { not: existing?.id }
  }
});

console.log(`[device/register] User ${userId} has ${activeDeviceCount}/${maxAllowed} active ${platformKey} devices for ${appType}`);

if (activeDeviceCount >= maxAllowed) {
  // Find the existing devices to show user
  const existingDevices = await prisma.authorizedDevice.findMany({
    where: {
      userId,
      appType,
      active: true,
      platform: {
        contains: platformKey,
        mode: 'insensitive'
      }
    },
    orderBy: { lastSeenAt: 'desc' },
    take: 3
  });

  return res.status(409).json({ 
    error: 'Device limit reached',
    code: 'DEVICE_LIMIT_REACHED',
    platform: platformKey,
    currentCount: activeDeviceCount,
    maxAllowed: maxAllowed,
    existingDevices: existingDevices.map(d => ({
      name: d.deviceName,
      registeredAt: d.registeredAt,
      lastSeenAt: d.lastSeenAt
    })),
    message: `Device limit reached for ${platformKey}. You have ${activeDeviceCount}/${maxAllowed} devices. Use a device reset token to switch devices.`
  });
}
    
    // Register new device
    const device = await prisma.authorizedDevice.create({
      data: {
        userId,
        deviceId,
        deviceName: deviceName || `${platform} Device`,
        appType,
        platform,
        active: true
      }
    });
    
    // Ensure user has reset tokens
    await generateDeviceResetTokens(userId);
    
    // Audit log
    const { ip } = getDeviceFingerprint(req);
    await prisma.deviceAuditLog.create({
      data: {
        userId,
        deviceId,
        appType,
        action: 'registered',
        ipAddress: ip
      }
    });
    
    log(`[device] registered: user=${userId} device=${deviceId} app=${appType}`);
    
    res.json({ ok: true, device });
  } catch (e) {
    console.error('[devices/register] error:', e?.message || e);
    res.status(500).json({ error: 'Device registration failed' });
  }
});

// ---------- Device Verification Endpoint ----------
app.post('/devices/verify', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { deviceId, appType } = req.body || {};
    
    if (!deviceId || !appType) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Check if device is registered and active
    const device = await prisma.authorizedDevice.findUnique({
      where: { 
        userId_deviceId_appType: { userId, deviceId, appType } 
      }
    });
    
    if (!device || !device.active) {
      return res.status(403).json({ 
        error: 'Device not authorized',
        code: 'DEVICE_NOT_AUTHORIZED',
        registered: !!device
      });
    }
    
    // Update last seen
    await prisma.authorizedDevice.update({
      where: { id: device.id },
      data: { lastSeenAt: new Date() }
    });
    
    res.json({ ok: true, authorized: true });
  } catch (e) {
    console.error('[devices/verify] error:', e?.message || e);
    res.status(500).json({ error: 'Device verification failed' });
  }
});

// ---------- List User Devices ----------
app.get('/devices', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    
    const devices = await prisma.authorizedDevice.findMany({
      where: { userId },
      orderBy: { lastSeenAt: 'desc' }
    });
    
    // Get reset token info
    const resetTokens = await prisma.deviceResetToken.findUnique({
      where: { userId }
    });
    
    const canReset = await canResetDevice(userId);
    
    res.json({ 
      devices,
      resetTokens: {
        remaining: canReset.tokensRemaining,
        canReset: canReset.canReset,
        daysUntilReset: canReset.daysUntilReset || null,
        lastResetAt: resetTokens?.lastResetAt || null
      }
    });
  } catch (e) {
    console.error('[devices] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to fetch devices' });
  }
});

// ---------- Reset Device (Deactivate Current) ----------
app.post('/devices/reset', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { appType } = req.body || {};
    
    if (!appType) {
      return res.status(400).json({ error: 'Missing appType' });
    }
    
    // Check if user can reset
    const resetStatus = await canResetDevice(userId);
    if (!resetStatus.canReset) {
      return res.status(403).json({ 
        error: 'No reset tokens available',
        code: 'NO_RESET_TOKENS',
        daysUntilReset: resetStatus.daysUntilReset
      });
    }
    
    // Deactivate all devices for this app type
    const result = await prisma.authorizedDevice.updateMany({
      where: { userId, appType, active: true },
      data: { active: false }
    });
    
    // Consume reset token
    await prisma.deviceResetToken.update({
      where: { userId },
      data: { 
        tokensRemaining: { decrement: 1 },
        lastResetAt: new Date()
      }
    });
    
    // Audit log
    const { ip } = getDeviceFingerprint(req);
    await prisma.deviceAuditLog.create({
      data: {
        userId,
        deviceId: 'ALL',
        appType,
        action: 'reset',
        reason: `Used reset token. ${resetStatus.tokensRemaining - 1} remaining.`,
        ipAddress: ip
      }
    });
    
    log(`[device] reset: user=${userId} app=${appType} devicesDeactivated=${result.count}`);
    
    res.json({ 
      ok: true, 
      devicesDeactivated: result.count,
      tokensRemaining: resetStatus.tokensRemaining - 1
    });
  } catch (e) {
    console.error('[devices/reset] error:', e?.message || e);
    res.status(500).json({ error: 'Device reset failed' });
  }
});

// ---------- Remove Specific Device ----------
app.delete('/devices/:deviceId', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { deviceId } = req.params;
    const { appType } = req.body || {};
    
    if (!appType) {
      return res.status(400).json({ error: 'Missing appType' });
    }
    
    // Check if user can reset
    const resetStatus = await canResetDevice(userId);
    if (!resetStatus.canReset) {
      return res.status(403).json({ 
        error: 'No reset tokens available',
        code: 'NO_RESET_TOKENS',
        daysUntilReset: resetStatus.daysUntilReset
      });
    }
    
    // Find and deactivate the device
    const device = await prisma.authorizedDevice.findUnique({
      where: { 
        userId_deviceId_appType: { userId, deviceId, appType } 
      }
    });
    
    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }
    
    await prisma.authorizedDevice.update({
      where: { id: device.id },
      data: { active: false }
    });
    
    // Consume reset token
    await prisma.deviceResetToken.update({
      where: { userId },
      data: { 
        tokensRemaining: { decrement: 1 },
        lastResetAt: new Date()
      }
    });
    
    // Audit log
    const { ip } = getDeviceFingerprint(req);
    await prisma.deviceAuditLog.create({
      data: {
        userId,
        deviceId,
        appType,
        action: 'unregistered',
        reason: 'User removed device',
        ipAddress: ip
      }
    });
    
    log(`[device] removed: user=${userId} device=${deviceId} app=${appType}`);
    
    res.json({ 
      ok: true,
      tokensRemaining: resetStatus.tokensRemaining - 1
    });
  } catch (e) {
    console.error('[devices/remove] error:', e?.message || e);
    res.status(500).json({ error: 'Device removal failed' });
  }
});

// ---------- Device Audit Log (Admin) ----------
app.get('/devices/audit', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    
    // Optional: check if user is admin
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user?.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { userId: targetUserId } = req.query;
    
    const logs = await prisma.deviceAuditLog.findMany({
      where: targetUserId ? { userId: targetUserId } : {},
      orderBy: { createdAt: 'desc' },
      take: 100
    });
    
    res.json({ logs });
  } catch (e) {
    console.error('[devices/audit] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// ========== ADMIN ENDPOINTS ==========

// Admin authorization middleware
function adminAuth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const [, token] = h.split(' ');
    if (!token) return res.status(401).json({ error: 'Missing bearer token' });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    
    // Check if user is admin
    prisma.user.findUnique({ 
      where: { id: decoded.sub },
      select: { isAdmin: true }
    }).then(user => {
      if (!user?.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
      }
      next();
    }).catch(err => {
      res.status(401).json({ error: 'Invalid token' });
    });
    
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Manually grant premium to any user (ADMIN ONLY)
app.post('/admin/grant_premium', adminAuth, async (req, res) => {
  try {
    const { email, days = 30 } = req.body;
    
    if (!email || !isEmail(email)) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    console.log('[admin/grant_premium] Granting premium to:', email, 'for', days, 'days');

    const user = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Find or create an org for this user
    let org = await prisma.org.findFirst({
      where: { ownerUserId: user.id }
    });

    if (!org) {
      org = await prisma.org.create({
        data: { 
          name: `${email.split('@')[0]}'s Org`,
          ownerUserId: user.id
        }
      });

      await prisma.member.create({
        data: { orgId: org.id, userId: user.id, role: 'owner' }
      });
    }

    // Create a manual subscription (no Stripe)
    const periodEnd = new Date();
    periodEnd.setDate(periodEnd.getDate() + parseInt(days));

    const manualSubId = `manual_${user.id}_${Date.now()}`;
    
    // Delete any existing manual subscriptions for this user
    await prisma.subscription.deleteMany({
      where: {
        orgId: org.id,
        provider: 'manual'
      }
    });

    // Create new manual subscription
    await prisma.subscription.create({
      data: {
        id: manualSubId,
        orgId: org.id,
        provider: 'manual',
        status: 'active',
        currentPeriodEnd: periodEnd,
        customerId: 'manual'
      }
    });

    console.log('[admin/grant_premium] Premium granted to', email, 'until:', periodEnd);

    res.json({
      ok: true,
      message: `Premium access granted to ${email} for ${days} days`,
      email: email,
      expiresAt: periodEnd.toISOString()
    });

  } catch (e) {
    console.error('[admin/grant_premium] error:', e?.message || e);
    res.status(500).json({ 
      error: 'Failed to grant premium', 
      detail: e?.message 
    });
  }
});

// Manually create account and send registration email (ADMIN ONLY)
app.post('/admin/create_account', adminAuth, async (req, res) => {
  try {
    const { email, grantPremiumDays } = req.body;
    
    if (!email || !isEmail(email)) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const cleanEmail = email.toLowerCase().trim();
    console.log('[admin/create_account] Creating account for:', cleanEmail);

    // Check if user already exists
    let user = await prisma.user.findUnique({ where: { email: cleanEmail } });
    
    if (user) {
      if (user.passwordHash) {
        return res.status(400).json({ 
          error: 'Account already exists with password set',
          note: 'User can login directly'
        });
      }
      console.log('[admin/create_account] User exists but no password, resending registration');
    } else {
      // Create new user
      user = await prisma.user.create({ 
        data: { email: cleanEmail }
      });
      console.log('[admin/create_account] Created new user:', user.id);
    }

    // Create and send registration token
    const raw = await issueRegistrationToken(user.id);
    await sendRegistrationEmail(cleanEmail, raw);
    console.log('[admin/create_account] Registration email sent to:', cleanEmail);

    // Optionally grant premium if days specified
    let premiumInfo = null;
    if (grantPremiumDays && grantPremiumDays > 0) {
      let org = await prisma.org.findFirst({
        where: { ownerUserId: user.id }
      });

      if (!org) {
        org = await prisma.org.create({
          data: { 
            name: `${cleanEmail.split('@')[0]}'s Org`,
            ownerUserId: user.id
          }
        });

        await prisma.member.create({
          data: { orgId: org.id, userId: user.id, role: 'owner' }
        });
      }

      const periodEnd = new Date();
      periodEnd.setDate(periodEnd.getDate() + parseInt(grantPremiumDays));

      const manualSubId = `manual_${user.id}_${Date.now()}`;
      
      await prisma.subscription.deleteMany({
        where: { orgId: org.id, provider: 'manual' }
      });

      await prisma.subscription.create({
        data: {
          id: manualSubId,
          orgId: org.id,
          provider: 'manual',
          status: 'active',
          currentPeriodEnd: periodEnd,
          customerId: 'manual'
        }
      });

      premiumInfo = {
        granted: true,
        days: grantPremiumDays,
        expiresAt: periodEnd.toISOString()
      };

      console.log('[admin/create_account] Premium granted for', grantPremiumDays, 'days');
    }

    res.json({
      ok: true,
      message: `Account created and registration email sent to ${cleanEmail}`,
      email: cleanEmail,
      userId: user.id,
      premium: premiumInfo,
      alreadyExisted: !!user.passwordHash
    });

  } catch (e) {
    console.error('[admin/create_account] error:', e?.message || e);
    res.status(500).json({ 
      error: 'Failed to create account', 
      detail: e?.message 
    });
  }
});

// List all users (ADMIN ONLY)
app.get('/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        isAdmin: true,
        createdAt: true,
        ownedOrgs: {
          include: {
            subscriptions: {
              orderBy: { updatedAt: 'desc' },
              take: 1
            }
          }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    const usersWithStatus = users.map(u => {
      const org = u.ownedOrgs?.[0];
      const sub = org?.subscriptions?.[0];
      const premium = sub && isPremium(sub.status, sub.currentPeriodEnd);

      return {
        id: u.id,
        email: u.email,
        isAdmin: u.isAdmin,
        createdAt: u.createdAt,
        premium: premium,
        subscriptionStatus: sub?.status || 'none',
        subscriptionEnd: sub?.currentPeriodEnd || null
      };
    });

    res.json({ users: usersWithStatus });
  } catch (e) {
    console.error('[admin/users] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to list users' });
  }
});

// ============================================================================
// ADMIN DEVICE MANAGEMENT ENDPOINTS
// ============================================================================

// Set user's max devices per platform
app.post('/admin/users/set_device_limits', adminAuth, async (req, res) => {
  try {
    const { email, maxWindows, maxLinux } = req.body;
    
    if (!email || !isEmail(email)) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    console.log('[admin/set_device_limits] Setting limits for:', email, 
                'Windows:', maxWindows, 'Linux:', maxLinux);

    const user = await prisma.user.findUnique({ 
      where: { email: email.toLowerCase().trim() } 
    });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const updateData = {};
    if (maxWindows !== undefined && maxWindows !== null) {
      updateData.maxWindowsDevices = parseInt(maxWindows);
    }
    if (maxLinux !== undefined && maxLinux !== null) {
      updateData.maxLinuxDevices = parseInt(maxLinux);
    }

    await prisma.user.update({
      where: { id: user.id },
      data: updateData
    });

    console.log('[admin/set_device_limits] Updated device limits for', email);

    res.json({
      ok: true,
      message: `Device limits updated for ${email}`,
      maxWindows: updateData.maxWindowsDevices,
      maxLinux: updateData.maxLinuxDevices
    });

  } catch (e) {
    console.error('[admin/set_device_limits] error:', e?.message || e);
    res.status(500).json({ 
      error: 'Failed to set device limits', 
      detail: e?.message 
    });
  }
});

// Grant reset tokens to a user
// Grant reset tokens to a user
app.post('/admin/users/grant_reset_tokens', adminAuth, async (req, res) => {
  try {
    const { email, tokens } = req.body;
    
    if (!email || !isEmail(email)) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const tokensToAdd = parseInt(tokens) || 1;
    if (tokensToAdd < 1 || tokensToAdd > 10) {
      return res.status(400).json({ error: 'Tokens must be between 1 and 10' });
    }

    console.log('[admin/grant_reset_tokens] Granting', tokensToAdd, 'tokens to:', email);

    const user = await prisma.user.findUnique({ 
      where: { email: email.toLowerCase().trim() } 
    });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Upsert reset tokens (with ID for create)
    await prisma.deviceResetToken.upsert({
      where: { userId: user.id },
      create: {
        id: `drt_${user.id}_${Date.now()}`,  // ⭐ ADDED: Required ID field
        userId: user.id,
        tokensRemaining: tokensToAdd,
        updatedAt: new Date()  // ⭐ ADD THIS LINE
      },
      update: {
        tokensRemaining: { increment: tokensToAdd }
      }
    });

    // Get updated count
    const updated = await prisma.deviceResetToken.findUnique({
      where: { userId: user.id }
    });

    console.log('[admin/grant_reset_tokens] User now has', updated?.tokensRemaining, 'tokens');

    res.json({
      ok: true,
      message: `Granted ${tokensToAdd} reset token(s) to ${email}`,
      totalTokens: updated?.tokensRemaining || 0
    });

  } catch (e) {
    console.error('[admin/grant_reset_tokens] error:', e?.message || e);
    res.status(500).json({ 
      error: 'Failed to grant reset tokens', 
      detail: e?.message 
    });
  }
});

// Get user's device status (for admin panel)
app.get('/admin/users/:email/devices', adminAuth, async (req, res) => {
  try {
    const { email } = req.params;
    
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
      include: {
        authorizedDevices: {
          where: { active: true },
          orderBy: { lastSeenAt: 'desc' }
        }
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const resetTokens = await prisma.deviceResetToken.findUnique({
      where: { userId: user.id }
    });

    res.json({
      email: user.email,
      maxWindowsDevices: user.maxWindowsDevices || 1,
      maxLinuxDevices: user.maxLinuxDevices || 1,
      activeDevices: user.authorizedDevices,
      resetTokens: {
        remaining: resetTokens?.tokensRemaining || 0,
        lastUsed: resetTokens?.lastResetAt
      }
    });

  } catch (e) {
    console.error('[admin/users/devices] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to get user devices' });
  }
});

// ========== END OF ADMIN ENDPOINTS ==========

// Cancel subscription (keeps access until period end) - FIXED VERSION
app.post('/billing/cancel_subscription', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    console.log('[cancel_subscription] Request from user:', userId);

    // Verify user has an active premium subscription
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(400).json({ error: 'No active subscription to cancel' });
    }

    // Find user's orgs with active subscriptions
    const orgs = await prisma.org.findMany({
      where: { 
        OR: [
          { ownerUserId: userId }, 
          { members: { some: { userId } } }
        ]
      },
      include: {
        subscriptions: {
          where: {
            status: { in: ['active', 'trialing'] },
            currentPeriodEnd: { gt: new Date() }
          },
          orderBy: { updatedAt: 'desc' },
          take: 1
        }
      }
    });

    // Find the first org with an active subscription
    const orgWithSub = orgs.find(o => o.subscriptions.length > 0);
    if (!orgWithSub || !orgWithSub.subscriptions[0]) {
      return res.status(400).json({ error: 'No active subscription found' });
    }

    const subscription = orgWithSub.subscriptions[0];
    const stripeSubId = subscription.id.replace('stripe_', '');

    console.log('[cancel_subscription] Attempting to cancel Stripe subscription:', stripeSubId);

    try {
      // Try to cancel in Stripe at period end
      const updatedSub = await stripe.subscriptions.update(stripeSubId, {
        cancel_at_period_end: true
      });

      // Update our database with Stripe's response
      await prisma.subscription.update({
        where: { id: subscription.id },
        data: { 
          status: updatedSub.status,
          updatedAt: new Date()
        }
      });

      const periodEnd = subscription.currentPeriodEnd;
      console.log('[cancel_subscription] Subscription canceled successfully, access until:', periodEnd);

      return res.json({ 
        ok: true, 
        message: 'Subscription canceled',
        accessUntil: periodEnd.toISOString()
      });

    } catch (stripeError) {
      console.error('[cancel_subscription] Stripe error:', stripeError.message);

      // Handle specific Stripe errors
      if (stripeError.message?.includes('No such subscription')) {
        // Subscription doesn't exist in Stripe, so mark it canceled in our DB
        console.log('[cancel_subscription] Subscription not found in Stripe, marking as canceled in DB');
        
        await prisma.subscription.update({
          where: { id: subscription.id },
          data: { 
            status: 'canceled',
            updatedAt: new Date()
          }
        });

        return res.json({
          ok: true,
          message: 'Subscription was already canceled or not found in payment system',
          note: 'Your subscription has been marked as canceled'
        });
      }

      // For other Stripe errors, throw to outer catch
      throw stripeError;
    }

  } catch (e) {
    console.error('[cancel_subscription] error:', e?.message || e);
    res.status(500).json({ 
      error: 'Failed to cancel subscription', 
      detail: e?.message 
    });
  }
});


// Delete user account (GDPR compliant)
app.delete('/auth/delete_account', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { confirmEmail } = req.body || {};
    
    console.log('[delete_account] Request from user:', userId);

    // Get user details
    const user = await prisma.user.findUnique({ 
      where: { id: userId },
      include: {
        ownedOrgs: {
          include: { 
            subscriptions: true,
            members: true
          }
        },
        memberships: true,
        notificationSettings: {
          include: { rules: true }
        },
        notificationTriggers: true
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Email confirmation check (optional but recommended)
    if (confirmEmail && confirmEmail.toLowerCase().trim() !== user.email) {
      return res.status(400).json({ error: 'Email confirmation does not match' });
    }

    console.log('[delete_account] User found:', user.email);

    // Step 1: Cancel ALL active Stripe subscriptions first
    const activeSubscriptions = [];
    for (const org of user.ownedOrgs) {
      for (const sub of org.subscriptions) {
        if (sub.status === 'active' || sub.status === 'trialing') {
          activeSubscriptions.push(sub);
        }
      }
    }

    console.log('[delete_account] Found', activeSubscriptions.length, 'active subscriptions to cancel');

    for (const sub of activeSubscriptions) {
      try {
        const stripeSubId = sub.id.replace('stripe_', '');
        console.log('[delete_account] Canceling subscription:', stripeSubId);
        
        // Cancel immediately (not at period end) since user is deleting account
        await stripe.subscriptions.cancel(stripeSubId);
        
        // Update our database
        await prisma.subscription.update({
          where: { id: sub.id },
          data: { status: 'canceled' }
        });
      } catch (stripeErr) {
        console.error('[delete_account] Failed to cancel subscription:', stripeErr?.message);
        // Continue with deletion even if Stripe fails
      }
    }

    // Step 2: Delete user data in transaction
    console.log('[delete_account] Deleting user data...');

    await prisma.$transaction(async (tx) => {
      // Delete notification triggers
      await tx.notificationTrigger.deleteMany({
        where: { userId }
      });

      // Delete notification rules and settings
      if (user.notificationSettings) {
        await tx.notificationRule.deleteMany({
          where: { settingsId: user.notificationSettings.id }
        });
        await tx.notificationSettings.delete({
          where: { id: user.notificationSettings.id }
        });
      }

      // Delete password tokens
      await tx.passwordToken.deleteMany({
        where: { userId }
      });

      // Delete memberships
      await tx.member.deleteMany({
        where: { userId }
      });

      // Delete subscriptions from owned orgs
      for (const org of user.ownedOrgs) {
        await tx.subscription.deleteMany({
          where: { orgId: org.id }
        });
      }

      // Delete owned orgs
      await tx.org.deleteMany({
        where: { ownerUserId: userId }
      });

      // Finally, delete the user
      await tx.user.delete({
        where: { id: userId }
      });
    });

    console.log('[delete_account] Account deleted successfully:', user.email);

    // Log the deletion for compliance/audit trail
    console.log('[AUDIT] Account deletion:', {
      userId,
      email: user.email,
      timestamp: new Date().toISOString(),
      subscriptionsCanceled: activeSubscriptions.length
    });

    res.json({ 
      ok: true, 
      message: 'Account deleted successfully' 
    });

  } catch (e) {
    console.error('[delete_account] error:', e?.message || e);
    console.error('[delete_account] stack:', e?.stack);
    res.status(500).json({ 
      error: 'Failed to delete account', 
      detail: e?.message 
    });
  }
});

// Add this endpoint to check if subscription is set to cancel

app.get('/billing/subscription_status', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    
    const orgs = await prisma.org.findMany({
      where: { 
        OR: [
          { ownerUserId: userId }, 
          { members: { some: { userId } } }
        ]
      },
      include: {
        subscriptions: {
          where: {
            status: { in: ['active', 'trialing'] },
            currentPeriodEnd: { gt: new Date() }
          },
          orderBy: { updatedAt: 'desc' },
          take: 1
        }
      }
    });

    const orgWithSub = orgs.find(o => o.subscriptions.length > 0);
    if (!orgWithSub || !orgWithSub.subscriptions[0]) {
      return res.json({ hasSubscription: false });
    }

    const subscription = orgWithSub.subscriptions[0];
    const stripeSubId = subscription.id.replace('stripe_', '');
    
    // Get full subscription details from Stripe
    const stripeSub = await stripe.subscriptions.retrieve(stripeSubId);
    
    res.json({
      hasSubscription: true,
      status: stripeSub.status,
      cancelAtPeriodEnd: stripeSub.cancel_at_period_end,
      currentPeriodEnd: stripeSub.current_period_end ? 
        new Date(stripeSub.current_period_end * 1000).toISOString() : null
    });

  } catch (e) {
    console.error('[subscription_status] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to get subscription status' });
  }
});


// Cleanup stale subscriptions (removes subscriptions that don't exist in Stripe)
app.post('/billing/cleanup_subscriptions', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    console.log('[cleanup_subscriptions] Request from user:', userId);

    // Find all orgs for this user
    const orgs = await prisma.org.findMany({
      where: { 
        OR: [
          { ownerUserId: userId }, 
          { members: { some: { userId } } }
        ]
      },
      include: {
        subscriptions: {
          where: {
            status: { in: ['active', 'trialing'] }
          }
        }
      }
    });

    let cleanedCount = 0;
    let errors = [];

    // Check each subscription in Stripe
    for (const org of orgs) {
      for (const sub of org.subscriptions) {
        const stripeSubId = sub.id.replace('stripe_', '');
        console.log('[cleanup] Checking subscription:', stripeSubId);

        try {
          // Try to retrieve from Stripe
          const stripeSub = await stripe.subscriptions.retrieve(stripeSubId);
          
          // If subscription exists but is canceled, update our DB
          if (stripeSub.status === 'canceled' || stripeSub.cancel_at_period_end) {
            await prisma.subscription.update({
              where: { id: sub.id },
              data: { 
                status: 'canceled',
                updatedAt: new Date()
              }
            });
            cleanedCount++;
            console.log('[cleanup] Marked as canceled:', stripeSubId);
          }
        } catch (stripeErr) {
          // Subscription doesn't exist in Stripe
          if (stripeErr.code === 'resource_missing' || stripeErr.message?.includes('No such subscription')) {
            await prisma.subscription.update({
              where: { id: sub.id },
              data: { 
                status: 'canceled',
                updatedAt: new Date()
              }
            });
            cleanedCount++;
            console.log('[cleanup] Removed stale subscription:', stripeSubId);
          } else {
            errors.push({ subId: stripeSubId, error: stripeErr.message });
            console.error('[cleanup] Error checking subscription:', stripeErr.message);
          }
        }
      }
    }

    res.json({
      ok: true,
      cleaned: cleanedCount,
      errors: errors.length > 0 ? errors : undefined,
      message: cleanedCount > 0 
        ? `Cleaned up ${cleanedCount} stale subscription(s)` 
        : 'No stale subscriptions found'
    });

  } catch (e) {
    console.error('[cleanup_subscriptions] error:', e?.message || e);
    res.status(500).json({ 
      error: 'Failed to cleanup subscriptions', 
      detail: e?.message 
    });
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

// ============================================================================
// DEVICE AUTHORIZATION HELPER
// ============================================================================
async function verifyDeviceAuthorization(userId, deviceId, appType = 'commander') {
  if (!deviceId) {
    // If no device ID provided, allow for backward compatibility
    console.log('[verifyDeviceAuthorization] No device ID provided, allowing access');
    return true;
  }

  try {
    const device = await prisma.authorizedDevice.findFirst({
      where: {
        userId,
        deviceId,
        appType,
        active: true
      }
    });

    if (!device) {
      console.log('[verifyDeviceAuthorization] Device not found or not active for user:', userId);
      return false;
    }

    // Update last seen
    await prisma.authorizedDevice.update({
      where: { id: device.id },
      data: { lastSeenAt: new Date() }
    });

    console.log('[verifyDeviceAuthorization] Device authorized:', device.deviceName);
    return true;
  } catch (error) {
    console.error('[verifyDeviceAuthorization] error:', error);
    return false;
  }
}

// ============================================================================
// NOTIFICATION ENDPOINTS
// ============================================================================

// Get user's notification settings
app.get('/premium/notifications/settings', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const deviceId = req.headers['x-device-id'];
    
    console.log('[DEBUG] Getting notification settings for user:', userId);
    console.log('[DEBUG] Device ID:', deviceId);
    
    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    console.log('[DEBUG] User has premium:', hasPremium);
    
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Verify device authorization
    const isDeviceAuthorized = await verifyDeviceAuthorization(userId, deviceId);
    if (!isDeviceAuthorized && deviceId) {
      console.log('[DEBUG] Device not authorized');
      return res.status(403).json({ error: 'Device not authorized. Please manage your devices.' });
    }

    // Get or create default notification settings
    let settings = await prisma.notificationSettings.findUnique({
      where: { userId },
      include: { rules: true }
    });

    console.log('[DEBUG] Found existing settings:', !!settings);

    if (!settings) {
      console.log('[DEBUG] Creating default settings with updated Bedrock patterns...');
      
      const defaultRules = createDefaultNotificationRules();
      
      settings = await prisma.notificationSettings.create({
        data: {
          userId,
          soundEnabled: false,
          rules: {
            create: defaultRules
          }
        },
        include: { rules: true }
      });
    }

    const response = {
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
    };

    console.log('[DEBUG] Sending response:', JSON.stringify(response, null, 2));
    res.json(response);
  } catch (e) {
    console.error('[premium/notifications/settings] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to get notification settings' });
  }
});

// Update a specific notification rule
app.post('/premium/notifications/rule', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const deviceId = req.headers['x-device-id'];
    const { name, type, pattern, soundFile, enabled } = req.body || {};

    console.log('[RULE_UPDATE] Update request for user:', userId);
    console.log('[RULE_UPDATE] Device ID:', deviceId);
    console.log('[RULE_UPDATE] Request body:', { name, type, pattern, soundFile, enabled });

    // Validate required fields
    if (!name) {
      console.log('[RULE_UPDATE] Missing rule name');
      return res.status(400).json({ error: 'Rule name is required' });
    }

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      console.log('[RULE_UPDATE] User does not have premium');
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Verify device authorization
    const isDeviceAuthorized = await verifyDeviceAuthorization(userId, deviceId);
    if (!isDeviceAuthorized && deviceId) {
      console.log('[RULE_UPDATE] Device not authorized');
      return res.status(403).json({ error: 'Device not authorized. Please manage your devices.' });
    }

    // Get user's notification settings
    const settings = await prisma.notificationSettings.findUnique({
      where: { userId },
      include: { rules: true }
    });

    if (!settings) {
      console.log('[RULE_UPDATE] No notification settings found for user');
      return res.status(404).json({ error: 'Notification settings not found' });
    }

    // Find the rule to update
    const rule = settings.rules.find(r => r.name === name);
    if (!rule) {
      console.log('[RULE_UPDATE] Rule not found:', name);
      console.log('[RULE_UPDATE] Available rules:', settings.rules.map(r => r.name));
      return res.status(404).json({ error: 'Notification rule not found' });
    }

    console.log('[RULE_UPDATE] Found rule to update:', { 
      id: rule.id, 
      name: rule.name,
      currentSoundFile: rule.soundFile, 
      newSoundFile: soundFile 
    });

    // Build update data object
    const updateData = {};
    if (type !== undefined && type !== null) updateData.type = type;
    if (pattern !== undefined && pattern !== null) updateData.pattern = pattern;
    if (soundFile !== undefined && soundFile !== null) updateData.soundFile = soundFile;
    if (enabled !== undefined && enabled !== null) updateData.enabled = enabled;

    console.log('[RULE_UPDATE] Updating rule with data:', updateData);

    // Perform the update
    const updatedRule = await prisma.notificationRule.update({
      where: { id: rule.id },
      data: updateData
    });

    console.log('[RULE_UPDATE] Rule updated successfully:', {
      id: updatedRule.id,
      name: updatedRule.name,
      soundFile: updatedRule.soundFile,
      pattern: updatedRule.pattern,
      enabled: updatedRule.enabled
    });

    res.json({ 
      ok: true, 
      rule: {
        name: updatedRule.name,
        type: updatedRule.type,
        pattern: updatedRule.pattern,
        soundFile: updatedRule.soundFile,
        enabled: updatedRule.enabled
      }
    });

  } catch (e) {
    console.error('[RULE_UPDATE] error:', e?.message || e);
    console.error('[RULE_UPDATE] stack:', e?.stack);
    res.status(500).json({ 
      error: 'Failed to update notification rule', 
      detail: e?.message,
      code: e?.code 
    });
  }
});

// Reset notification rules to defaults
app.post('/premium/notifications/reset', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const deviceId = req.headers['x-device-id'];
    
    console.log('[DEBUG] Reset request for user:', userId);
    console.log('[DEBUG] Device ID:', deviceId);

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      console.log('[DEBUG] User does not have premium');
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Verify device authorization
    const isDeviceAuthorized = await verifyDeviceAuthorization(userId, deviceId);
    if (!isDeviceAuthorized && deviceId) {
      console.log('[DEBUG] Device not authorized');
      return res.status(403).json({ error: 'Device not authorized. Please manage your devices.' });
    }

    console.log('[DEBUG] Resetting notification rules to updated Bedrock patterns...');

    // Use a transaction to ensure atomicity
    await prisma.$transaction(async (tx) => {
      // First, delete all notification rules for this user
      const settings = await tx.notificationSettings.findUnique({
        where: { userId },
        include: { rules: true }
      });

      if (settings) {
        console.log('[DEBUG] Found existing settings, deleting rules...');
        
        // Delete rules first (due to foreign key constraint)
        await tx.notificationRule.deleteMany({
          where: { settingsId: settings.id }
        });
        
        // Delete the settings
        await tx.notificationSettings.delete({
          where: { id: settings.id }
        });
        
        console.log('[DEBUG] Deleted existing settings and rules');
      }

      // Create new settings with updated rules
      const defaultRules = createDefaultNotificationRules();
      console.log('[DEBUG] Creating new settings with rules:', defaultRules.map(r => r.name));

      const newSettings = await tx.notificationSettings.create({
        data: {
          userId,
          soundEnabled: false,
          rules: {
            create: defaultRules
          }
        },
        include: { rules: true }
      });

      console.log('[DEBUG] Created new settings with', newSettings.rules.length, 'rules');
    });

    console.log('[DEBUG] Reset completed successfully');
    res.json({ ok: true });
    
  } catch (e) {
    console.error('[premium/notifications/reset] error:', e?.message || e);
    console.error('[premium/notifications/reset] stack:', e?.stack);
    res.status(500).json({ error: 'Failed to reset notification rules', detail: e?.message });
  }
});

// Enable/disable sound notifications
app.post('/premium/notifications/sound', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const deviceId = req.headers['x-device-id'];
    const { enabled } = req.body || {};

    console.log('[SOUND_TOGGLE] User:', userId, 'Device:', deviceId, 'Enabled:', enabled);

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Verify device authorization
    const isDeviceAuthorized = await verifyDeviceAuthorization(userId, deviceId);
    if (!isDeviceAuthorized && deviceId) {
      console.log('[SOUND_TOGGLE] Device not authorized');
      return res.status(403).json({ error: 'Device not authorized. Please manage your devices.' });
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
    const deviceId = req.headers['x-device-id'];
    const { filename } = req.params;

    console.log(`[premium/sounds] Request for sound: ${filename} by user: ${userId}, device: ${deviceId}`);

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      console.log(`[premium/sounds] User ${userId} does not have premium`);
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Verify device authorization
    const isDeviceAuthorized = await verifyDeviceAuthorization(userId, deviceId);
    if (!isDeviceAuthorized && deviceId) {
      console.log(`[premium/sounds] Device not authorized`);
      return res.status(403).json({ error: 'Device not authorized. Please manage your devices.' });
    }

    // Validate filename for security
    if (!/^[a-zA-Z0-9_-]+\.(wav|mp3)$/.test(filename)) {
      console.log(`[premium/sounds] Invalid filename: ${filename}`);
      return res.status(400).json({ error: 'Invalid filename' });
    }

    // Ensure sounds directory exists
    const soundsDir = path.join(process.cwd(), 'sounds');
    if (!fs.existsSync(soundsDir)) {
      console.log(`[premium/sounds] Creating sounds directory: ${soundsDir}`);
      fs.mkdirSync(soundsDir, { recursive: true });
    }

    const soundPath = path.join(soundsDir, filename);
    
    // Check if file exists, if not create a minimal default
    if (!fs.existsSync(soundPath)) {
      console.log(`[premium/sounds] Sound file not found: ${filename}, creating minimal default`);
      
      // Create a minimal WAV file (silent audio)
      const wavHeader = Buffer.from([
        0x52, 0x49, 0x46, 0x46, // "RIFF"
        0x24, 0x00, 0x00, 0x00, // File size - 8
        0x57, 0x41, 0x56, 0x45, // "WAVE"
        0x66, 0x6D, 0x74, 0x20, // "fmt "
        0x10, 0x00, 0x00, 0x00, // Subchunk1Size (16 for PCM)
        0x01, 0x00,             // AudioFormat (1 for PCM)
        0x01, 0x00,             // NumChannels (1 = mono)
        0x44, 0xAC, 0x00, 0x00, // SampleRate (44100)
        0x44, 0xAC, 0x00, 0x00, // ByteRate
        0x01, 0x00,             // BlockAlign
        0x08, 0x00,             // BitsPerSample (8)
        0x64, 0x61, 0x74, 0x61, // "data"
        0x00, 0x00, 0x00, 0x00  // Subchunk2Size (0 = no audio data)
      ]);

      try {
        fs.writeFileSync(soundPath, wavHeader);
        console.log(`[premium/sounds] Created default sound file: ${soundPath}`);
      } catch (writeError) {
        console.error(`[premium/sounds] Failed to create default sound: ${writeError.message}`);
        return res.status(500).json({ error: 'Could not create default sound file' });
      }
    }

    // Set proper headers for audio files
    const ext = path.extname(filename).toLowerCase();
    const mimeType = ext === '.wav' ? 'audio/wav' : 'audio/mpeg';
    
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
    res.setHeader('Access-Control-Allow-Origin', '*'); // Allow CORS for audio files
    
    console.log(`[premium/sounds] Serving sound file: ${soundPath}`);
    
    // Stream the file
    const stream = fs.createReadStream(soundPath);
    stream.on('error', (streamError) => {
      console.error(`[premium/sounds] Stream error: ${streamError.message}`);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Failed to stream sound file' });
      }
    });
    
    stream.pipe(res);
    
  } catch (e) {
    console.error('[premium/sounds] error:', e?.message || e);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to serve sound file' });
    }
  }
});

// ---------- start ----------
app.listen(PORT, () => {
  log(`API up on :${PORT}`);
  log('[env] allowed CORS:', allowed);
});
