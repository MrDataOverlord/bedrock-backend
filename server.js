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

/ ---------- World Backup Premium Features ----------

// Get backup settings
app.get('/premium/backups/settings', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    let settings = await prisma.backupSettings.findUnique({
      where: { userId }
    });

    if (!settings) {
      // Create default settings
      settings = await prisma.backupSettings.create({
        data: {
          userId,
          enabled: true,
          intervalHours: 24,
          backupTime: "00:00",
          maxBackups: 7,
          unlimitedBackups: false
        }
      });
    }

    res.json(settings);
  } catch (e) {
    console.error('[premium/backups/settings] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to get backup settings' });
  }
});

// Update backup settings
app.post('/premium/backups/settings', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { 
      enabled, 
      intervalHours, 
      backupTime, 
      maxBackups, 
      unlimitedBackups,
      serverFolder,
      worldName 
    } = req.body || {};

    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    // Validate inputs
    if (intervalHours && (intervalHours < 1 || intervalHours > 168)) {
      return res.status(400).json({ error: 'Interval must be between 1 and 168 hours' });
    }

    if (maxBackups && !unlimitedBackups && (maxBackups < 1 || maxBackups > 100)) {
      return res.status(400).json({ error: 'Max backups must be between 1 and 100' });
    }

    if (backupTime && !/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(backupTime)) {
      return res.status(400).json({ error: 'Backup time must be in HH:MM format' });
    }

    const updateData = {};
    if (enabled !== undefined) updateData.enabled = Boolean(enabled);
    if (intervalHours !== undefined) updateData.intervalHours = Math.max(1, Math.min(168, intervalHours));
    if (backupTime !== undefined) updateData.backupTime = backupTime;
    if (maxBackups !== undefined) updateData.maxBackups = unlimitedBackups ? 999 : Math.max(1, Math.min(100, maxBackups));
    if (unlimitedBackups !== undefined) updateData.unlimitedBackups = Boolean(unlimitedBackups);
    if (serverFolder !== undefined) updateData.serverFolder = serverFolder;
    if (worldName !== undefined) updateData.worldName = worldName;

    const settings = await prisma.backupSettings.upsert({
      where: { userId },
      create: {
        userId,
        enabled: Boolean(enabled ?? true),
        intervalHours: Math.max(1, Math.min(168, intervalHours ?? 24)),
        backupTime: backupTime ?? "00:00",
        maxBackups: unlimitedBackups ? 999 : Math.max(1, Math.min(100, maxBackups ?? 7)),
        unlimitedBackups: Boolean(unlimitedBackups ?? false),
        serverFolder: serverFolder ?? null,
        worldName: worldName ?? null
      },
      update: updateData
    });

    res.json(settings);
  } catch (e) {
    console.error('[premium/backups/settings] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to update backup settings' });
  }
});

// Get backup history
app.get('/premium/backups/history', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    const history = await prisma.backupHistory.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 50 // Limit to last 50 backups
    });

    res.json({ backups: history });
  } catch (e) {
    console.error('[premium/backups/history] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to get backup history' });
  }
});

// List available backups for restore
app.get('/premium/backups/available/:serverFolder', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const serverFolder = decodeURIComponent(req.params.serverFolder);
    
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    if (!serverFolder || !fs.existsSync(serverFolder)) {
      return res.status(400).json({ error: 'Invalid server folder path' });
    }

    const backupsPath = path.join(serverFolder, 'world_backups');
    if (!fs.existsSync(backupsPath)) {
      return res.json({ backups: [] });
    }

    const backups = await scanBackupDirectory(backupsPath);
    res.json({ backups });
  } catch (e) {
    console.error('[premium/backups/available] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to scan backup directory' });
  }
});

// Create manual backup
app.post('/premium/backups/create', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { serverFolder, worldName } = req.body || {};
    
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    if (!serverFolder || !worldName) {
      return res.status(400).json({ error: 'Server folder and world name are required' });
    }

    if (!fs.existsSync(serverFolder)) {
      return res.status(400).json({ error: 'Server folder does not exist' });
    }

    const worldPath = path.join(serverFolder, worldName);
    if (!fs.existsSync(worldPath)) {
      return res.status(400).json({ error: 'World folder does not exist' });
    }

    // Create backup
    const backupResult = await createWorldBackup(serverFolder, worldName, userId, 'manual');
    
    if (backupResult.success) {
      res.json({ 
        success: true, 
        backupPath: backupResult.backupPath,
        message: 'Backup created successfully' 
      });
    } else {
      res.status(500).json({ error: backupResult.error || 'Backup creation failed' });
    }
  } catch (e) {
    console.error('[premium/backups/create] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to create backup' });
  }
});

// Restore from backup
app.post('/premium/backups/restore', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const { serverFolder, currentWorldName, backupPath } = req.body || {};
    
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    if (!serverFolder || !currentWorldName || !backupPath) {
      return res.status(400).json({ error: 'All parameters are required' });
    }

    const fullBackupPath = path.join(serverFolder, 'world_backups', backupPath);
    if (!fs.existsSync(fullBackupPath)) {
      return res.status(400).json({ error: 'Backup does not exist' });
    }

    const restoreResult = await restoreWorldFromBackup(
      serverFolder, 
      currentWorldName, 
      fullBackupPath, 
      userId
    );
    
    if (restoreResult.success) {
      res.json({ 
        success: true, 
        corruptedPath: restoreResult.corruptedPath,
        message: 'World restored successfully' 
      });
    } else {
      res.status(500).json({ error: restoreResult.error || 'Restore failed' });
    }
  } catch (e) {
    console.error('[premium/backups/restore] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to restore backup' });
  }
});

// Delete specific backup
app.delete('/premium/backups/:backupId', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    const backupId = req.params.backupId;
    
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
    }

    const backup = await prisma.backupHistory.findFirst({
      where: { id: backupId, userId }
    });

    if (!backup) {
      return res.status(404).json({ error: 'Backup not found' });
    }

    // Delete physical backup folder
    if (fs.existsSync(backup.backupPath)) {
      await fs.promises.rm(backup.backupPath, { recursive: true, force: true });
    }

    // Delete database record
    await prisma.backupHistory.delete({
      where: { id: backupId }
    });

    res.json({ success: true, message: 'Backup deleted successfully' });
  } catch (e) {
    console.error('[premium/backups/delete] error:', e?.message || e);
    res.status(500).json({ error: 'Failed to delete backup' });
  }
});

// ---------- Backup Utility Functions ----------

async function createWorldBackup(serverFolder, worldName, userId, backupType = 'automatic') {
  try {
    const worldPath = path.join(serverFolder, worldName);
    if (!fs.existsSync(worldPath)) {
      return { success: false, error: 'World folder does not exist' };
    }

    // Create backup directory structure
    const now = new Date();
    const year = now.getFullYear();
    const month = now.toLocaleString('default', { month: 'long' });
    const day = now.getDate().toString().padStart(2, '0');
    const hour = now.getHours();
    const ampm = hour >= 12 ? 'PM' : 'AM';
    const hour12 = hour % 12 || 12;
    const timeStr = `${hour12}_${ampm}`;

    const backupBaseDir = path.join(serverFolder, 'world_backups', year.toString(), month, day);
    const backupFolderName = `${worldName}_${timeStr}`;
    const backupPath = path.join(backupBaseDir, backupFolderName);

    // Ensure backup directory exists
    await fs.promises.mkdir(backupBaseDir, { recursive: true });

    // Copy world folder to backup location
    await copyDirectory(worldPath, backupPath);

    // Calculate backup size
    const backupSize = await getDirectorySize(backupPath);

    // Record in database
    await prisma.backupHistory.create({
      data: {
        userId,
        worldName,
        backupPath,
        backupSize: BigInt(backupSize),
        backupType
      }
    });

    // Clean up old backups if needed
    await cleanupOldBackups(userId, serverFolder);

    console.log(`[BACKUP] Created ${backupType} backup: ${backupPath}`);
    return { success: true, backupPath };
  } catch (error) {
    console.error('[BACKUP] Creation failed:', error);
    return { success: false, error: error.message };
  }
}

async function restoreWorldFromBackup(serverFolder, currentWorldName, backupPath, userId) {
  try {
    const currentWorldPath = path.join(serverFolder, currentWorldName);
    
    // Create corrupted backup of current world
    const now = new Date();
    const timeStr = `${now.getHours().toString().padStart(2, '0')}_${now.getHours() >= 12 ? 'PM' : 'AM'}`;
    const corruptedName = `corrupted_${currentWorldName}_${timeStr}`;
    
    const year = now.getFullYear();
    const month = now.toLocaleString('default', { month: 'long' });
    const day = now.getDate().toString().padStart(2, '0');
    
    const corruptedBackupDir = path.join(serverFolder, 'world_backups', year.toString(), month, day);
    const corruptedPath = path.join(corruptedBackupDir, corruptedName);
    
    await fs.promises.mkdir(corruptedBackupDir, { recursive: true });

    // Move current world to corrupted backup location
    if (fs.existsSync(currentWorldPath)) {
      await fs.promises.rename(currentWorldPath, corruptedPath);
    }

    // Copy backup to current world location
    await copyDirectory(backupPath, currentWorldPath);

    console.log(`[BACKUP] Restored world from: ${backupPath}`);
    console.log(`[BACKUP] Current world saved as: ${corruptedPath}`);
    
    return { success: true, corruptedPath };
  } catch (error) {
    console.error('[BACKUP] Restore failed:', error);
    return { success: false, error: error.message };
  }
}

async function cleanupOldBackups(userId, serverFolder) {
  try {
    const settings = await prisma.backupSettings.findUnique({
      where: { userId }
    });

    if (!settings || settings.unlimitedBackups) {
      return; // No cleanup needed
    }

    const backups = await prisma.backupHistory.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' }
    });

    if (backups.length <= settings.maxBackups) {
      return; // Within limit
    }

    const backupsToDelete = backups.slice(settings.maxBackups);
    
    for (const backup of backupsToDelete) {
      try {
        // Delete physical backup
        if (fs.existsSync(backup.backupPath)) {
          await fs.promises.rm(backup.backupPath, { recursive: true, force: true });
        }
        
        // Delete database record
        await prisma.backupHistory.delete({
          where: { id: backup.id }
        });
        
        console.log(`[BACKUP] Cleaned up old backup: ${backup.backupPath}`);
      } catch (error) {
        console.error(`[BACKUP] Failed to cleanup: ${backup.backupPath}`, error);
      }
    }
  } catch (error) {
    console.error('[BACKUP] Cleanup failed:', error);
  }
}

async function copyDirectory(src, dest) {
  const stat = await fs.promises.stat(src);
  
  if (stat.isDirectory()) {
    await fs.promises.mkdir(dest, { recursive: true });
    const entries = await fs.promises.readdir(src);
    
    for (const entry of entries) {
      const srcPath = path.join(src, entry);
      const destPath = path.join(dest, entry);
      await copyDirectory(srcPath, destPath);
    }
  } else {
    await fs.promises.copyFile(src, dest);
  }
}

async function getDirectorySize(dirPath) {
  let totalSize = 0;
  
  const stats = await fs.promises.stat(dirPath);
  if (stats.isFile()) {
    return stats.size;
  }
  
  if (stats.isDirectory()) {
    const entries = await fs.promises.readdir(dirPath);
    for (const entry of entries) {
      const entryPath = path.join(dirPath, entry);
      totalSize += await getDirectorySize(entryPath);
    }
  }
  
  return totalSize;
}

async function scanBackupDirectory(backupsPath) {
  const backups = [];
  
  try {
    const years = await fs.promises.readdir(backupsPath);
    
    for (const year of years) {
      const yearPath = path.join(backupsPath, year);
      if (!fs.statSync(yearPath).isDirectory()) continue;
      
      const months = await fs.promises.readdir(yearPath);
      
      for (const month of months) {
        const monthPath = path.join(yearPath, month);
        if (!fs.statSync(monthPath).isDirectory()) continue;
        
        const days = await fs.promises.readdir(monthPath);
        
        for (const day of days) {
          const dayPath = path.join(monthPath, day);
          if (!fs.statSync(dayPath).isDirectory()) continue;
          
          const backupFolders = await fs.promises.readdir(dayPath);
          
          for (const backupFolder of backupFolders) {
            const backupFolderPath = path.join(dayPath, backupFolder);
            if (!fs.statSync(backupFolderPath).isDirectory()) continue;
            
            // Parse backup folder name: worldname_12_AM
            const match = backupFolder.match(/^(.+)_(\d{1,2})_(AM|PM)$/);
            if (match) {
              const [, worldName, hour, ampm] = match;
              
              const stats = fs.statSync(backupFolderPath);
              
              backups.push({
                worldName,
                date: `${year}-${String(new Date(`${month} 1, ${year}`).getMonth() + 1).padStart(2, '0')}-${day}`,
                time: `${hour}_${ampm}`,
                displayTime: `${hour} ${ampm}`,
                path: path.join(year, month, day, backupFolder),
                size: await getDirectorySize(backupFolderPath),
                created: stats.ctime
              });
            }
          }
        }
      }
    }
  } catch (error) {
    console.error('[BACKUP] Failed to scan backup directory:', error);
  }
  
  return backups.sort((a, b) => new Date(b.created) - new Date(a.created));
}

// ---------- Premium Features (Server-Side Validation) ----------

// Get user's notification settings
app.get('/premium/notifications/settings', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    console.log('[DEBUG] Getting notification settings for user:', userId);
    
    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    console.log('[DEBUG] User has premium:', hasPremium);
    
    if (!hasPremium) {
      return res.status(403).json({ error: 'Premium subscription required' });
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
    const { name, type, pattern, soundFile, enabled } = req.body || {};

    console.log('[RULE_UPDATE] Update request for user:', userId);
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

// Reset notification rules to defaults:
app.post('/premium/notifications/reset', auth, async (req, res) => {
  try {
    const userId = req.user.sub;
    console.log('[DEBUG] Reset request for user:', userId);

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      console.log('[DEBUG] User does not have premium');
      return res.status(403).json({ error: 'Premium subscription required' });
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

    console.log(`[premium/sounds] Request for sound: ${filename} by user: ${userId}`);

    // Verify premium status
    const hasPremium = await userHasActivePremium(userId);
    if (!hasPremium) {
      console.log(`[premium/sounds] User ${userId} does not have premium`);
      return res.status(403).json({ error: 'Premium subscription required' });
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
