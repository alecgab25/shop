const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const argon2 = require('argon2');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const DATA_FILE = path.join(__dirname, 'data.json');
const SESSION_COOKIE = 'admin_session';
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes
const USER_SESSION_COOKIE = 'user_session';
const RESET_TTL_MS = 30 * 60 * 1000; // 30 minutes
const secureCookies = process.env.NODE_ENV === 'production';
const APP_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:5173';
const SMTP_USER = (process.env.SMTP_USER || '').trim();
const SMTP_PASS = (process.env.SMTP_PASS || '').replace(/\s+/g, '');
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_SECURE = process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : SMTP_PORT === 465;
const SMTP_FROM = (process.env.SMTP_FROM || SMTP_USER).trim();

const mailTransport = SMTP_USER && SMTP_PASS
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    })
  : null;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

// --- simple file storage ---
function loadDB() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf-8');
    const parsed = JSON.parse(raw);
    if (!parsed.users) parsed.users = [];
    if (!parsed.user_sessions) parsed.user_sessions = [];
    if (!parsed.reset_tokens) parsed.reset_tokens = [];
    parsed.users = parsed.users.map((u) => ({
      ...u,
      verified: u.verified !== false,
      verify_token: u.verify_token || null,
    }));
    if (!parsed.backgrounds) {
      parsed.backgrounds = {
        front_page: { color: '', image: '' },
        shop: { color: '', image: '' },
      };
    }
    return parsed;
  } catch (_e) {
    return {
      admins: [],
      sessions: [],
      users: [],
      user_sessions: [],
      reset_tokens: [],
      bank_info: { account_name: '', account_number: '', instructions: '' },
      backgrounds: {
        front_page: { color: '', image: '' },
        shop: { color: '', image: '' },
      },
      orders: [],
      lastOrderId: 0,
    };
  }
}

function saveDB(db) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), 'utf-8');
}

let db = loadDB();

function countAdmins() {
  return db.admins.length;
}

function getSession(id) {
  return db.sessions.find((s) => s.id === id) || null;
}

function deleteSession(id) {
  db.sessions = db.sessions.filter((s) => s.id !== id);
  saveDB(db);
}

function sessionMiddleware(opts = {}) {
  return (req, res, next) => {
    const sid = req.cookies[SESSION_COOKIE];
    if (!sid) return res.status(401).end();
    const session = getSession(sid);
    if (!session || session.expires_at < Date.now()) {
      deleteSession(sid);
      res.clearCookie(SESSION_COOKIE);
      return res.status(401).end();
    }
    const admin = db.admins.find((a) => a.id === session.admin_id);
    if (!admin) {
      deleteSession(sid);
      res.clearCookie(SESSION_COOKIE);
      return res.status(401).end();
    }
    if (opts.owner && !admin.is_owner) return res.status(403).end();
    req.admin = admin;
    req.sessionId = sid;
    next();
  };
}

function setSessionCookie(res, sid) {
  res.cookie(SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: 'lax',
    secure: secureCookies,
    maxAge: SESSION_TTL_MS,
  });
}

function getUserSession(id) {
  return db.user_sessions.find((s) => s.id === id) || null;
}

function deleteUserSession(id) {
  db.user_sessions = db.user_sessions.filter((s) => s.id !== id);
  saveDB(db);
}

function setUserSessionCookie(res, sid) {
  res.cookie(USER_SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: 'lax',
    secure: secureCookies,
    maxAge: SESSION_TTL_MS,
  });
}

function userSessionMiddleware() {
  return (req, res, next) => {
    const sid = req.cookies[USER_SESSION_COOKIE];
    if (!sid) return res.status(401).end();
    const session = getUserSession(sid);
    if (!session || session.expires_at < Date.now()) {
      deleteUserSession(sid);
      res.clearCookie(USER_SESSION_COOKIE);
      return res.status(401).end();
    }
    req.userEmail = session.email;
    next();
  };
}

// --- routes ---
app.get('/api/admins/has-admin', (req, res) => {
  res.json({ hasAdmin: countAdmins() > 0 });
});

app.post('/api/admins/bootstrap', async (req, res) => {
  if (countAdmins() > 0) return res.status(403).json({ error: 'Already bootstrapped' });
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hash = await argon2.hash(password);
  const id = crypto.randomUUID();
  db.admins.push({ id, email: email.toLowerCase(), password_hash: hash, is_owner: true, created_at: new Date().toISOString() });
  saveDB(db);
  res.status(201).end();
});

// User registration/login for site access
app.post('/api/users/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const lower = email.toLowerCase();
  if (db.users.find((u) => u.email === lower) || db.admins.find((a) => a.email === lower)) {
    return res.status(409).json({ error: 'Email already in use' });
  }
  const hash = await argon2.hash(password);
  const verifyToken = crypto.randomUUID();
  db.users.push({
    id: crypto.randomUUID(),
    email: lower,
    password_hash: hash,
    verified: false,
    verify_token: verifyToken,
    created_at: new Date().toISOString(),
  });
  saveDB(db);
  const verifyUrl = `/api/users/verify?token=${verifyToken}`;
  res.status(201).json({ message: 'Check your inbox to verify.', verify_url: verifyUrl });
});

app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const lower = email.toLowerCase();
  // If email is admin, verify admin credentials and issue both sessions
  const admin = db.admins.find((a) => a.email === lower);
  if (admin) {
    const ok = await argon2.verify(admin.password_hash, password || '');
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const sid = crypto.randomUUID();
    const expiresAt = Date.now() + SESSION_TTL_MS;
    db.sessions.push({
      id: sid,
      admin_id: admin.id,
      expires_at: expiresAt,
      user_agent: req.headers['user-agent'] || '',
      ip: req.ip || '',
    });
    setSessionCookie(res, sid);
    // also issue user session
    const userSid = crypto.randomUUID();
    db.user_sessions.push({
      id: userSid,
      email: admin.email,
      expires_at: expiresAt,
      user_agent: req.headers['user-agent'] || '',
      ip: req.ip || '',
    });
    saveDB(db);
    setUserSessionCookie(res, userSid);
    return res.json({ email: admin.email, is_admin: true, is_owner: !!admin.is_owner });
  }
  // regular user
  const user = db.users.find((u) => u.email === lower);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.verified === false) return res.status(403).json({ error: 'Please verify your email before signing in.' });
  const ok = await argon2.verify(user.password_hash, password || '');
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const userSid = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  db.user_sessions.push({
    id: userSid,
    email: user.email,
    expires_at: expiresAt,
    user_agent: req.headers['user-agent'] || '',
    ip: req.ip || '',
  });
  saveDB(db);
  setUserSessionCookie(res, userSid);
  res.json({ email: user.email, is_admin: false, is_owner: false });
});

// Password reset (request + confirm)
app.post('/api/users/reset-request', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  const lower = email.toLowerCase();
  const isAdmin = !!db.admins.find((a) => a.email === lower);
  const isUser = !!db.users.find((u) => u.email === lower);
  if (!isAdmin && !isUser) {
    return res.json({ message: 'If this email exists, a reset link was sent.' });
  }
  if (!mailTransport || !SMTP_FROM) {
    return res.status(500).json({ error: 'Email sending is not configured.' });
  }
  const token = crypto.randomUUID();
  const expiresAt = Date.now() + RESET_TTL_MS;
  const target = isAdmin ? 'admin' : 'user';
  const resetUrl = `${APP_BASE_URL.replace(/\/+$/, '')}/?reset_token=${token}`;
  try {
    const info = await mailTransport.sendMail({
      from: SMTP_FROM,
      to: lower,
      subject: 'Reset your Glow Up password',
      text: `Click this link to reset your password: ${resetUrl}\nThis link expires in 30 minutes.`,
      html: `<p>Click this link to reset your password:</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>This link expires in 30 minutes.</p>`,
    });
    console.log('Reset email sent:', {
      to: lower,
      messageId: info && info.messageId,
      accepted: info && info.accepted,
      rejected: info && info.rejected,
    });
  } catch (err) {
    console.error('Reset email failed:', err);
    return res.status(500).json({ error: 'Could not send reset email.' });
  }
  db.reset_tokens = db.reset_tokens.filter((t) => t.email !== lower);
  db.reset_tokens.push({ token, email: lower, target, expires_at: expiresAt });
  saveDB(db);
  res.json({ message: 'If this email exists, a reset link was sent.' });
});

app.post('/api/users/reset-confirm', async (req, res) => {
  const token = (req.body && req.body.token) || (req.query && req.query.token);
  const password = req.body && req.body.password;
  if (!token || !password) return res.status(400).json({ error: 'Token and new password required' });
  const entry = db.reset_tokens.find((t) => t.token === token);
  if (!entry) return res.status(400).json({ error: 'Invalid or expired token' });
  if (entry.expires_at < Date.now()) {
    db.reset_tokens = db.reset_tokens.filter((t) => t.token !== token);
    saveDB(db);
    return res.status(400).json({ error: 'Invalid or expired token' });
  }
  const hash = await argon2.hash(password);
  if (entry.target === 'admin') {
    const admin = db.admins.find((a) => a.email === entry.email);
    if (admin) admin.password_hash = hash;
  } else {
    const user = db.users.find((u) => u.email === entry.email);
    if (user) {
      user.password_hash = hash;
      user.verified = true;
      user.verify_token = null;
    }
  }
  db.reset_tokens = db.reset_tokens.filter((t) => t.email !== entry.email);
  saveDB(db);
  res.json({ success: true });
});

app.get('/api/users/verify', (req, res) => {
  const token = (req.query.token || '').toString();
  if (!token) return res.status(400).json({ error: 'Missing token' });
  const user = db.users.find((u) => u.verify_token === token);
  if (!user) return res.status(400).json({ error: 'Invalid or expired token' });
  user.verified = true;
  user.verify_token = null;
  saveDB(db);
  res.json({ success: true });
});

app.get('/api/user-session', userSessionMiddleware(), (req, res) => {
  const email = req.userEmail || '';
  const admin = db.admins.find((a) => a.email === email);
  res.json({ email, is_admin: !!admin, is_owner: !!(admin && admin.is_owner) });
});

app.delete('/api/user-session', userSessionMiddleware(), (req, res) => {
  const sid = req.cookies[USER_SESSION_COOKIE];
  if (sid) deleteUserSession(sid);
  res.clearCookie(USER_SESSION_COOKIE);
  res.clearCookie(SESSION_COOKIE);
  res.status(204).end();
});

app.post('/api/sessions', async (req, res) => {
  const { email, password } = req.body || {};
  const admin = db.admins.find((a) => a.email === (email || '').toLowerCase());
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await argon2.verify(admin.password_hash, password || '');
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const sid = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  db.sessions.push({
    id: sid,
    admin_id: admin.id,
    expires_at: expiresAt,
    user_agent: req.headers['user-agent'] || '',
    ip: req.ip || '',
  });
  saveDB(db);
  setSessionCookie(res, sid);
  res.json({ email: admin.email, is_owner: !!admin.is_owner });
});

app.get('/api/session', sessionMiddleware(), (req, res) => {
  res.json({ email: req.admin.email, is_owner: !!req.admin.is_owner });
});

app.delete('/api/sessions', sessionMiddleware(), (req, res) => {
  deleteSession(req.sessionId);
  res.clearCookie(SESSION_COOKIE);
  res.status(204).end();
});

app.get('/api/admins', sessionMiddleware({ owner: true }), (req, res) => {
  const admins = db.admins
    .slice()
    .sort((a, b) => (a.created_at || '').localeCompare(b.created_at || ''))
    .map((a) => ({ id: a.id, email: a.email, is_owner: !!a.is_owner, created_at: a.created_at }));
  res.json(admins);
});

app.post('/api/admins', sessionMiddleware({ owner: true }), async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (db.admins.find((a) => a.email === email.toLowerCase())) return res.status(409).json({ error: 'Email already admin' });
  const hash = await argon2.hash(password);
  db.admins.push({
    id: crypto.randomUUID(),
    email: email.toLowerCase(),
    password_hash: hash,
    is_owner: false,
    created_at: new Date().toISOString(),
  });
  saveDB(db);
  res.status(201).end();
});

app.delete('/api/admins/:id', sessionMiddleware({ owner: true }), (req, res) => {
  const admin = db.admins.find((a) => a.id === req.params.id);
  if (!admin) return res.status(404).end();
  if (admin.is_owner) return res.status(400).json({ error: 'Cannot remove owner' });
  db.admins = db.admins.filter((a) => a.id !== req.params.id);
  saveDB(db);
  res.status(204).end();
});

// Bank info
app.get('/api/bank-info', (req, res) => {
  res.json(db.bank_info || { account_name: '', account_number: '', instructions: '' });
});

app.put('/api/bank-info', sessionMiddleware({ owner: true }), (req, res) => {
  const { account_name, account_number, instructions } = req.body || {};
  db.bank_info = {
    account_name: account_name || '',
    account_number: account_number || '',
    instructions: instructions || '',
  };
  saveDB(db);
  res.status(204).end();
});

// Backgrounds (admin/owner)
app.get('/api/backgrounds', (req, res) => {
  const defaults = {
    front_page: { color: '', image: '' },
    shop: { color: '', image: '' },
  };
  res.json(db.backgrounds || defaults);
});

app.put('/api/backgrounds', sessionMiddleware(), (req, res) => {
  const { front_page = {}, shop = {} } = req.body || {};
  db.backgrounds = {
    front_page: {
      color: typeof front_page.color === 'string' ? front_page.color : '',
      image: typeof front_page.image === 'string' ? front_page.image : '',
    },
    shop: {
      color: typeof shop.color === 'string' ? shop.color : '',
      image: typeof shop.image === 'string' ? shop.image : '',
    },
  };
  saveDB(db);
  res.status(204).end();
});

// Orders
app.post('/api/orders', (req, res) => {
  const { customer_name, email, address_line, city, region, postal_code, items, total } = req.body || {};
  if (!customer_name || !address_line || !city || !postal_code || !Array.isArray(items)) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const id = (db.lastOrderId || 0) + 1;
  db.lastOrderId = id;
  db.orders.unshift({
    id,
    customer_name,
    email: email || '',
    address_line,
    city,
    region: region || '',
    postal_code,
    items,
    total_cents: Math.round((Number(total) || 0) * 100),
    created_at: new Date().toISOString(),
  });
  saveDB(db);
  res.status(201).end();
});

app.get('/api/orders', sessionMiddleware({ owner: true }), (req, res) => {
  res.json(db.orders || []);
});

// Cleanup expired sessions periodically
setInterval(() => {
  const now = Date.now();
  const before = db.sessions.length;
  db.sessions = db.sessions.filter((s) => s.expires_at > now);
  if (db.sessions.length !== before) saveDB(db);
}, 5 * 60 * 1000);
setInterval(() => {
  const now = Date.now();
  const before = db.user_sessions.length;
  db.user_sessions = db.user_sessions.filter((s) => s.expires_at > now);
  if (db.user_sessions.length !== before) saveDB(db);
}, 5 * 60 * 1000);

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
