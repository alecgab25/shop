const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const mongoose = require('mongoose');
const argon2 = require('argon2');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const SESSION_COOKIE = 'admin_session';
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes
const USER_SESSION_COOKIE = 'user_session';
const RESET_TTL_MS = 30 * 60 * 1000; // 30 minutes
const secureCookies = process.env.NODE_ENV === 'production';
const APP_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:5173';
const MONGODB_URI = (process.env.MONGODB_URI || '').trim();
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

if (!MONGODB_URI) {
  console.error('Missing MONGODB_URI in environment.');
  process.exit(1);
}

const adminSchema = new mongoose.Schema(
  {
    _id: String,
    email: { type: String, unique: true, index: true },
    password_hash: String,
    is_owner: Boolean,
    created_at: String,
  },
  { collection: 'admins' }
);

const sessionSchema = new mongoose.Schema(
  {
    _id: String,
    admin_id: String,
    expires_at: Number,
    user_agent: String,
    ip: String,
  },
  { collection: 'sessions' }
);

const userSchema = new mongoose.Schema(
  {
    _id: String,
    email: { type: String, unique: true, index: true },
    password_hash: String,
    verified: Boolean,
    verify_token: String,
    created_at: String,
  },
  { collection: 'users' }
);

const userSessionSchema = new mongoose.Schema(
  {
    _id: String,
    email: String,
    expires_at: Number,
    user_agent: String,
    ip: String,
  },
  { collection: 'user_sessions' }
);

const resetTokenSchema = new mongoose.Schema(
  {
    _id: String,
    email: String,
    target: String,
    expires_at: Number,
  },
  { collection: 'reset_tokens' }
);

const settingsSchema = new mongoose.Schema(
  {
    _id: String,
    bank_info: {
      account_name: String,
      account_number: String,
      instructions: String,
    },
    backgrounds: {
      front_page: { color: String, image: String },
      shop: { color: String, image: String },
    },
  },
  { collection: 'settings' }
);

const orderSchema = new mongoose.Schema(
  {
    id: Number,
    customer_name: String,
    email: String,
    address_line: String,
    city: String,
    region: String,
    postal_code: String,
    items: Array,
    total_cents: Number,
    created_at: String,
  },
  { collection: 'orders' }
);

const counterSchema = new mongoose.Schema(
  {
    _id: String,
    value: { type: Number, default: 0 },
  },
  { collection: 'counters' }
);

const Admin = mongoose.model('Admin', adminSchema);
const Session = mongoose.model('Session', sessionSchema);
const User = mongoose.model('User', userSchema);
const UserSession = mongoose.model('UserSession', userSessionSchema);
const ResetToken = mongoose.model('ResetToken', resetTokenSchema);
const Settings = mongoose.model('Settings', settingsSchema);
const Order = mongoose.model('Order', orderSchema);
const Counter = mongoose.model('Counter', counterSchema);

const DEFAULT_SETTINGS = {
  bank_info: { account_name: '', account_number: '', instructions: '' },
  backgrounds: {
    front_page: { color: '', image: '' },
    shop: { color: '', image: '' },
  },
};

async function getSettingsDoc() {
  let doc = await Settings.findById('global').lean();
  if (!doc) {
    await Settings.create({ _id: 'global', ...DEFAULT_SETTINGS });
    doc = await Settings.findById('global').lean();
  }
  return doc;
}

async function countAdmins() {
  return Admin.countDocuments();
}

async function getSession(id) {
  return Session.findById(id).lean();
}

async function deleteSession(id) {
  await Session.deleteOne({ _id: id });
}

function sessionMiddleware(opts = {}) {
  return async (req, res, next) => {
    const sid = req.cookies[SESSION_COOKIE];
    if (!sid) return res.status(401).end();
    const session = await getSession(sid);
    if (!session || session.expires_at < Date.now()) {
      await deleteSession(sid);
      res.clearCookie(SESSION_COOKIE);
      return res.status(401).end();
    }
    const admin = await Admin.findById(session.admin_id).lean();
    if (!admin) {
      await deleteSession(sid);
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

async function getUserSession(id) {
  return UserSession.findById(id).lean();
}

async function deleteUserSession(id) {
  await UserSession.deleteOne({ _id: id });
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
  return async (req, res, next) => {
    const sid = req.cookies[USER_SESSION_COOKIE];
    if (!sid) return res.status(401).end();
    const session = await getUserSession(sid);
    if (!session || session.expires_at < Date.now()) {
      await deleteUserSession(sid);
      res.clearCookie(USER_SESSION_COOKIE);
      return res.status(401).end();
    }
    req.userEmail = session.email;
    next();
  };
}

// --- routes ---
app.get('/api/admins/has-admin', (req, res) => {
  countAdmins()
    .then((count) => res.json({ hasAdmin: count > 0 }))
    .catch((err) => {
      console.error('Has-admin failed:', err);
      res.status(500).json({ error: 'Server error' });
    });
});

app.post('/api/admins/bootstrap', async (req, res) => {
  if ((await countAdmins()) > 0) return res.status(403).json({ error: 'Already bootstrapped' });
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const hash = await argon2.hash(password);
  const id = crypto.randomUUID();
  await Admin.create({
    _id: id,
    email: email.toLowerCase(),
    password_hash: hash,
    is_owner: true,
    created_at: new Date().toISOString(),
  });
  res.status(201).end();
});

// User registration/login for site access
app.post('/api/users/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const lower = email.toLowerCase();
  const existingUser = await User.findOne({ email: lower }).lean();
  const existingAdmin = await Admin.findOne({ email: lower }).lean();
  if (existingUser || existingAdmin) {
    return res.status(409).json({ error: 'Email already in use' });
  }
  const hash = await argon2.hash(password);
  const verifyToken = crypto.randomUUID();
  await User.create({
    _id: crypto.randomUUID(),
    email: lower,
    password_hash: hash,
    verified: false,
    verify_token: verifyToken,
    created_at: new Date().toISOString(),
  });
  const verifyUrl = `/api/users/verify?token=${verifyToken}`;
  res.status(201).json({ message: 'Check your inbox to verify.', verify_url: verifyUrl });
});

app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const lower = email.toLowerCase();
  // If email is admin, verify admin credentials and issue both sessions
  const admin = await Admin.findOne({ email: lower }).lean();
  if (admin) {
    const ok = await argon2.verify(admin.password_hash, password || '');
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const sid = crypto.randomUUID();
    const expiresAt = Date.now() + SESSION_TTL_MS;
    await Session.create({
      _id: sid,
      admin_id: admin._id,
      expires_at: expiresAt,
      user_agent: req.headers['user-agent'] || '',
      ip: req.ip || '',
    });
    setSessionCookie(res, sid);
    // also issue user session
    const userSid = crypto.randomUUID();
    await UserSession.create({
      _id: userSid,
      email: admin.email,
      expires_at: expiresAt,
      user_agent: req.headers['user-agent'] || '',
      ip: req.ip || '',
    });
    setUserSessionCookie(res, userSid);
    return res.json({ email: admin.email, is_admin: true, is_owner: !!admin.is_owner });
  }
  // regular user
  const user = await User.findOne({ email: lower }).lean();
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.verified === false) return res.status(403).json({ error: 'Please verify your email before signing in.' });
  const ok = await argon2.verify(user.password_hash, password || '');
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const userSid = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  await UserSession.create({
    _id: userSid,
    email: user.email,
    expires_at: expiresAt,
    user_agent: req.headers['user-agent'] || '',
    ip: req.ip || '',
  });
  setUserSessionCookie(res, userSid);
  res.json({ email: user.email, is_admin: false, is_owner: false });
});

// Password reset (request + confirm)
app.post('/api/users/reset-request', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  const lower = email.toLowerCase();
  const isAdmin = !!(await Admin.findOne({ email: lower }).lean());
  const isUser = !!(await User.findOne({ email: lower }).lean());
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
  await ResetToken.deleteMany({ email: lower });
  await ResetToken.create({ _id: token, email: lower, target, expires_at: expiresAt });
  res.json({ message: 'If this email exists, a reset link was sent.' });
});

app.post('/api/users/reset-confirm', async (req, res) => {
  const token = (req.body && req.body.token) || (req.query && req.query.token);
  const password = req.body && req.body.password;
  if (!token || !password) return res.status(400).json({ error: 'Token and new password required' });
  const entry = await ResetToken.findById(token).lean();
  if (!entry) return res.status(400).json({ error: 'Invalid or expired token' });
  if (entry.expires_at < Date.now()) {
    await ResetToken.deleteOne({ _id: token });
    return res.status(400).json({ error: 'Invalid or expired token' });
  }
  const hash = await argon2.hash(password);
  if (entry.target === 'admin') {
    await Admin.updateOne({ email: entry.email }, { $set: { password_hash: hash } });
  } else {
    await User.updateOne(
      { email: entry.email },
      { $set: { password_hash: hash, verified: true, verify_token: null } }
    );
  }
  await ResetToken.deleteMany({ email: entry.email });
  res.json({ success: true });
});

app.get('/api/users/verify', async (req, res) => {
  const token = (req.query.token || '').toString();
  if (!token) return res.status(400).json({ error: 'Missing token' });
  const user = await User.findOne({ verify_token: token }).lean();
  if (!user) return res.status(400).json({ error: 'Invalid or expired token' });
  await User.updateOne({ _id: user._id }, { $set: { verified: true, verify_token: null } });
  res.json({ success: true });
});

app.get('/api/user-session', userSessionMiddleware(), (req, res) => {
  const email = req.userEmail || '';
  Admin.findOne({ email })
    .lean()
    .then((admin) => {
      res.json({ email, is_admin: !!admin, is_owner: !!(admin && admin.is_owner) });
    })
    .catch((err) => {
      console.error('User session lookup failed:', err);
      res.status(500).json({ error: 'Server error' });
    });
});

app.delete('/api/user-session', userSessionMiddleware(), async (req, res) => {
  const sid = req.cookies[USER_SESSION_COOKIE];
  if (sid) await deleteUserSession(sid);
  res.clearCookie(USER_SESSION_COOKIE);
  res.clearCookie(SESSION_COOKIE);
  res.status(204).end();
});

app.post('/api/sessions', async (req, res) => {
  const { email, password } = req.body || {};
  const admin = await Admin.findOne({ email: (email || '').toLowerCase() }).lean();
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await argon2.verify(admin.password_hash, password || '');
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const sid = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  await Session.create({
    _id: sid,
    admin_id: admin._id,
    expires_at: expiresAt,
    user_agent: req.headers['user-agent'] || '',
    ip: req.ip || '',
  });
  setSessionCookie(res, sid);
  res.json({ email: admin.email, is_owner: !!admin.is_owner });
});

app.get('/api/session', sessionMiddleware(), (req, res) => {
  res.json({ email: req.admin.email, is_owner: !!req.admin.is_owner });
});

app.delete('/api/sessions', sessionMiddleware(), async (req, res) => {
  await deleteSession(req.sessionId);
  res.clearCookie(SESSION_COOKIE);
  res.status(204).end();
});

app.get('/api/admins', sessionMiddleware({ owner: true }), async (req, res) => {
  const admins = await Admin.find()
    .sort({ created_at: 1 })
    .lean();
  res.json(
    admins.map((a) => ({ id: a._id, email: a.email, is_owner: !!a.is_owner, created_at: a.created_at }))
  );
});

app.post('/api/admins', sessionMiddleware({ owner: true }), async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (await Admin.findOne({ email: email.toLowerCase() }).lean()) return res.status(409).json({ error: 'Email already admin' });
  const hash = await argon2.hash(password);
  await Admin.create({
    _id: crypto.randomUUID(),
    email: email.toLowerCase(),
    password_hash: hash,
    is_owner: false,
    created_at: new Date().toISOString(),
  });
  res.status(201).end();
});

app.delete('/api/admins/:id', sessionMiddleware({ owner: true }), async (req, res) => {
  const admin = await Admin.findById(req.params.id).lean();
  if (!admin) return res.status(404).end();
  if (admin.is_owner) return res.status(400).json({ error: 'Cannot remove owner' });
  await Admin.deleteOne({ _id: req.params.id });
  res.status(204).end();
});

// Bank info
app.get('/api/bank-info', (req, res) => {
  getSettingsDoc()
    .then((doc) => res.json(doc.bank_info || DEFAULT_SETTINGS.bank_info))
    .catch((err) => {
      console.error('Bank info fetch failed:', err);
      res.status(500).json({ error: 'Server error' });
    });
});

app.put('/api/bank-info', sessionMiddleware({ owner: true }), (req, res) => {
  const { account_name, account_number, instructions } = req.body || {};
  Settings.updateOne(
    { _id: 'global' },
    {
      $set: {
        bank_info: {
          account_name: account_name || '',
          account_number: account_number || '',
          instructions: instructions || '',
        },
      },
    },
    { upsert: true }
  )
    .then(() => res.status(204).end())
    .catch((err) => {
      console.error('Bank info update failed:', err);
      res.status(500).json({ error: 'Server error' });
    });
});

// Backgrounds (admin/owner)
app.get('/api/backgrounds', (req, res) => {
  const defaults = {
    front_page: { color: '', image: '' },
    shop: { color: '', image: '' },
  };
  getSettingsDoc()
    .then((doc) => res.json(doc.backgrounds || defaults))
    .catch((err) => {
      console.error('Backgrounds fetch failed:', err);
      res.status(500).json({ error: 'Server error' });
    });
});

app.put('/api/backgrounds', sessionMiddleware(), (req, res) => {
  const { front_page = {}, shop = {} } = req.body || {};
  Settings.updateOne(
    { _id: 'global' },
    {
      $set: {
        backgrounds: {
          front_page: {
            color: typeof front_page.color === 'string' ? front_page.color : '',
            image: typeof front_page.image === 'string' ? front_page.image : '',
          },
          shop: {
            color: typeof shop.color === 'string' ? shop.color : '',
            image: typeof shop.image === 'string' ? shop.image : '',
          },
        },
      },
    },
    { upsert: true }
  )
    .then(() => res.status(204).end())
    .catch((err) => {
      console.error('Backgrounds update failed:', err);
      res.status(500).json({ error: 'Server error' });
    });
});

// Orders
app.post('/api/orders', (req, res) => {
  const { customer_name, email, address_line, city, region, postal_code, items, total } = req.body || {};
  if (!customer_name || !address_line || !city || !postal_code || !Array.isArray(items)) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  Counter.findByIdAndUpdate('orders', { $inc: { value: 1 } }, { new: true, upsert: true })
    .then((counter) => {
      const id = counter.value;
      return Order.create({
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
    })
    .then(() => res.status(201).end())
    .catch((err) => {
      console.error('Create order failed:', err);
      res.status(500).json({ error: 'Server error' });
    });
});

app.get('/api/orders', sessionMiddleware({ owner: true }), (req, res) => {
  Order.find()
    .sort({ created_at: -1 })
    .lean()
    .then((orders) => res.json(orders))
    .catch((err) => {
      console.error('Orders fetch failed:', err);
      res.status(500).json({ error: 'Server error' });
    });
});

// Cleanup expired sessions periodically
setInterval(() => {
  const now = Date.now();
  Session.deleteMany({ expires_at: { $lte: now } }).catch((err) => {
    console.error('Session cleanup failed:', err);
  });
}, 5 * 60 * 1000);
setInterval(() => {
  const now = Date.now();
  UserSession.deleteMany({ expires_at: { $lte: now } }).catch((err) => {
    console.error('User session cleanup failed:', err);
  });
}, 5 * 60 * 1000);

// Start server
const port = process.env.PORT || 3000;
async function startServer() {
  await mongoose.connect(MONGODB_URI);
  app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
