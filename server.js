// sfe prototype server: accounts, protector vetting, ring-all alerts, WebRTC signalling.
// PROTOTYPE ONLY: see README.md for what is not production-ready.
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const { marked } = require('marked');
const LEGAL_VERSION = '2026-10-pilot-3';
const CHECKS = ['id', 'record', 'references', 'experience', 'training'];

const PORT = Number(process.env.PORT || 3000);
const ANSWER_SECONDS = Number(process.env.ANSWER_SECONDS || 30);
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'db.json');
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@sfe.local').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me-now';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || 'sfe <onboarding@resend.dev>';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_TOKEN_URL = process.env.GOOGLE_TOKEN_URL || 'https://oauth2.googleapis.com/token';
const DONATE_URL = /^https:\/\//.test(process.env.DONATE_URL || '') ? process.env.DONATE_URL : '';
const MAX_ALERTS_PER_HOUR = Number(process.env.MAX_ALERTS_PER_HOUR || 5);
const ICE_SERVERS = process.env.ICE_SERVERS
  ? JSON.parse(process.env.ICE_SERVERS)
  : [{ urls: 'stun:stun.l.google.com:19302' }];

// ---------- tiny JSON store ----------
let db = { users: [], alerts: [], reports: [], sessions: {}, tokens: {} };
if (fs.existsSync(DB_FILE)) db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
let saveTimer = null;
function save() {
  if (process.env.NO_PERSIST) return;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)), 100);
}
function flushSave() {
  if (process.env.NO_PERSIST) return;
  clearTimeout(saveTimer);
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
const now = () => Date.now();
const id = () => crypto.randomUUID();

if (!db.users.find((u) => u.email === ADMIN_EMAIL)) {
  db.users.push({
    id: id(), name: 'Admin', email: ADMIN_EMAIL, passHash: bcrypt.hashSync(ADMIN_PASSWORD, 10),
    role: 'admin', status: 'approved', createdAt: now(), emailVerified: true,
  });
  save();
  if (ADMIN_PASSWORD === 'change-me-now') console.warn('WARNING: default admin password in use. Set ADMIN_PASSWORD.');
}

{ const adm = db.users.find((u) => u.email === ADMIN_EMAIL); if (adm && !adm.emailVerified) { adm.emailVerified = true; save(); } }

// ---------- helpers ----------
const sha = (x) => crypto.createHash('sha256').update(String(x)).digest('hex');
function newToken(type, data, ttlMs) {
  const t = crypto.randomBytes(24).toString('hex');
  db.tokens[sha(t)] = { type, ...data, exp: Date.now() + ttlMs };
  save();
  return t;
}
function takeToken(t, type, consume = true) {
  const k = sha(t || '');
  const r = db.tokens[k];
  if (!r || r.type !== type || r.exp < Date.now()) return null;
  if (consume) { delete db.tokens[k]; save(); }
  return r;
}
const baseUrl = (req) => (process.env.APP_URL || `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers.host}`).replace(/\/$/, '');
const mailOutbox = []; // filled only when MAIL_CAPTURE is set (tests)
async function sendMail(to, subject, text, extra = {}) {
  if (process.env.MAIL_CAPTURE) mailOutbox.push({ to, subject, text, ...extra });
  if (!RESEND_API_KEY) { if (!process.env.NO_PERSIST) console.log(`[email not configured] to=${to} subject=${subject}\n${text}`); return false; }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { Authorization: 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, text }),
    });
    if (!r.ok) { console.error('Resend error', r.status, (await r.text().catch(() => '')).slice(0, 200)); return false; }
    return true;
  } catch (e) { console.error('Email send failed:', e.message); return false; }
}
function sendVerification(u, req) {
  const t = newToken('verify', { userId: u.id }, 24 * 3600 * 1000);
  const link = `${baseUrl(req)}/verify?token=${t}`;
  u.lastVerifySent = Date.now();
  return sendMail(u.email, 'Confirm your email for sfe',
    `Hi ${first(u.name)},\n\nPlease confirm your email address for sfe by opening this link:\n\n${link}\n\nThe link works for 24 hours. If you did not create an sfe account, ignore this email.\n\nsfe is not an emergency service. In danger, call 112.`, { type: 'verify', link, token: t });
}
function startSession(u) {
  const token = crypto.randomBytes(24).toString('hex');
  db.sessions[token] = { userId: u.id, at: now() };
  save();
  return token;
}
const dropSessions = (uid) => { for (const t of Object.keys(db.sessions)) if (db.sessions[t].userId === uid) delete db.sessions[t]; };
const cookiesOf = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter((a) => a[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));

// Validates role-specific sign-up fields and builds a user. Used by password and Google sign-up.
function buildUser(body, { name, email, passHash, role, verified, googleSub }) {
  if (role === 'protector' && (!clean(body.experienceType, 80) || !clean(body.experienceRef, 200)))
    return { error: 'Protectors must give their relevant experience and a reference who can confirm it' };
  if (body.acceptTerms !== true) return { error: 'Please confirm you are 18 or over and accept the Terms of Use and Privacy Notice' };
  if (role === 'protector' && body.acceptAgreement !== true) return { error: 'Please accept the Protector Agreement' };
  const u = {
    id: id(), name, email, passHash, role, createdAt: now(),
    status: role === 'protector' ? 'pending' : 'approved',
    acceptedTerms: { at: now(), version: LEGAL_VERSION },
    emailVerified: !!verified || !!(process.env.NO_PERSIST && process.env.TEST_AUTO_VERIFY),
  };
  if (googleSub) { u.googleSub = googleSub; u.noPassword = true; }
  if (role === 'protector') {
    u.acceptedAgreement = { at: now(), version: LEGAL_VERSION };
    Object.assign(u, {
      languages: clean(body.languages, 100), bio: clean(body.bio, 500), country: clean(body.country, 60),
      available: false, checks: { id: false, record: false, references: false, experience: false, training: false }, ratingSum: 0, ratingCount: 0,
      experienceType: clean(body.experienceType, 80), experienceYears: clean(body.experienceYears, 10), experienceRef: clean(body.experienceRef, 200),
    });
  }
  return { user: u };
}
const first = (name) => String(name || '').trim().split(/\s+/)[0] || 'Someone';
const clean = (s, n) => String(s == null ? '' : s).trim().slice(0, n);
const userById = (uid) => db.users.find((u) => u.id === uid);
function publicUser(u) {
  const o = { id: u.id, name: u.name, email: u.email, role: u.role, status: u.status, emailVerified: !!u.emailVerified, noPassword: !!u.noPassword, acceptedTerms: u.acceptedTerms || null, acceptedAgreement: u.acceptedAgreement || null };
  if (u.role === 'protector') {
    Object.assign(o, {
      available: !!u.available, languages: u.languages || '', bio: u.bio || '', country: u.country || '',
      checks: u.checks || {}, experienceType: u.experienceType || '', experienceYears: u.experienceYears || '', experienceRef: u.experienceRef || '', rating: u.ratingCount ? +(u.ratingSum / u.ratingCount).toFixed(2) : null,
      ratingCount: u.ratingCount || 0,
    });
  }
  return o;
}

// ---------- presence ----------
const clients = new Map(); // userId -> Set<ws>
function push(uid, msg) {
  const set = clients.get(uid);
  if (!set) return;
  const data = JSON.stringify(msg);
  for (const ws of set) if (ws.readyState === 1) ws.send(data);
}
const isOnline = (uid) => clients.has(uid) && clients.get(uid).size > 0;
const activeAlertFor = (uid) =>
  db.alerts.find((a) => a.status === 'active' && (a.callerId === uid || a.acceptedBy === uid));
function availableProtectors() {
  return db.users.filter(
    (u) => u.role === 'protector' && u.status === 'approved' && u.available && isOnline(u.id) && !activeAlertFor(u.id)
  );
}
const timers = new Map(); // alertId -> timeout
function ringPayload(a) {
  const caller = userById(a.callerId);
  return {
    type: 'alert', alertId: a.id, caller: first(caller && caller.name), note: a.note || '',
    hasLocation: !!a.location, secondsLeft: Math.max(0, Math.round((a.createdAt + ANSWER_SECONDS * 1000 - now()) / 1000)),
  };
}

// ---------- app ----------
const app = express();
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- legal pages (text lives in legal/*.md) ----------
const LEGAL_PAGES = { '/privacy': ['privacy.md', 'Privacy Notice'], '/terms': ['terms.md', 'Terms of Use'], '/protector-agreement': ['protector-agreement.md', 'Protector Agreement'] };
for (const [route, [file, title]] of Object.entries(LEGAL_PAGES)) {
  app.get(route, (req, res) => {
    const md = fs.readFileSync(path.join(__dirname, 'legal', file), 'utf8');
    res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>sfe — ${title}</title>
<style>:root{color-scheme:light dark}body{font:16px/1.55 system-ui,sans-serif;max-width:720px;margin:0 auto;padding:16px}h1{font-size:1.6rem}h2{font-size:1.15rem;margin-top:1.6em}table{border-collapse:collapse;width:100%;font-size:.9rem}td,th{border:1px solid #8884;padding:6px;text-align:left;vertical-align:top}.pilot{background:#fff3cd;color:#5c4400;padding:10px 12px;border-radius:8px;font-size:.9rem}a{color:inherit}nav{margin-top:2em;font-size:.9rem}</style></head><body>
<p class="pilot"><b>Pilot version ${LEGAL_VERSION}.</b> sfe is in a closed test with friends. These texts are working drafts and are being reviewed by a lawyer. Anything in [square brackets] is still to be completed.</p>
<p><a href="/">← Back to sfe</a></p>${marked.parse(md)}
<nav><a href="/privacy">Privacy Notice</a> · <a href="/terms">Terms of Use</a> · <a href="/protector-agreement">Protector Agreement</a></nav></body></html>`);
  });
}

const loginAttempts = new Map();
function tooManyLogins(key) {
  const t = now();
  const arr = (loginAttempts.get(key) || []).filter((x) => t - x < 15 * 60 * 1000);
  loginAttempts.set(key, arr);
  return arr.length >= 10;
}

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  const s = db.sessions[token];
  const u = s && userById(s.userId);
  if (!u) return res.status(401).json({ error: 'Please log in' });
  if (u.status === 'suspended') return res.status(403).json({ error: 'Account suspended' });
  req.user = u;
  req.token = token;
  next();
}
const need = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Not allowed' });

app.get('/api/config', (req, res) => res.json({ iceServers: ICE_SERVERS, answerSeconds: ANSWER_SECONDS, legalVersion: LEGAL_VERSION, googleEnabled: !!GOOGLE_CLIENT_ID, donateUrl: DONATE_URL }));

app.post('/api/signup', async (req, res) => {
  const name = clean(req.body.name, 60), email = clean(req.body.email, 120).toLowerCase();
  const password = String(req.body.password || ''), role = req.body.role === 'protector' ? 'protector' : 'caller';
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Name and a valid email are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (db.users.find((u) => u.email === email)) return res.status(409).json({ error: 'Email already registered' });
  const built = buildUser(req.body, { name, email, passHash: bcrypt.hashSync(password, 10), role });
  if (built.error) return res.status(400).json({ error: built.error });
  const u = built.user;
  db.users.push(u);
  const token = startSession(u);
  if (!u.emailVerified) await sendVerification(u, req);
  save();
  res.json({ token, user: publicUser(u) });
});

app.get('/verify', (req, res) => {
  const r = takeToken(String(req.query.token || ''), 'verify');
  const u = r && userById(r.userId);
  if (u) { u.emailVerified = true; save(); }
  res.redirect(u ? '/?verified=1' : '/?verified=0');
});

app.post('/api/resend-verification', auth, async (req, res) => {
  const u = req.user;
  if (u.emailVerified) return res.json({ ok: true, already: true });
  if (u.lastVerifySent && Date.now() - u.lastVerifySent < 60 * 1000) return res.status(429).json({ error: 'Please wait a minute before asking for another email' });
  await sendVerification(u, req);
  save();
  res.json({ ok: true });
});

const forgotAttempts = new Map();
app.post('/api/forgot', async (req, res) => {
  const email = clean(req.body.email, 120).toLowerCase();
  const t = Date.now();
  const arr = (forgotAttempts.get(email) || []).filter((x) => t - x < 3600 * 1000);
  forgotAttempts.set(email, arr);
  const u = db.users.find((x) => x.email === email);
  if (arr.length < 3 && u && u.role !== 'admin' && u.status !== 'suspended') {
    arr.push(t);
    const tok = newToken('reset', { userId: u.id }, 3600 * 1000);
    const link = `${baseUrl(req)}/?reset=${tok}`;
    await sendMail(u.email, 'Reset your sfe password', `Hi ${first(u.name)},\n\nOpen this link to choose a new password:\n\n${link}\n\nThe link works for one hour. If you did not ask for this, ignore this email and your password stays the same.`, { type: 'reset', link, token: tok });
  }
  res.json({ ok: true }); // same answer whether or not the email exists
});

app.post('/api/reset', (req, res) => {
  const password = String(req.body.password || '');
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const r = takeToken(String(req.body.token || ''), 'reset');
  const u = r && userById(r.userId);
  if (!u) return res.status(400).json({ error: 'This link has expired. Ask for a new one.' });
  u.passHash = bcrypt.hashSync(password, 10); u.noPassword = false; u.emailVerified = true;
  dropSessions(u.id);
  save();
  res.json({ ok: true });
});

// ----- Google sign-in (authorisation-code flow) -----
app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(404).send('Google sign-in is not set up');
  const state = crypto.randomBytes(16).toString('hex');
  const base = baseUrl(req);
  res.cookie('sfe_oauth', state, { httpOnly: true, sameSite: 'lax', secure: base.startsWith('https'), maxAge: 10 * 60 * 1000, path: '/auth/google' });
  const q = new URLSearchParams({ client_id: GOOGLE_CLIENT_ID, redirect_uri: base + '/auth/google/callback', response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account' });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + q);
});

app.get('/auth/google/callback', async (req, res) => {
  const fail = () => res.redirect('/?gerror=1');
  if (!GOOGLE_CLIENT_ID || !req.query.state || cookiesOf(req).sfe_oauth !== req.query.state) return res.status(400).send('Sign-in session expired. Go back to sfe and try again.');
  res.clearCookie('sfe_oauth', { path: '/auth/google' });
  if (req.query.error || !req.query.code) return fail();
  try {
    const r = await fetch(GOOGLE_TOKEN_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: String(req.query.code), client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET, redirect_uri: baseUrl(req) + '/auth/google/callback', grant_type: 'authorization_code' }),
    });
    const j = await r.json();
    // the id_token comes straight from Google over TLS, so its claims can be trusted without checking the signature
    const p = JSON.parse(Buffer.from(String(j.id_token || '').split('.')[1] || '', 'base64url').toString() || '{}');
    if (!r.ok || p.aud !== GOOGLE_CLIENT_ID || !['https://accounts.google.com', 'accounts.google.com'].includes(p.iss) || p.exp * 1000 < Date.now() || p.email_verified !== true || !p.email) return fail();
    const email = String(p.email).toLowerCase();
    let u = db.users.find((x) => x.email === email);
    if (u) {
      if (u.role === 'admin' || u.status === 'suspended') return fail();
      if (!u.emailVerified) { // someone may have registered this address with a password they chose: remove it
        u.passHash = bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10); u.noPassword = true; dropSessions(u.id); u.emailVerified = true;
      }
      u.googleSub = u.googleSub || p.sub;
      return res.redirect('/#token=' + startSession(u));
    }
    const t = newToken('gsignup', { email, name: clean(p.name || email.split('@')[0], 60), sub: p.sub }, 15 * 60 * 1000);
    res.redirect('/#google=' + t);
  } catch (e) { console.error('Google sign-in failed:', e.message); fail(); }
});

app.get('/api/google/pending', (req, res) => {
  const r = takeToken(String(req.query.token || ''), 'gsignup', false);
  if (!r) return res.status(400).json({ error: 'This sign-up has expired. Please start again.' });
  res.json({ email: r.email, name: r.name });
});

app.post('/api/google/complete', (req, res) => {
  const r = takeToken(String(req.body.token || ''), 'gsignup', false);
  if (!r) return res.status(400).json({ error: 'This sign-up has expired. Please start again.' });
  if (db.users.find((x) => x.email === r.email)) return res.status(409).json({ error: 'Email already registered' });
  const role = req.body.role === 'protector' ? 'protector' : 'caller';
  const name = clean(req.body.name, 60) || r.name;
  const built = buildUser(req.body, { name, email: r.email, passHash: bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10), role, verified: true, googleSub: r.sub });
  if (built.error) return res.status(400).json({ error: built.error });
  db.users.push(built.user);
  takeToken(String(req.body.token), 'gsignup');
  res.json({ token: startSession(built.user), user: publicUser(built.user) });
});

app.post('/api/login', (req, res) => {
  const email = clean(req.body.email, 120).toLowerCase();
  if (tooManyLogins(email)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  const u = db.users.find((x) => x.email === email);
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.passHash)) {
    loginAttempts.get(email).push(now());
    return res.status(401).json({ error: 'Wrong email or password' });
  }
  if (u.status === 'suspended') return res.status(403).json({ error: 'Account suspended' });
  res.json({ token: startSession(u), user: publicUser(u) });
});

app.post('/api/logout', auth, (req, res) => {
  delete db.sessions[req.token];
  save();
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  const a = activeAlertFor(req.user.id);
  res.json({
    user: publicUser(req.user),
    protectorsOnline: availableProtectors().length,
    activeAlert: a ? { id: a.id, role: a.callerId === req.user.id ? 'caller' : 'protector' } : null,
  });
});

app.get('/api/me/export', auth, (req, res) => {
  const uid = req.user.id;
  const { passHash, ...account } = req.user;
  res.setHeader('Content-Disposition', 'attachment; filename="sfe-my-data.json"');
  res.json({
    exportedAt: new Date().toISOString(), account,
    alerts: db.alerts.filter((a) => a.callerId === uid || a.acceptedBy === uid),
    reportsIMade: db.reports.filter((r) => r.reporterId === uid),
  });
});

app.post('/api/me/delete', auth, (req, res) => {
  const u = req.user;
  if (u.role === 'admin') return res.status(403).json({ error: 'The admin account cannot be deleted here' });
  if (u.noPassword ? String(req.body.confirmEmail || '').toLowerCase() !== u.email : !bcrypt.compareSync(String(req.body.password || ''), u.passHash)) return res.status(401).json({ error: u.noPassword ? 'Type your email address to confirm' : 'Wrong password' });
  if (db.alerts.find((a) => (a.status === 'ringing' || a.status === 'active') && (a.callerId === u.id || a.acceptedBy === u.id)))
    return res.status(409).json({ error: 'Please end your open call first' });
  // keep anonymous alert totals for pilot statistics, remove everything personal
  for (const a of db.alerts) {
    if (a.callerId === u.id) { a.callerId = 'deleted'; a.note = ''; a.location = null; }
    if (a.acceptedBy === u.id) a.acceptedBy = 'deleted';
    if (Array.isArray(a.notified)) a.notified = a.notified.filter((x) => x !== u.id);
  }
  for (const t of Object.keys(db.sessions)) if (db.sessions[t].userId === u.id) delete db.sessions[t];
  for (const k of Object.keys(db.tokens)) if (db.tokens[k].userId === u.id || db.tokens[k].email === u.email) delete db.tokens[k];
  db.users = db.users.filter((x) => x.id !== u.id);
  save();
  for (const ws of clients.get(u.id) || []) ws.close();
  res.json({ ok: true });
});

app.get('/api/availability', auth, (req, res) => res.json({ protectorsOnline: availableProtectors().length }));

// ----- protector -----
app.post('/api/protector/available', auth, need('protector'), (req, res) => {
  if (!req.user.emailVerified) return res.status(403).json({ error: 'Please confirm your email first', code: 'email_unverified' });
  if (req.user.status !== 'approved') return res.status(403).json({ error: 'Your application is not approved yet' });
  req.user.available = !!req.body.available;
  save();
  if (req.user.available && !activeAlertFor(req.user.id)) {
    for (const a of db.alerts) if (a.status === 'ringing') push(req.user.id, ringPayload(a));
  }
  res.json({ available: req.user.available });
});

// ----- alerts -----
app.post('/api/alerts', auth, need('caller'), (req, res) => {
  if (!req.user.emailVerified) return res.status(403).json({ error: 'Please confirm your email first. If you are in danger, call 112.', code: 'email_unverified' });
  if (activeAlertFor(req.user.id) || db.alerts.find((a) => a.callerId === req.user.id && a.status === 'ringing'))
    return res.status(409).json({ error: 'You already have an alert open' });
  const recent = db.alerts.filter((a) => a.callerId === req.user.id && now() - a.createdAt < 3600e3).length;
  if (recent >= MAX_ALERTS_PER_HOUR) return res.status(429).json({ error: 'Too many alerts in the last hour. If this is an emergency, call 112.' });
  const loc = req.body.location;
  const a = {
    id: id(), callerId: req.user.id, status: 'ringing', createdAt: now(), note: clean(req.body.note, 200),
    location: loc && isFinite(loc.lat) && isFinite(loc.lng) ? { lat: +loc.lat, lng: +loc.lng, acc: +loc.acc || null, at: now() } : null,
    acceptedBy: null, notified: [], escalated: false,
  };
  db.alerts.push(a);
  const targets = availableProtectors();
  a.notified = targets.map((u) => u.id);
  if (!targets.length) {
    a.status = 'unanswered';
    a.reason = 'no_protectors_online';
    a.endedAt = now();
    save();
    return res.json({ alertId: a.id, ringing: 0, status: 'unanswered', reason: 'no_protectors_online' });
  }
  for (const u of targets) push(u.id, ringPayload(a));
  timers.set(a.id, setTimeout(() => {
    timers.delete(a.id);
    if (a.status !== 'ringing') return;
    a.status = 'unanswered';
    a.reason = 'timeout';
    a.endedAt = now();
    save();
    push(a.callerId, { type: 'unanswered', alertId: a.id, reason: 'timeout' });
    for (const uid of a.notified) push(uid, { type: 'taken', alertId: a.id, reason: 'timeout' });
  }, ANSWER_SECONDS * 1000));
  save();
  res.json({ alertId: a.id, ringing: targets.length, status: 'ringing', answerSeconds: ANSWER_SECONDS });
});

const getAlert = (req, res) => {
  const a = db.alerts.find((x) => x.id === req.params.id);
  if (!a) { res.status(404).json({ error: 'Alert not found' }); return null; }
  return a;
};
const otherParty = (a, uid) => (a.callerId === uid ? a.acceptedBy : a.callerId);
const inAlert = (a, uid) => a.callerId === uid || a.acceptedBy === uid;

app.post('/api/alerts/:id/accept', auth, need('protector'), (req, res) => {
  const a = getAlert(req, res); if (!a) return;
  if (req.user.status !== 'approved' || !req.user.available) return res.status(403).json({ error: 'You are not available' });
  if (activeAlertFor(req.user.id)) return res.status(409).json({ error: 'You are already in a call' });
  if (a.status !== 'ringing') return res.status(409).json({ error: 'Someone else already took this call' });
  a.status = 'active';
  a.acceptedBy = req.user.id;
  a.acceptedAt = now();
  clearTimeout(timers.get(a.id)); timers.delete(a.id);
  save();
  push(a.callerId, { type: 'accepted', alertId: a.id, protector: first(req.user.name) });
  for (const uid of a.notified) if (uid !== req.user.id) push(uid, { type: 'taken', alertId: a.id, reason: 'taken' });
  const caller = userById(a.callerId);
  res.json({ alertId: a.id, caller: first(caller.name), note: a.note, location: a.location, called112: !!(a.called112 || a.escalated) });
});

app.post('/api/alerts/:id/decline', auth, need('protector'), (req, res) => res.json({ ok: true }));

app.post('/api/alerts/:id/location', auth, need('caller'), (req, res) => {
  const a = getAlert(req, res); if (!a) return;
  if (a.callerId !== req.user.id) return res.status(403).json({ error: 'Not allowed' });
  const loc = req.body;
  if (!isFinite(loc.lat) || !isFinite(loc.lng)) return res.status(400).json({ error: 'Bad location' });
  if (a.status === 'ringing' || a.status === 'active') {
    a.location = { lat: +loc.lat, lng: +loc.lng, acc: +loc.acc || null, at: now() };
    if (a.acceptedBy) push(a.acceptedBy, { type: 'location', alertId: a.id, location: a.location });
  }
  res.json({ ok: true });
});

// Called when the caller taps the 112 button (logged for pilot metrics).
app.post('/api/alerts/:id/escalate', auth, need('caller'), (req, res) => {
  const a = getAlert(req, res); if (!a) return;
  if (a.callerId !== req.user.id) return res.status(403).json({ error: 'Not allowed' });
  a.escalated = true; a.called112 = true;
  a.escalatedAt = a.escalatedAt || now();
  save();
  if (a.acceptedBy) push(a.acceptedBy, { type: 'escalated', alertId: a.id });
  res.json({ ok: true });
});

// Caller confirms they have already called 112 (so protectors know to support, not replace, the call).
app.post('/api/alerts/:id/called112', auth, need('caller'), (req, res) => {
  const a = getAlert(req, res); if (!a) return;
  if (a.callerId !== req.user.id) return res.status(403).json({ error: 'Not allowed' });
  a.called112 = true; a.called112At = a.called112At || now();
  save();
  if (a.acceptedBy) push(a.acceptedBy, { type: 'called112', alertId: a.id });
  res.json({ ok: true });
});

app.post('/api/alerts/:id/end', auth, (req, res) => {
  const a = getAlert(req, res); if (!a) return;
  if (!inAlert(a, req.user.id)) return res.status(403).json({ error: 'Not allowed' });
  if (a.status === 'ringing' && a.callerId === req.user.id) {
    a.status = 'cancelled'; a.endedAt = now();
    clearTimeout(timers.get(a.id)); timers.delete(a.id);
    for (const uid of a.notified) push(uid, { type: 'taken', alertId: a.id, reason: 'cancelled' });
  } else if (a.status === 'active') {
    a.status = 'ended'; a.endedAt = now(); a.endedBy = req.user.id;
    push(otherParty(a, req.user.id), { type: 'ended', alertId: a.id });
  }
  save();
  res.json({ status: a.status });
});

app.post('/api/alerts/:id/rate', auth, need('caller'), (req, res) => {
  const a = getAlert(req, res); if (!a) return;
  const stars = Math.round(Number(req.body.stars));
  if (a.callerId !== req.user.id || !a.acceptedBy || !(stars >= 1 && stars <= 5)) return res.status(400).json({ error: 'Cannot rate' });
  if (a.rating) return res.status(409).json({ error: 'Already rated' });
  a.rating = stars;
  const p = userById(a.acceptedBy);
  p.ratingSum = (p.ratingSum || 0) + stars;
  p.ratingCount = (p.ratingCount || 0) + 1;
  save();
  res.json({ ok: true });
});

app.post('/api/alerts/:id/report', auth, (req, res) => {
  const a = getAlert(req, res); if (!a) return;
  if (!inAlert(a, req.user.id) || !a.acceptedBy) return res.status(403).json({ error: 'Not allowed' });
  const reason = clean(req.body.reason, 500);
  if (!reason) return res.status(400).json({ error: 'Please describe what happened' });
  db.reports.push({ id: id(), alertId: a.id, reporterId: req.user.id, targetId: otherParty(a, req.user.id), reason, createdAt: now(), resolved: false });
  save();
  res.json({ ok: true });
});

// ----- admin -----
app.get('/api/admin/users', auth, need('admin'), (req, res) => {
  const role = req.query.role;
  res.json(db.users.filter((u) => u.role !== 'admin' && (!role || u.role === role)).map((u) => ({ ...publicUser(u), createdAt: u.createdAt, online: isOnline(u.id) })));
});
app.post('/api/admin/users/:id/checks', auth, need('admin'), (req, res) => {
  const u = userById(req.params.id);
  if (!u || u.role !== 'protector') return res.status(404).json({ error: 'Not found' });
  u.checks = u.checks || {};
  for (const k of CHECKS) if (k in req.body) u.checks[k] = !!req.body[k];
  save();
  res.json(publicUser(u));
});
app.post('/api/admin/users/:id/:action', auth, need('admin'), (req, res) => {
  const u = userById(req.params.id);
  if (!u || u.role === 'admin') return res.status(404).json({ error: 'Not found' });
  const act = req.params.action;
  if (!['approve', 'reject', 'suspend', 'reinstate'].includes(act)) return res.status(404).json({ error: 'Unknown action' });
  if (act === 'approve') {
    if (!u.emailVerified) return res.status(400).json({ error: 'This protector has not confirmed their email yet' });
    const c = u.checks || {};
    if (!CHECKS.every((k) => c[k])) return res.status(400).json({ error: 'All five vetting checks must be completed before approval' });
    u.status = 'approved';
  } else if (act === 'reject') { u.status = 'rejected'; u.available = false; }
  else if (act === 'suspend') {
    u.status = 'suspended'; u.available = false;
    for (const t of Object.keys(db.sessions)) if (db.sessions[t].userId === u.id) delete db.sessions[t];
    const a = activeAlertFor(u.id);
    if (a) { a.status = 'ended'; a.endedAt = now(); push(otherParty(a, u.id), { type: 'ended', alertId: a.id }); }
    for (const ws of clients.get(u.id) || []) ws.close();
  } else if (act === 'reinstate') u.status = 'approved';
  save();
  res.json(publicUser(u));
});
app.get('/api/admin/reports', auth, need('admin'), (req, res) =>
  res.json(db.reports.slice().reverse().map((r) => ({
    ...r, reporter: (userById(r.reporterId) || {}).name, target: (userById(r.targetId) || {}).name,
  }))));
app.post('/api/admin/reports/:id/resolve', auth, need('admin'), (req, res) => {
  const r = db.reports.find((x) => x.id === req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  r.resolved = true; r.resolvedAt = now(); save(); res.json(r);
});
app.get('/api/admin/stats', auth, need('admin'), (req, res) => {
  const A = db.alerts;
  const answered = A.filter((a) => a.acceptedAt);
  const waits = answered.map((a) => (a.acceptedAt - a.createdAt) / 1000).sort((x, y) => x - y);
  const med = waits.length ? waits[Math.floor(waits.length / 2)] : null;
  const rated = A.filter((a) => a.rating);
  res.json({
    alerts: A.length, answered: answered.length, unanswered: A.filter((a) => a.status === 'unanswered').length,
    answeredShare: A.length ? +(answered.length / A.length).toFixed(2) : null,
    within30s: answered.length ? +(waits.filter((w) => w <= 30).length / answered.length).toFixed(2) : null,
    medianAnswerSeconds: med == null ? null : +med.toFixed(1),
    answeredWithout112: answered.filter((a) => !a.called112 && !a.escalated).length,
    escalatedTo112: A.filter((a) => a.escalated).length,
    escalatedShare: A.length ? +(A.filter((a) => a.escalated).length / A.length).toFixed(2) : null,
    avgRating: rated.length ? +(rated.reduce((s, a) => s + a.rating, 0) / rated.length).toFixed(2) : null,
    protectorsApproved: db.users.filter((u) => u.role === 'protector' && u.status === 'approved').length,
    protectorsPending: db.users.filter((u) => u.role === 'protector' && u.status === 'pending').length,
    protectorsOnline: availableProtectors().length,
    openReports: db.reports.filter((r) => !r.resolved).length,
  });
});

// ---------- retention (see Privacy Notice) ----------
const DAY = 24 * 3600 * 1000;
function sweep(nowMs = now()) {
  const nA = db.alerts.length, nR = db.reports.length;
  db.alerts = db.alerts.filter((a) => (a.status === 'ringing' || a.status === 'active') || nowMs - a.createdAt < 365 * DAY);
  db.reports = db.reports.filter((r) => !(r.resolved && nowMs - (r.resolvedAt || r.createdAt) > 730 * DAY));
  for (const t of Object.keys(db.sessions)) if (nowMs - db.sessions[t].at > 90 * DAY) delete db.sessions[t];
  for (const k of Object.keys(db.tokens)) if (db.tokens[k].exp < nowMs) delete db.tokens[k];
  if (db.alerts.length !== nA || db.reports.length !== nR) save();
  return { alerts: nA - db.alerts.length, reports: nR - db.reports.length };
}
sweep();
setInterval(sweep, 6 * 3600 * 1000).unref();

// ---------- websocket: presence + WebRTC signalling ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 64 * 1024 });
wss.on('connection', (ws, req) => {
  const token = new URL(req.url, 'http://x').searchParams.get('token');
  const s = db.sessions[token];
  const u = s && userById(s.userId);
  if (!u || u.status === 'suspended') return ws.close(4001, 'unauthorised');
  if (!clients.has(u.id)) clients.set(u.id, new Set());
  clients.get(u.id).add(ws);
  ws.send(JSON.stringify({ type: 'hello', userId: u.id }));
  if (u.role === 'protector' && u.available && u.status === 'approved' && !activeAlertFor(u.id)) {
    for (const a of db.alerts) if (a.status === 'ringing') ws.send(JSON.stringify(ringPayload(a)));
  }
  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (m.type === 'signal') {
      const a = db.alerts.find((x) => x.id === m.alertId);
      if (!a || a.status !== 'active' || !inAlert(a, u.id)) return;
      push(otherParty(a, u.id), { type: 'signal', alertId: a.id, data: m.data });
    }
  });
  ws.on('close', () => {
    const set = clients.get(u.id);
    if (set) { set.delete(ws); if (!set.size) clients.delete(u.id); }
    // a protector who drops offline stops being available for new alerts automatically (see availableProtectors)
  });
});

if (require.main === module) {
  server.listen(PORT, () => console.log(`sfe prototype running on http://localhost:${PORT}`));
  // clean shutdown when the host stops the app (every deploy): save pending data, then exit normally
  const shutdown = () => { try { flushSave(); } catch (e) { console.error(e.message); } server.close(); process.exit(0); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}
module.exports = { server, app, db, sweep, mailOutbox };
