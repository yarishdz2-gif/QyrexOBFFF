'use strict';

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { obfuscate } = require('./obfuscate');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'users.json');
const SESSION_TTL = 1000 * 60 * 60 * 24 * 7;
const REGISTRATION_WINDOW = 1000 * 60 * 60 * 24;
const MAX_REGISTRATIONS_PER_IP = 1;
const DISCORD_INVITE = 'https://discord.gg/YzCsksufde';

// Needed when the site is behind Render/Cloudflare/etc.
app.set('trust proxy', true);
fs.mkdirSync(DATA_DIR, { recursive: true });

function blankDb() {
  return { version: 2, users: [], sessions: {}, purchases: [], registrations: {} };
}

function normalizeDb(raw) {
  const d = raw && typeof raw === 'object' ? raw : {};
  d.version = 2;
  d.users = Array.isArray(d.users) ? d.users : [];
  d.sessions = d.sessions && typeof d.sessions === 'object' ? d.sessions : {};
  d.purchases = Array.isArray(d.purchases) ? d.purchases : [];
  d.registrations = d.registrations && typeof d.registrations === 'object' ? d.registrations : {};
  for (const u of d.users) {
    u.stats = u.stats && typeof u.stats === 'object' ? u.stats : {};
    u.stats.obfuscations = Number(u.stats.obfuscations) || 0;
    u.stats.bytes = Number(u.stats.bytes) || 0;
    u.tokens = Math.max(0, Number(u.tokens) || 0);
    u.tasks = u.tasks && typeof u.tasks === 'object' ? u.tasks : {};
    u.tasks.account = true;
    u.tasks.openObfuscator = !!u.tasks.openObfuscator;
    u.tasks.firstObfuscation = !!u.tasks.firstObfuscation;
  }
  return d;
}

if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify(blankDb(), null, 2));

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

function db() {
  try {
    return normalizeDb(JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
  } catch {
    const fresh = blankDb();
    try { fs.writeFileSync(DB_FILE, JSON.stringify(fresh, null, 2)); } catch {}
    return fresh;
  }
}

function save(d) {
  normalizeDb(d);
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(d, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

function norm(v) { return String(v ?? '').trim().toLowerCase(); }
function requestIp(req) { return String(req.ip || req.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim(); }
function hashPassword(password, salt) { return crypto.scryptSync(password, salt, 64).toString('hex'); }
function makePassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: hashPassword(password, salt) };
}
function validPassword(password, user) {
  try {
    const a = Buffer.from(hashPassword(password, user.salt), 'hex');
    const b = Buffer.from(user.passwordHash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}
function makeToken() { return crypto.randomBytes(32).toString('hex'); }
function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    email: u.email,
    tokens: u.tokens,
    createdAt: u.createdAt,
    stats: u.stats,
    tasks: u.tasks
  };
}
function cleanup(d) {
  for (const [key, value] of Object.entries(d.sessions)) {
    if (!value || Number(value.expiresAt) <= Date.now()) delete d.sessions[key];
  }
  for (const [ip, value] of Object.entries(d.registrations)) {
    if (!value || Number(value.resetAt) <= Date.now()) delete d.registrations[ip];
  }
}
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const sessionToken = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  const d = db();
  cleanup(d);
  const session = d.sessions[sessionToken];
  if (!session || session.expiresAt <= Date.now()) {
    if (sessionToken && session) delete d.sessions[sessionToken];
    save(d);
    return res.status(401).json({ ok: false, error: 'Sesión inválida o expirada' });
  }
  const user = d.users.find(x => x.id === session.userId);
  if (!user) return res.status(401).json({ ok: false, error: 'Usuario no encontrado' });
  req.user = user;
  req.db = d;
  req.sessionToken = sessionToken;
  next();
}

app.get('/api/health', (req, res) => res.json({ ok: true, version: '1.0.0' }));
app.get('/api/config', (req, res) => res.json({ ok: true, priceUsdPerToken: 1, discordInvite: DISCORD_INVITE }));

app.post('/api/register', (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const email = norm(req.body?.email);
    const password = String(req.body?.password || '');
    const ip = requestIp(req);

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({ ok: false, error: 'El usuario debe tener 3-24 caracteres y solo usar letras, números o _.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ ok: false, error: 'Introduce un email válido.' });
    }
    if (password.length < 8) return res.status(400).json({ ok: false, error: 'La contraseña debe tener al menos 8 caracteres.' });

    const d = db();
    cleanup(d);

    // Prevent multiple accounts from the same public IP during the registration window.
    const reg = d.registrations[ip];
    if (reg && reg.count >= MAX_REGISTRATIONS_PER_IP && reg.resetAt > Date.now()) {
      return res.status(429).json({ ok: false, error: 'Ya existe una cuenta registrada desde esta conexión. Intenta de nuevo más tarde.' });
    }
    if (d.users.some(u => norm(u.username) === norm(username))) return res.status(409).json({ ok: false, error: 'Ese usuario ya está registrado.' });
    if (d.users.some(u => norm(u.email) === email)) return res.status(409).json({ ok: false, error: 'Ese email ya está registrado.' });

    const p = makePassword(password);
    const id = crypto.randomUUID();
    const user = {
      id,
      username,
      email,
      salt: p.salt,
      passwordHash: p.hash,
      tokens: 0,
      createdAt: new Date().toISOString(),
      lastIp: ip,
      stats: { obfuscations: 0, bytes: 0 },
      tasks: { account: true, openObfuscator: false, firstObfuscation: false }
    };

    d.users.push(user);
    d.registrations[ip] = { count: (reg?.count || 0) + 1, resetAt: Date.now() + REGISTRATION_WINDOW };
    const session = makeToken();
    d.sessions[session] = { userId: id, expiresAt: Date.now() + SESSION_TTL };
    save(d);
    return res.status(201).json({ ok: true, token: session, user: publicUser(user) });
  } catch (error) {
    console.error('REGISTER_ERROR', error);
    return res.status(500).json({ ok: false, error: 'No se pudo crear la cuenta. Revisa el servidor.' });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const login = norm(req.body?.login);
    const password = String(req.body?.password || '');
    const d = db();
    cleanup(d);
    const user = d.users.find(u => norm(u.email) === login || norm(u.username) === login);
    if (!user || !validPassword(password, user)) return res.status(401).json({ ok: false, error: 'Usuario/email o contraseña incorrectos.' });
    const session = makeToken();
    d.sessions[session] = { userId: user.id, expiresAt: Date.now() + SESSION_TTL };
    save(d);
    return res.json({ ok: true, token: session, user: publicUser(user) });
  } catch (error) {
    console.error('LOGIN_ERROR', error);
    return res.status(500).json({ ok: false, error: 'No se pudo iniciar sesión.' });
  }
});

app.post('/api/logout', auth, (req, res) => {
  delete req.db.sessions[req.sessionToken];
  save(req.db);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ ok: true, user: publicUser(req.user) }));

app.post('/api/task/open-obfuscator', auth, (req, res) => {
  req.user.tasks.openObfuscator = true;
  save(req.db);
  res.json({ ok: true, user: publicUser(req.user) });
});

app.post('/api/obfuscate', auth, (req, res) => {
  try {
    const code = String(req.body?.code || '');
    if (!code.trim()) return res.status(400).json({ ok: false, error: 'El código está vacío.' });
    if (code.length > 1000000) return res.status(413).json({ ok: false, error: 'El código supera el límite permitido.' });
    if (req.user.tokens < 1) {
      return res.status(402).json({ ok: false, error: 'Necesitas 1 token para ofuscar código.', tokens: req.user.tokens, code: 'TOKEN_REQUIRED' });
    }

    const result = obfuscate(code);
    req.user.tokens -= 1;
    req.user.stats.obfuscations += 1;
    req.user.stats.bytes += Buffer.byteLength(code, 'utf8');
    req.user.tasks.openObfuscator = true;
    req.user.tasks.firstObfuscation = true;
    save(req.db);

    return res.json({ ok: true, code: result.code, stats: result.stats, tokens: req.user.tokens });
  } catch (error) {
    console.error('OBFUSCATE_ERROR', error);
    return res.status(400).json({ ok: false, error: String(error.message || error) });
  }
});

app.post('/api/purchases/create', auth, (req, res) => {
  const qty = Math.max(1, Math.min(1000, Math.floor(Number(req.body?.tokens) || 1)));
  const purchase = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    tokens: qty,
    amountUsd: qty,
    status: 'pending',
    createdAt: new Date().toISOString(),
    discordInvite: DISCORD_INVITE
  };
  req.db.purchases.push(purchase);
  save(req.db);
  res.json({ ok: true, purchase, redirect: DISCORD_INVITE });
});

app.get('/api/purchases', auth, (req, res) => res.json({ ok: true, purchases: req.db.purchases.filter(x => x.userId === req.user.id).slice(-50).reverse() }));

// After creating a purchase, users are directed to the official Qyrex Discord.
// Token credit must be performed after your real payment provider confirms the purchase.
app.get('/api/purchase-destination', (req, res) => {
  res.json({ ok: true, discordInvite: DISCORD_INVITE });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`QyrexObf VM 1.0.0 running on :${PORT}`));
