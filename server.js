'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { obfuscate, findLua, findLuac, getRoot } = require('./obfuscate');

function stripAnsi(str) {
  return String(str || '')
    .replace(/\u001b\[[0-9;]*m/g, '')
    .replace(/\x1b\[[0-9;]*m/g, '')
    .replace(/\[0m/g, '')
    .replace(/\[[0-9;]*m/g, '')
    .trim();
}

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.API_KEY || '';

process.on('uncaughtException', (err) => {
  console.error('[QyrexOBF] uncaughtException', stripAnsi(err && err.message));
});
process.on('unhandledRejection', (err) => {
  console.error('[QyrexOBF] unhandledRejection', stripAnsi(err && (err.message || String(err))));
});

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '32mb' }));
app.use(rateLimit({
  windowMs: 60000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Rate limit — espera un momento' }
}));

function requireKey(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers['x-api-key'] || req.query.key || (req.body && req.body.apiKey);
  if (key === API_KEY) return next();
  return res.status(401).json({ success: false, error: 'Invalid API key' });
}

app.get('/health', (req, res) => {
  let engines = false;
  try { engines = fs.existsSync(path.join(getRoot(), 'Prometheus-master', 'cli.lua')); } catch (e) {}
  const lua = findLua();
  const luac = findLuac();
  res.json({
    ok: !!(lua && engines),
    product: 'QyrexOBF v2',
    fused: 'AntiTamper → Prometheus Strong → Hercules → IronBrew2',
    lua: lua,
    luac: luac,
    enginesReady: engines,
    hint: lua ? null : 'lua5.1 missing — deploy with Dockerfile (Runtime: Docker on Render)',
    uptime: process.uptime()
  });
});

app.post('/obfuscate', requireKey, (req, res) => {
  const reply = (status, body) => {
    if (res.headersSent) return;
    try {
      res.status(status).json(body);
    } catch (e) {
      try { res.status(status).end(JSON.stringify(body)); } catch (_) {}
    }
  };

  try {
    if (!findLua()) {
      return reply(500, {
        success: false,
        error: 'QyrexOBF: lua5.1 no encontrado. En Render usa Runtime DOCKER (no Node). Abre /health para diagnosticar.'
      });
    }

    const source = (req.body && (req.body.source || req.body.code)) || '';
    if (!source || String(source).trim().length < 2) {
      return reply(400, { success: false, error: 'Missing source — pega código Lua/Luau' });
    }
    if (source.length > 8000000) {
      return reply(400, { success: false, error: 'Source too large (max ~8MB)' });
    }

    const t0 = Date.now();
    const opts = {};
    if (req.body && req.body.antiTamper === false) opts.antiTamper = false;

    let result;
    try {
      result = obfuscate(source, opts);
    } catch (err) {
      const clean = stripAnsi(err && (err.message || String(err))) || 'Obfuscation failed';
      console.error('[QyrexOBF] obfuscate error:', clean);
      return reply(500, { success: false, error: clean });
    }

    if (!result || typeof result.code !== 'string' || !result.code.length) {
      return reply(500, { success: false, error: 'QyrexOBF no generó output' });
    }

    return reply(200, {
      success: true,
      product: 'QyrexOBF v2',
      timeMs: Date.now() - t0,
      originalSize: source.length,
      obfuscatedSize: result.code.length,
      engine: 'QyrexOBF',
      steps: result.steps || null,
      antiTamper: !!result.antiTamper,
      code: result.code
    });
  } catch (err) {
    const clean = stripAnsi(err && (err.message || String(err))) || 'fail';
    console.error('[QyrexOBF]', clean);
    return reply(500, { success: false, error: clean });
  }
});

const indexPath = path.join(__dirname, 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ product: 'QyrexOBF v2' });
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Not found' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('========== QyrexOBF ==========');
  console.log('PORT', PORT);
  console.log('lua ', findLua());
  console.log('luac', findLuac());
  try { getRoot(); console.log('engines extracted'); } catch (e) { console.error('extract', e.message); }
  console.log('==============================');
});
