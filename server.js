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
    .replace(/\[[0-9]+m/g, '')
    .trim();
}

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.API_KEY || '';

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '32mb' }));
app.use(rateLimit({ windowMs: 60000, max: 20, message: { error: 'Rate limit' } }));

function requireKey(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers['x-api-key'] || req.query.key || (req.body && req.body.apiKey);
  if (key === API_KEY) return next();
  return res.status(401).json({ error: 'Invalid API key' });
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
  try {
    if (!findLua()) {
      return res.status(500).json({
        success: false,
        error: 'QyrexOBF: lua5.1 no encontrado. En Render usa Runtime DOCKER (no Node). Abre /health para diagnosticar.'
      });
    }
    const source = (req.body && (req.body.source || req.body.code)) || '';
    if (!source || String(source).trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Missing source' });
    }
    if (source.length > 8000000) {
      return res.status(400).json({ success: false, error: 'Source too large (max ~8MB)' });
    }
    const t0 = Date.now();
    const opts = {};
    if (req.body && req.body.antiTamper === false) opts.antiTamper = false;
    const result = obfuscate(source, opts);
    res.json({
      success: true,
      product: 'QyrexOBF v2',
      timeMs: Date.now() - t0,
      originalSize: source.length,
      obfuscatedSize: result.code.length,
      engine: 'QyrexOBF',
      steps: result.steps || null,
      code: result.code
    });
  } catch (err) {
    const raw = err && (err.message || String(err));
    const clean = stripAnsi(raw) || 'fail';
    console.error('[QyrexOBF]', clean);
    res.status(500).json({ success: false, error: clean });
  }
});

const indexPath = path.join(__dirname, 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ product: 'QyrexOBF v2' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('========== QyrexOBF ==========');
  console.log('PORT', PORT);
  console.log('lua ', findLua());
  console.log('luac', findLuac());
  try { getRoot(); console.log('engines extracted'); } catch (e) { console.error('extract', e.message); }
  console.log('==============================');
});
