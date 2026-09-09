'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { obfuscate, findLua, findLuac, getRoot } = require('./obfuscate');

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.API_KEY || '';

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));
app.use(rateLimit({ windowMs: 60000, max: 15, message: { error: 'Rate limit' } }));

function requireKey(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers['x-api-key'] || req.query.key || (req.body && req.body.apiKey);
  if (key === API_KEY) return next();
  return res.status(401).json({ error: 'Invalid API key' });
}

app.get('/health', (req, res) => {
  let ok = false;
  try { ok = fs.existsSync(path.join(getRoot(), 'Prometheus-master', 'cli.lua')); } catch (e) {}
  res.json({
    ok: true,
    product: 'QyrexOBF',
    lua: findLua(),
    luac: findLuac(),
    enginesReady: ok,
    uptime: process.uptime()
  });
});

app.post('/obfuscate', requireKey, (req, res) => {
  try {
    const source = (req.body && (req.body.source || req.body.code)) || '';
    if (!source || String(source).trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Missing source' });
    }
    if (source.length > 600000) {
      return res.status(400).json({ success: false, error: 'Source too large' });
    }
    const options = {
      mode: req.body.mode || req.body.engine || 'max',
      preset: req.body.preset || 'Strong'
    };
    const t0 = Date.now();
    const result = obfuscate(source, options);
    res.json({
      success: true,
      product: 'QyrexOBF',
      timeMs: Date.now() - t0,
      originalSize: source.length,
      obfuscatedSize: result.code.length,
      engine: result.engine,
      steps: result.steps || null,
      warning: result.warning || null,
      code: result.code
    });
  } catch (err) {
    console.error('[QyrexOBF]', err.message);
    res.status(500).json({ success: false, error: err.message || 'fail' });
  }
});

const indexPath = path.join(__dirname, 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ product: 'QyrexOBF', endpoint: 'POST /obfuscate' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('QyrexOBF listening on :' + PORT);
  try {
    getRoot();
    console.log('Engines ready · lua=', findLua(), 'luac=', findLuac());
  } catch (e) {
    console.error('Extract error:', e.message);
  }
});
