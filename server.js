'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { obfuscate, findLua, findLuac, getEnginesRoot } = require('./obfuscate');

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.API_KEY || '';

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));
app.use(rateLimit({ windowMs: 60000, max: 20, message: { error: 'Rate limit' } }));

function requireKey(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers['x-api-key'] || req.query.key || (req.body && req.body.apiKey);
  if (key === API_KEY) return next();
  return res.status(401).json({ error: 'Invalid API key' });
}

app.get('/health', (req, res) => {
  let enginesOk = false;
  try {
    enginesOk = fs.existsSync(path.join(getEnginesRoot(), 'Prometheus-master', 'cli.lua'));
  } catch (e) {}
  res.json({
    ok: true,
    lua: findLua(),
    luac: findLuac(),
    enginesExtracted: enginesOk,
    uptime: process.uptime()
  });
});

app.post('/obfuscate', requireKey, (req, res) => {
  try {
    const source = (req.body && (req.body.source || req.body.code)) || '';
    if (!source || String(source).trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Missing source' });
    }
    if (source.length > 800000) {
      return res.status(400).json({ success: false, error: 'Source too large' });
    }
    const options = Object.assign({}, req.body.options || {}, {
      engine: req.body.engine || (req.body.options && req.body.options.engine) || 'mega',
      preset: req.body.preset || (req.body.options && req.body.options.preset) || 'Strong'
    });
    const t0 = Date.now();
    const result = obfuscate(source, options);
    res.json({
      success: true,
      timeMs: Date.now() - t0,
      originalSize: source.length,
      obfuscatedSize: result.code.length,
      engine: result.engine,
      steps: result.steps || null,
      warning: result.warning || null,
      code: result.code
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message || 'fail' });
  }
});

const indexPath = path.join(__dirname, 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ service: 'Mega Obfuscator', engines: ['mega', 'prometheus', 'ib2', 'hercules'] });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('Mega Obfuscator :' + PORT);
  try { getEnginesRoot(); console.log('Engines extracted OK'); } catch (e) { console.error('Extract fail', e.message); }
});
