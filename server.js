'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { obfuscate } = require('./obfuscate');

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.API_KEY || '';

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '1.5mb' }));
app.use(express.urlencoded({ extended: true, limit: '1.5mb' }));

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit: máx 40/min' }
}));

function requireKey(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers['x-api-key'] || req.query.key || (req.body && req.body.apiKey);
  if (key === API_KEY) return next();
  return res.status(401).json({ error: 'API key inválida o ausente (header x-api-key)' });
}

app.get('/health', (req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

app.post('/obfuscate', requireKey, (req, res) => {
  try {
    const source = (req.body && (req.body.source || req.body.code)) || '';
    if (!source || String(source).trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Falta "source" (código Lua)' });
    }
    if (source.length > 1.2 * 1024 * 1024) {
      return res.status(400).json({ success: false, error: 'Código demasiado grande (máx ~1.2 MB)' });
    }

    const options = (req.body && req.body.options) || {};
    const t0 = Date.now();
    const code = obfuscate(source, options);
    const ms = Date.now() - t0;

    res.json({
      success: true,
      timeMs: ms,
      originalSize: source.length,
      obfuscatedSize: code.length,
      code
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message || 'Error al ofuscar' });
  }
});

// Static: index.html en la misma carpeta
const indexPath = path.join(__dirname, 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.type('json').json({
    service: 'Lua Obfuscator API',
    endpoints: { 'POST /obfuscate': '{ source, options }', 'GET /health': 'ok' }
  });
});

app.get('/ui', (req, res) => {
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.status(404).send('index.html not found');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Lua Obfuscator on 0.0.0.0:${PORT}`);
  console.log('API_KEY set:', !!API_KEY);
});
