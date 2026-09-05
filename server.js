'use strict';

const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { obfuscate, VERSION } = require('./obfuscate');

const app = express();
const PORT = process.env.PORT || 10000;

app.disable('x-powered-by');
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(
  express.static(path.join(__dirname, 'public'), {
    maxAge: '1h',
    etag: true
  })
);

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'QyrexObf', version: VERSION });
});

app.post('/api/obfuscate', (req, res) => {
  try {
    const body = req.body || {};
    const source = body.source ?? body.code ?? '';
    if (!String(source).trim()) {
      return res.status(400).json({ error: 'Empty source' });
    }
    const result = obfuscate(source);
    res.json(result);
  } catch (e) {
    console.error('[QyrexObf]', e.message);
    res.status(400).json({ error: e.message || 'obfuscation failed' });
  }
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`QyrexObf ${VERSION} listening on 0.0.0.0:${PORT}`);
});
