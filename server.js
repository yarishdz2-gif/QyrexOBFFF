'use strict';
const express = require('express');
const cors = require('cors');
const path = require('path');
const { obfuscate } = require('./obfuscate');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/obfuscate', (req, res) => {
  try {
    const code = (req.body && req.body.code) || '';
    const result = obfuscate(code);
    res.json({ ok: true, code: result.code, stats: result.stats });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e && e.message ? e.message : e) });
  }
});

app.get('/health', (_, res) => res.json({ ok: true, version: '1.0.0' }));

app.listen(PORT, () => console.log('QyrexObf 1.0.0 on ' + PORT));
