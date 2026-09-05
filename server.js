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

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, name: 'QyrexObf', version: '1.6.7' });
});

app.post('/api/obfuscate', (req, res) => {
  try {
    const source = String((req.body && req.body.source) || '');
    if (!source.trim()) {
      return res.status(400).json({ error: 'source vacío' });
    }
    const result = obfuscate(source);
    res.json({
      code: result.code,
      stats: result.stats
    });
  } catch (e) {
    res.status(400).json({ error: e.message || 'error' });
  }
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('QyrexObf listening on', PORT);
});
