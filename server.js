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
    const result = obfuscate((req.body && req.body.code) || '');
    res.json({ ok: true, code: result.code, stats: result.stats });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});
app.listen(PORT, () => console.log('QyrexObf 1.0.0 :' + PORT));
