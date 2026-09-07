'use strict';
const express = require('express');
const cors = require('cors');
const path = require('path');
const { obfuscate, VERSION, EXTRA_LAYERS } = require('./obfuscate');
const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.post('/api/obfuscate', (req, res) => {
  try {
    const code = (req.body && req.body.code) || '';
    const extra = req.body && req.body.extraLayers;
    const r = obfuscate(code, { extraLayers: extra != null ? Number(extra) : EXTRA_LAYERS });
    res.json({
      ok: true,
      code: r.code,
      stats: r.stats,
      reward: { tokens: 1, reason: 'obfuscation_complete' },
      version: VERSION,
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});
app.get('/api/info', (_req, res) => {
  res.json({ version: VERSION, defaultExtraLayers: EXTRA_LAYERS, alphabet: "!#$%&()*+,-./:;<=>?@[]^_{|}~'" });
});
app.listen(PORT, () => console.log('QyrexObf ' + VERSION + ' :' + PORT));
