'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
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

// In-memory jobs (single instance). Survives long MAX runs without proxy 502.
const jobs = new Map();
const JOB_TTL_MS = 30 * 60 * 1000;

function cleanJobs() {
  const now = Date.now();
  for (const [id, j] of jobs) {
    if (now - j.createdAt > JOB_TTL_MS) jobs.delete(id);
  }
}
setInterval(cleanJobs, 60000).unref();

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
  max: 40,
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
    mode: 'max',
    async: true,
    lua: lua,
    luac: luac,
    enginesReady: engines,
    jobs: jobs.size,
    hint: lua ? null : 'lua5.1 missing — deploy with Dockerfile (Runtime: Docker on Render)',
    uptime: process.uptime()
  });
});

function startJob(source, opts) {
  const id = crypto.randomBytes(12).toString('hex');
  const job = {
    id,
    status: 'queued', // queued | running | done | error
    createdAt: Date.now(),
    startedAt: null,
    finishedAt: null,
    error: null,
    result: null
  };
  jobs.set(id, job);

  setImmediate(() => {
    const j = jobs.get(id);
    if (!j) return;
    j.status = 'running';
    j.startedAt = Date.now();
    try {
      if (!findLua()) {
        throw new Error('QyrexOBF: lua5.1 no encontrado. En Render usa Runtime DOCKER.');
      }
      const result = obfuscate(source, opts || {});
      if (!result || typeof result.code !== 'string' || !result.code.length) {
        throw new Error('QyrexOBF no generó output');
      }
      j.status = 'done';
      j.finishedAt = Date.now();
      j.result = {
        success: true,
        product: 'QyrexOBF v2',
        timeMs: j.finishedAt - j.startedAt,
        originalSize: source.length,
        obfuscatedSize: result.code.length,
        engine: 'QyrexOBF',
        steps: result.steps || null,
        antiTamper: !!result.antiTamper,
        mode: 'max',
        code: result.code
      };
    } catch (err) {
      j.status = 'error';
      j.finishedAt = Date.now();
      j.error = stripAnsi(err && (err.message || String(err))) || 'Obfuscation failed';
      console.error('[QyrexOBF] job', id, j.error);
    }
  });

  return id;
}

// Start MAX obfuscation (async — avoids 502 on long runs)
app.post('/obfuscate', requireKey, (req, res) => {
  try {
    const source = (req.body && (req.body.source || req.body.code)) || '';
    if (!source || String(source).trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Missing source — pega código Lua/Luau' });
    }
    if (source.length > 8000000) {
      return res.status(400).json({ success: false, error: 'Source too large (max ~8MB)' });
    }
    if (!findLua()) {
      return res.status(500).json({
        success: false,
        error: 'QyrexOBF: lua5.1 no encontrado. En Render usa Runtime DOCKER (no Node). Abre /health.'
      });
    }

    const opts = { antiTamper: true, mode: 'max' };
    if (req.body && req.body.antiTamper === false) opts.antiTamper = false;

    const jobId = startJob(String(source), opts);
    return res.status(202).json({
      success: true,
      async: true,
      jobId,
      status: 'queued',
      mode: 'max',
      message: 'Ofuscación MAX en segundo plano. Consulta /job/' + jobId
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: stripAnsi(err && err.message) || 'fail'
    });
  }
});

// Poll job status / result
app.get('/job/:id', requireKey, (req, res) => {
  const j = jobs.get(req.params.id);
  if (!j) {
    return res.status(404).json({ success: false, error: 'Job no encontrado o expirado' });
  }
  if (j.status === 'done' && j.result) {
    return res.json(j.result);
  }
  if (j.status === 'error') {
    return res.status(500).json({
      success: false,
      status: 'error',
      error: j.error || 'fail',
      timeMs: j.finishedAt && j.startedAt ? (j.finishedAt - j.startedAt) : null
    });
  }
  return res.json({
    success: true,
    async: true,
    jobId: j.id,
    status: j.status,
    mode: 'max',
    elapsedMs: Date.now() - (j.startedAt || j.createdAt)
  });
});

const indexPath = path.join(__dirname, 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ product: 'QyrexOBF v2', mode: 'max', async: true });
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Not found' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('========== QyrexOBF MAX ==========');
  console.log('PORT', PORT);
  console.log('mode MAX async jobs');
  console.log('lua ', findLua());
  console.log('luac', findLuac());
  try { getRoot(); console.log('engines extracted'); } catch (e) { console.error('extract', e.message); }
  console.log('==================================');
});
