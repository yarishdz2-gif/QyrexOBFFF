'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
const {
  obfuscate, findLua, findLuac, getRoot,
  runPrometheus, runHercules, runIB2, buildAntiTamper
} = require('./obfuscate');

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

// Prefer app-local jobs dir (survives better than random tmp on some hosts)
const JOB_ROOT = process.env.QYREX_JOBS || path.join(__dirname, 'jobs');
try { fs.mkdirSync(JOB_ROOT, { recursive: true }); } catch (_) {}

/** @type {Map<string, any>} */
const MEM = new Map();

function now() { return Date.now(); }

function saveMem(id, patch) {
  const cur = MEM.get(id) || { id, createdAt: now(), logs: [] };
  const next = Object.assign({}, cur, patch, { updatedAt: now() });
  if (patch && patch.logLine) {
    const logs = Array.isArray(next.logs) ? next.logs.slice(-60) : [];
    logs.push('[' + new Date().toISOString().slice(11, 19) + '] ' + patch.logLine);
    next.logs = logs;
    next.lastLog = logs[logs.length - 1];
    delete next.logLine;
  }
  MEM.set(id, next);
  // disk mirror (best-effort)
  try {
    const dir = path.join(JOB_ROOT, id);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify(next), 'utf8');
  } catch (_) {}
  return next;
}

function loadJob(id) {
  if (MEM.has(id)) return MEM.get(id);
  try {
    const raw = fs.readFileSync(path.join(JOB_ROOT, id, 'meta.json'), 'utf8');
    const j = JSON.parse(raw);
    MEM.set(id, j);
    return j;
  } catch (_) {
    return null;
  }
}

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
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Rate limit' }
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
  res.json({
    ok: !!(findLua() && engines),
    product: 'QyrexOBF v2',
    mode: 'max',
    async: true,
    jobsInMemory: MEM.size,
    jobRoot: JOB_ROOT,
    lua: findLua(),
    enginesReady: engines,
    uptime: process.uptime()
  });
});

function runMaxInProcess(id, source, opts) {
  const t0 = now();
  const steps = [];
  try {
    saveMem(id, { status: 'running', progress: 5, stage: 'boot', logLine: 'In-process MAX start' });
    if (!findLua()) throw new Error('lua5.1 no encontrado');
    saveMem(id, { progress: 10, stage: 'extract-engines', logLine: 'Extrayendo engines…' });
    getRoot();
    saveMem(id, { progress: 18, stage: 'read-source', logLine: 'Source ' + source.length + ' bytes' });

    let code = source;
    if (opts.antiTamper !== false) {
      saveMem(id, { progress: 22, stage: 'antitamper', logLine: 'AntiTamper v2…' });
      try {
        code = buildAntiTamper() + '\n' + source;
        steps.push('AntiTamper:v2');
        saveMem(id, { logLine: 'AntiTamper OK' });
      } catch (e) {
        steps.push('AntiTamper:skip');
        code = source;
        saveMem(id, { logLine: 'AntiTamper skip: ' + (e.message || e) });
      }
    }

    saveMem(id, { progress: 30, stage: 'prometheus', logLine: 'Prometheus Strong…' });
    try {
      code = runPrometheus(code, 'Strong');
      steps.push('Prometheus:Strong');
      saveMem(id, { progress: 55, logLine: 'Prometheus Strong OK · ' + code.length + ' B' });
    } catch (e1) {
      saveMem(id, { progress: 40, stage: 'prometheus-medium', logLine: 'Strong falló, Medium…' });
      try {
        code = runPrometheus(code, 'Medium');
        steps.push('Prometheus:Medium');
        saveMem(id, { progress: 55, logLine: 'Prometheus Medium OK' });
      } catch (e2) {
        code = runPrometheus(source, 'Medium');
        steps.push('Prometheus:Medium:clean');
        saveMem(id, { progress: 55, logLine: 'Prometheus Medium clean OK' });
      }
    }

    saveMem(id, { progress: 65, stage: 'hercules', logLine: 'Hercules…' });
    try {
      code = runHercules(code);
      steps.push('Hercules');
      saveMem(id, { progress: 80, logLine: 'Hercules OK · ' + code.length + ' B' });
    } catch (e) {
      steps.push('Hercules:skip');
      saveMem(id, { logLine: 'Hercules skip' });
    }

    saveMem(id, { progress: 85, stage: 'ironbrew2', logLine: 'IronBrew2…' });
    try {
      code = runIB2(code);
      steps.push('IronBrew2');
      saveMem(id, { progress: 95, logLine: 'IronBrew2 OK · ' + code.length + ' B' });
    } catch (e) {
      steps.push('IronBrew2:skip');
      saveMem(id, { logLine: 'IronBrew2 skip' });
    }

    if (!code || !code.length) throw new Error('Sin output');
    const header = '--QyrexObf [qyrex.hopto.org]\n';
    if (!code.startsWith('--QyrexObf')) code = header + code;

    try {
      fs.mkdirSync(path.join(JOB_ROOT, id), { recursive: true });
      fs.writeFileSync(path.join(JOB_ROOT, id, 'out.lua'), code, 'utf8');
    } catch (_) {}

    saveMem(id, {
      status: 'done',
      progress: 100,
      stage: 'done',
      steps,
      code,
      antiTamper: steps.indexOf('AntiTamper:v2') >= 0,
      originalSize: source.length,
      obfuscatedSize: code.length,
      elapsedMs: now() - t0,
      logLine: 'DONE en ' + Math.round((now() - t0) / 1000) + 's · ' + steps.join(' → ')
    });
  } catch (err) {
    saveMem(id, {
      status: 'error',
      progress: 100,
      stage: 'error',
      error: stripAnsi(err && (err.message || String(err))).slice(0, 2000),
      elapsedMs: now() - t0,
      logLine: 'ERROR: ' + stripAnsi(err && err.message)
    });
  }
}

app.post('/obfuscate', requireKey, (req, res) => {
  try {
    const source = (req.body && (req.body.source || req.body.code)) || '';
    if (!source || String(source).trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Missing source' });
    }
    if (source.length > 8000000) {
      return res.status(400).json({ success: false, error: 'Source too large (max ~8MB)' });
    }
    if (!findLua()) {
      return res.status(500).json({
        success: false,
        error: 'lua5.1 no encontrado. Usa Runtime DOCKER en Render.'
      });
    }

    const id = crypto.randomBytes(12).toString('hex');
    const opts = { antiTamper: true, mode: 'max' };
    if (req.body && req.body.antiTamper === false) opts.antiTamper = false;

    // Store IMMEDIATELY in memory so first poll never 404s
    saveMem(id, {
      id,
      status: 'queued',
      progress: 1,
      stage: 'queued',
      createdAt: now(),
      logs: ['[' + new Date().toISOString().slice(11, 19) + '] Job creado en memoria'],
      opts,
      error: null
    });

    // Run in-process on next tick (same instance = poll always finds job)
    setImmediate(() => {
      saveMem(id, { status: 'running', progress: 3, stage: 'boot', logLine: 'Arrancando pipeline MAX' });
      runMaxInProcess(id, String(source), opts);
    });

    return res.status(202).json({
      success: true,
      async: true,
      jobId: id,
      status: 'queued',
      mode: 'max'
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: stripAnsi(err && err.message) || 'fail' });
  }
});

app.get('/job/:id', requireKey, (req, res) => {
  const id = String(req.params.id || '').trim();
  const j = loadJob(id);
  if (!j) {
    return res.status(404).json({
      success: false,
      status: 'missing',
      error: 'Job no encontrado. ¿Redeploy a mitad? Vuelve a pulsar Ofuscar.',
      memoryJobs: MEM.size,
      lookedFor: id
    });
  }

  const elapsedMs = j.createdAt ? (now() - j.createdAt) : j.elapsedMs;

  if (j.status === 'done' && j.code) {
    return res.json({
      success: true,
      status: 'done',
      progress: 100,
      stage: 'done',
      product: 'QyrexOBF v2',
      timeMs: j.elapsedMs || elapsedMs,
      originalSize: j.originalSize,
      obfuscatedSize: j.obfuscatedSize || j.code.length,
      engine: 'QyrexOBF',
      steps: j.steps || null,
      antiTamper: !!j.antiTamper,
      mode: 'max',
      logs: j.logs || [],
      code: j.code
    });
  }

  if (j.status === 'done' && !j.code) {
    // try disk
    try {
      const code = fs.readFileSync(path.join(JOB_ROOT, id, 'out.lua'), 'utf8');
      j.code = code;
      MEM.set(id, j);
      return res.json({
        success: true,
        status: 'done',
        progress: 100,
        stage: 'done',
        timeMs: j.elapsedMs || elapsedMs,
        originalSize: j.originalSize,
        obfuscatedSize: code.length,
        steps: j.steps || null,
        mode: 'max',
        logs: j.logs || [],
        code
      });
    } catch (_) {
      return res.json({
        success: false,
        status: 'error',
        error: 'Job done sin código',
        logs: j.logs || []
      });
    }
  }

  if (j.status === 'error') {
    return res.json({
      success: false,
      status: 'error',
      progress: 100,
      stage: 'error',
      error: j.error || 'fail',
      logs: j.logs || [],
      elapsedMs
    });
  }

  // Soft progress creep so UI never looks frozen while blocked in lua
  let progress = typeof j.progress === 'number' ? j.progress : 1;
  if (j.status === 'running' && progress < 90) {
    progress = Math.min(90, progress + 0.5);
    j.progress = progress;
    MEM.set(id, j);
  }

  return res.json({
    success: true,
    async: true,
    jobId: id,
    status: j.status || 'running',
    progress: Math.floor(progress),
    stage: j.stage || 'running',
    logs: j.logs || [],
    lastLog: j.lastLog || null,
    elapsedMs,
    mode: 'max'
  });
});

app.get('/jobs', requireKey, (req, res) => {
  const list = [];
  for (const [id, j] of MEM) {
    list.push({
      id,
      status: j.status,
      progress: j.progress,
      stage: j.stage,
      createdAt: j.createdAt
    });
  }
  res.json({ count: list.length, jobs: list });
});

const indexPath = path.join(__dirname, 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ product: 'QyrexOBF v2', mode: 'max' });
});

app.use((req, res) => res.status(404).json({ success: false, error: 'Not found' }));

app.listen(PORT, '0.0.0.0', () => {
  console.log('========== QyrexOBF MAX ==========');
  console.log('PORT', PORT);
  console.log('jobs', JOB_ROOT);
  console.log('lua', findLua());
  try { getRoot(); console.log('engines ok'); } catch (e) { console.error('engines', e.message); }
  console.log('==================================');
});
