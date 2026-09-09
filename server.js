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
const { findLua, findLuac, getRoot } = require('./obfuscate');

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
const JOB_ROOT = path.join(os.tmpdir(), 'qyrex-jobs');
try { fs.mkdirSync(JOB_ROOT, { recursive: true }); } catch (_) {}

const children = new Map(); // jobId -> ChildProcess

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
  max: 60,
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

function jobDir(id) { return path.join(JOB_ROOT, id); }
function metaPath(id) { return path.join(jobDir(id), 'meta.json'); }
function inPath(id) { return path.join(jobDir(id), 'in.lua'); }
function outPath(id) { return path.join(jobDir(id), 'out.lua'); }

function readMeta(id) {
  try {
    return JSON.parse(fs.readFileSync(metaPath(id), 'utf8'));
  } catch (_) {
    return null;
  }
}

function writeMeta(id, patch) {
  const cur = readMeta(id) || {};
  const next = Object.assign({}, cur, patch, { updatedAt: Date.now() });
  fs.writeFileSync(metaPath(id), JSON.stringify(next), 'utf8');
  return next;
}

app.get('/health', (req, res) => {
  let engines = false;
  try { engines = fs.existsSync(path.join(getRoot(), 'Prometheus-master', 'cli.lua')); } catch (e) {}
  res.json({
    ok: !!(findLua() && engines),
    product: 'QyrexOBF v2',
    fused: 'AntiTamper → Prometheus Strong → Hercules → IronBrew2',
    mode: 'max',
    async: true,
    worker: true,
    lua: findLua(),
    luac: findLuac(),
    enginesReady: engines,
    activeJobs: children.size,
    uptime: process.uptime()
  });
});

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
        error: 'QyrexOBF: lua5.1 no encontrado. Usa Runtime DOCKER en Render.'
      });
    }

    const id = crypto.randomBytes(12).toString('hex');
    fs.mkdirSync(jobDir(id), { recursive: true });
    fs.writeFileSync(inPath(id), String(source), 'utf8');

    const opts = { antiTamper: true, mode: 'max' };
    if (req.body && req.body.antiTamper === false) opts.antiTamper = false;

    writeMeta(id, {
      id,
      status: 'queued',
      progress: 0,
      stage: 'queued',
      createdAt: Date.now(),
      logs: ['[' + new Date().toISOString().slice(11, 19) + '] Job creado'],
      opts,
      error: null
    });

    const workerPath = path.join(__dirname, 'worker.js');
    const child = spawn(process.execPath, [workerPath, id, inPath(id), metaPath(id)], {
      cwd: __dirname,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    children.set(id, child);
    writeMeta(id, { status: 'running', progress: 3, stage: 'spawn', pid: child.pid });

    // Parent heartbeat: keeps UI moving even while worker is blocked in execFileSync
    const beat = setInterval(() => {
      try {
        const m = readMeta(id);
        if (!m || m.status === 'done' || m.status === 'error') {
          clearInterval(beat);
          return;
        }
        let p = typeof m.progress === 'number' ? m.progress : 5;
        // creep forward slowly up to 92% while still running
        if (p < 92) p = Math.min(92, p + 1);
        writeMeta(id, {
          progress: p,
          elapsedMs: Date.now() - (m.createdAt || Date.now()),
          heartbeat: Date.now()
        });
      } catch (_) {}
    }, 1500);
    child.on('close', () => { try { clearInterval(beat); } catch (_) {} });

    child.stdout.on('data', (buf) => {
      const line = String(buf).trim();
      if (line) console.log('[job ' + id.slice(0, 8) + ']', line);
    });
    child.stderr.on('data', (buf) => {
      const line = stripAnsi(String(buf).trim());
      if (!line) return;
      console.error('[job ' + id.slice(0, 8) + ' err]', line);
      try {
        const m = readMeta(id) || {};
        const logs = Array.isArray(m.logs) ? m.logs.slice(-40) : [];
        logs.push('[' + new Date().toISOString().slice(11, 19) + '] ' + line.slice(0, 300));
        writeMeta(id, { logs, lastLog: line.slice(0, 300) });
      } catch (_) {}
    });
    child.on('exit', (code) => {
      children.delete(id);
      const m = readMeta(id) || {};
      if (m.status !== 'done' && m.status !== 'error') {
        writeMeta(id, {
          status: code === 0 ? 'done' : 'error',
          progress: 100,
          error: code === 0 ? null : ('Worker exit code ' + code),
          stage: code === 0 ? 'done' : 'error'
        });
      }
      console.log('[job ' + id.slice(0, 8) + '] exit', code);
    });

    return res.status(202).json({
      success: true,
      async: true,
      jobId: id,
      status: 'queued',
      mode: 'max',
      message: 'MAX job iniciado'
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: stripAnsi(err && err.message) || 'fail' });
  }
});

app.get('/job/:id', requireKey, (req, res) => {
  const id = req.params.id;
  const m = readMeta(id);
  if (!m) {
    return res.status(404).json({ success: false, error: 'Job no encontrado o expirado', status: 'missing' });
  }

  // Always return JSON — never empty
  if (m.status === 'done') {
    let code = '';
    try {
      const op = m.outPath || outPath(id);
      if (fs.existsSync(op)) code = fs.readFileSync(op, 'utf8');
    } catch (_) {}
    if (!code) {
      return res.status(500).json({
        success: false,
        status: 'error',
        error: 'Job done pero sin archivo out.lua',
        logs: m.logs || [],
        progress: 100
      });
    }
    return res.json({
      success: true,
      status: 'done',
      progress: 100,
      stage: 'done',
      product: 'QyrexOBF v2',
      timeMs: m.elapsedMs || null,
      originalSize: m.originalSize || null,
      obfuscatedSize: m.obfuscatedSize || code.length,
      engine: 'QyrexOBF',
      steps: m.steps || null,
      antiTamper: !!m.antiTamper,
      mode: 'max',
      logs: m.logs || [],
      code
    });
  }

  if (m.status === 'error') {
    return res.status(200).json({
      success: false,
      status: 'error',
      progress: 100,
      stage: 'error',
      error: m.error || 'fail',
      logs: m.logs || [],
      elapsedMs: m.elapsedMs || null
    });
  }

  // running / queued
  return res.json({
    success: true,
    async: true,
    jobId: id,
    status: m.status || 'running',
    progress: typeof m.progress === 'number' ? m.progress : 0,
    stage: m.stage || 'running',
    logs: m.logs || [],
    lastLog: m.lastLog || null,
    elapsedMs: m.createdAt ? (Date.now() - m.createdAt) : null,
    mode: 'max'
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
  console.log('========== QyrexOBF MAX ==========' );
  console.log('PORT', PORT);
  console.log('async worker jobs ·', JOB_ROOT);
  console.log('lua ', findLua());
  try { getRoot(); console.log('engines extracted'); } catch (e) { console.error('extract', e.message); }
  console.log('==================================');
});
