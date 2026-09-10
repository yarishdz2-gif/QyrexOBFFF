'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
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
const JOB_ROOT = path.join(__dirname, 'jobs');
try { fs.mkdirSync(JOB_ROOT, { recursive: true }); } catch (_) {}

const children = new Map();

function metaPath(id) { return path.join(JOB_ROOT, id, 'meta.json'); }
function readMeta(id) {
  try { return JSON.parse(fs.readFileSync(metaPath(id), 'utf8')); } catch (_) { return null; }
}
function writeMeta(id, patch) {
  const dir = path.join(JOB_ROOT, id);
  fs.mkdirSync(dir, { recursive: true });
  const cur = readMeta(id) || { id, logs: [], createdAt: Date.now() };
  const logs = Array.isArray(cur.logs) ? cur.logs.slice(-80) : [];
  if (patch.logLine) {
    logs.push('[' + new Date().toISOString().slice(11, 19) + '] ' + patch.logLine);
    delete patch.logLine;
  }
  const next = Object.assign({}, cur, patch, {
    logs,
    lastLog: logs.length ? logs[logs.length - 1] : cur.lastLog,
    updatedAt: Date.now()
  });
  fs.writeFileSync(metaPath(id), JSON.stringify(next), 'utf8');
  return next;
}

process.on('uncaughtException', (e) => console.error('[QyrexOBF]', e && e.message));
process.on('unhandledRejection', (e) => console.error('[QyrexOBF]', e));

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '32mb' }));
app.use(rateLimit({ windowMs: 60000, max: 300, message: { success: false, error: 'Rate limit' } }));

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
    jobRoot: JOB_ROOT,
    activeChildren: children.size,
    lua: findLua(),
    enginesReady: engines,
    uptime: process.uptime()
  });
});

app.post('/obfuscate', requireKey, (req, res) => {
  try {
    const source = (req.body && (req.body.source || req.body.code)) || '';
    if (!source || String(source).trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Missing source' });
    }
    if (source.length > 8000000) {
      return res.status(400).json({ success: false, error: 'Source too large' });
    }
    if (!findLua()) {
      return res.status(500).json({ success: false, error: 'lua5.1 no encontrado — Runtime DOCKER' });
    }

    const id = crypto.randomBytes(12).toString('hex');
    const dir = path.join(JOB_ROOT, id);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'in.lua'), String(source), 'utf8');

    const opts = { antiTamper: true, mode: 'max' };
    if (req.body && req.body.antiTamper === false) opts.antiTamper = false;

    // Write meta BEFORE responding so poll never 404s
    writeMeta(id, {
      id,
      status: 'queued',
      progress: 2,
      stage: 'queued',
      createdAt: Date.now(),
      opts,
      error: null,
      logLine: 'Job creado · esperando worker'
    });

    const workerJs = path.join(__dirname, 'worker.js');
    const child = spawn(process.execPath, [workerJs, dir], {
      cwd: __dirname,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false
    });
    children.set(id, child);
    writeMeta(id, { status: 'running', progress: 4, stage: 'spawn', pid: child.pid, logLine: 'Worker PID ' + child.pid });

    // Parent heartbeat while child blocked in lua — UI keeps moving
    const beat = setInterval(() => {
      const m = readMeta(id);
      if (!m || m.status === 'done' || m.status === 'error') {
        clearInterval(beat);
        return;
      }
      let p = typeof m.progress === 'number' ? m.progress : 4;
      if (p < 88) p += 1;
      writeMeta(id, {
        progress: p,
        elapsedMs: Date.now() - (m.createdAt || Date.now()),
        heartbeat: Date.now()
      });
    }, 2000);

    child.stdout.on('data', (b) => {
      const line = String(b).trim();
      if (line) console.log('[w ' + id.slice(0, 8) + ']', line);
    });
    child.stderr.on('data', (b) => {
      const line = stripAnsi(String(b).trim());
      if (!line) return;
      console.error('[w ' + id.slice(0, 8) + ']', line);
      writeMeta(id, { logLine: line.slice(0, 240) });
    });
    child.on('exit', (code) => {
      clearInterval(beat);
      children.delete(id);
      const m = readMeta(id) || {};
      if (m.status !== 'done' && m.status !== 'error') {
        writeMeta(id, {
          status: code === 0 ? 'done' : 'error',
          progress: 100,
          stage: code === 0 ? 'done' : 'error',
          error: code === 0 ? null : ('Worker exit ' + code),
          logLine: 'Worker exit ' + code
        });
      }
      console.log('[w ' + id.slice(0, 8) + '] exit', code);
    });

    return res.status(202).json({ success: true, async: true, jobId: id, status: 'queued', mode: 'max' });
  } catch (err) {
    return res.status(500).json({ success: false, error: stripAnsi(err && err.message) || 'fail' });
  }
});

app.get('/job/:id', requireKey, (req, res) => {
  const id = String(req.params.id || '').trim();
  const m = readMeta(id);
  if (!m) {
    return res.status(404).json({
      success: false,
      status: 'missing',
      error: 'Job no encontrado. Vuelve a Ofuscar (¿redeploy a mitad?).',
      lookedFor: id
    });
  }

  const elapsedMs = m.createdAt ? (Date.now() - m.createdAt) : (m.elapsedMs || null);

  if (m.status === 'done') {
    let code = '';
    try {
      const op = m.outPath || path.join(JOB_ROOT, id, 'out.lua');
      code = fs.readFileSync(op, 'utf8');
    } catch (_) {}
    if (!code) {
      return res.json({
        success: false,
        status: 'error',
        error: 'Done pero sin out.lua',
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
      timeMs: m.elapsedMs || elapsedMs,
      originalSize: m.originalSize,
      obfuscatedSize: m.obfuscatedSize || code.length,
      steps: m.steps || null,
      antiTamper: !!m.antiTamper,
      mode: 'max',
      logs: m.logs || [],
      code
    });
  }

  if (m.status === 'error') {
    return res.json({
      success: false,
      status: 'error',
      progress: 100,
      stage: 'error',
      error: m.error || 'fail',
      logs: m.logs || [],
      elapsedMs
    });
  }

  return res.json({
    success: true,
    async: true,
    jobId: id,
    status: m.status || 'running',
    progress: Math.max(1, Math.floor(Number(m.progress) || 1)),
    stage: m.stage || 'running',
    logs: m.logs || [],
    lastLog: m.lastLog || null,
    elapsedMs,
    mode: 'max'
  });
});

app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ product: 'QyrexOBF v2' });
});

app.use((req, res) => res.status(404).json({ success: false, error: 'Not found' }));

app.listen(PORT, '0.0.0.0', () => {
  console.log('QyrexOBF MAX on', PORT, 'jobs=', JOB_ROOT);
  console.log('lua', findLua());
  try { getRoot(); console.log('engines ok'); } catch (e) { console.error('engines', e.message); }
});
