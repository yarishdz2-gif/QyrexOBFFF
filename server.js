'use strict';

/**
 * QyrexOBF Pure Node server — same API surface as v2, 100% Node (no lua binaries)
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { obfuscate, getRoot } = require('./obfuscate');

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
  res.json({
    ok: true,
    pureNode: true,
    product: 'QyrexOBF PureNode v3',
    node: process.version,
    enginesReady: true,
    lua: null
  });
});

app.post('/obfuscate', requireKey, (req, res) => {
  try {
    const source = (req.body && req.body.source) || (req.body && req.body.code) || '';
    const mode = String((req.body && req.body.mode) || 'max').toLowerCase();
    const antiTamper = (req.body && req.body.antiTamper) !== false;
    if (!source || !String(source).trim()) {
      return res.status(400).json({ success: false, error: 'source vacío' });
    }

    const id = crypto.randomBytes(12).toString('hex');
    const dir = path.join(JOB_ROOT, id);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'in.lua'), String(source), 'utf8');
    writeMeta(id, {
      status: 'queued',
      progress: 1,
      stage: 'queued',
      originalSize: String(source).length,
      mode,
      antiTamper,
      logLine: 'Job creado (Pure Node)'
    });

    const workerPath = path.join(__dirname, 'worker.js');
    const child = spawn(process.execPath, [workerPath, id, dir], {
      cwd: __dirname,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: Object.assign({}, process.env, {
        QYREX_JOB_ID: id,
        QYREX_JOB_DIR: dir,
        QYREX_MODE: mode,
        QYREX_ANTITAMPER: antiTamper ? '1' : '0'
      })
    });
    children.set(id, child);

    let stderrBuf = '';
    child.stderr.on('data', (d) => { stderrBuf += String(d).slice(0, 4000); });
    child.on('exit', (code) => {
      children.delete(id);
      const m = readMeta(id) || {};
      if (code !== 0 && m.status !== 'done') {
        writeMeta(id, {
          status: 'error',
          progress: 100,
          stage: 'error',
          error: stripAnsi(stderrBuf || ('worker exit ' + code)).slice(0, 1500),
          logLine: 'Worker exit ' + code
        });
      }
    });

    res.json({
      success: true,
      async: true,
      jobId: id,
      status: 'queued',
      progress: 1,
      stage: 'queued',
      mode,
      pureNode: true
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message || 'Error' });
  }
});

app.post('/obfuscate/sync', requireKey, (req, res) => {
  try {
    const source = (req.body && req.body.source) || (req.body && req.body.code) || '';
    const mode = String((req.body && req.body.mode) || 'max').toLowerCase();
    const antiTamper = (req.body && req.body.antiTamper) !== false;
    if (!source || !String(source).trim()) {
      return res.status(400).json({ success: false, error: 'source vacío' });
    }
    const t0 = Date.now();
    const result = obfuscate(String(source), { mode, antiTamper });
    res.json({
      success: true,
      status: 'done',
      progress: 100,
      product: 'QyrexOBF PureNode v3',
      timeMs: Date.now() - t0,
      originalSize: String(source).length,
      obfuscatedSize: (result.code || '').length,
      steps: result.steps,
      antiTamper: !!result.antiTamper,
      mode: result.mode,
      pureNode: true,
      code: result.code
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message || 'Error' });
  }
});

app.get('/job/:id', (req, res) => {
  const id = String(req.params.id || '').replace(/[^a-f0-9]/gi, '');
  const m = readMeta(id);
  if (!m) {
    return res.status(404).json({
      success: false,
      status: 'missing',
      error: 'Job no encontrado. Vuelve a Ofuscar.',
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
      product: 'QyrexOBF PureNode v3',
      timeMs: m.elapsedMs || elapsedMs,
      originalSize: m.originalSize,
      obfuscatedSize: m.obfuscatedSize || code.length,
      steps: m.steps || null,
      antiTamper: !!m.antiTamper,
      mode: m.mode || 'max',
      pureNode: true,
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
    mode: m.mode || 'max',
    pureNode: true
  });
});

app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ product: 'QyrexOBF PureNode v3' });
});

app.use((req, res) => res.status(404).json({ success: false, error: 'Not found' }));

app.listen(PORT, '0.0.0.0', () => {
  console.log('QyrexOBF PureNode v3 on', PORT, 'jobs=', JOB_ROOT);
  console.log('engine: pure Node (no lua binaries required)');
});
