'use strict';

/**
 * QyrexOBF Pure Node worker — runs obfuscate() in a child process
 */

const path = require('path');
const fs = require('fs');

const jobId = process.env.QYREX_JOB_ID || process.argv[2];
const jobDir = process.env.QYREX_JOB_DIR || process.argv[3];
const mode = String(process.env.QYREX_MODE || 'max').toLowerCase();
const antiTamper = process.env.QYREX_ANTITAMPER !== '0';

if (!jobId || !jobDir) {
  console.error('worker: missing jobId/jobDir');
  process.exit(1);
}

const metaFile = path.join(jobDir, 'meta.json');
const inFile = path.join(jobDir, 'in.lua');
const outFile = path.join(jobDir, 'out.lua');

function readMeta() {
  try { return JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch (_) { return {}; }
}
function save(patch) {
  const cur = readMeta();
  const logs = Array.isArray(cur.logs) ? cur.logs.slice(-80) : [];
  if (patch.logLine) {
    logs.push('[' + new Date().toISOString().slice(11, 19) + '] ' + patch.logLine);
    delete patch.logLine;
  }
  const next = Object.assign({}, cur, patch, {
    logs,
    lastLog: logs.length ? logs[logs.length - 1] : cur.lastLog,
    updatedAt: Date.now(),
    elapsedMs: Date.now() - (cur.createdAt || Date.now())
  });
  fs.writeFileSync(metaFile, JSON.stringify(next), 'utf8');
  if (patch.logLine || logs.length) process.stdout.write((logs[logs.length - 1] || '') + '\n');
  return next;
}

const t0 = Date.now();

try {
  save({ status: 'running', progress: 5, stage: 'boot', logLine: 'Worker PureNode arrancado' });

  if (!fs.existsSync(inFile)) throw new Error('in.lua no encontrado');
  const source = fs.readFileSync(inFile, 'utf8');
  save({ progress: 15, stage: 'read', logLine: 'Fuente leída (' + source.length + ' bytes)' });

  save({ progress: 25, stage: 'obfuscate', logLine: 'Ofuscando modo=' + mode });

  const { obfuscate } = require('./obfuscate');
  const result = obfuscate(source, { mode, antiTamper });

  if (!result || typeof result.code !== 'string') {
    throw new Error('obfuscate no devolvió código');
  }

  save({
    progress: 85,
    stage: 'write',
    logLine: 'Capas: ' + (result.steps || []).join(' → '),
    steps: result.steps,
    antiTamper: !!result.antiTamper
  });

  fs.writeFileSync(outFile, result.code, 'utf8');

  save({
    status: 'done',
    progress: 100,
    stage: 'done',
    outPath: outFile,
    obfuscatedSize: result.code.length,
    steps: result.steps,
    antiTamper: !!result.antiTamper,
    mode: result.mode || mode,
    elapsedMs: Date.now() - t0,
    logLine: 'Listo (' + result.code.length + ' bytes, ' + (Date.now() - t0) + 'ms)'
  });

  process.exit(0);
} catch (e) {
  const msg = (e && e.message) ? e.message : String(e);
  try {
    save({
      status: 'error',
      progress: 100,
      stage: 'error',
      error: msg.slice(0, 1500),
      elapsedMs: Date.now() - t0,
      logLine: 'ERROR: ' + msg.slice(0, 200)
    });
  } catch (_) {}
  console.error(msg);
  process.exit(1);
}
