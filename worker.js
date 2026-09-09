'use strict';
/**
 * QyrexOBF worker — runs MAX obfuscation in a child process
 * so the HTTP server stays alive (no 502 / poll vacío).
 *
 * Usage: node worker.js <jobId> <inputPath> <metaPath>
 * Reads input lua from inputPath, writes progress to metaPath JSON,
 * writes final code to sibling out.lua
 */
const fs = require('fs');
const path = require('path');

const jobId = process.argv[2];
const inputPath = process.argv[3];
const metaPath = process.argv[4];

function writeMeta(patch) {
  let cur = {};
  try { cur = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (_) {}
  const next = Object.assign({}, cur, patch, { updatedAt: Date.now() });
  fs.writeFileSync(metaPath, JSON.stringify(next), 'utf8');
}

function log(line) {
  let cur = {};
  try { cur = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (_) {}
  const logs = Array.isArray(cur.logs) ? cur.logs.slice(-40) : [];
  logs.push('[' + new Date().toISOString().slice(11, 19) + '] ' + line);
  writeMeta({ logs: logs, lastLog: line });
  console.log('[worker]', line);
}

try {
  writeMeta({ status: 'running', progress: 5, stage: 'boot', error: null });
  log('Worker arrancado · job ' + jobId);

  const { obfuscate, findLua, getRoot } = require('./obfuscate');

  if (!findLua()) {
    throw new Error('lua5.1 no encontrado en el worker');
  }
  log('lua5.1 OK');
  writeMeta({ progress: 10, stage: 'extract-engines' });

  try {
    getRoot();
    log('Engines listos');
  } catch (e) {
    log('Extract engines: ' + (e.message || e));
  }

  writeMeta({ progress: 15, stage: 'read-source' });
  const source = fs.readFileSync(inputPath, 'utf8');
  log('Source leído · ' + source.length + ' bytes');

  // Patch progress by monkey-wrapping is hard; we report stages around obfuscate
  writeMeta({ progress: 25, stage: 'max-pipeline' });
  log('MAX pipeline: AntiTamper → Prometheus Strong → Hercules → IronBrew2');

  const t0 = Date.now();
  // opts from meta
  let opts = { antiTamper: true, mode: 'max' };
  try {
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    if (meta.opts) opts = Object.assign(opts, meta.opts);
  } catch (_) {}

  // Heartbeat while obfuscate runs (sync) — update progress slowly
  const beat = setInterval(() => {
    try {
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      let p = typeof meta.progress === 'number' ? meta.progress : 25;
      if (p < 85) p += 2;
      writeMeta({
        progress: p,
        stage: 'max-pipeline',
        elapsedMs: Date.now() - t0
      });
    } catch (_) {}
  }, 2000);

  let result;
  try {
    result = obfuscate(source, opts);
  } finally {
    clearInterval(beat);
  }

  if (!result || typeof result.code !== 'string' || !result.code.length) {
    throw new Error('Sin output del ofuscador');
  }

  const outPath = path.join(path.dirname(inputPath), 'out.lua');
  fs.writeFileSync(outPath, result.code, 'utf8');

  writeMeta({
    status: 'done',
    progress: 100,
    stage: 'done',
    elapsedMs: Date.now() - t0,
    steps: result.steps || [],
    antiTamper: !!result.antiTamper,
    originalSize: source.length,
    obfuscatedSize: result.code.length,
    outPath: outPath,
    error: null
  });
  log('DONE · ' + result.code.length + ' bytes · ' + (Date.now() - t0) + 'ms · ' + (result.steps || []).join(' → '));
  process.exit(0);
} catch (err) {
  const msg = String(err && (err.message || err)).slice(0, 2000);
  try {
    writeMeta({ status: 'error', progress: 100, stage: 'error', error: msg });
    log('ERROR · ' + msg);
  } catch (_) {}
  process.exit(1);
}
