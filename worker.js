'use strict';
/**
 * QyrexOBF worker — MAX pipeline step-by-step with live progress
 * node worker.js <jobId> <inputPath> <metaPath>
 */
const fs = require('fs');
const path = require('path');

const jobId = process.argv[2];
const inputPath = process.argv[3];
const metaPath = process.argv[4];

function readMeta() {
  try { return JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (_) { return {}; }
}
function writeMeta(patch) {
  const cur = readMeta();
  const next = Object.assign({}, cur, patch, { updatedAt: Date.now() });
  fs.writeFileSync(metaPath, JSON.stringify(next), 'utf8');
  return next;
}
function log(line) {
  const cur = readMeta();
  const logs = Array.isArray(cur.logs) ? cur.logs.slice(-50) : [];
  const row = '[' + new Date().toISOString().slice(11, 19) + '] ' + line;
  logs.push(row);
  writeMeta({ logs: logs, lastLog: row });
  console.log(row);
}

const t0 = Date.now();
function elapsed() { return Date.now() - t0; }

try {
  writeMeta({ status: 'running', progress: 3, stage: 'boot', error: null, elapsedMs: 0 });
  log('Worker start · job ' + jobId);

  const obf = require('./obfuscate');
  const {
    findLua, getRoot, buildAntiTamper,
    runPrometheus, runHercules, runIB2
  } = obf;

  if (!findLua()) throw new Error('lua5.1 no encontrado');
  log('lua5.1: ' + findLua());
  writeMeta({ progress: 8, stage: 'extract-engines', elapsedMs: elapsed() });

  log('Extrayendo engines (solo la 1ª vez tarda)…');
  try {
    getRoot();
    log('Engines listos');
  } catch (e) {
    throw new Error('No se pudieron extraer engines: ' + (e.message || e));
  }
  writeMeta({ progress: 18, stage: 'read-source', elapsedMs: elapsed() });

  const source = fs.readFileSync(inputPath, 'utf8');
  log('Source: ' + source.length + ' bytes');

  let opts = { antiTamper: true };
  try {
    const m = readMeta();
    if (m.opts) opts = Object.assign(opts, m.opts);
  } catch (_) {}

  let code = source;
  const steps = [];

  // --- AntiTamper ---
  if (opts.antiTamper !== false) {
    writeMeta({ progress: 22, stage: 'antitamper', elapsedMs: elapsed() });
    log('AntiTamper v2…');
    try {
      const at = buildAntiTamper();
      code = at + '\n' + source;
      steps.push('AntiTamper:v2');
      log('AntiTamper OK');
    } catch (e) {
      log('AntiTamper skip: ' + (e.message || e));
      steps.push('AntiTamper:skip');
      code = source;
    }
  } else {
    steps.push('AntiTamper:off');
    log('AntiTamper desactivado');
  }

  // --- Prometheus Strong ---
  writeMeta({ progress: 30, stage: 'prometheus', elapsedMs: elapsed() });
  log('Prometheus Strong (puede tardar 30–120s)…');
  try {
    code = runPrometheus(code, 'Strong');
    steps.push('Prometheus:Strong');
    log('Prometheus Strong OK · ' + code.length + ' bytes');
  } catch (e1) {
    log('Strong falló: ' + String(e1.message || e1).slice(0, 200));
    writeMeta({ progress: 40, stage: 'prometheus-medium', elapsedMs: elapsed() });
    log('Reintento Prometheus Medium…');
    try {
      code = runPrometheus(code, 'Medium');
      steps.push('Prometheus:Medium');
      log('Prometheus Medium OK · ' + code.length + ' bytes');
    } catch (e2) {
      // last chance: original source without AT
      log('Medium falló, último intento con source limpio…');
      try {
        code = runPrometheus(source, 'Medium');
        steps.push('Prometheus:Medium:clean');
        log('Prometheus Medium (clean) OK');
      } catch (e3) {
        throw new Error('Prometheus falló: ' + String(e3.message || e3).slice(0, 500));
      }
    }
  }
  writeMeta({ progress: 60, stage: 'hercules', elapsedMs: elapsed(), steps });

  // --- Hercules ---
  log('Hercules…');
  try {
    code = runHercules(code);
    steps.push('Hercules');
    log('Hercules OK · ' + code.length + ' bytes');
  } catch (e) {
    steps.push('Hercules:skip');
    log('Hercules skip: ' + String(e.message || e).slice(0, 200));
  }
  writeMeta({ progress: 78, stage: 'ironbrew2', elapsedMs: elapsed(), steps });

  // --- IronBrew2 ---
  log('IronBrew2…');
  try {
    code = runIB2(code);
    steps.push('IronBrew2');
    log('IronBrew2 OK · ' + code.length + ' bytes');
  } catch (e) {
    steps.push('IronBrew2:skip');
    log('IronBrew2 skip: ' + String(e.message || e).slice(0, 200));
  }

  if (!code || typeof code !== 'string' || !code.length) {
    throw new Error('Sin output final');
  }

  const header = '--QyrexObf [qyrex.hopto.org]\n';
  if (!code.startsWith('--QyrexObf')) code = header + code;

  const outFile = path.join(path.dirname(inputPath), 'out.lua');
  fs.writeFileSync(outFile, code, 'utf8');

  writeMeta({
    status: 'done',
    progress: 100,
    stage: 'done',
    elapsedMs: elapsed(),
    steps,
    antiTamper: steps.indexOf('AntiTamper:v2') >= 0,
    originalSize: source.length,
    obfuscatedSize: code.length,
    outPath: outFile,
    error: null
  });
  log('DONE en ' + Math.round(elapsed() / 1000) + 's · ' + code.length + ' bytes · ' + steps.join(' → '));
  process.exit(0);
} catch (err) {
  const msg = String(err && (err.message || err)).slice(0, 2000);
  try {
    writeMeta({
      status: 'error',
      progress: 100,
      stage: 'error',
      error: msg,
      elapsedMs: elapsed()
    });
    log('ERROR: ' + msg);
  } catch (_) {}
  process.exit(1);
}
