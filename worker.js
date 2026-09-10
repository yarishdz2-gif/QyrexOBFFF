'use strict';
// node worker.js <jobDir>
const fs = require('fs');
const path = require('path');

const jobDir = process.argv[2];
if (!jobDir) {
  console.error('usage: worker.js <jobDir>');
  process.exit(2);
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
  save({ status: 'running', progress: 5, stage: 'boot', logLine: 'Worker hijo arrancado' });

  const {
    findLua, getRoot, buildAntiTamper,
    runPrometheus, runHercules, runIB2
  } = require('./obfuscate');

  if (!findLua()) throw new Error('lua5.1 no encontrado');
  save({ progress: 8, stage: 'extract-engines', logLine: 'lua OK: ' + findLua() });

  save({ progress: 12, logLine: 'Cargando engines…' });
  const eng = getRoot();
  save({ progress: 20, stage: 'read-source', logLine: 'Engines OK · ' + eng });

  const source = fs.readFileSync(inFile, 'utf8');
  save({ progress: 22, logLine: 'Source ' + source.length + ' bytes' });

  const meta0 = readMeta();
  const opts = (meta0 && meta0.opts) || { antiTamper: true };

  let code = source;
  const steps = [];

  if (opts.antiTamper !== false) {
    save({ progress: 25, stage: 'antitamper', logLine: 'AntiTamper v2…' });
    try {
      code = buildAntiTamper() + '\n' + source;
      steps.push('AntiTamper:v2');
      save({ progress: 28, logLine: 'AntiTamper OK' });
    } catch (e) {
      code = source;
      steps.push('AntiTamper:skip');
      save({ progress: 28, logLine: 'AntiTamper skip' });
    }
  }

  save({ progress: 32, stage: 'prometheus', logLine: 'Prometheus MAX… (Encrypt+Split+Proxy+VM+Constants)' });
  try {
    code = runPrometheus(code, 'Strong');
    steps.push('Prometheus:Strong');
    save({ progress: 58, logLine: 'Prometheus Strong OK · ' + code.length + ' B' });
  } catch (e1) {
    save({ progress: 40, stage: 'prometheus-medium', logLine: 'Strong falló → Medium…' });
    try {
      code = runPrometheus(code, 'Medium');
      steps.push('Prometheus:Medium');
      save({ progress: 58, logLine: 'Prometheus Medium OK' });
    } catch (e2) {
      code = runPrometheus(source, 'Medium');
      steps.push('Prometheus:Medium:clean');
      save({ progress: 58, logLine: 'Prometheus Medium clean OK' });
    }
  }

  save({ progress: 65, stage: 'hercules', logLine: 'Hercules --maximum…' });
  try {
    code = runHercules(code);
    steps.push('Hercules');
    save({ progress: 80, logLine: 'Hercules OK · ' + code.length + ' B' });
  } catch (e) {
    steps.push('Hercules:skip');
    save({ progress: 80, logLine: 'Hercules skip' });
  }

  save({ progress: 85, stage: 'ironbrew2', logLine: 'IronBrew2… (máx ~75s, si tarda se salta)' });
  try {
    code = runIB2(code);
    steps.push('IronBrew2');
    save({ progress: 95, logLine: 'IronBrew2 OK · ' + code.length + ' B' });
  } catch (e) {
    steps.push('IronBrew2:skip');
    save({ progress: 95, logLine: 'IronBrew2 skip (timeout o error) · seguimos con output actual' });
  }

  if (!code || !String(code).length) throw new Error('Sin output');
  const header = '--QyrexObf [qyrex.hopto.org]\n';
  if (!String(code).startsWith('--QyrexObf')) code = header + code;

  fs.writeFileSync(outFile, code, 'utf8');
  // Do NOT put full code in meta (can be huge) — server reads out.lua
  save({
    status: 'done',
    progress: 100,
    stage: 'done',
    steps,
    antiTamper: steps.indexOf('AntiTamper:v2') >= 0,
    originalSize: source.length,
    obfuscatedSize: code.length,
    elapsedMs: Date.now() - t0,
    outPath: outFile,
    logLine: 'DONE en ' + Math.round((Date.now() - t0) / 1000) + 's · ' + steps.join(' → ')
  });
  process.exit(0);
} catch (err) {
  let msg = String(err && (err.message || err)).slice(0, 2000);
  const code = err && err.code;
  if (code === 'ETIMEDOUT' || /ETIMEDOUT|timed out|timeout/i.test(msg)) {
    msg = 'Timeout de engine (Prometheus/Hercules/IB2). Script muy pesado o host lento. Prueba sin AntiTamper o un script más corto. Detalle: ' + msg.slice(0, 400);
  } else if (code === 'ENOMEM' || /heap|out of memory|ENOMEM/i.test(msg)) {
    msg = 'Sin memoria (OOM). Sube el plan o reduce tamaño del script. ' + msg.slice(0, 300);
  }
  try {
    save({
      status: 'error',
      progress: 100,
      stage: 'error',
      error: msg,
      elapsedMs: Date.now() - t0,
      logLine: 'ERROR: ' + msg
    });
  } catch (_) {}
  process.exit(1);
}
