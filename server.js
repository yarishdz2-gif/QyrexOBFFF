'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync, execSync } = require('child_process');

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.API_KEY || '';
const ROOT = __dirname;

const ENGINES = {
  prometheus: path.join(ROOT, 'engines', 'Prometheus-master'),
  ib2: path.join(ROOT, 'engines', 'ib2js', 'ib2js'),
  hercules: path.join(ROOT, 'engines', 'hercules-obfuscator-source', 'src'),
  moonsec: path.join(ROOT, 'engines', 'moonsec-source-code-ef1cf6388be2fdcb6dea2b9ea3f83bc64fe46169')
};

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Rate limit: max 20/min' }
}));

function requireKey(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers['x-api-key'] || req.query.key || (req.body && req.body.apiKey);
  if (key === API_KEY) return next();
  return res.status(401).json({ error: 'Invalid API key' });
}

function findLua() {
  for (const c of ['lua5.1', 'lua', 'lua5.2', 'lua5.3', 'lua5.4']) {
    try {
      const p = execSync('which ' + c, { encoding: 'utf8' }).trim();
      if (p) return p;
    } catch {}
  }
  return null;
}

function findLuac() {
  for (const c of ['luac5.1', 'luac']) {
    try {
      const p = execSync('which ' + c, { encoding: 'utf8' }).trim();
      if (p) return p;
    } catch {}
  }
  return null;
}

function runPrometheus(source, preset) {
  const lua = findLua();
  if (!lua) throw new Error('lua not installed (need lua5.1)');
  const dir = ENGINES.prometheus;
  if (!fs.existsSync(path.join(dir, 'cli.lua'))) {
    throw new Error('Prometheus engine missing');
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'prom-'));
  const input = path.join(tmp, 'in.lua');
  const output = path.join(tmp, 'out.lua');
  try {
    fs.writeFileSync(input, source, 'utf8');
    const safePreset = ['Minify', 'Weak', 'Medium', 'Strong'].includes(preset) ? preset : 'Strong';
    execFileSync(lua, [
      path.join(dir, 'cli.lua'),
      '--preset', safePreset,
      '--out', output,
      input
    ], {
      cwd: dir,
      timeout: 120000,
      maxBuffer: 20 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env }
    });
    if (!fs.existsSync(output)) throw new Error('Prometheus produced no output');
    return fs.readFileSync(output, 'utf8');
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
}

function runIB2(source, options = {}) {
  const luac = findLuac();
  if (!luac) throw new Error('luac not installed (need lua5.1)');
  const dir = ENGINES.ib2;
  const runJs = path.join(dir, 'run.js');
  if (!fs.existsSync(runJs)) throw new Error('IronBrew2 engine missing');

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ib2-'));
  const input = path.join(tmp, 'input.lua');
  const output = path.join(tmp, 'output.lua');
  try {
    fs.writeFileSync(input, source, 'utf8');
    const args = [runJs, input, output];
    if (options.encryptStrings) args.push('--encrypt-strings');
    if (options.noMinify) args.push('--no-minify');
    if (options.noControlFlow) args.push('--no-control-flow');
    execFileSync(process.execPath, args, {
      cwd: dir,
      timeout: 120000,
      maxBuffer: 20 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    if (!fs.existsSync(output)) throw new Error('IB2 produced no output');
    return fs.readFileSync(output, 'latin1');
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
}

function runHercules(source) {
  const lua = findLua();
  if (!lua) throw new Error('lua not installed');
  const dir = ENGINES.hercules;
  const entry = path.join(dir, 'hercules.lua');
  if (!fs.existsSync(entry)) throw new Error('Hercules engine missing');

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'herc-'));
  const input = path.join(tmp, 'in.lua');
  try {
    fs.writeFileSync(input, source, 'utf8');
    // Hercules writes next to input with suffix by default
    const out = execFileSync(lua, [entry, input], {
      cwd: dir,
      timeout: 120000,
      maxBuffer: 20 * 1024 * 1024,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    // Find generated file
    const candidates = fs.readdirSync(tmp).filter(f => f !== 'in.lua');
    if (candidates.length) {
      return fs.readFileSync(path.join(tmp, candidates[0]), 'utf8');
    }
    // Some versions print path
    const m = String(out).match(/([\/\w.-]+\.lua)/);
    if (m && fs.existsSync(m[1])) return fs.readFileSync(m[1], 'utf8');
    throw new Error('Hercules produced no output file. May need Lua 5.2+ (continue keyword).');
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
}

/**
 * engines:
 *  - prometheus (default Strong)
 *  - ib2
 *  - hercules
 *  - mega = prometheus Strong -> ib2 (máxima fuerza)
 */
function obfuscate(source, opts = {}) {
  const engine = String(opts.engine || 'mega').toLowerCase();
  const preset = opts.preset || 'Strong';

  if (engine === 'prometheus') {
    return { code: runPrometheus(source, preset), engine: 'prometheus', preset };
  }
  if (engine === 'ib2') {
    return { code: runIB2(source, opts), engine: 'ib2' };
  }
  if (engine === 'hercules') {
    return { code: runHercules(source), engine: 'hercules' };
  }
  // mega: Prometheus Strong then IronBrew2
  if (engine === 'mega' || engine === 'chain' || engine === 'max') {
    let code = runPrometheus(source, 'Strong');
    try {
      code = runIB2(code, { encryptStrings: true });
      return { code, engine: 'mega', steps: ['prometheus:Strong', 'ib2'] };
    } catch (e) {
      // if IB2 fails (no luac), still return prometheus
      return { code, engine: 'prometheus', preset: 'Strong', warning: 'IB2 skipped: ' + e.message };
    }
  }
  throw new Error('Unknown engine: ' + engine + ' (use prometheus|ib2|hercules|mega)');
}

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    lua: findLua(),
    luac: findLuac(),
    engines: {
      prometheus: fs.existsSync(path.join(ENGINES.prometheus, 'cli.lua')),
      ib2: fs.existsSync(path.join(ENGINES.ib2, 'run.js')),
      hercules: fs.existsSync(path.join(ENGINES.hercules, 'hercules.lua')),
      moonsec: fs.existsSync(ENGINES.moonsec)
    },
    uptime: process.uptime()
  });
});

app.post('/obfuscate', requireKey, (req, res) => {
  try {
    const source = (req.body && (req.body.source || req.body.code)) || '';
    if (!source || String(source).trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Missing source' });
    }
    if (source.length > 800000) {
      return res.status(400).json({ success: false, error: 'Source too large' });
    }
    const options = Object.assign({}, req.body.options || {}, {
      engine: (req.body.engine || (req.body.options && req.body.options.engine) || 'mega'),
      preset: (req.body.preset || (req.body.options && req.body.options.preset) || 'Strong')
    });
    const t0 = Date.now();
    const result = obfuscate(source, options);
    const ms = Date.now() - t0;
    res.json({
      success: true,
      timeMs: ms,
      originalSize: source.length,
      obfuscatedSize: result.code.length,
      engine: result.engine,
      steps: result.steps || null,
      warning: result.warning || null,
      code: result.code
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message || 'Obfuscation failed' });
  }
});

const indexPath = path.join(ROOT, 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.json({ service: 'Mega Lua Obfuscator', engines: ['prometheus', 'ib2', 'hercules', 'mega'] });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('Mega Obfuscator on :' + PORT);
  console.log('lua:', findLua(), 'luac:', findLuac());
});
