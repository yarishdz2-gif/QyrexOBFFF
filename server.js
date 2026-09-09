'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync, execSync } = require('child_process');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.API_KEY || ''; // optional protection

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 1.5 * 1024 * 1024 } // 1.5 MB
});

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded. Max 30 requests per minute.' }
});
app.use(limiter);

function requireApiKey(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers['x-api-key'] || req.query.key || (req.body && req.body.apiKey);
  if (key === API_KEY) return next();
  return res.status(401).json({ error: 'Invalid or missing API key' });
}

function findLuac() {
  try {
    const result = execSync('which luac || which luac5.1', { encoding: 'utf8' }).trim();
    if (result) return result.split('\n')[0];
  } catch {}
  const candidates = ['/usr/bin/luac', '/usr/bin/luac5.1', '/usr/local/bin/luac'];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function obfuscateLua(source, options = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ib2-'));
  const inputFile = path.join(tmpDir, 'input.lua');
  const outputFile = path.join(tmpDir, 'output.lua');
  const bytecodeFile = path.join(tmpDir, 'input.luac');

  try {
    fs.writeFileSync(inputFile, source, 'utf8');

    const luac = findLuac();
    if (!luac) {
      throw new Error('luac (Lua 5.1 compiler) not found on the server. Install lua5.1.');
    }

    // Compile to bytecode
    execFileSync(luac, ['-o', bytecodeFile, inputFile], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 15000
    });

    // Build CLI args for run.js
    const args = [inputFile, outputFile];
    if (options.noControlFlow) args.push('--no-control-flow');
    if (options.noMutate) args.push('--no-mutate');
    if (options.noSuperOps) args.push('--no-super-ops');
    if (options.noCompress) args.push('--no-compress');
    if (options.noMinify) args.push('--no-minify');
    if (options.encryptStrings) args.push('--encrypt-strings');
    if (options.preserveLines) args.push('--preserve-lines');

    // Call the IronBrew2 runner
    const runJs = path.join(__dirname, 'ib2', 'run.js');
    execFileSync(process.execPath, [runJs, ...args], {
      cwd: path.join(__dirname, 'ib2'),
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 60000,
      env: { ...process.env, PATH: process.env.PATH }
    });

    if (!fs.existsSync(outputFile)) {
      throw new Error('Obfuscation produced no output file');
    }

    const result = fs.readFileSync(outputFile, 'latin1');
    return result;
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
}

// Health
app.get('/', (req, res) => {
  res.json({
    service: 'IronBrew2 Obfuscator API',
    status: 'online',
    endpoints: {
      'POST /obfuscate': 'Body: { "source": "lua code", "options": {...} } or multipart file',
      'GET /health': 'Health check'
    },
    options: {
      noControlFlow: false,
      noMutate: false,
      noSuperOps: false,
      noCompress: false,
      noMinify: false,
      encryptStrings: false,
      preserveLines: false
    },
    note: API_KEY ? 'API key required (header x-api-key)' : 'No API key configured'
  });
});

app.get('/health', (req, res) => {
  const luac = findLuac();
  res.json({
    ok: true,
    luac: !!luac,
    luacPath: luac || null,
    uptime: process.uptime()
  });
});

// Main obfuscate endpoint (JSON)
app.post('/obfuscate', requireApiKey, async (req, res) => {
  try {
    let source = '';
    if (req.body && typeof req.body.source === 'string') {
      source = req.body.source;
    } else if (req.body && typeof req.body.code === 'string') {
      source = req.body.code;
    }

    if (!source || source.trim().length < 3) {
      return res.status(400).json({ error: 'Missing or empty "source" (Lua code)' });
    }
    if (source.length > 1.2 * 1024 * 1024) {
      return res.status(400).json({ error: 'Source too large (max ~1.2 MB)' });
    }

    const options = (req.body && req.body.options) || {};
    const start = Date.now();
    const obfuscated = obfuscateLua(source, options);
    const ms = Date.now() - start;

    res.json({
      success: true,
      timeMs: ms,
      originalSize: source.length,
      obfuscatedSize: obfuscated.length,
      code: obfuscated
    });
  } catch (err) {
    console.error('Obfuscate error:', err.message);
    res.status(500).json({
      success: false,
      error: err.message || 'Obfuscation failed'
    });
  }
});

// Also accept file upload
app.post('/obfuscate/file', requireApiKey, upload.single('file'), async (req, res) => {
  try {
    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ error: 'No file uploaded (field name: file)' });
    }
    const source = req.file.buffer.toString('utf8');
    if (source.length < 3) {
      return res.status(400).json({ error: 'Empty file' });
    }

    const options = {};
    if (req.body) {
      if (req.body.encryptStrings === 'true' || req.body.encryptStrings === true) options.encryptStrings = true;
      if (req.body.noMinify === 'true' || req.body.noMinify === true) options.noMinify = true;
      if (req.body.noControlFlow === 'true') options.noControlFlow = true;
    }

    const start = Date.now();
    const obfuscated = obfuscateLua(source, options);
    const ms = Date.now() - start;

    res.json({
      success: true,
      timeMs: ms,
      originalSize: source.length,
      obfuscatedSize: obfuscated.length,
      code: obfuscated
    });
  } catch (err) {
    console.error('Obfuscate file error:', err.message);
    res.status(500).json({ success: false, error: err.message || 'Obfuscation failed' });
  }
});

// Simple HTML UI for testing
app.get('/ui', (req, res) => {
  res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IronBrew2 Obfuscator</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; background: #0f0f12; color: #e4e4e7; margin: 0; padding: 24px; }
    h1 { font-size: 1.5rem; margin-bottom: 8px; }
    .sub { color: #a1a1aa; margin-bottom: 24px; }
    textarea { width: 100%; height: 220px; background: #18181b; border: 1px solid #27272a; color: #e4e4e7;
               border-radius: 10px; padding: 12px; font-family: ui-monospace, monospace; font-size: 13px; resize: vertical; }
    .row { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; align-items: center; }
    button { background: #7c3aed; color: white; border: none; padding: 10px 20px; border-radius: 8px;
             font-weight: 600; cursor: pointer; }
    button:hover { background: #6d28d9; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    label { display: flex; align-items: center; gap: 6px; font-size: 14px; color: #a1a1aa; }
    .status { margin-top: 12px; font-size: 14px; color: #a1a1aa; }
    .ok { color: #34d399; }
    .err { color: #f87171; }
  </style>
</head>
<body>
  <h1>IronBrew2 Lua Obfuscator</h1>
  <p class="sub">Paste your Lua / Luau script and click Obfuscate. Ready for Render.</p>
  <textarea id="src" placeholder="-- your lua code here&#10;print('hello')"></textarea>
  <div class="row">
    <label><input type="checkbox" id="enc"> Encrypt strings</label>
    <label><input type="checkbox" id="nominify"> No minify</label>
    <label><input type="checkbox" id="nocf"> No control-flow</label>
    <button id="btn" onclick="run()">Obfuscate</button>
  </div>
  <div class="status" id="st"></div>
  <textarea id="out" placeholder="Obfuscated output will appear here..." readonly style="margin-top:12px;height:280px"></textarea>
  <script>
    async function run() {
      const btn = document.getElementById('btn');
      const st = document.getElementById('st');
      const src = document.getElementById('src').value;
      if (!src.trim()) { st.className = 'status err'; st.textContent = 'Empty source'; return; }
      btn.disabled = true; st.className = 'status'; st.textContent = 'Obfuscating...';
      try {
        const body = {
          source: src,
          options: {
            encryptStrings: document.getElementById('enc').checked,
            noMinify: document.getElementById('nominify').checked,
            noControlFlow: document.getElementById('nocf').checked
          }
        };
        const r = await fetch('/obfuscate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        const data = await r.json();
        if (!data.success) throw new Error(data.error || 'Failed');
        document.getElementById('out').value = data.code;
        st.className = 'status ok';
        st.textContent = 'OK — ' + data.timeMs + ' ms | ' + data.originalSize + ' → ' + data.obfuscatedSize + ' bytes';
      } catch (e) {
        st.className = 'status err';
        st.textContent = e.message || String(e);
      } finally {
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>`);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`IronBrew2 Obfuscator API listening on 0.0.0.0:${PORT}`);
  console.log('luac available:', !!findLuac());
  console.log('API_KEY set:', !!API_KEY);
});
