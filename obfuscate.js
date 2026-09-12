'use strict';
/**
 * QyrexOBF Pure Node — Luau (Roblox)
 * NO full-script loadstring (that breaks game/executor APIs).
 * Keeps code in the same chunk so everything works like the original.
 * Strings XOR-encrypted + junk + safe AT + messy look.
 */

const crypto = require('crypto');

function rndInt(a, b) {
  return a + (crypto.randomBytes(4).readUInt32BE(0) % (b - a + 1));
}
function rndName(len) {
  const a = 'IlO01abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ';
  let s = a[rndInt(10, a.length - 1)];
  for (let i = 1; i < (len || rndInt(6, 12)); i++) s += a[rndInt(0, a.length - 1)];
  return '_' + s;
}
function rndHexName() {
  const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
  return a[rndInt(0, a.length - 1)] + a[rndInt(0, a.length - 1)];
}

function xorEncode(str, key) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    const I = i + 1;
    const k = (key * ((I % 11) + 1) + I * 7 + (key % 31)) % 256;
    out.push(str.charCodeAt(i) ^ k);
  }
  return out;
}

function escapeLuaString(s) {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/\0/g, '\\0');
}

// SAFE AT — no executor bans, no hard service checks
function buildAntiTamper() {
  return [
    'do',
    'local function __qc() local t while true do t={t} end end',
    'local G=_G or {}',
    'local BAD={"lune","lute","darklua","selene","rojo","wally","process","window","document","__dirname","__filename"}',
    'for i=1,#BAD do if rawget(G,BAD[i])~=nil then __qc() end end',
    'if type(rawget(G,"process"))=="table" then __qc() end',
    'if string.byte("A")~=65 or math.floor(3.9)~=3 then __qc() end',
    'do local n=0/0 if n==n then __qc() end end',
    'end'
  ].join('\n');
}

// Decrypt helper injected once
function buildXorDecoder(fnName) {
  return [
    `local function ${fnName}(C,f)`,
    `local l={}`,
    `for I=1,#C do`,
    `local M=(f*((I%11)+1)+I*7+(f%31))%256`,
    `l[I]=string.char(bit32.bxor(C[I],M))`,
    `end`,
    `return table.concat(l)`,
    `end`
  ].join('\n');
}

/**
 * Encrypt string literals only — rest of script stays real Luau in same chunk.
 * This is why print AND game:GetService AND executor APIs all work.
 */
function encryptStringsInSource(source) {
  const key = rndInt(17, 240);
  const decName = rndName(8);
  const strings = [];

  // Match "..." and '...' strings (simple, non-nested; skips long [[ ]])
  // Avoid matching inside comments already stripped
  let code = source;

  // Double-quoted
  code = code.replace(/"(?:\\.|[^"\\])*"/g, (match) => {
    if (match.length <= 2) return match;
    let raw;
    try {
      raw = match.slice(1, -1)
        .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
        .replace(/\\"/g, '"').replace(/\\'/g, "'").replace(/\\\\/g, '\\')
        .replace(/\\0/g, '\0');
    } catch {
      return match;
    }
    if (raw.length < 1) return match;
    const bytes = xorEncode(raw, key);
    const idx = strings.length;
    strings.push(bytes);
    return `${decName}({${bytes.join(',')}},${key})`;
  });

  // Single-quoted
  code = code.replace(/'(?:\\.|[^'\\])*'/g, (match) => {
    if (match.length <= 2) return match;
    // skip if this looks like it was already replaced area - still ok
    let raw;
    try {
      raw = match.slice(1, -1)
        .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
        .replace(/\\"/g, '"').replace(/\\'/g, "'").replace(/\\\\/g, '\\')
        .replace(/\\0/g, '\0');
    } catch {
      return match;
    }
    if (raw.length < 1) return match;
    const bytes = xorEncode(raw, key);
    const idx = strings.length;
    strings.push(bytes);
    return `${decName}({${bytes.join(',')}},${key})`;
  });

  if (strings.length === 0) {
    return { code: source, header: '', used: false };
  }

  const header = buildXorDecoder(decName);
  return { code, header, used: true, key, count: strings.length };
}

function injectJunk(source) {
  const lines = source.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    out.push(lines[i]);
    if (lines[i].trim() && rndInt(0, 10) === 0) {
      const a = rndName(5);
      const b = rndInt(1, 99);
      out.push(`do local ${a}=${b} if ${a}<0 then error("x") end end`);
    }
  }
  return out.join('\n');
}

function numbersToExpr(source) {
  return source.replace(/\b([2-9]\d{1,5})\b/g, (m, num) => {
    if (rndInt(0, 3) !== 0) return m;
    const n = parseInt(num, 10);
    const a = rndInt(1, Math.min(n - 1, 50));
    return `(${a}+${n - a})`;
  });
}

function wrapMessy(body) {
  const t = rndHexName();
  const r = rndHexName();
  const lines = [];
  lines.push('-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]');
  lines.push('-- Target: Luau (Roblox)');
  lines.push(`local ${t}={`);
  lines.push(`  ${r}=bit32.rrotate,`);
  lines.push(`  a=function(self,y,C,f) y[C]=C-f end,`);
  lines.push(`  b=function(self,C,f,l,I,M) if M<=0x5f then else end return C,l,nil,f end,`);
  lines.push(`}`);
  lines.push(`do local _=${t}.${r} end`);
  lines.push(body);
  return lines.join('\n');
}

function lightMinify(s) {
  return String(s)
    .replace(/--\[\[[\s\S]*?\]\]/g, '')
    .replace(/--(?!\[)[^\n]*/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n /g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function obfuscate(source, opts) {
  opts = opts || {};
  const mode = String(opts.mode || 'max').toLowerCase();
  const wantAT = opts.antiTamper !== false;
  const steps = [];
  let src = lightMinify(String(source || ''));

  if (!src) {
    return {
      code: '-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]\nreturn nil',
      engine: 'QyrexOBF-PureNode-Luau',
      steps: ['empty'],
      antiTamper: false,
      mode
    };
  }

  const parts = [];

  if (wantAT) {
    parts.push(buildAntiTamper());
    steps.push('AntiTamper:safe');
  }

  // String encryption (same chunk — NO loadstring of whole script)
  const enc = encryptStringsInSource(src);
  if (enc.used) {
    parts.push(enc.header);
    src = enc.code;
    steps.push('StringXOR:' + enc.count);
  }

  if (mode === 'max' || mode === 'strong') {
    src = numbersToExpr(src);
    steps.push('Numbers');
  }

  if (mode === 'max') {
    src = injectJunk(src);
    steps.push('Junk');
  }

  parts.push(src);
  let code = parts.join('\n');

  if (mode === 'max') {
    code = wrapMessy(code);
    steps.push('MessyWrap');
  } else {
    code =
      '-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]\n' +
      '-- Target: Luau (Roblox)\n' +
      code;
  }

  return {
    code,
    engine: 'QyrexOBF-PureNode-Luau',
    steps,
    antiTamper: wantAT,
    mode
  };
}

function buildAntiTamper() {
  return buildAntiTamperSafe();
}
function buildAntiTamperSafe() {
  return [
    'do',
    'local function __qc() local t while true do t={t} end end',
    'local G=_G or {}',
    'local BAD={"lune","lute","darklua","selene","process","window","document","__dirname"}',
    'for i=1,#BAD do if rawget(G,BAD[i])~=nil then __qc() end end',
    'if string.byte("A")~=65 then __qc() end',
    'end'
  ].join('\n');
}

function getRoot() { return process.cwd(); }
function findLua() { return null; }
function findLua54() { return null; }
function findLuac() { return null; }
function runPrometheus() { throw new Error('Pure Node'); }
function runHercules() { throw new Error('Pure Node'); }
function runIB2() { throw new Error('Pure Node'); }

module.exports = {
  obfuscate,
  getRoot,
  findLua,
  findLua54,
  findLuac,
  runPrometheus,
  runHercules,
  runIB2,
  buildAntiTamper
};
