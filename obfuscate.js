'use strict';
/**
 * QyrexOBF Pure Node — Luau (Roblox) target
 * XOR pack + messy VM look + safe AT
 * No setfenv/getfenv (Luau). Uses bit32.
 */

const crypto = require('crypto');

function rndInt(a, b) {
  return a + (crypto.randomBytes(4).readUInt32BE(0) % (b - a + 1));
}
function rndHexName() {
  const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
  return a[rndInt(0, a.length - 1)] + a[rndInt(0, a.length - 1)];
}
function toLuaNum(n) {
  const r = rndInt(0, 2);
  if (r === 0) return '0x' + n.toString(16);
  if (r === 1) return '0X' + n.toString(16).toUpperCase();
  return String(n);
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

function minifyLuau(s) {
  return String(s)
    .replace(/--\[\[[\s\S]*?\]\]/g, '')
    .replace(/--[^\n]*/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n+/g, '\n')
    .trim();
}

// Safe AT for Luau executors (does NOT ban syn/getgenv/krnl/etc.)
function buildAntiTamper() {
  return [
    'do',
    '  local function _crash() local t while true do t={t} end end',
    '  local G=getfenv and getfenv(0) or _G or {}',
    '  local BAD={"lune","lute","wally","rojo","selene","darklua","remodel","tarmac","stylua","lemur","busted","process","window","document","navigator","localStorage","globalThis","__dirname","__filename","js"}',
    '  for i=1,#BAD do',
    '    if rawget(G,BAD[i])~=nil then _crash() end',
    '  end',
    '  if type(rawget(G,"process"))=="table" then _crash() end',
    '  if string.byte("A")~=65 or math.floor(3.9)~=3 then _crash() end',
    '  do local n=0/0 if n==n then _crash() end end',
    'end'
  ].join('\n');
}

function buildPacked(source) {
  const key = rndInt(17, 240);
  const bytes = xorEncode(source, key);

  const chunkSize = rndInt(10, 16);
  const chunks = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    chunks.push(bytes.slice(i, i + chunkSize));
  }

  const N = {
    rot: rndHexName(),
    dec: rndHexName(),
    set: rndHexName(),
    get: rndHexName(),
    load: rndHexName(),
    ep: rndHexName(),
    run: rndHexName(),
    wrap: rndHexName()
  };

  const lines = [];
  lines.push('-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]');
  lines.push('-- Target: Luau (Roblox)');
  lines.push('local _Q = {');

  // bit32 is always present in Roblox Luau
  lines.push(`  ${N.rot} = bit32.rrotate,`);

  // XOR decrypt using bit32.bxor (Luau)
  lines.push(`  ${N.dec} = function(self, C, f)`);
  lines.push(`    local l = {}`);
  lines.push(`    for I = 1, #C do`);
  lines.push(`      local M = (f * ((I % 11) + 1) + I * 7 + (f % 31)) % 256`);
  lines.push(`      l[I] = string.char(bit32.bxor(C[I], M))`);
  lines.push(`    end`);
  lines.push(`    return table.concat(l)`);
  lines.push(`  end,`);

  lines.push(`  ${N.set} = function(self, y, C, f) y[C] = C - f end,`);

  lines.push(`  ${N.get} = function(self, C, f, l, I, M)`);
  lines.push(`    local c`);
  lines.push(`    if M <= 0x5f then`);
  lines.push(`      if not (M < 0x5f) then else end`);
  lines.push(`    else`);
  lines.push(`      c, C, f, l = self.${N.wrap}(M, I, f, l, C)`);
  lines.push(`      if c == ${toLuaNum(rndInt(20000, 50000))} then`);
  lines.push(`        return C, l, ${toLuaNum(rndInt(10000, 40000))}, f`);
  lines.push(`      elseif c == ${toLuaNum(rndInt(10000, 40000))} then`);
  lines.push(`        return C, l, ${toLuaNum(rndInt(10000, 40000))}, f`);
  lines.push(`      end`);
  lines.push(`    end`);
  lines.push(`    return C, l, nil, f`);
  lines.push(`  end,`);

  lines.push(`  ${N.load} = function(self, y, C, f, l)`);
  lines.push(`    C[${toLuaNum(rndInt(1, 9))}][f + 1] = y`);
  lines.push(`    return ${toLuaNum(rndInt(0x40, 0xff))}`);
  lines.push(`  end,`);

  lines.push(`  ${N.ep} = function(self, y, C)`);
  lines.push(`    return C[${toLuaNum(rndInt(20, 45))}]()`);
  lines.push(`  end,`);

  const chunkNames = [];
  for (let i = 0; i < chunks.length; i++) {
    const cn = rndHexName() + i;
    chunkNames.push(cn);
    lines.push(`  ${cn} = {${chunks[i].map(toLuaNum).join(',')}},`);
  }

  lines.push(`  ${N.wrap} = function(self, C, f, l, I)`);
  lines.push(`    return ${toLuaNum(rndInt(10000, 50000))}, C, f, l`);
  lines.push(`  end,`);

  // runner — Luau: loadstring provided by executors; no setfenv
  lines.push(`  ${N.run} = function(self)`);
  lines.push(`    local C = {}`);
  lines.push(`    local f = ${key}`);
  for (const cn of chunkNames) {
    lines.push(`    for I = 1, #self.${cn} do`);
    lines.push(`      C[#C + 1] = self.${cn}[I]`);
    lines.push(`    end`);
  }
  lines.push(`    local src = self.${N.dec}(self, C, f)`);
  lines.push(`    local fn = loadstring(src)`);
  lines.push(`    if type(fn) ~= "function" then`);
  lines.push(`      error("protected", 0)`);
  lines.push(`    end`);
  lines.push(`    return fn()`);
  lines.push(`  end`);

  lines.push('}');
  // FIXED: pass table (no nil self)
  lines.push(`return _Q.${N.run}(_Q)`);

  return lines.join('\n');
}

function obfuscate(source, opts) {
  opts = opts || {};
  const mode = String(opts.mode || 'max').toLowerCase();
  const wantAT = opts.antiTamper !== false;
  const steps = [];
  let src = minifyLuau(String(source || ''));

  if (!src) {
    return {
      code: '-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]\nreturn nil',
      engine: 'QyrexOBF-PureNode-Luau',
      steps: ['empty'],
      antiTamper: false,
      mode
    };
  }

  if (wantAT) {
    src = buildAntiTamper() + '\n' + src;
    steps.push('AntiTamper:safe');
  }

  const code = buildPacked(src);
  steps.push('XOR', 'VM-Pack-Luau');

  return {
    code,
    engine: 'QyrexOBF-PureNode-Luau',
    steps,
    antiTamper: wantAT,
    mode
  };
}

function getRoot() { return process.cwd(); }
function findLua() { return null; }
function findLua54() { return null; }
function findLuac() { return null; }
function runPrometheus() { throw new Error('Pure Node Luau build'); }
function runHercules() { throw new Error('Pure Node Luau build'); }
function runIB2() { throw new Error('Pure Node Luau build'); }

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
