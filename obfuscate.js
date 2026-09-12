'use strict';
/**
 * QyrexOBF Pure Node v11.2
 * Output: return({...})["x"]() + watermark
 * 100% Node — fixed encode/decode + Luau-safe literals
 */

const crypto = require('crypto');

function rnd(n) {
  return crypto.randomBytes(4).readUInt32BE(0) % (n || 0xffffffff);
}
function rndInt(a, b) {
  return a + (rnd(b - a + 1));
}
function rndHexName() {
  const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
  return a[rndInt(0, a.length - 1)] + a[rndInt(0, a.length - 1)];
}
function toLuaNum(n) {
  // Only decimal + hex (no 0B) — safe on Luau and Lua 5.1
  const r = rndInt(0, 3);
  if (r === 0) return '0x' + n.toString(16);
  if (r === 1) return '0X' + n.toString(16).toUpperCase();
  return String(n);
}

// CRITICAL: 1-based index must match Lua decode loop `for I=1,#C`
function encodeStr(str, key) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    const I = i + 1; // 1-based, same as Lua
    const ki = (key * ((I % 11) + 1) + I * 7 + (key % 31)) % 256;
    out.push((str.charCodeAt(i) + ki) % 256);
  }
  return out;
}

function minifyLua(s) {
  return String(s)
    .replace(/--\[\[[\s\S]*?\]\]/g, '')
    .replace(/--[^\n]*/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n+/g, '\n')
    .trim();
}

function buildLightAT() {
  return 'do local function _c()local t while true do t={t}end end if type(game)~="userdata"then _c()end end';
}

function buildVmPayload(source) {
  const key = rndInt(17, 240);
  const bytes = encodeStr(source, key);
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
    wrap: rndHexName(),
    x: 'x'
  };

  const parts = [];

  // bit32.rrotate alias (Luau-safe arithmetic fallback, no >> <<)
  parts.push(
    `${N.rot}=bit32 and bit32.rrotate or function(a,b)b=b%32 local c=4294967296 a=a%c local d=2^b return((a-a%d)/d+(a*2^(32-b))%c)%c end`
  );

  // decrypt — MUST match encodeStr 1-based formula
  parts.push(
    `${N.dec}=function(y,C,f)local l={}for I=1,#C do local M=(f*((I%11)+1)+I*7+(f%31))%256 l[I]=string.char((C[I]-M+512)%256)end return table.concat(l)end`
  );

  // dummy VM ops (style only)
  parts.push(`${N.set}=function(y,y,C,f)y[C]=C-f end`);
  parts.push(
    `${N.get}=function(y,C,f,l,I,M)local c if M<=0X5f then if not(M<0x5f)then else end else c,C,f,l=y.${N.wrap}(M,I,f,l,C) if c==${toLuaNum(rndInt(20000, 50000))} then return C,l,${toLuaNum(rndInt(10000, 40000))},f else if c~=${toLuaNum(rndInt(10000, 40000))} then else return C,l,${toLuaNum(rndInt(10000, 40000))},f end end end return C,l,nil,f end`
  );
  parts.push(
    `${N.load}=function(y,y,C,f,l)(C[${toLuaNum(rndInt(1, 9))}])[f+1]=(y)l=${toLuaNum(rndInt(0x40, 0xff))} return l end`
  );
  parts.push(`${N.ep}=function(y,y,C)y=C[${toLuaNum(rndInt(20, 45))}]() return y end`);

  // payload chunks
  const chunkNames = [];
  for (let i = 0; i < chunks.length; i++) {
    const cn = rndHexName() + i;
    chunkNames.push(cn);
    parts.push(`${cn}={${chunks[i].map(toLuaNum).join(',')}}`);
  }

  // runner: concat chunks → decrypt → loadstring → call
  // Use getfenv/setfenv when available so game/workspace resolve inside payload
  const concatLoops = chunkNames
    .map((cn) => `for I=1,#y.${cn} do C[#C+1]=y.${cn}[I] end`)
    .join(' ');
  parts.push(
    `${N.run}=function(y)local C={}local f=${key} ${concatLoops} local l=y.${N.dec}(y,C,f)local I=(loadstring or load)local M=I(l)if not M then error("protected")end if setfenv and getfenv then pcall(setfenv,M,getfenv(0))end return M()end`
  );

  parts.push(`${N.wrap}=function(y,C,f,l,I)return ${toLuaNum(rndInt(10000, 50000))},C,f,l end`);
  parts.push(`${N.x}=function(y)return y.${N.run}(y)end`);

  const tableBody = parts.join(',');
  const watermark =
    '-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]';

  return watermark + '\n' + `return({${tableBody}})["x"]()`;
}

function obfuscate(source, opts) {
  opts = opts || {};
  const mode = String(opts.mode || 'max').toLowerCase();
  const wantAT = opts.antiTamper !== false;
  const steps = [];
  let src = minifyLua(String(source || ''));

  if (!src) {
    return {
      code:
        '-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]\nreturn({x=function()end})["x"]()',
      engine: 'QyrexOBF-PureNode',
      steps: ['empty'],
      antiTamper: false,
      mode
    };
  }

  if (wantAT && (mode === 'max' || mode === 'strong')) {
    src = buildLightAT() + '\n' + src;
    steps.push('AntiTamper');
  }

  let code;
  try {
    code = buildVmPayload(src);
    steps.push('VM-Pack', 'StringEncrypt', 'DenseReturn');
  } catch (e) {
    const key = rndInt(20, 200);
    const bytes = encodeStr(src, key);
    code =
      '-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]\n' +
      `return(function(y,C)local f={}for l=1,#C do f[l]=string.char((C[l]-((y*((l%11)+1)+l*7+(y%31))%256)+512)%256)end local I=(loadstring or load)(table.concat(f))if not I then error("protected")end if setfenv and getfenv then pcall(setfenv,I,getfenv(0))end return I()end)(${key},{${bytes.join(',')}})`;
    steps.push('Fallback-Pack');
  }

  return {
    code,
    engine: 'QyrexOBF-PureNode',
    steps,
    antiTamper: wantAT && steps.includes('AntiTamper'),
    mode
  };
}

function buildAntiTamper() {
  return buildLightAT();
}
function getRoot() { return process.cwd(); }
function findLua() { return null; }
function findLua54() { return null; }
function findLuac() { return null; }
function runPrometheus() { throw new Error('Pure Node: external engines disabled'); }
function runHercules() { throw new Error('Pure Node: external engines disabled'); }
function runIB2() { throw new Error('Pure Node: external engines disabled'); }

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
