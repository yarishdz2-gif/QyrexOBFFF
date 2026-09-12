'use strict';
/**
 * QyrexOBF Pure Node — XOR pack, messy VM look, SAFE anti-tamper
 * Does NOT ban real executors (syn/getgenv/krnl/etc are allowed)
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

function minifyLua(s) {
  return String(s)
    .replace(/--\[\[[\s\S]*?\]\]/g, '')
    .replace(/--[^\n]*/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n+/g, '\n')
    .trim();
}

/**
 * SAFE AntiTamper:
 * - Blocks analysis tools / fake envs (lune, darklua, node, browser)
 * - Does NOT block real executors (syn, getgenv, krnl, fluxus, etc.)
 * - Soft game checks only when game exists
 */
function buildAntiTamper() {
  return [
    'do',
    'local function _crash() local t while true do t={t} end end',
    'local G=_G or (getfenv and getfenv(0)) or {}',
    // only analysis / non-roblox tools — NOT executor APIs
    'local BAD={"lune","lute","wally","rojo","selene","darklua","remodel","tarmac","stylua","lemur","busted","process","window","document","navigator","localStorage","globalThis","__dirname","__filename","js"}',
    'for i=1,#BAD do if rawget(G,BAD[i])~=nil then _crash() end end',
    'if type(G.process)=="table" and (G.process.env or G.process.platform) then _crash() end',
    // basic integrity (safe)
    'if string.byte("A")~=65 or math.floor(3.9)~=3 then _crash() end',
    'do local n=0/0 if n==n then _crash() end end',
    'do local ok=_pcall or pcall local e=_error or error local okE=ok(e,"x",0) if okE then _crash() end end',
    // soft roblox presence (only if game is present; do not hard-require services)
    'if game~=nil then',
    'if type(game)~="userdata" and type(game)~="table" then _crash() end',
    'end',
    'end'
  ].join(' ');
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

  const parts = [];

  // messy VM-style helpers
  parts.push(
    `${N.rot}=bit32 and bit32.rrotate or function(a,b)b=b%32 local c=4294967296 a=a%c local d=2^b return((a-a%d)/d+(a*2^(32-b))%c)%c end`
  );

  // pure XOR (bit32.bxor or portable)
  parts.push(
    `${N.dec}=function(y,C,f)local bxor=bit32 and bit32.bxor or function(a,b)local r,v=0,1 while a>0 or b>0 do local ab,bb=a%2,b%2 if ab~=bb then r=r+v end a,b,v=(a-ab)/2,(b-bb)/2,v*2 end return r end local l={} for I=1,#C do local M=(f*((I%11)+1)+I*7+(f%31))%256 l[I]=string.char(bxor(C[I],M)) end return table.concat(l) end`
  );

  parts.push(`${N.set}=function(y,y,C,f)y[C]=C-f end`);
  parts.push(
    `${N.get}=function(y,C,f,l,I,M)local c if M<=0X5f then if not(M<0x5f)then else end else c,C,f,l=y.${N.wrap}(M,I,f,l,C) if c==${toLuaNum(rndInt(20000, 50000))} then return C,l,${toLuaNum(rndInt(10000, 40000))},f else if c~=${toLuaNum(rndInt(10000, 40000))} then else return C,l,${toLuaNum(rndInt(10000, 40000))},f end end end return C,l,nil,f end`
  );
  parts.push(
    `${N.load}=function(y,y,C,f,l)(C[${toLuaNum(rndInt(1, 9))}])[f+1]=(y) l=${toLuaNum(rndInt(0x40, 0xff))} return l end`
  );
  parts.push(`${N.ep}=function(y,y,C)y=C[${toLuaNum(rndInt(20, 45))}]() return y end`);

  const chunkNames = [];
  for (let i = 0; i < chunks.length; i++) {
    const cn = rndHexName() + i;
    chunkNames.push(cn);
    parts.push(`${cn}={${chunks[i].map(toLuaNum).join(',')}}`);
  }

  const loops = chunkNames
    .map((cn) => `for I=1,#y.${cn} do C[#C+1]=y.${cn}[I] end`)
    .join(' ');

  parts.push(
    `${N.run}=function(y) local C={} local f=${key} ${loops} local l=y.${N.dec}(y,C,f) local I=loadstring or load local M=I(l) if not M then error("protected") end if setfenv and getfenv then pcall(setfenv,M,getfenv(0)) end return M() end`
  );
  parts.push(`${N.wrap}=function(y,C,f,l,I) return ${toLuaNum(rndInt(10000, 50000))},C,f,l end`);
  parts.push(`x=function(y) return y.${N.run}(y) end`);

  const watermark =
    '-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]';

  return watermark + '\n' + `return({${parts.join(',')}})["x"]()`;
}

function obfuscate(source, opts) {
  opts = opts || {};
  const mode = String(opts.mode || 'max').toLowerCase();
  // default ON but SAFE (does not kill executors)
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

  if (wantAT) {
    src = buildAntiTamper() + '\n' + src;
    steps.push('AntiTamper:safe');
  }

  const code = buildPacked(src);
  steps.push('XOR', 'VM-Pack');

  return {
    code,
    engine: 'QyrexOBF-PureNode',
    steps,
    antiTamper: wantAT,
    mode
  };
}

function buildAntiTamper() {
  return [
    'do',
    'local function _crash() local t while true do t={t} end end',
    'local G=_G or (getfenv and getfenv(0)) or {}',
    'local BAD={"lune","lute","wally","rojo","selene","darklua","remodel","tarmac","stylua","lemur","busted","process","window","document","navigator","localStorage","globalThis","__dirname","__filename","js"}',
    'for i=1,#BAD do if rawget(G,BAD[i])~=nil then _crash() end end',
    'if type(G.process)=="table" and (G.process.env or G.process.platform) then _crash() end',
    'if string.byte("A")~=65 or math.floor(3.9)~=3 then _crash() end',
    'do local n=0/0 if n==n then _crash() end end',
    'end'
  ].join(' ');
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
