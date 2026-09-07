/**
 * QyrexObf 1.0.0 — maximum practical protection on Luau
 * Alphabet: !#$%&()*+,-./:;<=>?@[]^_{|}~'
 * Underscore-only locals · multi-key XOR · fused AT from full suite
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.0';
const ALPHA = "!#$%&()*+,-./:;<=>?@[]^_{|}~'";
const BASE = ALPHA.length;
const WORD = 2;
const ROUNDS = 8;
const ri = (n) => crypto.randomInt(0, n);
const rb = (n) => crypto.randomBytes(n);

let _uid = 0;
function rid() {
  _uid += 1 + ri(2);
  return '_'.repeat(Math.max(1, _uid));
}

function encByte(b) {
  let n = b & 255, w = '';
  for (let i = 0; i < WORD; i++) {
    w = ALPHA[n % BASE] + w;
    n = (n / BASE) | 0;
  }
  return w;
}
function encBuf(buf) {
  let s = '';
  for (let i = 0; i < buf.length; i++) s += encByte(buf[i]);
  return s;
}
function encStr(s) {
  return encBuf(Buffer.from(String(s), 'utf8'));
}
function decBuf(sym) {
  const map = Object.create(null);
  for (let i = 0; i < BASE; i++) map[ALPHA[i]] = i;
  const out = Buffer.alloc((sym.length / WORD) | 0);
  let j = 0;
  for (let pos = 0; pos + WORD <= sym.length; pos += WORD) {
    let n = 0;
    for (let i = 0; i < WORD; i++) n = n * BASE + (map[sym[pos + i]] || 0);
    out[j++] = n & 255;
  }
  return out.subarray(0, j);
}
function luaEsc(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\0/g, '\\0');
}
function chunkSym(sym) {
  const out = [];
  const step = 72 + ri(36);
  for (let i = 0; i < sym.length; i += step) out.push(sym.slice(i, i + step));
  return out;
}

function roundEnc(data, key, salt) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i] & 255;
    const k = key[i % kl] & 255;
    const p = (i * 31 + 17 + salt) & 255;
    const q = (i * 131 + 7 + salt * 3) & 255;
    b = (b ^ k ^ p) & 255;
    b = (b + q) & 255;
    b = (b ^ ((k * 3 + p) & 255)) & 255;
    out[i] = b;
  }
  return out;
}
function roundDec(data, key, salt) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i] & 255;
    const k = key[i % kl] & 255;
    const p = (i * 31 + 17 + salt) & 255;
    const q = (i * 131 + 7 + salt * 3) & 255;
    b = (b ^ ((k * 3 + p) & 255)) & 255;
    b = (b - q + 256) & 255;
    b = (b ^ k ^ p) & 255;
    out[i] = b;
  }
  return out;
}

function simpleHash(buf) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < buf.length; i++) {
    h ^= buf[i];
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function buildLoader(sym, keys, salts, expectHash) {
  _uid = 0;
  const V = [];
  for (let i = 0; i < 48; i++) V[i] = rid();

  const parts = chunkSym(sym);
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');
  const keyLits = keys.map((k) => `"${luaEsc(encBuf(k))}"`).join(',');
  const saltLit = salts.join(',');
  const nm = (s) => luaEsc(encStr(s));

  const L = [];
  L.push('return(function(...)');
  L.push(`local ${V[0]}=_G`);
  L.push(`local ${V[1]}="${ALPHA}"`);
  L.push(`local ${V[2]}={}`);
  L.push(`for ${V[3]}=1,#${V[1]} do ${V[2]}[string.sub(${V[1]},${V[3]},${V[3]})]=${V[3]}-1 end`);
  L.push(`local function ${V[4]}(z) local o={} local p=1 local n=#z while p+1<=n do local v=0 local i=0 while i<2 do local c=string.sub(z,p+i,p+i) v=v*(#${V[1]})+(${V[2]}[c] or 0) i=i+1 end o[#o+1]=string.char(v%256) p=p+2 end return table.concat(o) end`);
  L.push(`local function ${V[5]}(a,b) a=a%256 b=b%256 local r=0 local p=1 for _=1,8 do local a1=a%2 local b1=b%2 if a1~=b1 then r=r+p end a=(a-a1)/2 b=(b-b1)/2 p=p*2 end return r end`);

  L.push(`local ${V[6]}=${V[4]}("${nm('type')}")`);
  L.push(`local ${V[7]}=${V[4]}("${nm('pcall')}")`);
  L.push(`local ${V[8]}=${V[4]}("${nm('string')}")`);
  L.push(`local ${V[9]}=${V[4]}("${nm('table')}")`);
  L.push(`local ${V[10]}=${V[0]}[${V[6]}] or type`);
  L.push(`local ${V[11]}=${V[0]}[${V[7]}] or pcall`);
  L.push(`local ${V[12]}=${V[0]}[${V[8]}] or string`);
  L.push(`local ${V[13]}=${V[0]}[${V[9]}] or table`);
  L.push(`local ${V[14]}=${V[12]}[${V[4]}("${nm('byte')}")]`);
  L.push(`local ${V[15]}=${V[12]}[${V[4]}("${nm('sub')}")]`);
  L.push(`local ${V[16]}=${V[13]}[${V[4]}("${nm('concat')}")]`);
  L.push(`local ${V[17]}=${V[12]}[${V[4]}("${nm('char')}")]`);
  L.push(`local ${V[18]}=${V[0]}[${V[4]}("${nm('rawget')}")] or rawget`);
  L.push(`local ${V[19]}=${V[4]}("${nm('function')}")`);
  L.push(`local ${V[20]}=0`);

  /* ════════ FUSED ANTI-TAMPER (soft — never kills clean Roblox) ════════ */
  /* primitives */
  L.push(`if ${V[10]}(${V[12]})==${V[4]}("${nm('table')}") then ${V[20]}=${V[20]}+8 end`);
  L.push(`if ${V[10]}(${V[14]})==${V[19]} then ${V[20]}=${V[20]}+8 end`);
  L.push(`if ${V[14]}(${V[17]}(65))==65 then ${V[20]}=${V[20]}+8 end`);
  L.push(`if math and math.floor(3.9)==3 and math.floor(math.pi)==3 then ${V[20]}=${V[20]}+8 end`);
  L.push(`do local a=${V[11]}(error,"\\0",0) if not a then ${V[20]}=${V[20]}+6 end end`);
  L.push(`if rawequal and rawequal(pcall,pcall) then ${V[20]}=${V[20]}+5 end`);
  L.push(`if rawequal and rawequal(tostring,tostring) then ${V[20]}=${V[20]}+4 end`);
  L.push(`if game~=nil and typeof and typeof(game)==${V[4]}("${nm('Instance')}") then ${V[20]}=${V[20]}+10 end`);
  L.push(`if type(game)==type({}) then ${V[20]}=${V[20]}-25 end`);

  /* sandbox env leaks (anti sandbox everything / aqua / message-9) */
  L.push(`do local bad=false`);
  L.push(`if ${V[10]}(${V[0]})==${V[4]}("${nm('table')}") then`);
  L.push(`local function has(k) local ok,val=${V[11]}(function() return ${V[18]}(${V[0]},k) end) return ok and val~=nil end`);
  const sand = [
    'process','window','document','lune','lute','rojo','lemur','Buffer','navigator',
    'dofile','loadfile','atob','btoa','__dirname','__filename','global','globalThis',
    'XMLHttpRequest','WebSocket','localStorage','sessionStorage','Worker',
    'console','setTimeout','setInterval','fetch','Headers','Request','Response',
    'wally','selene','darklua','remodel','tarmac','stylua','busted','plugin',
  ];
  for (const k of sand) {
    L.push(`if has(${V[4]}("${nm(k)}")) then bad=true end`);
  }
  L.push(`end`);
  L.push(`if bad then ${V[20]}=${V[20]}-60 else ${V[20]}=${V[20]}+10 end end`);

  /* JobId / PlaceId / GameId fingerprints */
  L.push(`pcall(function() if game and game[${V[4]}("${nm('JobId')}")]==${V[4]}("${nm('00000000-0000-0000-0000-000000000000')}") then ${V[20]}=${V[20]}-40 end end)`);
  L.push(`pcall(function() if game and (game[${V[4]}("${nm('PlaceId')}"]==8916037983 or game[${V[4]}("${nm('GameId')}"]==8916037983) then ${V[20]}=${V[20]}-40 end end)`);
  L.push(`pcall(function() local ok,plr=pcall(function() return game:GetService(${V[4]}("${nm('Players')}")).LocalPlayer end) if ok and plr then if plr.UserId==123456789 or plr.Name==${V[4]}("${nm('vole7vin')}") then ${V[20]}=${V[20]}-40 end end end)`);

  /* getfenv / debug hooks */
  L.push(`pcall(function() if getfenv then local ok,env=${V[11]}(getfenv,0) if ok and env then if env.getfenv~=nil and env.getfenv~=getfenv then ${V[20]}=${V[20]}-20 end if env.debug and env.debug.gethook then local ok2,h=${V[11]}(env.debug.gethook) if ok2 and h~=nil then ${V[20]}=${V[20]}-25 end end end end end)`);
  L.push(`pcall(function() if debug and debug.gethook then local ok,h=${V[11]}(debug.gethook) if ok and h~=nil then ${V[20]}=${V[20]}-25 end end end)`);
  L.push(`pcall(function() if getmetatable(_G)~=nil then ${V[20]}=${V[20]}-12 end end)`);

  /* opaque arithmetic traps (decoy — always true on clean) */
  L.push(`do local ${V[36]}=7 if ${V[36]}~=${V[36]} or ${V[36]}*0~=0 or ${V[36]}<0 then ${V[20]}=${V[20]}-30 end end`);
  L.push(`if ((42*4)%2)~=0 then ${V[20]}=${V[20]}-20 end`);

  /* never hard-abort — score only */

  /* payload → bytes */
  L.push(`local ${V[21]}={${vLit}}`);
  L.push(`local ${V[22]}=${V[4]}(${V[16]}(${V[21]}))`);
  L.push(`local ${V[23]}={} for ${V[24]}=1,#${V[22]} do ${V[23]}[${V[24]}]=${V[14]}(${V[22]},${V[24]}) end`);
  L.push(`${V[21]}=nil ${V[22]}=nil`);

  /* multi-key peel */
  L.push(`local ${V[25]}={${keyLits}}`);
  L.push(`local ${V[26]}={${saltLit}}`);
  L.push(`local ${V[27]}={}`);
  L.push(`for ${V[28]}=1,#${V[25]} do ${V[27]}[${V[28]}]=${V[4]}(${V[25]}[${V[28]}]) end`);
  L.push(`${V[25]}=nil`);
  L.push(`for ${V[29]}=#${V[27]},1,-1 do`);
  L.push(`local key=${V[27]}[${V[29]}] local salt=${V[26]}[${V[29]}] local kl=#key`);
  L.push(`local out={} for i=1,#${V[23]} do`);
  L.push(`local b=${V[23]}[i] local g=${V[14]}(key,((i-1)%kl)+1)`);
  L.push(`local p=((i-1)*31+17+salt)%256 local q=((i-1)*131+7+salt*3)%256`);
  L.push(`b=${V[5]}(b,((g*3+p)%256)) b=(b-q+256)%256 b=${V[5]}(${V[5]}(b,g),p) out[i]=b end`);
  L.push(`${V[23]}=out end`);
  L.push(`${V[27]}=nil`);

  /* integrity hash (FNV-ish) — soft check */
  L.push(`do local h=2166136261 for i=1,#${V[23]} do h=${V[5]}(h,${V[23]}[i]) h=(h*16777619)%4294967296 end`);
  L.push(`if h~=${expectHash} then ${V[20]}=${V[20]}-5 end end`);

  /* rebuild source */
  L.push(`local ${V[30]}={} for i=1,#${V[23]} do ${V[30]}[i]=${V[17]}(${V[23]}[i]%256) end`);
  L.push(`local ${V[31]}=${V[16]}(${V[30]})`);
  L.push(`${V[23]}=nil ${V[30]}=nil`);

  /* decoy loadstring noise */
  L.push(`pcall(function() local ls=${V[18]}(${V[0]},${V[4]}("${nm('loadstring')}")) if ls then for i=1,6 do ls(${V[17]}(45,45,32)..tostring(i*97)) end end end)`);

  L.push(`local ${V[32]}=${V[18]}(${V[0]},${V[4]}("${nm('loadstring')}")) or ${V[18]}(${V[0]},${V[4]}("${nm('load')}"))`);
  L.push(`if ${V[10]}(${V[32]})~=${V[19]} then return end`);
  L.push(`pcall(function() if iscclosure and not iscclosure(${V[32]}) then ${V[20]}=${V[20]}-15 end end)`);
  L.push(`local ${V[33]}=${V[32]}(${V[31]})`);
  L.push(`${V[31]}=nil`);
  L.push(`if ${V[10]}(${V[33]})==${V[19]} then local ${V[34]},${V[35]}=${V[11]}(${V[33]},...) if ${V[34]} then return ${V[35]} end end`);
  L.push(`end)(...)`);

  return `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org | ${keys.length}x ]]\n` + L.join(' ');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const raw = Buffer.from(src, 'utf8');
  if (raw.length > 1200000) throw new Error('Too large');

  const keys = [];
  const salts = [];
  let data = Buffer.from(raw);
  for (let r = 0; r < ROUNDS; r++) {
    const key = rb(36 + ri(20));
    const salt = ri(180) + 1;
    data = roundEnc(data, key, salt);
    keys.push(key);
    salts.push(salt);
  }

  let check = Buffer.from(data);
  for (let r = ROUNDS - 1; r >= 0; r--) check = roundDec(check, keys[r], salts[r]);
  if (!check.equals(raw)) throw new Error('roundtrip failed');

  const expectHash = simpleHash(raw);
  const sym = encBuf(data);
  for (const ch of sym) {
    if (!ALPHA.includes(ch)) throw new Error('alphabet violation');
  }

  const code = buildLoader(sym, keys, salts, expectHash);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      rounds: ROUNDS,
      layers: [
        'symbol-alphabet-strict',
        'underscore-only-ids',
        ROUNDS + '-round-xor',
        'payload-integrity-hash',
        'api-names-encoded',
        'fused-anti-tamper-full',
        'sandbox-env-probes',
        'jobid-placeid-fingerprint',
        'getfenv-debug-hooks',
        'opaque-predicates',
        'decoy-loadstring',
        'hook-probe',
        'single-line',
        'luau-ready',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
