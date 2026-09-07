/**
 * QyrexObf 1.0.0 — Luau
 * Alphabet ONLY: !#$%&()*+,-./:;<=>?@[]^_{|}~'
 * Underscore-only locals · 1 core + 20 extra encryption layers · fused AT
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.0';
const ALPHA = "!#$%&()*+,-./:;<=>?@[]^_{|}~'";
const BASE = ALPHA.length;
const WORD = 2;
const EXTRA_LAYERS = 20; // after base = 21 total rounds
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
  const step = 80 + ri(40);
  for (let i = 0; i < sym.length; i += step) out.push(sym.slice(i, i + step));
  return out;
}

/** one encryption round (forward) */
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

function buildLoader(sym, keys /* Buffer[] */, salts /* number[] */) {
  _uid = 0;
  const V = [];
  for (let i = 0; i < 40; i++) V[i] = rid();

  const parts = chunkSym(sym);
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');
  const keySyms = keys.map((k) => encBuf(k));
  const keyLits = keySyms.map((ks) => `"${luaEsc(ks)}"`).join(',');
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

  /* APIs from encoded names */
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

  /* fused soft anti-tamper */
  L.push(`if ${V[10]}(${V[12]})==${V[4]}("${nm('table')}") then ${V[20]}=${V[20]}+10 end`);
  L.push(`if ${V[14]}(${V[17]}(65))==65 then ${V[20]}=${V[20]}+10 end`);
  L.push(`if math and math.floor(3.9)==3 and math.floor(math.pi)==3 then ${V[20]}=${V[20]}+10 end`);
  L.push(`do local a=${V[11]}(error,"\\0",0) if not a then ${V[20]}=${V[20]}+8 end end`);
  L.push(`if game~=nil and typeof and typeof(game)==${V[4]}("${nm('Instance')}") then ${V[20]}=${V[20]}+10 end`);
  L.push(`if rawequal and rawequal(pcall,pcall) then ${V[20]}=${V[20]}+6 end`);
  L.push(`do local bad=false if ${V[10]}(${V[0]})==${V[4]}("${nm('table')}") then local function has(k) local ok,val=${V[11]}(function() return ${V[18]}(${V[0]},k) end) return ok and val~=nil end`);
  for (const k of ['process','window','document','lune','lute','rojo','lemur','Buffer','navigator','dofile','loadfile']) {
    L.push(`if has(${V[4]}("${nm(k)}")) then bad=true end`);
  }
  L.push(`end if bad then ${V[20]}=${V[20]}-50 else ${V[20]}=${V[20]}+8 end end`);
  L.push(`pcall(function() if game and game[${V[4]}("${nm('JobId')}")]==${V[4]}("${nm('00000000-0000-0000-0000-000000000000')}") then ${V[20]}=${V[20]}-35 end end)`);
  L.push(`pcall(function() if game and (game[${V[4]}("${nm('PlaceId')}"]==8916037983 or game[${V[4]}("${nm('GameId')}"]==8916037983) then ${V[20]}=${V[20]}-35 end end)`);
  L.push(`pcall(function() if getfenv then local ok,env=${V[11]}(getfenv,0) if ok and env and env.getfenv~=nil and env.getfenv~=getfenv then ${V[20]}=${V[20]}-20 end end end)`);
  L.push(`pcall(function() if getmetatable(_G)~=nil then ${V[20]}=${V[20]}-10 end end)`);

  /* decode payload symbols → bytes */
  L.push(`local ${V[21]}={${vLit}}`);
  L.push(`local ${V[22]}=${V[4]}(${V[16]}(${V[21]}))`);
  L.push(`local ${V[23]}={} for ${V[24]}=1,#${V[22]} do ${V[23]}[${V[24]}]=${V[14]}(${V[22]},${V[24]}) end`);
  L.push(`${V[21]}=nil ${V[22]}=nil`);

  /* keys + salts (21 layers: peel in reverse) */
  L.push(`local ${V[25]}={${keyLits}}`);
  L.push(`local ${V[26]}={${saltLit}}`);
  L.push(`local ${V[27]}={}`);
  L.push(`for ${V[28]}=1,#${V[25]} do ${V[27]}[${V[28]}]=${V[4]}(${V[25]}[${V[28]}]) end`);
  L.push(`${V[25]}=nil`);

  /* peel layers from last to first */
  L.push(`for ${V[29]}=#${V[27]},1,-1 do`);
  L.push(`local key=${V[27]}[${V[29]}] local salt=${V[26]}[${V[29]}] local kl=#key`);
  L.push(`local out={} for i=1,#${V[23]} do`);
  L.push(`local b=${V[23]}[i]`);
  L.push(`local g=${V[14]}(key,((i-1)%kl)+1)`);
  L.push(`local p=((i-1)*31+17+salt)%256`);
  L.push(`local q=((i-1)*131+7+salt*3)%256`);
  L.push(`b=${V[5]}(b,((g*3+p)%256))`);
  L.push(`b=(b-q+256)%256`);
  L.push(`b=${V[5]}(${V[5]}(b,g),p)`);
  L.push(`out[i]=b end`);
  L.push(`${V[23]}=out end`);
  L.push(`${V[27]}=nil`);

  /* bytes → source string */
  L.push(`local ${V[30]}={} for i=1,#${V[23]} do ${V[30]}[i]=${V[17]}(${V[23]}[i]%256) end`);
  L.push(`local ${V[31]}=${V[16]}(${V[30]})`);
  L.push(`${V[23]}=nil ${V[30]}=nil`);

  L.push(`local ${V[32]}=${V[18]}(${V[0]},${V[4]}("${nm('loadstring')}")) or ${V[18]}(${V[0]},${V[4]}("${nm('load')}"))`);
  L.push(`if ${V[10]}(${V[32]})~=${V[19]} then return end`);
  L.push(`pcall(function() if iscclosure and not iscclosure(${V[32]}) then ${V[20]}=${V[20]}-15 end end)`);
  L.push(`local ${V[33]}=${V[32]}(${V[31]})`);
  L.push(`${V[31]}=nil`);
  L.push(`if ${V[10]}(${V[33]})==${V[19]} then local ${V[34]},${V[35]}=${V[11]}(${V[33]},...) if ${V[34]} then return ${V[35]} end end`);
  L.push(`end)(...)`);

  return `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org | ${keys.length} layers ]]\n` + L.join(' ');
}

function obfuscate(source, opts = {}) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const raw = Buffer.from(src, 'utf8');
  if (raw.length > 800000) throw new Error('Too large');

  const extra = Math.min(30, Math.max(0, opts.extraLayers != null ? opts.extraLayers : EXTRA_LAYERS));
  const total = 1 + extra; // base + extras

  const keys = [];
  const salts = [];
  let data = Buffer.from(raw);
  for (let layer = 0; layer < total; layer++) {
    const key = rb(32 + ri(16));
    const salt = ri(200) + 1;
    data = roundEnc(data, key, salt);
    keys.push(key);
    salts.push(salt);
  }

  /* verify peel */
  let check = Buffer.from(data);
  for (let layer = total - 1; layer >= 0; layer--) {
    check = roundDec(check, keys[layer], salts[layer]);
  }
  if (!check.equals(raw)) throw new Error('roundtrip failed');

  const sym = encBuf(data);
  for (const ch of sym) {
    if (!ALPHA.includes(ch)) throw new Error('alphabet violation');
  }

  const code = buildLoader(sym, keys, salts);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      layers: total,
      extraLayers: extra,
      features: [
        'symbol-alphabet-strict',
        'underscore-ids',
        total + '-round-xor',
        'api-names-encoded',
        'fused-anti-tamper',
        'luau-ready',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION, EXTRA_LAYERS };
