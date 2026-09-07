/**
 * QyrexObf 1.0.0 — Luau stable + strong
 * Alphabet ONLY: !#$%&()*+,-./:;<=>?@[]^_{|}~'
 * Underscore-only ids · multi-round XOR · soft fused AT
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.0';
const ALPHA = "!#$%&()*+,-./:;<=>?@[]^_{|}~'";
const BASE = ALPHA.length;
const WORD = 2;
const ROUNDS = 5;
const ri = (n) => crypto.randomInt(0, n);
const rb = (n) => crypto.randomBytes(n);

let _uid = 8; // start long enough to avoid "_" clash with for-loops
function rid() {
  _uid += 1 + ri(1);
  return '_'.repeat(_uid);
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
  const step = 90 + ri(40);
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

function buildLoader(sym, keys, salts) {
  _uid = 8;
  const V = [];
  for (let i = 0; i < 40; i++) V[i] = rid();

  const parts = chunkSym(sym);
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');
  const keyLits = keys.map((k) => `"${luaEsc(encBuf(k))}"`).join(',');
  const saltLit = salts.join(',');
  const nm = (s) => luaEsc(encStr(s));

  const L = [];
  L.push('return(function(...)');

  /* bootstrap — pure Luau */
  L.push(`local ${V[0]}=_G`);
  L.push(`local ${V[1]}="${ALPHA}"`);
  L.push(`local ${V[2]}={}`);
  L.push(`for ${V[3]}=1,#${V[1]} do ${V[2]}[string.sub(${V[1]},${V[3]},${V[3]})]=${V[3]}-1 end`);
  L.push(`local function ${V[4]}(z)`);
  L.push(`local o={} local p=1 local n=#z`);
  L.push(`while p+1<=n do local v=0 local i=0`);
  L.push(`while i<2 do local c=string.sub(z,p+i,p+i) v=v*(#${V[1]})+(${V[2]}[c] or 0) i=i+1 end`);
  L.push(`o[#o+1]=string.char(v%256) p=p+2 end`);
  L.push(`return table.concat(o) end`);

  /* pure XOR 0-255 */
  L.push(`local function ${V[5]}(a,b)`);
  L.push(`a=a%256 b=b%256 local r=0 local p=1`);
  L.push(`for ${V[6]}=1,8 do local a1=a%2 local b1=b%2 if a1~=b1 then r=r+p end a=math.floor((a-a1)/2) b=math.floor((b-b1)/2) p=p*2 end`);
  L.push(`return r end`);

  /* resolve APIs via symbol-decoded names */
  L.push(`local ${V[7]}=${V[4]}("${nm('type')}")`);
  L.push(`local ${V[8]}=${V[4]}("${nm('pcall')}")`);
  L.push(`local ${V[9]}=${V[4]}("${nm('string')}")`);
  L.push(`local ${V[10]}=${V[4]}("${nm('table')}")`);
  L.push(`local ${V[11]}=${V[0]}[${V[7]}] or type`);
  L.push(`local ${V[12]}=${V[0]}[${V[8]}] or pcall`);
  L.push(`local ${V[13]}=${V[0]}[${V[9]}] or string`);
  L.push(`local ${V[14]}=${V[0]}[${V[10]}] or table`);
  L.push(`local ${V[15]}=${V[13]}[${V[4]}("${nm('byte')}")]`);
  L.push(`local ${V[16]}=${V[13]}[${V[4]}("${nm('sub')}")]`);
  L.push(`local ${V[17]}=${V[14]}[${V[4]}("${nm('concat')}")]`);
  L.push(`local ${V[18]}=${V[13]}[${V[4]}("${nm('char')}")]`);
  L.push(`local ${V[19]}=${V[0]}[${V[4]}("${nm('rawget')}")] or rawget`);
  L.push(`local ${V[20]}=${V[4]}("${nm('function')}")`);
  L.push(`local ${V[21]}=0`);

  /* soft anti-tamper (never aborts clean client) */
  L.push(`if ${V[11]}(${V[13]})==${V[4]}("${nm('table')}") then ${V[21]}=${V[21]}+1 end`);
  L.push(`if ${V[15]}(${V[18]}(65))==65 then ${V[21]}=${V[21]}+1 end`);
  L.push(`if math and math.floor(3.9)==3 then ${V[21]}=${V[21]}+1 end`);
  L.push(`do local ok=${V[12]}(error,"\\0",0) if not ok then ${V[21]}=${V[21]}+1 end end`);
  L.push(`if game~=nil and typeof and typeof(game)==${V[4]}("${nm('Instance')}") then ${V[21]}=${V[21]}+1 end`);
  L.push(`if rawequal and rawequal(pcall,pcall) then ${V[21]}=${V[21]}+1 end`);

  L.push(`do local bad=false`);
  L.push(`local function has(k) local ok,val=${V[12]}(function() return ${V[19]}(${V[0]},k) end) return ok and val~=nil end`);
  for (const k of [
    'process','window','document','lune','lute','rojo','lemur','Buffer','navigator',
    'dofile','loadfile','atob','__dirname','globalThis','XMLHttpRequest','console',
    'setTimeout','fetch','wally','selene','plugin',
  ]) {
    L.push(`if has(${V[4]}("${nm(k)}")) then bad=true end`);
  }
  L.push(`if bad then ${V[21]}=${V[21]}-20 else ${V[21]}=${V[21]}+1 end end`);

  L.push(`pcall(function()`);
  L.push(`if game and game[${V[4]}("${nm('JobId')}"]==${V[4]}("${nm('00000000-0000-0000-0000-000000000000')}") then ${V[21]}=${V[21]}-15 end`);
  L.push(`end)`);
  L.push(`pcall(function()`);
  L.push(`if game then local a=game[${V[4]}("${nm('PlaceId')}")] local b=game[${V[4]}("${nm('GameId')}")]`);
  L.push(`if a==8916037983 or b==8916037983 then ${V[21]}=${V[21]}-15 end end`);
  L.push(`end)`);
  L.push(`pcall(function() if getmetatable and getmetatable(_G)~=nil then ${V[21]}=${V[21]}-5 end end)`);
  L.push(`pcall(function() if debug and debug.gethook then local ok,h=${V[12]}(debug.gethook) if ok and h~=nil then ${V[21]}=${V[21]}-10 end end end)`);

  /* opaque always-true on clean */
  L.push(`do local x=7 if x~=x or x*0~=0 then ${V[21]}=${V[21]}-10 end end`);

  /* decode symbol payload → byte array */
  L.push(`local ${V[22]}={${vLit}}`);
  L.push(`local ${V[23]}=${V[4]}(${V[17]}(${V[22]}))`);
  L.push(`local ${V[24]}={} for ${V[25]}=1,#${V[23]} do ${V[24]}[${V[25]}]=${V[15]}(${V[23]},${V[25]}) end`);
  L.push(`${V[22]}=nil ${V[23]}=nil`);

  /* keys */
  L.push(`local ${V[26]}={${keyLits}}`);
  L.push(`local ${V[27]}={${saltLit}}`);
  L.push(`local ${V[28]}={}`);
  L.push(`for ${V[29]}=1,#${V[26]} do ${V[28]}[${V[29]}]=${V[4]}(${V[26]}[${V[29]}]) end`);
  L.push(`${V[26]}=nil`);

  /* peel rounds last→first */
  L.push(`for ${V[30]}=#${V[28]},1,-1 do`);
  L.push(`local key=${V[28]}[${V[30]}] local salt=${V[27]}[${V[30]}] local kl=#key`);
  L.push(`local out={} for i=1,#${V[24]} do`);
  L.push(`local b=${V[24]}[i]`);
  L.push(`local g=${V[15]}(key,((i-1)%kl)+1)`);
  L.push(`local p=((i-1)*31+17+salt)%256`);
  L.push(`local q=((i-1)*131+7+salt*3)%256`);
  L.push(`b=${V[5]}(b,((g*3+p)%256))`);
  L.push(`b=(b-q+256)%256`);
  L.push(`b=${V[5]}(${V[5]}(b,g),p)`);
  L.push(`out[i]=b end`);
  L.push(`${V[24]}=out end`);
  L.push(`${V[28]}=nil`);

  /* bytes → string */
  L.push(`local ${V[31]}={} for i=1,#${V[24]} do ${V[31]}[i]=${V[18]}(${V[24]}[i]%256) end`);
  L.push(`local ${V[32]}=${V[17]}(${V[31]})`);
  L.push(`${V[24]}=nil ${V[31]}=nil`);

  /* load + run */
  L.push(`local ${V[33]}=${V[19]}(${V[0]},${V[4]}("${nm('loadstring')}")) or ${V[19]}(${V[0]},${V[4]}("${nm('load')}"))`);
  L.push(`if ${V[11]}(${V[33]})~=${V[20]} then return end`);
  L.push(`pcall(function() if iscclosure and not iscclosure(${V[33]}) then ${V[21]}=${V[21]}-5 end end)`);
  L.push(`local ${V[34]}=${V[33]}(${V[32]})`);
  L.push(`${V[32]}=nil`);
  L.push(`if ${V[11]}(${V[34]})==${V[20]} then`);
  L.push(`local ${V[35]},${V[36]}=${V[12]}(${V[34]},...)`);
  L.push(`if ${V[35]} then return ${V[36]} end`);
  L.push(`end`);
  L.push(`end)(...)`);

  return `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]]\n` + L.join(' ');
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
    const key = rb(32 + ri(16));
    const salt = ri(120) + 1;
    data = roundEnc(data, key, salt);
    keys.push(key);
    salts.push(salt);
  }

  let check = Buffer.from(data);
  for (let r = ROUNDS - 1; r >= 0; r--) check = roundDec(check, keys[r], salts[r]);
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
      rounds: ROUNDS,
      layers: [
        'symbol-alphabet',
        'underscore-ids',
        ROUNDS + '-round-xor',
        'api-encoded',
        'soft-anti-tamper',
        'sandbox-probes',
        'jobid-checks',
        'luau-stable',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
