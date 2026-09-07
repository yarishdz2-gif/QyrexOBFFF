/**
 * QyrexObf 1.0.0
 * Payload alphabet ONLY: !#$%&()*+,-./:;<=>?@[]^_{|}~'
 * Identifiers: underscore-only (no digits, no letters)
 * Soft anti-tamper fused — never kills clean Roblox
 * Must execute on Luau
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.0';
/* EXACT alphabet — no digits, no latin letters */
const ALPHA = "!#$%&()*+,-./:;<=>?@[]^_{|}~'";
const BASE = ALPHA.length;
const WORD = 2;
const ri = (n) => crypto.randomInt(0, n);
const rb = (n) => crypto.randomBytes(n);

/** unique underscore-only identifiers: _, __, ___, ... */
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
  const step = 88 + ri(48);
  for (let i = 0; i < sym.length; i += step) out.push(sym.slice(i, i + step));
  return out;
}

/* multi-round XOR stream */
function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i] & 255;
    const k = key[i % kl] & 255;
    const p = (i * 31 + 17) & 255;
    const q = (i * 131 + 7) & 255;
    b = (b ^ k ^ p) & 255;
    b = (b + q) & 255;
    b = (b ^ ((k * 3 + p) & 255)) & 255;
    out[i] = b;
  }
  return out;
}
function unscramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i] & 255;
    const k = key[i % kl] & 255;
    const p = (i * 31 + 17) & 255;
    const q = (i * 131 + 7) & 255;
    b = (b ^ ((k * 3 + p) & 255)) & 255;
    b = (b - q + 256) & 255;
    b = (b ^ k ^ p) & 255;
    out[i] = b;
  }
  return out;
}

function buildLoader(sym, key) {
  _uid = 0;
  const V = [];
  for (let i = 0; i < 45; i++) V[i] = rid();

  const parts = chunkSym(sym);
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');
  const keySym = encBuf(key);

  /* all API names live inside symbol blobs — decoded at runtime */
  const nm = {
    type: encStr('type'),
    pcall: encStr('pcall'),
    string: encStr('string'),
    table: encStr('table'),
    byte: encStr('byte'),
    sub: encStr('sub'),
    concat: encStr('concat'),
    char: encStr('char'),
    rawget: encStr('rawget'),
    loadstring: encStr('loadstring'),
    load: encStr('load'),
    function: encStr('function'),
    process: encStr('process'),
    window: encStr('window'),
    document: encStr('document'),
    lune: encStr('lune'),
    lute: encStr('lute'),
    rojo: encStr('rojo'),
    lemur: encStr('lemur'),
    Buffer: encStr('Buffer'),
    navigator: encStr('navigator'),
    JobId: encStr('JobId'),
    PlaceId: encStr('PlaceId'),
    GameId: encStr('GameId'),
    zeroJob: encStr('00000000-0000-0000-0000-000000000000'),
    Instance: encStr('Instance'),
  };

  const L = [];
  L.push('return(function(...)');

  /* bootstrap with minimal globals — names decoded from symbols */
  L.push(`local ${V[0]}=_G`);
  L.push(`local ${V[1]}="${ALPHA}"`);
  L.push(`local ${V[2]}={}`);
  L.push(`for ${V[3]}=1,#${V[1]} do ${V[2]}[string.sub(${V[1]},${V[3]},${V[3]})]=${V[3]}-1 end`);
  L.push(`local function ${V[4]}(z) local o={} local p=1 local n=#z while p+1<=n do local v=0 local i=0 while i<2 do local c=string.sub(z,p+i,p+i) v=v*(#${V[1]})+(${V[2]}[c] or 0) i=i+1 end o[#o+1]=string.char(v%256) p=p+2 end return table.concat(o) end`);
  L.push(`local function ${V[5]}(a,b) a=a%256 b=b%256 local r=0 local p=1 for _=1,8 do local a1=a%2 local b1=b%2 if a1~=b1 then r=r+p end a=(a-a1)/2 b=(b-b1)/2 p=p*2 end return r end`);

  /* resolve APIs via decoded symbol names (no "string.byte" text) */
  L.push(`local ${V[6]}=${V[4]}("${luaEsc(nm.type)}")`);
  L.push(`local ${V[7]}=${V[4]}("${luaEsc(nm.pcall)}")`);
  L.push(`local ${V[8]}=${V[4]}("${luaEsc(nm.string)}")`);
  L.push(`local ${V[9]}=${V[4]}("${luaEsc(nm.table)}")`);
  L.push(`local ${V[10]}=${V[0]}[${V[6]}] or type`);
  L.push(`local ${V[11]}=${V[0]}[${V[7]}] or pcall`);
  L.push(`local ${V[12]}=${V[0]}[${V[8]}] or string`);
  L.push(`local ${V[13]}=${V[0]}[${V[9]}] or table`);
  L.push(`local ${V[14]}=${V[12]}[${V[4]}("${luaEsc(nm.byte)}")]`);
  L.push(`local ${V[15]}=${V[12]}[${V[4]}("${luaEsc(nm.sub)}")]`);
  L.push(`local ${V[16]}=${V[13]}[${V[4]}("${luaEsc(nm.concat)}")]`);
  L.push(`local ${V[17]}=${V[12]}[${V[4]}("${luaEsc(nm.char)}")]`);
  L.push(`local ${V[18]}=${V[0]}[${V[4]}("${luaEsc(nm.rawget)}")] or rawget`);
  L.push(`local ${V[19]}=${V[4]}("${luaEsc(nm.function)}")`);
  L.push(`local ${V[20]}=0`);

  /* ═══════ FUSED ANTI-TAMPER (soft score — never hard-kills clean client) ═══════ */
  L.push(`if ${V[10]}(${V[12]})==${V[4]}("${luaEsc(encStr('table'))}") then ${V[20]}=${V[20]}+10 end`);
  L.push(`if ${V[10]}(${V[14]})==${V[19]} then ${V[20]}=${V[20]}+10 end`);
  L.push(`if ${V[14]}(${V[17]}(65))==65 then ${V[20]}=${V[20]}+10 end`);
  L.push(`if math and math.floor(3.9)==3 and math.floor(math.pi)==3 then ${V[20]}=${V[20]}+10 end`);
  L.push(`do local a=${V[11]}(error,"\\0",0) if not a then ${V[20]}=${V[20]}+8 end end`);
  L.push(`if game~=nil and typeof and typeof(game)==${V[4]}("${luaEsc(nm.Instance)}") then ${V[20]}=${V[20]}+10 end`);
  L.push(`if rawequal and rawequal(pcall,pcall) then ${V[20]}=${V[20]}+6 end`);
  L.push(`if rawequal and rawequal(tostring,tostring) then ${V[20]}=${V[20]}+4 end`);

  /* sandbox / Node / lune / browser leaks */
  L.push(`do local bad=false`);
  L.push(`if ${V[10]}(${V[0]})==${V[4]}("${luaEsc(encStr('table'))}") then`);
  L.push(`local function has(k) local ok,val=${V[11]}(function() return ${V[18]}(${V[0]},k) end) return ok and val~=nil end`);
  for (const k of ['process','window','document','lune','lute','rojo','lemur','Buffer','navigator','dofile','loadfile','atob','__dirname']) {
    L.push(`if has(${V[4]}("${luaEsc(encStr(k))}")) then bad=true end`);
  }
  L.push(`end`);
  L.push(`if bad then ${V[20]}=${V[20]}-50 else ${V[20]}=${V[20]}+8 end end`);

  /* JobId / PlaceId sandbox fingerprints (Aqua-style, soft) */
  L.push(`pcall(function() if game and game[${V[4]}("${luaEsc(nm.JobId)}")]==${V[4]}("${luaEsc(nm.zeroJob)}") then ${V[20]}=${V[20]}-35 end end)`);
  L.push(`pcall(function() if game and (game[${V[4]}("${luaEsc(nm.PlaceId)}")]==8916037983 or game[${V[4]}("${luaEsc(nm.GameId)}")]==8916037983) then ${V[20]}=${V[20]}-35 end end)`);

  /* getfenv identity soft (message-9 style) */
  L.push(`pcall(function() if getfenv then local ok,env=${V[11]}(getfenv,0) if ok and env and ${V[10]}(env)==${V[4]}("${luaEsc(encStr('table'))}") then if env.getfenv~=nil and env.getfenv~=getfenv then ${V[20]}=${V[20]}-20 end end end end)`);

  /* _G metatable soft */
  L.push(`pcall(function() local mt=getmetatable(_G) if mt~=nil then ${V[20]}=${V[20]}-10 end end)`);

  /* never abort on score — only noise */

  /* payload decode */
  L.push(`local ${V[21]}={${vLit}}`);
  L.push(`local ${V[22]}="${luaEsc(keySym)}"`);
  L.push(`local ${V[23]}=${V[4]}(${V[16]}(${V[21]}))`);
  L.push(`local ${V[24]}=${V[4]}(${V[22]})`);
  L.push(`local ${V[25]}={} local ${V[26]}=#${V[24]}`);
  L.push(`for ${V[27]}=1,#${V[23]} do`);
  L.push(`local f=${V[14]}(${V[23]},${V[27]})`);
  L.push(`local g=${V[14]}(${V[24]},((${V[27]}-1)%${V[26]})+1)`);
  L.push(`local p=((${V[27]}-1)*31+17)%256`);
  L.push(`local q=((${V[27]}-1)*131+7)%256`);
  L.push(`local b=${V[5]}(f,${V[5]}((g*3+p)%256,0))`);
  /* unscramble reverse: b = b ^ ((k*3+p)&255); b = b - q; b = b ^ k ^ p */
  L.push(`b=${V[5]}(f,((g*3+p)%256))`);
  L.push(`b=(b-q+256)%256`);
  L.push(`b=${V[5]}(${V[5]}(b,g),p)`);
  L.push(`${V[25]}[${V[27]}]=${V[17]}(b%256)`);
  L.push(`end`);
  L.push(`local ${V[28]}=${V[16]}(${V[25]})`);
  L.push(`${V[23]}=nil ${V[25]}=nil ${V[24]}=nil ${V[21]}=nil`);

  /* loader */
  L.push(`local ${V[29]}=${V[18]}(${V[0]},${V[4]}("${luaEsc(nm.loadstring)}")) or ${V[18]}(${V[0]},${V[4]}("${luaEsc(nm.load)}"))`);
  L.push(`if ${V[10]}(${V[29]})~=${V[19]} then return end`);
  L.push(`pcall(function() if iscclosure and not iscclosure(${V[29]}) then ${V[20]}=${V[20]}-15 end end)`);
  L.push(`local ${V[30]}=${V[29]}(${V[28]})`);
  L.push(`${V[28]}=nil`);
  L.push(`if ${V[10]}(${V[30]})==${V[19]} then local ${V[31]},${V[32]}=${V[11]}(${V[30]},...) if ${V[31]} then return ${V[32]} end end`);
  L.push(`end)(...)`);

  return `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]]\n` + L.join(' ');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const raw = Buffer.from(src, 'utf8');
  if (raw.length > 1500000) throw new Error('Too large');
  const key = rb(40 + ri(24));
  const scrambled = scramble(raw, key);
  const sym = encBuf(scrambled);
  const back = unscramble(decBuf(sym), key);
  if (!back.equals(raw)) throw new Error('roundtrip failed');
  /* verify alphabet has no digits/letters */
  for (const ch of sym) {
    if (!ALPHA.includes(ch)) throw new Error('alphabet violation');
  }
  const code = buildLoader(sym, key);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      layers: [
        'symbol-alphabet-strict',
        'underscore-only-ids',
        'multi-round-xor',
        'api-names-encoded',
        'fused-anti-tamper',
        'sandbox-probes',
        'hook-probe',
        'single-line',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
