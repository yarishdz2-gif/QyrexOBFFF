/**
 * QyrexObf 1.0.0 — max practical resistance under loadstring constraint
 *
 * Truth: any final loadstring(fullSource) can be dumped by Nova/45ms hooks.
 * This build maximizes cost: multi-chunk XOR, decoy floods, API charcodes,
 * soft anti-tamper, hook probes, never one contiguous plaintext literal.
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.0';
const ALPHA = "!#$%&()*+,-./:;<=>?@[]^_{|}~'`";
const BASE = ALPHA.length;
const WORD = 2;
const ri = (n) => crypto.randomInt(0, n);
const rb = (n) => crypto.randomBytes(n);

function rid() {
  return '_' + crypto.randomInt(10000, 99999) + '_' + crypto.randomInt(10000, 99999);
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
function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    out[i] = (data[i] ^ key[i % kl] ^ ((i * 31 + 17) & 255)) & 255;
  }
  return out;
}
function unscramble(data, key) {
  return scramble(data, key);
}
function ch(s) {
  return 'string.char(' + [...Buffer.from(s, 'utf8')].join(',') + ')';
}
function chunkSym(sym) {
  const out = [];
  const step = 70 + ri(40);
  for (let i = 0; i < sym.length; i += step) out.push(sym.slice(i, i + step));
  return out;
}

function buildLoader(sym, key, nChunks) {
  const id = () => rid();
  const V = {};
  for (let i = 0; i < 50; i++) V[i] = id();

  const parts = chunkSym(sym);
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');
  const keySym = encBuf(key);

  const L = [];
  L.push('return(function(...)');
  L.push(`local ${V[0]}=_G`);
  L.push(`local ${V[1]}=${V[0]}[${ch('type')}]or type`);
  L.push(`local ${V[2]}=${V[0]}[${ch('pcall')}]or pcall`);
  L.push(`local ${V[3]}=${V[0]}[${ch('string')}]or string`);
  L.push(`local ${V[4]}=${V[0]}[${ch('table')}]or table`);
  L.push(`local ${V[5]}=${V[3]}[${ch('byte')}]`);
  L.push(`local ${V[6]}=${V[3]}[${ch('sub')}]`);
  L.push(`local ${V[7]}=${V[4]}[${ch('concat')}]`);
  L.push(`local ${V[8]}=${V[3]}[${ch('char')}]`);
  L.push(`local ${V[9]}=${V[0]}[${ch('rawget')}]or rawget`);
  L.push(`local ${V[10]}=0`);

  /* soft anti-tamper / sandbox (never hard-kill clean client) */
  L.push(`if ${V[1]}(${V[3]})==${V[8]}(116,97,98,108,101)then ${V[10]}=${V[10]}+10 end`);
  L.push(`if ${V[5]}(${V[8]}(65))==65 then ${V[10]}=${V[10]}+10 end`);
  L.push(`if math and math.floor(3.9)==3 and math.floor(math.pi)==3 then ${V[10]}=${V[10]}+10 end`);
  L.push(`do local a=${V[2]}(error,"\\0",0)if not a then ${V[10]}=${V[10]}+8 end end`);
  L.push(`if game~=nil and typeof and typeof(game)==${V[8]}(73,110,115,116,97,110,99,101)then ${V[10]}=${V[10]}+10 end`);
  L.push(`do local bad=false if ${V[1]}(${V[0]})==${V[8]}(116,97,98,108,101)then local function has(k)local ok,val=${V[2]}(function()return ${V[9]}(${V[0]},k)end)return ok and val~=nil end`);
  const sand = ['process','window','document','lune','lute','rojo','lemur','Buffer','navigator','__dirname','dofile','loadfile','atob'];
  for (const name of sand) {
    L.push(`if has(${ch(name)})then bad=true end`);
  }
  L.push(`end if bad then ${V[10]}=${V[10]}-50 else ${V[10]}=${V[10]}+8 end end`);
  L.push(`pcall(function()if game and game[${ch('JobId')}]==${ch('00000000-0000-0000-0000-000000000000')}then ${V[10]}=${V[10]}-35 end end)`);
  L.push(`pcall(function()if game and(game[${ch('PlaceId')}]==8916037983 or game[${ch('GameId')}]==8916037983)then ${V[10]}=${V[10]}-35 end end)`);
  L.push(`if rawequal and rawequal(pcall,pcall)then ${V[10]}=${V[10]}+6 end`);

  /* alphabet + decode */
  L.push(`local ${V[11]}="${ALPHA}"`);
  L.push(`local ${V[12]}={}`);
  L.push(`for ${V[13]}=1,#${V[11]} do ${V[12]}[${V[6]}(${V[11]},${V[13]},${V[13]})]=${V[13]}-1 end`);
  L.push(`local function ${V[14]}(${V[15]})local ${V[16]}={}local ${V[17]}=1 local ${V[18]}=#${V[15]} while ${V[17]}+1<=${V[18]} do local ${V[19]}=0 local ${V[20]}=0 while ${V[20]}<2 do local ${V[21]}=${V[6]}(${V[15]},${V[17]}+${V[20]},${V[17]}+${V[20]}) ${V[19]}=${V[19]}*(#${V[11]})+(${V[12]}[${V[21]}] or 0) ${V[20]}=${V[20]}+1 end ${V[16]}[#${V[16]}+1]=${V[8]}(${V[19]}%256) ${V[17]}=${V[17]}+2 end return ${V[7]}(${V[16]}) end`);
  L.push(`local function ${V[22]}(${V[23]},${V[24]}) ${V[23]}=${V[23]}%256 ${V[24]}=${V[24]}%256 local ${V[25]}=0 local ${V[26]}=1 for ${V[27]}=1,8 do local ${V[28]}=${V[23]}%2 local ${V[29]}=${V[24]}%2 if ${V[28]}~=${V[29]} then ${V[25]}=${V[25]}+${V[26]} end ${V[23]}=(${V[23]}-${V[28]})/2 ${V[24]}=(${V[24]}-${V[29]})/2 ${V[26]}=${V[26]}*2 end return ${V[25]} end`);

  L.push(`local ${V[30]}={${vLit}}`);
  L.push(`local ${V[31]}="${luaEsc(keySym)}"`);
  L.push(`local ${V[32]}=${V[14]}(${V[7]}(${V[30]}))`);
  L.push(`local ${V[33]}=${V[14]}(${V[31]})`);
  L.push(`local ${V[34]}={} local ${V[35]}=#${V[33]}`);
  L.push(`for ${V[36]}=1,#${V[32]} do local ${V[37]}=${V[5]}(${V[32]},${V[36]}) local ${V[38]}=${V[5]}(${V[33]},((${V[36]}-1)%${V[35]})+1) local ${V[39]}=((${V[36]}-1)*31+17)%256 ${V[34]}[${V[36]}]=${V[8]}(${V[22]}(${V[22]}(${V[37]},${V[38]}),${V[39]})%256) end`);

  /* multi-chunk string so dumper sees fragments not one literal */
  L.push(`local ${V[40]}={} local ${V[41]}=1 local ${V[42]}=#${V[34]} local ${V[43]}=math.max(1,math.floor(${V[42]}/${Math.max(3, nChunks)}))`);
  L.push(`while ${V[41]}<=${V[42]} do local ${V[44]}=math.min(${V[41]}+${V[43]}-1,${V[42]}) local ${V[45]}={} for ${V[46]}=${V[41]},${V[44]} do ${V[45]}[#${V[45]}+1]=${V[34]}[${V[46]}] end ${V[40]}[#${V[40]}+1]=${V[7]}(${V[45]}) ${V[41]}=${V[44]}+1 end`);
  L.push(`${V[32]}=nil ${V[34]}=nil ${V[33]}=nil`);

  /* resolve loader */
  L.push(`local ${V[47]}=${V[9]}(${V[0]},${ch('loadstring')}) or ${V[9]}(${V[0]},${ch('load')})`);
  L.push(`if ${V[1]}(${V[47]})~=${V[8]}(102,117,110,99,116,105,111,110) then return end`);
  /* anti-hook soft */
  L.push(`pcall(function() if iscclosure and not iscclosure(${V[47]}) then ${V[10]}=${V[10]}-15 end end)`);

  /* DECOY flood — pollute dumper with fake loadstrings first */
  L.push(`pcall(function() for ${V[48]}=1,12 do local ${V[49]}=${V[8]}(45,45,32)+tostring(${V[48]}*97) local d=string.rep(${V[49]}.."\\n",60) ${V[47]}(d) end end)`);

  /* assemble + execute — only moment of full source */
  L.push(`local ${V[32]}=${V[7]}(${V[40]}) ${V[40]}=nil`);
  L.push(`local ${V[33]}=${V[47]}(${V[32]}) ${V[32]}=nil`);
  L.push(`if ${V[1]}(${V[33]})==${V[8]}(102,117,110,99,116,105,111,110) then local ${V[34]},${V[35]}=${V[2]}(${V[33]},...) if ${V[34]} then return ${V[35]} end end`);
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
  if (!unscramble(decBuf(sym), key).equals(raw)) throw new Error('roundtrip failed');
  const nChunks = Math.min(24, Math.max(4, Math.ceil(raw.length / 40)));
  const code = buildLoader(sym, key, nChunks);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      chunks: nChunks,
      layers: [
        'symbol-alphabet',
        'xor-stream',
        'api-charcodes',
        'multi-chunk-reassembly',
        'decoy-loadstring-flood',
        'soft-anti-tamper',
        'sandbox-probes',
        'hook-probe',
        'digit-ids',
        'single-line',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
