/**
 * QyrexObf 1.0.0
 * - Symbol-only payload
 * - APIs resolved via string.char codes (no "string.byte" literals)
 * - Soft anti-tamper fused from user suites (never kills clean Roblox)
 * - Must execute
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
  const step = 90 + ri(50);
  for (let i = 0; i < sym.length; i += step) out.push(sym.slice(i, i + step));
  return out;
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

/** emit string.char(n1,n2,...) for a JS string */
function charCodes(s) {
  const bytes = Buffer.from(s, 'utf8');
  return 'string.char(' + [...bytes].join(',') + ')';
}

function buildLoader(sym, key) {
  const id = () => rid();
  const v = {};
  for (let i = 0; i < 40; i++) v['x' + i] = id();

  const parts = chunkSym(sym);
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');
  const keySym = encBuf(key);
  const e = (s) => luaEsc(encStr(s));

  // Resolve libraries without "string.byte" etc. as contiguous readable names in assignment
  // Use: local lib = _G[string.char(...)]
  const S_STRING = charCodes('string');
  const S_TABLE = charCodes('table');
  const S_BYTE = charCodes('byte');
  const S_SUB = charCodes('sub');
  const S_CONCAT = charCodes('concat');
  const S_CHAR = charCodes('char');
  const S_TYPE = charCodes('type');
  const S_PCALL = charCodes('pcall');
  const S_TOSTRING = charCodes('tostring');
  const S_RAWGET = charCodes('rawget');
  const S_LOADSTRING = charCodes('loadstring');
  const S_LOAD = charCodes('load');

  const L = [];
  L.push('return(function(...)');

  /* bootstrap resolve */
  L.push(`local ${v.x0}=_G`);
  L.push(`local ${v.x1}=${v.x0}[${S_TYPE}] or type`);
  L.push(`local ${v.x2}=${v.x0}[${S_PCALL}] or pcall`);
  L.push(`local ${v.x3}=${v.x0}[${S_STRING}] or string`);
  L.push(`local ${v.x4}=${v.x0}[${S_TABLE}] or table`);
  L.push(`local ${v.x5}=${v.x3}[${S_BYTE}]`);
  L.push(`local ${v.x6}=${v.x3}[${S_SUB}]`);
  L.push(`local ${v.x7}=${v.x4}[${S_CONCAT}]`);
  L.push(`local ${v.x8}=${v.x3}[${S_CHAR}]`);
  L.push(`local ${v.x9}=${v.x0}[${S_RAWGET}] or rawget`);
  L.push(`local ${v.x10}=0`);

  /* soft anti-tamper (message-9 / message-8 / BESTAT style, score only) */
  L.push(`if ${v.x1}(${v.x3})==${v.x8}(116,97,98,108,101) then ${v.x10}=${v.x10}+10 end`);
  L.push(`if ${v.x1}(${v.x5})==${v.x8}(102,117,110,99,116,105,111,110) then ${v.x10}=${v.x10}+10 end`);
  L.push(`if ${v.x5}(${v.x8}(65))==65 then ${v.x10}=${v.x10}+10 end`);
  L.push(`if math and math.floor(3.9)==3 then ${v.x10}=${v.x10}+8 end`);
  L.push(`do local a=${v.x2}(error,"\\0",0) if not a then ${v.x10}=${v.x10}+8 end end`);
  L.push(`if game~=nil and typeof and typeof(game)==${v.x8}(73,110,115,116,97,110,99,101) then ${v.x10}=${v.x10}+10 end`);
  /* sandbox leaks */
  L.push(`do local bad=false if ${v.x1}(${v.x0})==${v.x8}(116,97,98,108,101) then local function has(k) local ok,val=${v.x2}(function() return ${v.x9}(${v.x0},k) end) return ok and val~=nil end if has(${v.x8}(112,114,111,99,101,115,115)) or has(${v.x8}(119,105,110,100,111,119)) or has(${v.x8}(100,111,99,117,109,101,110,116)) or has(${v.x8}(108,117,110,101)) or has(${v.x8}(108,117,116,101)) or has(${v.x8}(114,111,106,111)) then bad=true end end if bad then ${v.x10}=${v.x10}-40 else ${v.x10}=${v.x10}+8 end end`);
  /* JobId zero sandbox */
  L.push(`pcall(function() if game and game[${v.x8}(74,111,98,73,100)]==${v.x8}(48,48,48,48,48,48,48,48,45,48,48,48,48,45,48,48,48,48,45,48,48,48,48,45,48,48,48,48,48,48,48,48,48,48,48,48) then ${v.x10}=${v.x10}-30 end end)`);
  /* getfenv identity soft */
  L.push(`pcall(function() if getfenv then local ok,env=${v.x2}(getfenv,0) if ok and env and ${v.x1}(env)==${v.x8}(116,97,98,108,101) then if env.getfenv~=nil and env.getfenv~=getfenv then ${v.x10}=${v.x10}-20 end end end end)`);
  /* rawequal pcall */
  L.push(`if rawequal and rawequal(pcall,pcall) then ${v.x10}=${v.x10}+6 end`);
  /* never abort on score */

  /* alphabet decoder */
  L.push(`local ${v.x11}="${ALPHA}"`);
  L.push(`local ${v.x12}={}`);
  L.push(`for ${v.x13}=1,#${v.x11} do ${v.x12}[${v.x6}(${v.x11},${v.x13},${v.x13})]=${v.x13}-1 end`);
  L.push(`local function ${v.x14}(${v.x15}) local ${v.x16}={} local ${v.x17}=1 local ${v.x18}=#${v.x15} while ${v.x17}+1<=${v.x18} do local ${v.x19}=0 local ${v.x20}=0 while ${v.x20}<2 do local ${v.x21}=${v.x6}(${v.x15},${v.x17}+${v.x20},${v.x17}+${v.x20}) ${v.x19}=${v.x19}*(#${v.x11})+(${v.x12}[${v.x21}] or 0) ${v.x20}=${v.x20}+1 end ${v.x16}[#${v.x16}+1]=${v.x8}(${v.x19}%256) ${v.x17}=${v.x17}+2 end return ${v.x7}(${v.x16}) end`);

  /* pure XOR */
  L.push(`local function ${v.x22}(${v.x23},${v.x24}) ${v.x23}=${v.x23}%256 ${v.x24}=${v.x24}%256 local ${v.x25}=0 local ${v.x26}=1 for ${v.x27}=1,8 do local ${v.x28}=${v.x23}%2 local ${v.x29}=${v.x24}%2 if ${v.x28}~=${v.x29} then ${v.x25}=${v.x25}+${v.x26} end ${v.x23}=(${v.x23}-${v.x28})/2 ${v.x24}=(${v.x24}-${v.x29})/2 ${v.x26}=${v.x26}*2 end return ${v.x25} end`);

  L.push(`local ${v.x30}={${vLit}}`);
  L.push(`local ${v.x31}="${luaEsc(keySym)}"`);
  L.push(`local ${v.x32}=${v.x14}(${v.x7}(${v.x30}))`);
  L.push(`local ${v.x33}=${v.x14}(${v.x31})`);
  L.push(`local ${v.x34}={} local ${v.x35}=#${v.x33}`);
  L.push(`for ${v.x36}=1,#${v.x32} do local ${v.x37}=${v.x5}(${v.x32},${v.x36}) local ${v.x38}=${v.x5}(${v.x33},((${v.x36}-1)%${v.x35})+1) local ${v.x39}=((${v.x36}-1)*31+17)%256 ${v.x34}[${v.x36}]=${v.x8}(${v.x22}(${v.x22}(${v.x37},${v.x38}),${v.x39})%256) end`);
  L.push(`local ${v.x30}=${v.x7}(${v.x34})`);
  L.push(`${v.x32}=nil ${v.x34}=nil ${v.x33}=nil`);

  /* loader without literal loadstring if possible */
  L.push(`local ${v.x31}=${v.x9}(${v.x0},${S_LOADSTRING}) or ${v.x9}(${v.x0},${S_LOAD}) `);
  L.push(`if ${v.x1}(${v.x31})~=${v.x8}(102,117,110,99,116,105,111,110) then return end`);
  L.push(`local ${v.x32}=${v.x31}(${v.x30})`);
  L.push(`${v.x30}=nil`);
  L.push(`if ${v.x1}(${v.x32})==${v.x8}(102,117,110,99,116,105,111,110) then local ${v.x33},${v.x34}=${v.x2}(${v.x32},...) if ${v.x33} then return ${v.x34} end end`);
  L.push(`end)(...)`);

  return `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]]\n` + L.join(' ');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const raw = Buffer.from(src, 'utf8');
  if (raw.length > 1500000) throw new Error('Too large');
  const key = rb(32 + ri(16));
  const scrambled = scramble(raw, key);
  const sym = encBuf(scrambled);
  if (!unscramble(decBuf(sym), key).equals(raw)) throw new Error('roundtrip failed');
  const code = buildLoader(sym, key);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      layers: [
        'symbol-alphabet',
        'xor',
        'api-via-charcodes',
        'soft-anti-tamper',
        'sandbox-probes',
        'digit-ids',
        'single-line',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
