/**
 * Symbolic Overload v2 — table-style payload
 * Output shape:
 *   return(function(...)local v={"iA7_Wm";"b..==",...} ... end)(...)
 *
 * NO standard Base64 · NO XOR · arithmetic scramble + custom alphabet
 * Alphabet includes: ! # $ % & / ( ) = ? ¡ _ > : Z ; X and alphanumerics
 */
'use strict';
const crypto = require('crypto');

const MAX = 1_000_000;

// Custom alphabet (NOT standard base64). Includes user symbols.
// Avoid double-quote and backslash so Lua string literals stay valid.
const ALPHA =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' +
  '!#$%&/()=?¡_>:;X+*~@[]{}|^';
const BASE = ALPHA.length; // ~90+
const WORD = 2; // BASE^2 >> 255

const rb = n => crypto.randomBytes(n);
const ri = n => rb(1)[0] % n;

function rid(len) {
  len = len || (6 + ri(4));
  const A = 'IlOabcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  let s = '_';
  const b = rb(len);
  for (let i = 0; i < len; i++) s += A[b[i] % A.length];
  return s + String(ri(9));
}

function encodeByte(b) {
  let n = b & 255;
  let w = '';
  for (let i = 0; i < WORD; i++) {
    w = ALPHA[n % BASE] + w;
    n = (n / BASE) | 0;
  }
  return w;
}

function encodeBuf(buf) {
  let out = '';
  for (let i = 0; i < buf.length; i++) out += encodeByte(buf[i]);
  // sprinkle visual noise tokens that decoder ignores (pad groups of 0 length via marker)
  return out;
}

/* arithmetic scramble — no XOR */
function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    const k = key[i % kl];
    const p = (i * 131 + 17) & 255;
    const q = (i * 47 + k * 3) & 255;
    b = (b + k + p) & 255;
    const rot = (k % 7) + 1;
    b = ((b << rot) | (b >>> (8 - rot))) & 255;
    let m = ((k | 1) * 5) & 255;
    if (!m) m = 1;
    b = (b * m + q) & 255;
    b = (b - ((p * 3 + k) & 255) + 256) & 255;
    out[i] = b;
  }
  return out;
}

function invTable() {
  const t = new Array(256);
  for (let kk = 0; kk < 256; kk++) {
    let m = ((kk | 1) * 5) & 255;
    if (!m) m = 1;
    let inv = 1;
    for (let x = 1; x < 256; x++) {
      if (((m * x) & 255) === 1) { inv = x; break; }
    }
    t[kk] = inv;
  }
  return t;
}

function checksum(buf) {
  let h = 0x9e3779b1 >>> 0;
  for (let i = 0; i < buf.length; i++) {
    h = (h + buf[i] * (i + 31) + ((h % 89) * 17) + 13) >>> 0;
  }
  return h >>> 0;
}

/** Split encoded stream into random-looking table entries */
function chunkPayload(sym, minLen, maxLen) {
  const parts = [];
  let i = 0;
  while (i < sym.length) {
    const n = minLen + ri(maxLen - minLen + 1);
    // keep even length (WORD-aligned)
    const take = Math.min(sym.length - i, n - (n % WORD));
    if (take < WORD) {
      parts.push(sym.slice(i));
      break;
    }
    parts.push(sym.slice(i, i + take));
    i += take;
  }
  return parts;
}

function buildAntiTamper(N) {
  // Conservative anti-tamper inspired by provided samples — no infinite loops on legit envs
  return [
    `local ${N.safe}=true`,
    `local function ${N.chk}()`,
    `  if type(pcall)~="function" then ${N.safe}=false return end`,
    `  if type(string)~="table" and type(string)~="userdata" then ${N.safe}=false return end`,
    `  if type(table)~="table" and type(table)~="userdata" then ${N.safe}=false return end`,
    `  if type(loadstring)~="function" and type(load)~="function" then ${N.safe}=false return end`,
    `  local ok,env=pcall(function() return (getfenv and getfenv(0)) or _G end)`,
    `  if not ok or type(env)~="table" then ${N.safe}=false return end`,
    `  if rawget and rawget(env,"__builtins__")~=nil then ${N.safe}=false return end`,
    `  local t0=(os and os.clock and os.clock()) or 0`,
    `  for ${N.i}=1,40 do pcall(function() return ${N.i}*${N.i} end) end`,
    `  local t1=(os and os.clock and os.clock()) or 0`,
    `  if t1>0 and t0>0 and (t1-t0)>0.35 then ${N.safe}=false return end`,
    `end`,
    `${N.chk}()`,
    `if not ${N.safe} then return function() end end`
  ].join('\n');
}

function build(symPayload, key, sum, rawLen) {
  const N = {
    v: 'v',
    a: rid(), b: rid(), c: rid(), d: rid(), e: rid(),
    f: rid(), g: rid(), h: rid(), i: rid(), k: rid(),
    p: rid(), s: rid(), t: rid(), u: rid(), x: rid(),
    y: rid(), safe: rid(), chk: rid()
  };

  const parts = chunkPayload(symPayload, 8, 28);
  // Mix separators like the sample: ; and ,
  const tableLit = parts.map((p, idx) => {
    const sep = idx < parts.length - 1 ? (ri(3) === 0 ? ';' : ',') : '';
    return `"${p}"${sep}`;
  }).join('');

  const keySym = encodeBuf(key);
  const inv = invTable();
  const invLit = inv.join(',');
  const alphaLit = [...ALPHA].map(c => {
    if (c === '\\') return '"\\\\"';
    if (c === '"') return '"\\""';
    return `"${c}"`;
  }).join(',');

  // Compact single-expression style close to the sample
  const lines = [];
  lines.push('return(function(...)');
  lines.push(buildAntiTamper(N));
  lines.push(`local ${N.v}={${tableLit}}`);
  lines.push(`local ${N.a}={${alphaLit}}`);
  lines.push(`local ${N.b}={}`);
  lines.push(`for ${N.i}=1,#${N.a} do ${N.b}[${N.a}[${N.i}]]=${N.i}-1 end`);
  lines.push(`local ${N.k}="${keySym}"`);
  lines.push(`local ${N.h}=${sum}`);
  lines.push(`local ${N.p}={${invLit}}`);
  lines.push(`local ${N.c}=table.concat(${N.v})`);

  // decode symbols → bytes
  lines.push(`local function ${N.d}(z)`);
  lines.push(`local o,pos={},1`);
  lines.push(`while pos<=#z do`);
  lines.push(`local n=0`);
  lines.push(`for ${N.i}=0,${WORD - 1} do local ch=string.sub(z,pos+${N.i},pos+${N.i}) n=n*${BASE}+(${N.b}[ch] or 0) end`);
  lines.push(`o[#o+1]=string.char(n%256) pos=pos+${WORD}`);
  lines.push(`end`);
  lines.push(`return table.concat(o) end`);

  // unscramble
  lines.push(`local function ${N.e}(data,key)`);
  lines.push(`local o,kl={},#key`);
  lines.push(`for ${N.i}=1,#data do`);
  lines.push(`local b=string.byte(data,${N.i})`);
  lines.push(`local k=string.byte(key,((${N.i}-1)%kl)+1)`);
  lines.push(`local p=((${N.i}-1)*131+17)%256`);
  lines.push(`local q=(((${N.i}-1)*47)+(k*3))%256`);
  lines.push(`b=(b+((p*3+k)%256))%256`);
  lines.push(`local m=((k%2==0 and k+1 or k)*5)%256 if m==0 then m=1 end`);
  lines.push(`b=((b-q+256)*${N.p}[k+1])%256`);
  lines.push(`local rot=(k%7)+1 local hi=math.floor(b/(2^rot)) local lo=b%(2^rot)`);
  lines.push(`b=(lo*(2^(8-rot))+hi)%256`);
  lines.push(`b=(b-k-p+512)%256`);
  lines.push(`o[${N.i}]=string.char(b)`);
  lines.push(`end return table.concat(o) end`);

  lines.push(`local ${N.t}=${N.d}(${N.c})`);
  lines.push(`local ${N.u}=${N.d}(${N.k})`);

  // integrity
  lines.push(`do local h=2654435761`);
  lines.push(`for ${N.i}=1,#${N.t} do local b=string.byte(${N.t},${N.i}) h=(h+b*(${N.i}+30)+((h%89)*17)+13)%4294967296 end`);
  lines.push(`if h~=${N.h} or #${N.t}~=${rawLen} then return function()end end end`);

  lines.push(`local ${N.s}=${N.e}(${N.t},${N.u})`);
  lines.push(`local ${N.x}=(loadstring or load)(${N.s})`);
  lines.push(`if type(${N.x})=="function" then return ${N.x}(...) end`);
  lines.push(`end)(...)`);

  return lines.join('\n');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  if (Buffer.byteLength(src, 'utf8') > MAX) throw new Error('Too large');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(28 + ri(12));
  const scrambled = scramble(raw, key);
  const sum = checksum(scrambled);
  const sym = encodeBuf(scrambled);
  const code = build(sym, key, sum, scrambled.length);

  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'symbolic-table-v2',
      alphabetSize: BASE,
      encoding: 'arith-scramble + custom-alphabet (no xor / no std base64)'
    }
  };
}

module.exports = { obfuscate };
