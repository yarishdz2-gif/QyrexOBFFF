/**
 * QyrexObf 1.6.7 — working symbolic packer
 * ASCII-only alphabet (Luau string.sub is byte-based)
 * NO XOR · arithmetic scramble · anti-tamper · header comment
 */
'use strict';
const crypto = require('crypto');

const MAX = 1_000_000;
// ASCII ONLY — critical for Luau byte strings
const ALPHA =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
  '!#$%&/()=?@_:;+*~[]{}|^<>';
const BASE = ALPHA.length; // 88
const WORD = 2; // 88^2 = 7744 > 255

const rb = n => crypto.randomBytes(n);
const ri = n => rb(1)[0] % n;

function rid(n) {
  n = n || (5 + ri(3));
  const A = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  let s = '_';
  const b = rb(n);
  for (let i = 0; i < n; i++) s += A[b[i] % A.length];
  return s;
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
  let o = '';
  for (let i = 0; i < buf.length; i++) o += encByte(buf[i]);
  return o;
}

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
    for (let x = 1; x < 256; x++) if (((m * x) & 255) === 1) { inv = x; break; }
    t[kk] = inv;
  }
  return t;
}

function checksum(buf) {
  let h = 0x9e3779b1 >>> 0;
  for (let i = 0; i < buf.length; i++)
    h = (h + buf[i] * (i + 31) + ((h % 89) * 17) + 13) >>> 0;
  return h >>> 0;
}

function chunks(sym) {
  const parts = [];
  let i = 0;
  while (i < sym.length) {
    let n = 12 + ri(24);
    n -= n % WORD;
    if (n < WORD) n = WORD;
    const take = Math.min(sym.length - i, n);
    const aligned = take - (take % WORD) || take;
    parts.push(sym.slice(i, i + aligned));
    i += aligned;
  }
  return parts;
}

/** Node-side decode to verify roundtrip */
function decodeBuf(sym) {
  const map = {};
  for (let i = 0; i < ALPHA.length; i++) map[ALPHA[i]] = i;
  const out = [];
  for (let pos = 0; pos < sym.length; pos += WORD) {
    let n = 0;
    for (let i = 0; i < WORD; i++) {
      const ch = sym[pos + i];
      n = n * BASE + (map[ch] || 0);
    }
    out.push(n % 256);
  }
  return Buffer.from(out);
}

function unscramble(data, key) {
  const inv = invTable();
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    const k = key[i % kl];
    const p = (i * 131 + 17) & 255;
    const q = (i * 47 + k * 3) & 255;
    b = (b + ((p * 3 + k) & 255)) & 255;
    let m = ((k | 1) * 5) & 255;
    if (!m) m = 1;
    b = ((b - q + 256) * inv[k]) & 255;
    const rot = (k % 7) + 1;
    b = ((b >>> rot) | (b << (8 - rot))) & 255; // inverse rotate
    b = (b - k - p + 512) & 255;
    out[i] = b;
  }
  return out;
}

function build(sym, key, sum, len) {
  const A = rid(), B = rid(), C = rid(), D = rid(), E = rid();
  const F = rid(), G = rid(), H = rid(), I = rid(), J = rid();
  const K = rid(), L = rid(), M = rid(), N = rid(), O = rid();
  const P = rid(), Q = rid(), R = rid(), S = rid(), T = rid();
  const U = rid(), V = rid(), W = rid(), X = rid(), Y = rid(), Z = rid();

  const parts = chunks(sym);
  const vLit = parts.map((p, idx) => {
    const sep = idx < parts.length - 1 ? (ri(3) ? ',' : ';') : '';
    return `"${p}"${sep}`;
  }).join('');

  const keySym = encBuf(key);
  const inv = invTable().join(',');
  // escape alpha for Lua string
  const alphaLit = ALPHA.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

  // Readable multi-line for reliability — still dense payload
  const lines = [];
  lines.push(`-- Protect by QyrexObf 1.6.7`);
  lines.push(`return(function(...)`);
  // anti-tamper (won't kill non-Roblox / legit clients)
  lines.push(`local ${A}=1`);
  lines.push(`local ${B}=type`);
  lines.push(`local ${C}=rawget`);
  lines.push(`local ${D}=pcall`);
  lines.push(`do`);
  lines.push(`if ${B}(pcall)~="function" then ${A}=0 end`);
  lines.push(`if ${B}(string)~="table" and ${B}(string)~="userdata" then ${A}=0 end`);
  lines.push(`if ${B}(table)~="table" and ${B}(table)~="userdata" then ${A}=0 end`);
  lines.push(`if ${B}(math)~="table" and ${B}(math)~="userdata" then ${A}=0 end`);
  lines.push(`if ${B}(loadstring)~="function" and ${B}(load)~="function" then ${A}=0 end`);
  lines.push(`if string.byte("A")~=65 then ${A}=0 end`);
  lines.push(`if math.floor(3.9)~=3 then ${A}=0 end`);
  lines.push(`do local ok=${D}(error,"x",0) if ok then ${A}=0 end end`);
  lines.push(`local ${E},${F}=${D}(function() return (getfenv and getfenv(0)) or _G end)`);
  lines.push(`if not ${E} or ${B}(${F})~="table" then ${A}=0 end`);
  lines.push(`if ${C} and ${F} then`);
  lines.push(`if ${C}(${F},"__builtins__")~=nil then ${A}=0 end`);
  lines.push(`if ${C}(${F},"__name__")~=nil then ${A}=0 end`);
  lines.push(`end`);
  lines.push(`if game~=nil then`);
  lines.push(`if ${B}(game)==${B}({}) then ${A}=0 end`);
  lines.push(`local okj,jid=${D}(function() return game.JobId end)`);
  lines.push(`if okj and jid=="00000000-0000-0000-0000-000000000000" then ${A}=0 end`);
  lines.push(`local okp,pid=${D}(function() return game.PlaceId end)`);
  lines.push(`if okp and pid==8916037983 then ${A}=0 end`);
  lines.push(`end`);
  lines.push(`end`);
  lines.push(`if ${A}~=1 then return function() end end`);

  lines.push(`local ${G}={${vLit}}`);
  lines.push(`local ${H}="${alphaLit}"`);
  lines.push(`local ${I}={}`);
  lines.push(`for ${J}=1,#${H} do ${I}[string.sub(${H},${J},${J})]=${J}-1 end`);
  lines.push(`local ${K}="${keySym}"`);
  lines.push(`local ${L}=${sum}`);
  lines.push(`local ${M}={${inv}}`);
  lines.push(`local ${N}=table.concat(${G})`);

  // decode
  lines.push(`local function ${O}(z)`);
  lines.push(`local o,pos={},1`);
  lines.push(`while pos<=#z do`);
  lines.push(`local n=0`);
  lines.push(`for i=0,${WORD-1} do`);
  lines.push(`local ch=string.sub(z,pos+i,pos+i)`);
  lines.push(`n=n*${BASE}+(${I}[ch] or 0)`);
  lines.push(`end`);
  lines.push(`o[#o+1]=string.char(n%256)`);
  lines.push(`pos=pos+${WORD}`);
  lines.push(`end`);
  lines.push(`return table.concat(o)`);
  lines.push(`end`);

  // unscramble — must match Node unscramble exactly
  lines.push(`local function ${P}(data,key)`);
  lines.push(`local o,kl={},#key`);
  lines.push(`for i=1,#data do`);
  lines.push(`local b=string.byte(data,i)`);
  lines.push(`local k=string.byte(key,((i-1)%kl)+1)`);
  lines.push(`local p=((i-1)*131+17)%256`);
  lines.push(`local q=(((i-1)*47)+(k*3))%256`);
  lines.push(`b=(b+((p*3+k)%256))%256`);
  lines.push(`local m=((k%2==0 and k+1 or k)*5)%256`);
  lines.push(`if m==0 then m=1 end`);
  lines.push(`b=((b-q+256)*${M}[k+1])%256`);
  lines.push(`local rot=(k%7)+1`);
  lines.push(`local hi=math.floor(b/(2^rot))`);
  lines.push(`local lo=b%(2^rot)`);
  lines.push(`b=(lo*(2^(8-rot))+hi)%256`);
  lines.push(`b=(b-k-p+512)%256`);
  lines.push(`o[i]=string.char(b)`);
  lines.push(`end`);
  lines.push(`return table.concat(o)`);
  lines.push(`end`);

  lines.push(`local ${Q}=${O}(${N})`);
  lines.push(`local ${R}=${O}(${K})`);
  lines.push(`do local h=2654435761`);
  lines.push(`for i=1,#${Q} do local b=string.byte(${Q},i) h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 end`);
  lines.push(`if h~=${L} or #${Q}~=${len} then return function() end end`);
  lines.push(`end`);
  lines.push(`local ${S}=${P}(${Q},${R})`);
  lines.push(`if #${S}~=${len} then return function() end end`);
  lines.push(`local ${T}=(loadstring or load)(${S})`);
  lines.push(`if type(${T})~="function" then return function() end end`);
  lines.push(`return ${T}(...)`);
  lines.push(`end)(...)`);

  return lines.join('\n');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  if (Buffer.byteLength(src, 'utf8') > MAX) throw new Error('Too large');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(32 + ri(8));
  const scrambled = scramble(raw, key);
  const sum = checksum(scrambled);
  const sym = encBuf(scrambled);

  // verify roundtrip in Node before emitting
  const decoded = decodeBuf(sym);
  if (!decoded.equals(scrambled)) {
    throw new Error('Internal encode/decode mismatch');
  }
  const plain = unscramble(decoded, key);
  if (!plain.equals(raw)) {
    throw new Error('Internal scramble/unscramble mismatch');
  }

  const code = build(sym, key, sum, scrambled.length);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-1.6.7',
      encoding: 'arith-scramble + ascii-alphabet (NO xor)',
      verified: true
    }
  };
}

module.exports = { obfuscate };
