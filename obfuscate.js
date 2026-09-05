/**
 * QyrexObf 1.6.8
 * NO XOR · NO inv-table · NO Base64
 * Scramble: add / rot / add / sub  (all invertible with plain arithmetic)
 * Alphabet: ASCII symbols + digits
 */
'use strict';
const crypto = require('crypto');

const MAX = 1_000_000;
const ALPHA =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
  '!#$%&/()=?@_:;+*~[]{}|^<>';
const BASE = ALPHA.length;
const WORD = 2;

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
function decBuf(sym) {
  const map = Object.create(null);
  for (let i = 0; i < ALPHA.length; i++) map[ALPHA[i]] = i;
  const out = Buffer.allocUnsafe(sym.length / WORD);
  let j = 0;
  for (let pos = 0; pos < sym.length; pos += WORD) {
    let n = 0;
    for (let i = 0; i < WORD; i++) n = n * BASE + (map[sym[pos + i]] || 0);
    out[j++] = n & 255;
  }
  return out;
}

/* ---------- scramble: ONLY add / rotate / sub (NO xor, NO mul-inv) ---------- */
function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    const k = key[i % kl];
    const p = (i * 131 + 17) & 255;
    // 1. add
    b = (b + k) & 255;
    // 2. rotate left by (k%7)+1
    const rot = (k % 7) + 1;
    b = ((b << rot) | (b >>> (8 - rot))) & 255;
    // 3. add position mix
    b = (b + p) & 255;
    // 4. rotate left by ((p%5)+1)
    const rot2 = (p % 5) + 1;
    b = ((b << rot2) | (b >>> (8 - rot2))) & 255;
    // 5. subtract derived
    b = (b - ((k + p * 3) & 255) + 256) & 255;
    out[i] = b;
  }
  return out;
}

function unscramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    const k = key[i % kl];
    const p = (i * 131 + 17) & 255;
    const rot = (k % 7) + 1;
    const rot2 = (p % 5) + 1;
    // inverse 5: add back
    b = (b + ((k + p * 3) & 255)) & 255;
    // inverse 4: rotate right rot2
    b = ((b >>> rot2) | (b << (8 - rot2))) & 255;
    // inverse 3: sub p
    b = (b - p + 256) & 255;
    // inverse 2: rotate right rot
    b = ((b >>> rot) | (b << (8 - rot))) & 255;
    // inverse 1: sub k
    b = (b - k + 256) & 255;
    out[i] = b;
  }
  return out;
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

function build(sym, key, sum, len) {
  const id = {};
  for (const c of 'ABCDEFGHIJKLMNOPQRSTUV') id[c] = rid();

  const parts = chunks(sym);
  const vLit = parts.map((p, i) => {
    const sep = i < parts.length - 1 ? (ri(3) ? ',' : ';') : '';
    return `"${p}"${sep}`;
  }).join('');

  const keySym = encBuf(key);
  const alphaLit = ALPHA.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

  const L = [];
  L.push(`-- Protect by QyrexObf 1.6.8`);
  L.push(`return(function(...)`);
  L.push(`local ${id.A}=1`);
  L.push(`local ${id.B}=type`);
  L.push(`local ${id.C}=rawget`);
  L.push(`local ${id.D}=pcall`);
  L.push(`do`);
  L.push(`if ${id.B}(pcall)~="function" then ${id.A}=0 end`);
  L.push(`if ${id.B}(string)~="table" and ${id.B}(string)~="userdata" then ${id.A}=0 end`);
  L.push(`if ${id.B}(table)~="table" and ${id.B}(table)~="userdata" then ${id.A}=0 end`);
  L.push(`if ${id.B}(math)~="table" and ${id.B}(math)~="userdata" then ${id.A}=0 end`);
  L.push(`if ${id.B}(loadstring)~="function" and ${id.B}(load)~="function" then ${id.A}=0 end`);
  L.push(`if string.byte("A")~=65 then ${id.A}=0 end`);
  L.push(`if math.floor(3.9)~=3 then ${id.A}=0 end`);
  L.push(`do local ok=${id.D}(error,"x",0) if ok then ${id.A}=0 end end`);
  L.push(`local ${id.E},${id.F}=${id.D}(function() return (getfenv and getfenv(0)) or _G end)`);
  L.push(`if not ${id.E} or ${id.B}(${id.F})~="table" then ${id.A}=0 end`);
  L.push(`if ${id.C} and ${id.F} then`);
  L.push(`if ${id.C}(${id.F},"__builtins__")~=nil then ${id.A}=0 end`);
  L.push(`if ${id.C}(${id.F},"__name__")~=nil then ${id.A}=0 end`);
  L.push(`end`);
  L.push(`if game~=nil then`);
  L.push(`if ${id.B}(game)==${id.B}({}) then ${id.A}=0 end`);
  L.push(`local oj,jid=${id.D}(function() return game.JobId end)`);
  L.push(`if oj and jid=="00000000-0000-0000-0000-000000000000" then ${id.A}=0 end`);
  L.push(`local op,pid=${id.D}(function() return game.PlaceId end)`);
  L.push(`if op and pid==8916037983 then ${id.A}=0 end`);
  L.push(`end`);
  L.push(`end`);
  L.push(`if ${id.A}~=1 then return function() end end`);

  L.push(`local ${id.G}={${vLit}}`);
  L.push(`local ${id.H}="${alphaLit}"`);
  L.push(`local ${id.I}={}`);
  L.push(`for ${id.J}=1,#${id.H} do ${id.I}[string.sub(${id.H},${id.J},${id.J})]=${id.J}-1 end`);
  L.push(`local ${id.K}="${keySym}"`);
  L.push(`local ${id.L}=${sum}`);
  L.push(`local ${id.M}=table.concat(${id.G})`);

  // decode symbols -> bytes
  L.push(`local function ${id.N}(z)`);
  L.push(`local o,pos={},1`);
  L.push(`while pos<=#z do`);
  L.push(`local n=0`);
  L.push(`for i=0,${WORD-1} do local ch=string.sub(z,pos+i,pos+i) n=n*${BASE}+(${id.I}[ch] or 0) end`);
  L.push(`o[#o+1]=string.char(n%256)`);
  L.push(`pos=pos+${WORD}`);
  L.push(`end`);
  L.push(`return table.concat(o) end`);

  // unscramble — pure arithmetic, NO table, NO xor
  L.push(`local function ${id.O}(data,key)`);
  L.push(`local o,kl={},#key`);
  L.push(`for i=1,#data do`);
  L.push(`local b=string.byte(data,i)`);
  L.push(`local k=string.byte(key,((i-1)%kl)+1)`);
  L.push(`local p=((i-1)*131+17)%256`);
  L.push(`local rot=(k%7)+1`);
  L.push(`local rot2=(p%5)+1`);
  L.push(`b=(b+((k+p*3)%256))%256`);
  L.push(`local hi=math.floor(b/(2^rot2)) local lo=b%(2^rot2) b=(lo*(2^(8-rot2))+hi)%256`);
  L.push(`b=(b-p+256)%256`);
  L.push(`hi=math.floor(b/(2^rot)) lo=b%(2^rot) b=(lo*(2^(8-rot))+hi)%256`);
  L.push(`b=(b-k+256)%256`);
  L.push(`o[i]=string.char(b)`);
  L.push(`end`);
  L.push(`return table.concat(o) end`);

  L.push(`local ${id.P}=${id.N}(${id.M})`);
  L.push(`local ${id.Q}=${id.N}(${id.K})`);
  L.push(`do local h=2654435761`);
  L.push(`for i=1,#${id.P} do local b=string.byte(${id.P},i) h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 end`);
  L.push(`if h~=${id.L} or #${id.P}~=${len} then return function() end end`);
  L.push(`end`);
  L.push(`local ${id.R}=${id.O}(${id.P},${id.Q})`);
  L.push(`if #${id.R}~=${len} then return function() end end`);
  L.push(`local ${id.S}=(loadstring or load)(${id.R})`);
  L.push(`if type(${id.S})~="function" then return function() end end`);
  L.push(`return ${id.S}(...)`);
  L.push(`end)(...)`);

  return L.join('\n');
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

  // hard verify
  const back = unscramble(decBuf(sym), key);
  if (!back.equals(raw)) throw new Error('roundtrip failed');

  const code = build(sym, key, sum, scrambled.length);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-1.6.8',
      encoding: 'add+rot+sub only (NO xor, NO inv-table, NO base64)',
      verified: true
    }
  };
}

module.exports = { obfuscate };
