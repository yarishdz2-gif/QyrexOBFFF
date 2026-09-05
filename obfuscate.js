/**
 * QyrexObf 1.6.7 — EXECUTABLE single-line body
 * Header comment + one line return(function...)()
 * NO XOR · symbol alphabet · minimal safe checks only
 */
'use strict';
const crypto = require('crypto');

const MAX = 1_000_000;
const ALPHA =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
  '!#$%&/()=?@_:;+*~[]{}';
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
  const out = Buffer.allocUnsafe((sym.length / WORD) | 0);
  let j = 0;
  for (let pos = 0; pos + WORD <= sym.length; pos += WORD) {
    let n = 0;
    for (let i = 0; i < WORD; i++) n = n * BASE + (map[sym[pos + i]] || 0);
    out[j++] = n & 255;
  }
  return out.subarray(0, j);
}

function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    const k = key[i % kl];
    const p = (i * 131 + 17) & 255;
    b = (b + k) & 255;
    const rot = (k % 7) + 1;
    b = ((b << rot) | (b >>> (8 - rot))) & 255;
    b = (b + p) & 255;
    const rot2 = (p % 5) + 1;
    b = ((b << rot2) | (b >>> (8 - rot2))) & 255;
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
    b = (b + ((k + p * 3) & 255)) & 255;
    b = ((b >>> rot2) | (b << (8 - rot2))) & 255;
    b = (b - p + 256) & 255;
    b = ((b >>> rot) | (b << (8 - rot))) & 255;
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
    let n = 20 + ri(36);
    n -= n % WORD;
    if (n < WORD) n = WORD;
    const take = Math.min(sym.length - i, n);
    const aligned = take - (take % WORD) || take;
    parts.push(sym.slice(i, i + aligned));
    i += aligned;
  }
  return parts;
}

function noise(n) {
  const b = rb(n);
  let s = '';
  for (let i = 0; i < n; i++) s += ALPHA[b[i] % BASE];
  return s;
}

function build(sym, key, sum, len) {
  const A = rid(), B = rid(), C = rid(), D = rid(), E = rid();
  const F = rid(), G = rid(), H = rid(), I = rid(), J = rid();
  const K = rid(), L = rid(), M = rid(), N = rid(), O = rid();

  const parts = chunks(sym);
  const vLit = parts.map((p, idx) => {
    const sep = idx < parts.length - 1 ? (ri(2) ? ';' : ',') : '';
    return `"${p}"${sep}`;
  }).join('');

  const keySym = encBuf(key);
  const alphaLit = ALPHA;
  const junk1 = noise(32 + ri(24));
  const junk2 = noise(32 + ri(24));

  // ONE executable line (after header). Compact but valid Lua.
  // Minimal bootstrap: concat → decode → unscramble → load → call
  // No aggressive anti-tamper that can silent-fail on real executors.
  // Build as lines then join to ONE line (balanced)
  const lines = [];
  lines.push(`return(function(...)`);
  lines.push(`local ${A}={${vLit}}`);
  lines.push(`local ${B}="${junk1}"`);
  lines.push(`local ${C}="${junk2}"`);
  lines.push(`local ${D}="${alphaLit}"`);
  lines.push(`local ${E}={}`);
  lines.push(`for ${F}=1,#${D} do ${E}[string.sub(${D},${F},${F})]=${F}-1 end`);
  lines.push(`local ${G}="${keySym}"`);
  lines.push(`local ${H}=${sum}`);
  lines.push(`local ${I}=table.concat(${A})`);
  lines.push(`local function ${J}(z)`);
  lines.push(`local o,pos={},1`);
  lines.push(`while pos<=#z do`);
  lines.push(`local n=0`);
  lines.push(`for i=0,1 do`);
  lines.push(`local ch=string.sub(z,pos+i,pos+i)`);
  lines.push(`n=n*${BASE}+(${E}[ch] or 0)`);
  lines.push(`end`);
  lines.push(`o[#o+1]=string.char(n%256)`);
  lines.push(`pos=pos+2`);
  lines.push(`end`);
  lines.push(`return table.concat(o)`);
  lines.push(`end`);
  lines.push(`local function ${K}(data,key)`);
  lines.push(`local o,kl={},#key`);
  lines.push(`for i=1,#data do`);
  lines.push(`local b=string.byte(data,i)`);
  lines.push(`local k=string.byte(key,((i-1)%kl)+1)`);
  lines.push(`local p=((i-1)*131+17)%256`);
  lines.push(`local rot=(k%7)+1`);
  lines.push(`local rot2=(p%5)+1`);
  lines.push(`b=(b+((k+p*3)%256))%256`);
  lines.push(`local hi=math.floor(b/(2^rot2))`);
  lines.push(`local lo=b%(2^rot2)`);
  lines.push(`b=(lo*(2^(8-rot2))+hi)%256`);
  lines.push(`b=(b-p+256)%256`);
  lines.push(`hi=math.floor(b/(2^rot))`);
  lines.push(`lo=b%(2^rot)`);
  lines.push(`b=(lo*(2^(8-rot))+hi)%256`);
  lines.push(`b=(b-k+256)%256`);
  lines.push(`o[i]=string.char(b)`);
  lines.push(`end`);
  lines.push(`return table.concat(o)`);
  lines.push(`end`);
  lines.push(`local ${L}=${J}(${I})`);
  lines.push(`local ${M}=${J}(${G})`);
  lines.push(`do`);
  lines.push(`local h=2654435761`);
  lines.push(`for i=1,#${L} do`);
  lines.push(`local b=string.byte(${L},i)`);
  lines.push(`h=(h+b*(i+30)+((h%89)*17)+13)%4294967296`);
  lines.push(`end`);
  lines.push(`if h~=${H} or #${L}~=${len} then return end`);
  lines.push(`end`);
  lines.push(`local ${N}=${K}(${L},${M})`);
  lines.push(`if #${N}~=${len} then return end`);
  lines.push(`local ${O}=(loadstring or load)(${N})`);
  lines.push(`if type(${O})~="function" then return end`);
  lines.push(`return ${O}(...)`);
  lines.push(`end)(...)`);
  const body = lines.join(" ");

  return (
    `-- This file was protected using Qyrex Obfuscator v1.6.7[https://qyrex.hopto.org/]\n` +
    body
  );
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

  const back = unscramble(decBuf(sym), key);
  if (!back.equals(raw)) throw new Error('roundtrip failed');

  // also verify decoded string matches source
  if (back.toString('utf8') !== src) throw new Error('utf8 mismatch');

  const code = build(sym, key, sum, scrambled.length);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-1.6.7',
      encoding: 'single-line body · add/rot/sub (NO xor)',
      verified: true
    }
  };
}

module.exports = { obfuscate };
