/**
 * QyrexObf 1.6.7 — web generator (matches Lua generator semantics)
 * Header + single-line body · state-machine decode · NO XOR
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
    let n = 16 + ri(32);
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
  const A=rid(),B=rid(),C=rid(),D=rid(),E=rid(),F=rid(),G=rid(),H=rid();
  const I=rid(),J=rid(),K=rid(),L=rid(),M=rid(),N=rid();
  const parts = chunks(sym);
  const vLit = parts.map((p, i) => `"${p}"${i < parts.length - 1 ? (ri(2) ? ';' : ',') : ''}`).join('');
  const keySym = encBuf(key);
  const j1 = noise(24 + ri(16)), j2 = noise(24 + ri(16));

  const lines = [];
  lines.push(`return(function(...)`);
  lines.push(`local ${A}={${vLit}}`);
  lines.push(`local ${B}="${j1}"`);
  lines.push(`local ${C}="${j2}"`);
  lines.push(`local ${D}="${ALPHA}"`);
  lines.push(`local ${E}={}`);
  lines.push(`for ${F}=1,#${D} do ${E}[string.sub(${D},${F},${F})]=${F}-1 end`);
  lines.push(`local ${G}="${keySym}"`);
  lines.push(`local ${H}=${sum}`);
  lines.push(`local ${I}=table.concat(${A})`);
  lines.push(`local function ${J}(z) local o,pos={},1 while pos<=#z do local n=0 for i=0,1 do local ch=string.sub(z,pos+i,pos+i) n=n*${BASE}+(${E}[ch] or 0) end o[#o+1]=string.char(n%256) pos=pos+2 end return table.concat(o) end`);
  lines.push(`local function ${K}(data,key) local o,kl={},#key for i=1,#data do local b=string.byte(data,i) local k=string.byte(key,((i-1)%kl)+1) local p=((i-1)*131+17)%256 local rot=(k%7)+1 local rot2=(p%5)+1 b=(b+((k+p*3)%256))%256 local hi=math.floor(b/(2^rot2)) local lo=b%(2^rot2) b=(lo*(2^(8-rot2))+hi)%256 b=(b-p+256)%256 hi=math.floor(b/(2^rot)) lo=b%(2^rot) b=(lo*(2^(8-rot))+hi)%256 b=(b-k+256)%256 o[i]=string.char(b) end return table.concat(o) end`);
  lines.push(`local ${M}=${J}(${I})`);
  lines.push(`local ${N}=${J}(${G})`);
  lines.push(`do local h=2654435761 for i=1,#${M} do local b=string.byte(${M},i) h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 end if h~=${H} or #${M}~=${len} then return end end`);
  lines.push(`local ${L}=${K}(${M},${N})`);
  lines.push(`if #${L}~=${len} then return end`);
  lines.push(`local fn=(loadstring or load)(${L})`);
  lines.push(`if type(fn)~="function" then return end`);
  lines.push(`return fn(...)`);
  lines.push(`end)(...)`);
  const body = lines.join(' ');
  return (
    `--[[ Protected by QyrexObf v1.0.0 | qyrex.hopto.org ]]\n` +
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
  const code = build(sym, key, sum, scrambled.length);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-1.0.0',
      verified: true
    }
  };
}

module.exports = { obfuscate };
