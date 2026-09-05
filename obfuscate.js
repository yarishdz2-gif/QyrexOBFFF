/**
 * Symbolic Overload Obfuscator v1
 * Alphabet: ! # $ % & / ( ) = ? ¡ °
 * NO Base64 · NO XOR · NO classical ciphers · NO plain bytecode
 *
 * Pipeline:
 *  1) arithmetic scramble (add/rot/mul/sub)
 *  2) fixed-width base-12 symbol encoding
 *  3) fragmented payload + junk + anti-tamper bootstrap
 *  4) runtime: symbols → bytes → unscramble → loadstring/load
 */
'use strict';
const crypto = require('crypto');

const MAX = 1_000_000;
const ALPHA = ['!', '#', '$', '%', '&', '/', '(', ')', '=', '?', '¡', '°'];
const BASE = ALPHA.length;
const WORD = 3; // 12^3 > 255

const JUNK = [
  '!¡#%$&/()=?', '¡°!#%/()=?', '#$%&/()=?¡', '!#()/¡°=$%',
  '%&/()=?¡!#', '/()=?¡!#$%', '()=?¡!#$%&', '=?¡!#$%&/()',
  '?¡!#$%&/()', '¡!#$%&/()=?', '°!#%/()=?¡', '!¡°#$%&/()'
];

const rb = n => crypto.randomBytes(n);
const ri = n => rb(1)[0] % n;

function rid(pre, len) {
  len = len || (8 + ri(6));
  const A = 'IlO0abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  let s = pre || '_';
  const b = rb(len);
  for (let i = 0; i < len; i++) s += A[b[i] % A.length];
  return s.slice(0, 2) + String(10 + ri(89)) + s.slice(2) + String(ri(9));
}

function soup(n) {
  n = n || (8 + ri(12));
  let s = '';
  const b = rb(n);
  for (let i = 0; i < n; i++) s += ALPHA[b[i] % BASE];
  return s;
}

function cmt() {
  return `--${JUNK[ri(JUNK.length)]}${soup(4)}${100 + ri(899)}`;
}

function byteToWord(b) {
  let n = b & 255;
  let w = '';
  for (let i = 0; i < WORD; i++) {
    w = ALPHA[n % BASE] + w;
    n = (n / BASE) | 0;
  }
  return w;
}

function encodeSymbolic(buf) {
  let out = '';
  for (let i = 0; i < buf.length; i++) out += byteToWord(buf[i]);
  return out;
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

function build(symPayload, key, sum, rawLen) {
  const N = {};
  for (const k of 'abcdefghijklmnopstuvwxyz'.split('')) N[k] = rid('_');

  const alphaLit = ALPHA.map(c => `"${c}"`).join(',');
  const keySym = encodeSymbolic(key);
  const inv = invTable();
  const invLit = inv.join(',');

  const frags = [];
  const fragVars = [];
  let pos = 0;
  while (pos < symPayload.length) {
    const sz = 16 + ri(28);
    const v = rid('_f');
    fragVars.push(v);
    frags.push({ v, s: symPayload.slice(pos, pos + sz) });
    pos += sz;
  }

  const L = [];
  L.push(cmt());
  L.push(`--°SymbolicOverload°${soup(14)}°${sum}`);
  L.push(cmt());
  L.push('do');

  // anti-tamper (conservative)
  L.push(`  local ${N.g}=1`);
  L.push(`  if type(pcall)~="function" then ${N.g}=0 end`);
  L.push(`  if type(string)~="table" and type(string)~="userdata" then ${N.g}=0 end`);
  L.push(`  if type(table)~="table" and type(table)~="userdata" then ${N.g}=0 end`);
  const oa = 12 + ri(20) * 2;
  const ob = 2 + ri(7);
  L.push(`  if ((${oa}*${ob})%2)~=0 then ${N.g}=0 end`);
  L.push(`  if ${N.g}~=1 then return end`);

  // junk
  for (let i = 0; i < 6 + ri(5); i++) {
    const v = rid('_j');
    L.push(`  local ${v}="${JUNK[ri(JUNK.length)]}${soup(7)}${1000 + ri(8999)}"`);
    L.push(`  if #${v}<0 then ${v}=${v} end`);
  }

  L.push(`  local ${N.a}={${alphaLit}}`);
  L.push(`  local ${N.b}={}`);
  L.push(`  for ${N.i}=1,#${N.a} do ${N.b}[${N.a}[${N.i}]]=${N.i}-1 end`);

  for (const f of frags) {
    L.push(`  ${cmt()}`);
    L.push(`  local ${f.v}="${f.s}"`);
  }
  L.push(`  local ${N.c}=${fragVars.join('..')}`);
  L.push(`  local ${N.k}="${keySym}"`);
  L.push(`  local ${N.h}=${sum}`);
  L.push(`  local ${N.p}={${invLit}}`);

  // symbol → bytes
  L.push(`  local function ${N.d}(z)`);
  L.push(`    local o,pos={},1`);
  L.push(`    while pos<=#z do`);
  L.push(`      local n=0`);
  L.push(`      for ${N.i}=0,${WORD - 1} do`);
  L.push(`        local ch=string.sub(z,pos+${N.i},pos+${N.i})`);
  L.push(`        n=n*${BASE}+(${N.b}[ch] or 0)`);
  L.push(`      end`);
  L.push(`      o[#o+1]=string.char(n%256)`);
  L.push(`      pos=pos+${WORD}`);
  L.push(`    end`);
  L.push(`    return table.concat(o)`);
  L.push(`  end`);

  // unscramble
  L.push(`  local function ${N.e}(data,key)`);
  L.push(`    local o,kl={},#key`);
  L.push(`    for ${N.i}=1,#data do`);
  L.push(`      local b=string.byte(data,${N.i})`);
  L.push(`      local k=string.byte(key,((${N.i}-1)%kl)+1)`);
  L.push(`      local p=((${N.i}-1)*131+17)%256`);
  L.push(`      local q=(((${N.i}-1)*47)+(k*3))%256`);
  L.push(`      b=(b+((p*3+k)%256))%256`);
  L.push(`      local m=((k%2==0 and k+1 or k)*5)%256`);
  L.push(`      if m==0 then m=1 end`);
  L.push(`      b=((b-q+256)*${N.p}[k+1])%256`);
  L.push(`      local rot=(k%7)+1`);
  L.push(`      local hi=math.floor(b/(2^rot)) local lo=b%(2^rot)`);
  L.push(`      b=(lo*(2^(8-rot))+hi)%256`);
  L.push(`      b=(b-k-p+512)%256`);
  L.push(`      o[${N.i}]=string.char(b)`);
  L.push(`    end`);
  L.push(`    return table.concat(o)`);
  L.push(`  end`);

  L.push(`  ${cmt()}`);
  L.push(`  local ${N.v}=0`);
  L.push(`  for ${N.i}=1,${3 + ri(3)} do ${N.v}=${N.v}+${N.i} end`);
  L.push(`  if ${N.v}<0 then return end`);

  L.push(`  local ${N.t}=${N.d}(${N.c})`);
  L.push(`  local ${N.u}=${N.d}(${N.k})`);

  L.push(`  do local h=2654435761`);
  L.push(`    for ${N.i}=1,#${N.t} do`);
  L.push(`      local b=string.byte(${N.t},${N.i})`);
  L.push(`      h=(h+b*(${N.i}+30)+((h%89)*17)+13)%4294967296`);
  L.push(`    end`);
  L.push(`    if h~=${N.h} then return end`);
  L.push(`  end`);
  L.push(`  if #${N.t}~=${rawLen} then return end`);

  L.push(`  local ${N.s}=${N.e}(${N.t},${N.u})`);
  L.push(`  local ${N.x},${N.y}=(loadstring or load)(${N.s})`);
  L.push(`  if type(${N.x})=="function" then ${N.x}() end`);
  L.push('end');
  L.push(cmt());
  return L.join('\n');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  if (Buffer.byteLength(src, 'utf8') > MAX) throw new Error('Too large');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(32 + ri(16));
  const scrambled = scramble(raw, key);
  const sum = checksum(scrambled);
  const sym = encodeSymbolic(scrambled);
  const code = build(sym, key, sum, scrambled.length);

  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'symbolic-overload',
      alphabet: ALPHA.join(''),
      encoding: 'arith-scramble + base12-symbols'
    }
  };
}

module.exports = { obfuscate };
