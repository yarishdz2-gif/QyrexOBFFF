/**
 * QyrexObf 1.0.0 — minimal, always-runs, symbol payload
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
function chunkSym(sym) {
  const out = [];
  const step = 100 + ri(50);
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

function buildLoader(sym, key) {
  const id = () => rid();
  const A = id(), B = id(), C = id(), D = id(), E = id();
  const F = id(), G = id(), H = id(), I = id(), J = id();
  const K = id(), L = id(), M = id(), N = id(), O = id();
  const P = id(), Q = id(), R = id(), S = id(), T = id();
  const U = id(), V = id(), W = id(), X = id(), Y = id();
  const Z = id(), AA = id(), BB = id(), CC = id(), DD = id();
  const EE = id(), FF = id(), GG = id();

  const parts = chunkSym(sym);
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');
  const keySym = encBuf(key);

  // ONE continuous valid Lua chunk
  const code = [
    'return(function(...)',
    `local ${A}=string.byte`,
    `local ${B}=string.sub`,
    `local ${C}=table.concat`,
    `local ${D}="${ALPHA}"`,
    `local ${E}={}`,
    `for ${F}=1,#${D} do ${E}[${B}(${D},${F},${F})]=${F}-1 end`,
    `local function ${G}(${H})`,
    `local ${I}={} local ${J}=1 local ${K}=#${H}`,
    `while ${J}+1<=${K} do`,
    `local ${L}=0 local ${M}=0`,
    `while ${M}<2 do`,
    `local ${N}=${B}(${H},${J}+${M},${J}+${M})`,
    `${L}=${L}*(#${D})+(${E}[${N}] or 0)`,
    `${M}=${M}+1`,
    `end`,
    `${I}[#${I}+1]=string.char(${L}%256)`,
    `${J}=${J}+2`,
    `end`,
    `return ${C}(${I})`,
    `end`,
    `local function ${O}(${P},${Q})`,
    `${P}=${P}%256 ${Q}=${Q}%256`,
    `local ${R}=0 local ${S}=1`,
    `for ${T}=1,8 do`,
    `local ${U}=${P}%2 local ${V}=${Q}%2`,
    `if ${U}~=${V} then ${R}=${R}+${S} end`,
    `${P}=(${P}-${U})/2 ${Q}=(${Q}-${V})/2 ${S}=${S}*2`,
    `end`,
    `return ${R}`,
    `end`,
    `local ${W}={${vLit}}`,
    `local ${X}="${luaEsc(keySym)}"`,
    `local ${Y}=${G}(${C}(${W}))`,
    `local ${Z}=${G}(${X})`,
    `local ${AA}={} local ${BB}=#${Z}`,
    `for ${CC}=1,#${Y} do`,
    `local ${DD}=${A}(${Y},${CC})`,
    `local ${EE}=${A}(${Z},((${CC}-1)%${BB})+1)`,
    `local ${FF}=((${CC}-1)*31+17)%256`,
    `local ${GG}=${O}(${O}(${DD},${EE}),${FF})`,
    `${AA}[${CC}]=string.char(${GG}%256)`,
    `end`,
    `local src=${C}(${AA})`,
    `local ldr=loadstring or load`,
    `if type(ldr)~="function" then return end`,
    `local fn=ldr(src)`,
    `if type(fn)~="function" then return end`,
    `return fn(...)`,
    `end)(...)`,
  ].join(' ');

  return `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]]\n` + code;
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const raw = Buffer.from(src, 'utf8');
  if (raw.length > 1500000) throw new Error('Too large');
  const key = rb(32 + ri(16));
  const scrambled = scramble(raw, key);
  const sym = encBuf(scrambled);
  const back = unscramble(decBuf(sym), key);
  if (!back.equals(raw)) throw new Error('roundtrip failed');
  const code = buildLoader(sym, key);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      layers: ['symbol-alphabet', 'xor', 'digit-ids', 'single-line'],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
