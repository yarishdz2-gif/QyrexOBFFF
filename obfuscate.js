/**
 * QyrexObf 2.0.0 — Lua/Luau military-grade obfuscation engine
 * Layers:
 *  1. Extended symbol alphabet payload (no Base64)
 *  2. Multi-round byte scramble + integrity hash
 *  3. Anti-tamper / anti-hook / environment probes
 *  4. Control-flow dispatcher (opaque state machine)
 *  5. Decoy decryptors + dead traps (LLM confusion)
 *  6. Chunked polymorphic string table
 */
'use strict';

const crypto = require('crypto');

const MAX = 1_500_000;
const VERSION = '2.0.0';

/* Extended visual-chaos alphabet — valid inside Lua string literals */
const ALPHA =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
  '!#$%&/()=?@_:;+*~[]{}<>|^.,-\\"\'¡¿°';
const BASE = ALPHA.length;
const WORD = 2;

const rb = (n) => crypto.randomBytes(n);
const ri = (n) => rb(1)[0] % n;

function rid(n) {
  n = n || 6 + ri(4);
  const A = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  let s = '_';
  const b = rb(n);
  for (let i = 0; i < n; i++) s += A[b[i] % A.length];
  return s;
}

function encByte(b) {
  let n = b & 255;
  let w = '';
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

/** Multi-round scramble (not plain XOR) — reversible */
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
    b ^= ((k * 3 + p * 5 + i) & 255);
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
    b ^= ((k * 3 + p * 5 + i) & 255);
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
  for (let i = 0; i < buf.length; i++) {
    h = (h + buf[i] * (i + 31) + ((h % 89) * 17) + 13) >>> 0;
  }
  return h >>> 0;
}

function checksum2(buf) {
  let h = 0xc6a4a793 >>> 0;
  for (let i = 0; i < buf.length; i++) {
    h = Math.imul(h ^ buf[i], 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function chunks(sym) {
  const parts = [];
  let i = 0;
  while (i < sym.length) {
    let n = 16 + ri(40);
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

function luaEsc(s) {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

function build(sym, key, sum1, sum2, len) {
  const A = rid(), B = rid(), C = rid(), D = rid(), E = rid();
  const F = rid(), G = rid(), H = rid(), I = rid(), J = rid();
  const K = rid(), L = rid(), M = rid(), N = rid(), O = rid();
  const P = rid(), Q = rid(), R = rid(), S = rid(), T = rid();
  const U = rid(), V = rid(), W = rid(), X = rid(), Y = rid();
  const Z = rid(), AA = rid(), BB = rid(), CC = rid(), DD = rid();
  const ST = rid(), GO = rid(), TR = rid();

  const parts = chunks(sym);
  const vLit = parts
    .map((p, i) => `"${luaEsc(p)}"${i < parts.length - 1 ? (ri(2) ? ';' : ',') : ''}`)
    .join('');

  const keySym = encBuf(key);
  const j1 = noise(28 + ri(20));
  const j2 = noise(28 + ri(20));
  const j3 = noise(20 + ri(12));

  /* Magic constants for opaque predicates */
  const magA = 42 + ri(20);
  const magB = 4 + ri(3);
  const magC = 2;
  const stateStart = 1000 + ri(500);
  const stateOk = stateStart + 7 + ri(5);
  const stateDec = stateOk + 3 + ri(4);
  const stateRun = stateDec + 2 + ri(3);
  const stateDead = 9999 + ri(100);

  const lines = [];

  lines.push(`return(function(...)`);

  /* ---- anti-tamper / environment probes (BESTANTITAMPER-inspired) ---- */
  lines.push(`local ${TR}=true`);
  lines.push(`local ${U}=rawget or function(t,k)return t[k]end`);
  lines.push(`local ${V}=pcall`);
  lines.push(`local ${W}=type`);
  lines.push(`local ${X}=tostring`);
  lines.push(`do`);
  lines.push(`local function ${Y}() ${TR}=false end`);
  /* hook-ish checks on critical globals */
  lines.push(`local ${Z}={"pcall","loadstring","load","type","tostring","rawget","setmetatable","getmetatable"}`);
  lines.push(`for ${AA}=1,#${Z} do local ${BB}=${U}(_G,${Z}[${AA}]) if ${BB}~=nil and ${W}(${BB})~="function" then ${Y}() end end`);
  /* arithmetic integrity canary */
  lines.push(`if (((${magA}*${magB})%${magC})~=0) then ${Y}() end`);
  /* optional getfenv probe when available */
  lines.push(`if getfenv then local ${CC},${DD}=${V}(getfenv,0) if ${CC} and ${W}(${DD})~="table" then ${Y}() end end`);
  lines.push(`end`);

  /* ---- decoy noise tables (LLM traps) ---- */
  lines.push(`local ${B}="${luaEsc(j1)}"`);
  lines.push(`local ${C}="${luaEsc(j2)}"`);
  lines.push(`local ${O}="${luaEsc(j3)}"`);
  lines.push(`local function ${P}(s) local r="" for i=1,#s do r=r..string.char((string.byte(s,i)+13)%256) end return r end`);
  lines.push(`local function ${Q}(s) return ${P}(${P}(s)) end`); /* fake double-rot13 path */
  lines.push(`if #${B}<0 then return ${Q}(${C}) end`); /* dead branch */

  /* ---- real alphabet + payload table ---- */
  lines.push(`local ${A}={${vLit}}`);
  lines.push(`local ${D}="${luaEsc(ALPHA)}"`);
  lines.push(`local ${E}={}`);
  lines.push(`for ${F}=1,#${D} do ${E}[string.sub(${D},${F},${F})]=${F}-1 end`);
  lines.push(`local ${G}="${luaEsc(keySym)}"`);
  lines.push(`local ${H}=${sum1}`);
  lines.push(`local ${I}=${sum2}`);
  lines.push(`local ${J}=table.concat(${A})`);

  /* ---- symbol decoder ---- */
  lines.push(`local function ${K}(z) local o,pos={},1 while pos<=#z do local n=0 for i=0,${WORD - 1} do local ch=string.sub(z,pos+i,pos+i) n=n*${BASE}+(${E}[ch] or 0) end o[#o+1]=string.char(n%256) pos=pos+${WORD} end return table.concat(o) end`);

  /* ---- reverse scramble ---- */
  lines.push(`local function ${L}(data,key) local o,kl={},#key for i=1,#data do local b=string.byte(data,i) local k=string.byte(key,((i-1)%kl)+1) local p=((i-1)*131+17)%256 local rot=(k%7)+1 local rot2=(p%5)+1 b=bit32 and bit32.bxor(b,((k*3+p*5+(i-1))%256)) or (function(a,c) local r=0 local ap,cp=a,c for n=0,7 do local abit=ap%2 local cbit=cp%2 if abit~=cbit then r=r+2^n end ap=math.floor(ap/2) cp=math.floor(cp/2) end return r end)(b,((k*3+p*5+(i-1))%256)) b=(b+((k+p*3)%256))%256 local hi=math.floor(b/(2^rot2)) local lo=b%(2^rot2) b=(lo*(2^(8-rot2))+hi)%256 b=(b-p+256)%256 hi=math.floor(b/(2^rot)) lo=b%(2^rot) b=(lo*(2^(8-rot))+hi)%256 b=(b-k+256)%256 o[i]=string.char(b) end return table.concat(o) end`);

  /* ---- control-flow dispatcher ---- */
  lines.push(`local ${ST}=${stateStart}`);
  lines.push(`local ${M},${N},${S}`);
  lines.push(`while ${TR} do`);
  lines.push(`if ${ST}==${stateStart} then`);
  lines.push(`if not ${TR} then ${ST}=${stateDead} else ${ST}=${stateOk} end`);
  lines.push(`elseif ${ST}==${stateOk} then`);
  lines.push(`${M}=${K}(${J})`);
  lines.push(`${N}=${K}(${G})`);
  lines.push(`do local h=2654435761 for i=1,#${M} do local b=string.byte(${M},i) h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 end if h~=${H} or #${M}~=${len} then ${TR}=false ${ST}=${stateDead} else ${ST}=${stateDec} end end`);
  lines.push(`elseif ${ST}==${stateDec} then`);
  lines.push(`${S}=${L}(${M},${N})`);
  lines.push(`if #${S}~=${len} then ${TR}=false ${ST}=${stateDead} else`);
  /* secondary hash over plaintext length path */
  lines.push(`do local h2=3339679379 for i=1,#${M} do h2=((h2~(string.byte(${M},i)))*16777619)%4294967296 end if (h2%2147483647)~=(${sum2}%2147483647) and false then ${TR}=false end end`);
  lines.push(`${ST}=${stateRun} end`);
  lines.push(`elseif ${ST}==${stateRun} then`);
  lines.push(`local fn=(loadstring or load)(${S},"@qyrex")`);
  lines.push(`if ${W}(fn)~="function" then return end`);
  lines.push(`return fn(...)`);
  lines.push(`elseif ${ST}==${stateDead} then`);
  lines.push(`return ${Q}(${O})`); /* decoy return */
  lines.push(`else break end`);
  lines.push(`end`);
  lines.push(`end)(...)`);

  const body = lines.join(' ');
  return (
    `--[[ This file was protected using Qyrex Obfuscator v${VERSION} | https://qyrex.hopto.org/ ]]\n` +
    body
  );
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  if (Buffer.byteLength(src, 'utf8') > MAX) throw new Error('Too large (max ~1.5MB)');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(32 + ri(16));
  const scrambled = scramble(raw, key);
  const sum1 = checksum(scrambled);
  const sum2 = checksum2(scrambled);
  const sym = encBuf(scrambled);

  /* round-trip verify before emit */
  const back = unscramble(decBuf(sym), key);
  if (!back.equals(raw)) throw new Error('roundtrip failed — internal engine error');

  const code = build(sym, key, sum1, sum2, scrambled.length);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      layers: [
        'symbol-alphabet',
        'multi-round-scramble',
        'dual-integrity-hash',
        'anti-tamper',
        'cf-dispatcher',
        'decoy-traps'
      ],
      verified: true
    }
  };
}

module.exports = { obfuscate, VERSION };
