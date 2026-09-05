/**
 * QyrexObf 1.0.0 — Hardened Lua/Luau engine
 * Header: --[[ Protected by QyrexObf v1.0.0 | qyrex.hopto.org ]]
 */
'use strict';

const crypto = require('crypto');

const VERSION = '1.0.0';
const MAX_BYTES = 1_500_000;

const ALPHA =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
  '!#$%&/()=?@_:;+*~[]{}<>|^.,-\\"\'¡¿°';
const BASE = ALPHA.length;
const WORD = 2;

const rb = (n) => crypto.randomBytes(n);
const ri = (n) => crypto.randomInt(0, n);

function rid(n) {
  n = n || 7 + ri(4);
  const A = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  let s = '_';
  for (let i = 0; i < n; i++) s += A[ri(A.length)];
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

function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i] & 255;
    const k = key[i % kl] & 255;
    const p = (i * 131 + 17) & 255;
    const rot = (k % 7) + 1;
    const rot2 = (p % 5) + 1;
    b = (b + k) & 255;
    b = ((b << rot) | (b >>> (8 - rot))) & 255;
    b = (b + p) & 255;
    b = ((b << rot2) | (b >>> (8 - rot2))) & 255;
    b = (b - ((k + p * 3) & 255) + 256) & 255;
    b = (b ^ ((k * 3 + p * 5 + i) & 255)) & 255;
    out[i] = b;
  }
  return out;
}

function unscramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i] & 255;
    const k = key[i % kl] & 255;
    const p = (i * 131 + 17) & 255;
    const rot = (k % 7) + 1;
    const rot2 = (p % 5) + 1;
    b = (b ^ ((k * 3 + p * 5 + i) & 255)) & 255;
    b = (b + ((k + p * 3) & 255)) & 255;
    b = ((b >>> rot2) | (b << (8 - rot2))) & 255;
    b = (b - p + 256) & 255;
    b = ((b >>> rot) | (b << (8 - rot))) & 255;
    b = (b - k + 256) & 255;
    out[i] = b;
  }
  return out;
}

function checksum32(buf) {
  let h = 2654435761 % 4294967296;
  for (let i0 = 0; i0 < buf.length; i0++) {
    const i = i0 + 1;
    const b = buf[i0];
    h = (h + b * (i + 30) + ((h % 89) * 17) + 13) % 4294967296;
  }
  return h >>> 0;
}

function chunkSym(sym) {
  const parts = [];
  let i = 0;
  while (i < sym.length) {
    let n = 12 + ri(48);
    n -= n % WORD;
    if (n < WORD) n = WORD;
    const take = Math.min(sym.length - i, n);
    let aligned = take - (take % WORD);
    if (aligned <= 0) aligned = Math.min(WORD, sym.length - i);
    parts.push(sym.slice(i, i + aligned));
    i += aligned;
  }
  return parts;
}

function noise(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += ALPHA[ri(BASE)];
  return s;
}

function luaEsc(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\0/g, '\\0');
}

function buildLoader(sym, key, sumA, payloadLen) {
  const A = rid(), B = rid(), C = rid(), D = rid(), E = rid();
  const F = rid(), G = rid(), H = rid(), J = rid(), K = rid();
  const L = rid(), M = rid(), N = rid(), S = rid(), O = rid();
  const P = rid(), Q = rid(), ST = rid(), BX = rid();

  const parts = chunkSym(sym);
  const vLit = parts
    .map((p, idx) => `"${luaEsc(p)}"${idx < parts.length - 1 ? (ri(2) ? ',' : ';') : ''}`)
    .join('');

  const keySym = encBuf(key);
  const j1 = noise(32 + ri(24));
  const j2 = noise(32 + ri(24));
  const j3 = noise(24 + ri(16));

  const s0 = 1200 + ri(500);
  const s1 = s0 + 17 + ri(9);
  const s2 = s1 + 9 + ri(7);
  const s3 = s2 + 5 + ri(5);
  const sDead = 8000 + ri(400);

  const c1 = 7 + ri(5);
  const c2 = c1 * 2;

  const Lns = [];
  Lns.push('return(function(...)');
  Lns.push(`local ${BX}=true`);
  Lns.push(`if type(string)~="table" or type(string.byte)~="function" or type(string.sub)~="function" then ${BX}=false end`);
  Lns.push(`if type(table)~="table" or type(table.concat)~="function" then ${BX}=false end`);
  Lns.push(`if type(math)~="table" or type(math.floor)~="function" then ${BX}=false end`);
  Lns.push(`if ((${c1}*2)~=${c2}) then ${BX}=false end`);
  Lns.push(`local ${B}="${luaEsc(j1)}"`);
  Lns.push(`local ${C}="${luaEsc(j2)}"`);
  Lns.push(`local ${O}="${luaEsc(j3)}"`);
  Lns.push(`local function ${P}(s) local r={} for i=1,#s do r[i]=string.char((string.byte(s,i)+17)%256) end return table.concat(r) end`);
  Lns.push(`local function ${Q}(s) return ${P}(${P}(s)) end`);
  Lns.push(`if #${B}<0 then return ${Q}(${C}) end`);
  Lns.push(`local ${A}={${vLit}}`);
  Lns.push(`local ${D}="${luaEsc(ALPHA)}"`);
  Lns.push(`local ${E}={}`);
  Lns.push(`for ${F}=1,#${D} do ${E}[string.sub(${D},${F},${F})]=${F}-1 end`);
  Lns.push(`local ${G}="${luaEsc(keySym)}"`);
  Lns.push(`local ${H}=${sumA}`);
  Lns.push(`local ${J}=table.concat(${A})`);
  Lns.push(`local function ${K}(z) local o={} local pos=1 local zlen=#z while pos+1<=zlen do local n=0 for i=0,${WORD - 1} do local ch=string.sub(z,pos+i,pos+i) n=n*${BASE}+(${E}[ch] or 0) end o[#o+1]=string.char(n%256) pos=pos+${WORD} end return table.concat(o) end`);
  Lns.push(`local function ${L}(data,key) local o={} local kl=#key for i=1,#data do local b=string.byte(data,i) local k=string.byte(key,((i-1)%kl)+1) local p=((i-1)*131+17)%256 local rot=(k%7)+1 local rot2=(p%5)+1 local mix=((k*3+p*5+(i-1))%256) local x=0 local bb,mm,bit=b,mix,0 while bit<8 do local abit=bb%2 local mbit=mm%2 if abit~=mbit then x=x+(2^bit) end bb=math.floor(bb/2) mm=math.floor(mm/2) bit=bit+1 end b=x b=(b+((k+p*3)%256))%256 local hi=math.floor(b/(2^rot2)) local lo=b%(2^rot2) b=(lo*(2^(8-rot2))+hi)%256 b=(b-p+256)%256 hi=math.floor(b/(2^rot)) lo=b%(2^rot) b=(lo*(2^(8-rot))+hi)%256 b=(b-k+256)%256 o[i]=string.char(b) end return table.concat(o) end`);
  Lns.push(`local ${ST}=${s0}`);
  Lns.push(`local ${M},${N},${S}`);
  Lns.push(`while ${BX} do`);
  Lns.push(`if ${ST}==${s0} then ${ST}=${s1}`);
  Lns.push(`elseif ${ST}==${s1} then`);
  Lns.push(`${M}=${K}(${J}) ${N}=${K}(${G})`);
  Lns.push(`do local h=2654435761 for i=1,#${M} do local b=string.byte(${M},i) h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 end if h~=${H} or #${M}~=${payloadLen} then ${BX}=false ${ST}=${sDead} else ${ST}=${s2} end end`);
  Lns.push(`elseif ${ST}==${s2} then`);
  Lns.push(`${S}=${L}(${M},${N})`);
  Lns.push(`if #${S}~=${payloadLen} then ${BX}=false ${ST}=${sDead} else ${ST}=${s3} end`);
  Lns.push(`elseif ${ST}==${s3} then`);
  Lns.push(`local loader=loadstring or load`);
  Lns.push(`if type(loader)~="function" then return end`);
  Lns.push(`local fn=loader(${S},"@qyrex")`);
  Lns.push(`if type(fn)~="function" then return end`);
  Lns.push(`return fn(...)`);
  Lns.push(`elseif ${ST}==${sDead} then return ${Q}(${O})`);
  Lns.push(`else break end`);
  Lns.push(`end`);
  Lns.push(`end)(...)`);

  return (
    `--[[ Protected by QyrexObf v1.0.0 | qyrex.hopto.org ]]\n` +
    Lns.join(' ')
  );
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const inputBytes = Buffer.byteLength(src, 'utf8');
  if (inputBytes > MAX_BYTES) throw new Error('Too large (max ~1.5MB)');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(40 + ri(24));
  const scrambled = scramble(raw, key);
  const sumA = checksum32(scrambled);
  const sym = encBuf(scrambled);

  const recovered = unscramble(decBuf(sym), key);
  if (recovered.length !== raw.length || !recovered.equals(raw)) {
    throw new Error('roundtrip failed — refusing broken output');
  }

  let h = 2654435761 % 4294967296;
  for (let i = 1; i <= scrambled.length; i++) {
    const b = scrambled[i - 1];
    h = (h + b * (i + 30) + ((h % 89) * 17) + 13) % 4294967296;
  }
  if ((h >>> 0) !== sumA) throw new Error('checksum mirror mismatch');

  const code = buildLoader(sym, key, sumA, scrambled.length);
  return {
    code,
    stats: {
      inputBytes,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-1.0.0',
      layers: [
        'chaotic-alphabet',
        'multi-round-scramble',
        'integrity-hash',
        'soft-env-gate',
        'cf-dispatcher',
        'llm-decoys'
      ],
      verified: true
    }
  };
}

module.exports = { obfuscate, VERSION };
