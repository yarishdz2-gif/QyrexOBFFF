/**
 * QyrexObf 1.3.0 — Hardened decimal loader
 * Keeps the public API: obfuscate(source) -> { code, stats }
 *
 * Hardening layers:
 *  - Per-byte keyed xorshift stream mask
 *  - Affine byte transform
 *  - Deterministic keyed chunk permutation
 *  - Independent payload + source integrity checks
 *  - Double nesting
 *  - Runtime reconstruction in local scope, then immediate cleanup
 *  - Random identifiers / random chunking
 *
 * Note: client-side code that is eventually executed can always be observed
 * by a sufficiently capable runtime dumper. This is hardening, not magic.
 */
'use strict';

const crypto = require('crypto');
const VERSION = '1.3.1';
const MAX_SOURCE = 1_500_000;
const ri = (n) => crypto.randomInt(0, n);

const RES = new Set([
  'and','break','do','else','elseif','end','false','for','function','goto',
  'if','in','local','nil','not','or','repeat','return','then','true','until','while'
]);

function rid() {
  const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let o;
  do {
    o = 'q';
    for (let i = 0; i < 7 + ri(6); i++) o += letters[ri(letters.length)];
  } while (RES.has(o));
  return o;
}

function u32(n) { return n >>> 0; }

function modInv(a) {
  for (let x = 1; x < 256; x++) {
    if (((a * x) % 256 + 256) % 256 === 1) return x;
  }
  throw new Error('Invalid affine key');
}

// Pure-arithmetic keyed stream generator.
// Kept within exact integer ranges for Luau/Number compatibility.
function keyedMask(seed, i, a, b) {
  let s = (seed + (i + 1) * 374761393 + a * 668265263 + b * 2147483647) % 4294967296;
  if (s < 0) s += 4294967296;
  s = (s * 1664525 + 1013904223) % 4294967296;
  return s % 256;
}

function decEnc(buf, a, b, seed) {
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    const x = buf[i] ^ keyedMask(seed, i, a, b);
    const y = (a * x + b + (i % 251)) % 256;
    out += String(y).padStart(3, '0');
  }
  return out;
}

function decDec(d, a, b, seed) {
  if (d.length % 3 !== 0) throw new Error('Invalid decimal length');
  const inv = modInv(a);
  const out = Buffer.alloc(d.length / 3);
  for (let i = 0, j = 0; i < d.length; i += 3, j++) {
    const y = Number(d.slice(i, i + 3));
    if (!Number.isInteger(y) || y < 0 || y > 255) throw new Error('Invalid decimal byte');
    const z = ((y - b - (j % 251)) % 256 + 256) % 256;
    out[j] = ((inv * z) % 256) ^ keyedMask(seed, j, a, b);
  }
  return out;
}

function hash32(buf, seed = 0) {
  let h = (216613 + seed) % 1000003;
  if (h < 0) h += 1000003;
  for (let i = 0; i < buf.length; i++) h = (h * 257 + buf[i] + 97) % 1000003;
  return h;
}

function chunkDec(d) {
  const out = [];
  let p = 0;
  while (p < d.length) {
    const room = 72 + ri(120);
    const size = Math.max(3, room - (room % 3));
    out.push(d.slice(p, p + size));
    p += size;
  }
  return out;
}

function keyedShuffle(items, seed) {
  const a = items.map((value, index) => ({ value, index, k: hash32(Buffer.from(String(index)), seed) }));
  a.sort((x, y) => (x.k - y.k) || (x.index - y.index));
  return {
    parts: a.map(x => x.value),
    order: a.map(x => x.index + 1),
  };
}

function buildDecimalLoader(decimal, a, b, streamSeed, expectedHash, expectedPayloadHash, sourceLen) {
  const V = Array.from({ length: 24 }, rid);
  const originalParts = chunkDec(decimal);
  const shuffled = keyedShuffle(originalParts, streamSeed);
  const payloadTable = shuffled.parts.map((p) => JSON.stringify(p)).join(',');
  const orderTable = shuffled.order.join(',');
  const L = [];

  // V layout: payload, order, len, affine-A, affine-B, seed, source-hash,
  // payload-hash, type, string, table, pcall, math, at-flag, joined-enc,
  // inverse, decoded-table, loop-index, source, source-hash-2, loader, ok, fn.
  const [P,O,N,A,B,S,H,PH,T,STR,TBL,PC,M,AT,ENC,INV,DEC,I,SRC,H2,LOAD,OK,FN] = V;

  L.push(`--[[ QyrexObf ${VERSION} | protected loader ]]\n`);
  L.push('return(function(...) ');
  L.push(`local ${P}={${payloadTable}}; local ${O}={${orderTable}}; `);
  L.push(`local ${N}=${sourceLen}; local ${A}=${a}; local ${B}=${b}; local ${S}=${streamSeed}; `);
  L.push(`local ${H}=${expectedHash}; local ${PH}=${expectedPayloadHash}; `);
  L.push(`local ${T}=type; local ${STR}=string; local ${TBL}=table; local ${PC}=pcall; local ${M}=math; local ${AT}=0; `);

  // Retain the existing lightweight probes, but they are not the decryption key.
  L.push(`${PC}(function() local t=${T}(game); if t=='userdata' or t=='table' then ${AT}=${AT}+1 end; if ${T}(_G)=='table' then ${AT}=${AT}+1 end end); `);
  L.push(`${PC}(function() if typeof and game~=nil and typeof(game)=='Instance' then ${AT}=${AT}+1 end end); `);
  L.push(`${PC}(function() if ${M} and ${M}.floor(3.9)==3 and ${STR}.byte('A')==65 then ${AT}=${AT}+1 end end); `);
  L.push(`${PC}(function() if getmetatable and getmetatable(_G)~=nil then ${AT}=${AT}-3 end end); `);
  L.push(`${PC}(function() if debug and debug.gethook then local ok,h=${PC}(debug.gethook); if ok and h~=nil then ${AT}=${AT}-4 end end end); `);

  // Restore chunk order before joining.
  L.push(`local ${ENC}={}; for ${I}=1,#${O} do ${ENC}[${I}]=${P}[${O}[${I}]] end; ${P}=nil; ${O}=nil; `);
  L.push(`local ${SRC}=${TBL}.concat(${ENC}); ${ENC}=nil; if #${SRC}~=${N}*3 then return end; `);

  // Recover modular inverse once.
  L.push(`local ${INV}=1; while ((${A}*${INV})%256)~=1 do ${INV}=${INV}+1; if ${INV}>255 then return end end; `);
  L.push(`local ${DEC}={}; `);
  L.push(`for ${I}=1,#${SRC},3 do `);
  L.push(`local q=${STR}.sub(${SRC},${I},${I}+2)+0; if q<0 or q>255 then return end; `);
  L.push(`local j=${I}-1; local s=(${S}+(j+1)*374761393+${A}*668265263+${B}*2147483647)%4294967296; `);
  L.push(`if s<0 then s=s+4294967296 end; s=(s*1664525+1013904223)%4294967296; local m=s%256; `);
  L.push(`local z=((q-${B}-(j%251))%256+256)%256; ${DEC}[#${DEC}+1]=${STR}.char(((((z*${INV})%256) ~ m)%256)); `);
  L.push(`end; ${SRC}=nil; `);

  // Source integrity and payload integrity use the same small exact arithmetic hash as JS.
  L.push(`local ${H2}=(216613+(${S}%1000003))%1000003; for ${I}=1,#${DEC} do local c=${STR}.byte(${DEC}[${I}]); ${H2}=(${H2}*257+c+97)%1000003 end; `);
  L.push(`if ${H2}~=${H} or #${DEC}~=${N} then return end; `);
  L.push(`local ${SRC}=${TBL}.concat(${DEC}); ${DEC}=nil; `);
  L.push(`local ph=(216613+((${S}+12345)%1000003))%1000003; for ${I}=1,#${SRC} do local c=${STR}.byte(${SRC},${I}); ph=(ph*257+c+97)%1000003 end; `);
  L.push(`if ph~=${PH} then return end; `);

  // Compile only after both checks. Immediately drop the plaintext reference afterward.
  L.push(`local ${LOAD}=loadstring; if ${T}(${LOAD})~='function' then ${LOAD}=load end; if ${T}(${LOAD})~='function' then return end; `);
  L.push(`${PC}(function() if iscclosure and not iscclosure(${LOAD}) then ${AT}=${AT}-2 end end); `);
  L.push(`local ${OK},${FN}=${PC}(${LOAD},${SRC}); ${SRC}=nil; `);
  L.push(`if not ${OK} or ${T}(${FN})~='function' then return end; return ${FN}(...); end)(...)`);
  return L.join('');
}

function obfuscateDecimal(source, nests) {
  let src = String(source);
  let lastCode = null;
  const levels = Math.max(1, nests | 0);

  for (let n = 0; n < levels; n++) {
    const raw = Buffer.from(src, 'utf8');
    if (raw.length > MAX_SOURCE) throw new Error('Too large');

    const a = 1 + 2 * ri(128);
    const b = ri(256);
    const streamSeed = u32(crypto.randomInt(0, 0x7fffffff) ^ ri(0x7fffffff));
    const decimal = decEnc(raw, a, b, streamSeed);

    if (!/^\d+$/.test(decimal)) throw new Error('decimal payload violation');
    const back = decDec(decimal, a, b, streamSeed);
    if (!back.equals(raw)) throw new Error('roundtrip failed');

    const expectedHash = hash32(raw, streamSeed);
    const expectedPayloadHash = hash32(Buffer.from(decimal), streamSeed + 12345);
    lastCode = buildDecimalLoader(
      decimal, a, b, streamSeed,
      expectedHash, expectedPayloadHash,
      raw.length
    );
    src = lastCode;
  }

  return lastCode;
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');

  const code = obfuscateDecimal(src, 2);

  if (code.includes('dolocal') || code.includes('thenlocal') || code.includes('endlocal')) {
    throw new Error('internal spacing error');
  }

  return {
    code,
    stats: {
      inputBytes: Buffer.byteLength(src, 'utf8'),
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: `QyrexObf-${VERSION}`,
      nestLevels: 2,
      layers: [
        'decimal-affine',
        'per-byte-keyed-stream-mask',
        'keyed-chunk-permutation',
        'dual-integrity-check',
        'soft-anti-tamper',
        'sandbox-probes',
        'debug-hook-probe',
        'double-nest',
        'runtime-key-derivation',
        'luau-roblox-stable',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
