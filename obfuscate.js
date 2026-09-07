/**
 * QyrexObf 1.0.2
 * Roblox/Luau compatible numeric payload.
 * Visible payload alphabet: digits 0-9 only.
 * No Unicode payload symbols, XOR, or Base64.
 */
'use strict';

const crypto = require('crypto');
const VERSION = '1.0.2';
const MAX_SOURCE = 1_500_000;
const CHUNK_SIZE_MIN = 72;
const CHUNK_SIZE_MAX = 156;

const ri = (n) => crypto.randomInt(0, n);

const LUA_RESERVED = new Set([
  'and','break','do','else','elseif','end','false','for','function','goto','if','in','local','nil','not','or','repeat','return','then','true','until','while'
]);
function rid() {
  // Short randomized identifiers are far more reliable in Luau than long
  // underscore-only names, while the payload itself remains digits-only.
  const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let out = '';
  do {
    out = 'q';
    const len = 5 + ri(4);
    for (let i = 0; i < len; i++) out += letters[ri(letters.length)];
  } while (LUA_RESERVED.has(out));
  return out;
}

function modInverse256(a) {
  // Every odd integer has an inverse modulo 256.
  for (let x = 1; x < 256; x++) {
    if (((a * x) % 256 + 256) % 256 === 1) return x;
  }
  throw new Error('Invalid numeric key');
}

function decimalEncode(buf, a, b) {
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    const y = (a * buf[i] + b + (i % 251)) % 256;
    out += String(y).padStart(3, '0');
  }
  return out;
}

function decimalDecode(decimal, a, b) {
  const inv = modInverse256(a);
  if (decimal.length % 3 !== 0) throw new Error('Invalid decimal payload length');
  const out = Buffer.alloc(decimal.length / 3);
  for (let i = 0, j = 0; i < decimal.length; i += 3, j++) {
    const y = Number(decimal.slice(i, i + 3));
    if (!Number.isInteger(y) || y < 0 || y > 255) throw new Error('Invalid decimal byte');
    const z = ((y - b - (j % 251)) % 256 + 256) % 256;
    out[j] = (inv * z) % 256;
  }
  return out;
}

function rollingHash32(buf) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < buf.length; i++) {
    h = (Math.imul(h, 16777619) + buf[i] + 97) >>> 0;
  }
  return h >>> 0;
}

function luaQuote(value) {
  // JSON strings are valid Lua string literals for the characters we emit.
  return JSON.stringify(String(value));
}

function chunkDecimal(decimal) {
  const out = [];
  let p = 0;
  while (p < decimal.length) {
    // Keep each chunk aligned to 3 decimal digits.
    const room = CHUNK_SIZE_MIN + ri(CHUNK_SIZE_MAX - CHUNK_SIZE_MIN + 1);
    const size = Math.max(3, room - (room % 3));
    out.push(decimal.slice(p, p + size));
    p += size;
  }
  return out;
}

function buildLoader(decimalPayload, a, b, expectedHash, sourceLen) {
  const V = Array.from({ length: 18 }, rid);
  const parts = chunkDecimal(decimalPayload);
  const payloadTable = parts.map(luaQuote).join(',');
  const L = [];

  // Keep the runtime compact and Luau-friendly: one statement stream, semicolons
  // between every statement, no optional/nonstandard calls, and no Unicode payload.
  L.push('-- QyrexObf by ikgmonxr qyrex.hopto.org 1.0.2\n');
  L.push('return(function(...)');
  L.push(`local ${V[0]}={${payloadTable}};`);
  L.push(`local ${V[1]}=${sourceLen};local ${V[2]}=${a};local ${V[3]}=${b};local ${V[4]}=${expectedHash};`);
  L.push(`local ${V[5]}=type;local ${V[6]}=string;local ${V[7]}=table;local ${V[8]}=pcall;`);

  // Integrated soft anti-tamper. It only records an environment flag; it never
  // calls optional functions such as collectgarbage/hookfunction/gcinfo.
  L.push(`local ${V[9]}=0;${V[8]}(function()local ${V[10]}=${V[5]}(game);if ${V[10]}=='userdata' or ${V[10]}=='table' then ${V[9]}=${V[9]}+1 end;if ${V[5]}(_G)=='table' then ${V[9]}=${V[9]}+1 end end);`);

  // Find the modular inverse once using only arithmetic supported by Luau.
  L.push(`local ${V[11]}=1;while ((${V[2]}*${V[11]})%256)~=1 do ${V[11]}=${V[11]}+1;if ${V[11]}>255 then return end end;`);

  // Join and validate the numeric payload.
  L.push(`local ${V[12]}=${V[7]}.concat(${V[0]});${V[0]}=nil;if #${V[12]}~=${V[1]}*3 then return end;`);
  L.push(`local ${V[13]}={};local ${V[14]}=1;for ${V[15]}=1,#${V[12]},3 do local ${V[16]}=${V[6]}.sub(${V[12]},${V[15]},${V[15]}+2)+0;if ${V[16]}<0 or ${V[16]}>255 then return end;local ${V[17]}=(((${V[16]}-${V[3]}-(((${V[14]}-1)%251)))%256)+256)%256;${V[13]}[${V[14]}]=${V[6]}.char(((${V[17]}*${V[11]})%256));${V[14]}=${V[14]}+1 end;`);
  L.push(`local ${V[12]}=${V[7]}.concat(${V[13]});${V[13]}=nil;`);

  // Integrity check before compilation.
  L.push(`local ${V[17]}=2166136261;for ${V[14]}=1,#${V[12]} do local ${V[16]}=${V[6]}.byte(${V[12]},${V[14]});${V[17]}=(${V[17]}*16777619+${V[16]}+97)%4294967296 end;if ${V[17]}~=${V[4]} or #${V[12]}~=${V[1]} then return end;`);

  // Compile and execute. Prefer loadstring for Roblox; fall back to load only.
  L.push(`local ${V[13]}=loadstring;if ${V[5]}(${V[13]})~='function' then ${V[13]}=load end;if ${V[5]}(${V[13]})~='function' then return end;local ${V[14]},${V[15]}=${V[8]}(${V[13]},${V[12]});${V[12]}=nil;if not ${V[14]} or ${V[5]}(${V[15]})~='function' then return end;return ${V[15]}(...);`);
  L.push('end)(...)');
  return L.join('');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');

  const raw = Buffer.from(src, 'utf8');
  if (raw.length > MAX_SOURCE) throw new Error('Too large');

  // Random affine transform: invertible modulo 256 because a is odd.
  const a = 1 + 2 * ri(128);
  const b = ri(256);
  const decimal = decimalEncode(raw, a, b);

  if (!/^\d+$/.test(decimal)) throw new Error('decimal payload violation');
  if (decimal.length !== raw.length * 3) throw new Error('decimal length mismatch');

  const back = decimalDecode(decimal, a, b);
  if (!back.equals(raw)) throw new Error('numeric roundtrip failed');

  const expectedHash = rollingHash32(raw);
  const code = buildLoader(decimal, a, b, expectedHash, raw.length);

  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: `QyrexObf-${VERSION}`,
      layers: [
        'decimal-only-payload',
        'randomized-affine-byte-transform',
        'numeric-integrity-check',
        'luau-compatible-loader',
        'soft-environment-anti-tamper',
        'payload-wipe-after-decode',
        'randomized-chunking'
      ],
      verified: true,
      payloadAlphabet: '0123456789',
      decimalLayer: true
    }
  };
}

module.exports = { obfuscate, VERSION };
