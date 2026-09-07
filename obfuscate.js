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
  const V = Array.from({ length: 24 }, rid);
  const parts = chunkDecimal(decimalPayload);
  const payloadTable = parts.map(luaQuote).join(',');
  const L = [];

  L.push('-- QyrexObf by ikgmonxr qyrex.hopto.org 1.0.2');
  L.push('return(function(...)');

  // Static numeric configuration.
  L.push(`local ${V[0]}={${payloadTable}}`);
  L.push(`local ${V[1]}=${sourceLen}`);
  L.push(`local ${V[2]}=${a}`);
  L.push(`local ${V[3]}=${b}`);
  L.push(`local ${V[4]}=${expectedHash}`);

  // Conservative compatibility probes. None of these are fatal by themselves.
  // We only refuse to continue when core APIs needed by the loader are absent.
  L.push(`local ${V[5]}=type`);
  L.push(`local ${V[6]}=string`);
  L.push(`local ${V[7]}=table`);
  L.push(`local ${V[8]}=pcall`);
  L.push(`if ${V[5]}~='function' or ${V[5]}(${V[6]})~='table' or ${V[5]}(${V[6]}.sub)~='function' or ${V[5]}(${V[6]}.char)~='function' or ${V[5]}(${V[7]}.concat)~='function' then return end`);

  // Non-fatal anti-tamper/environment score. It is intentionally tolerant of
  // normal Roblox/Luau differences so legitimate scripts keep running.
  L.push(`local ${V[9]}=0`);
  L.push(`${V[8]}(function()`);
  L.push(`  local ${V[23]}=${V[5]}(game)`);
  L.push(`  if ${V[23]}=='userdata' or ${V[23]}=='table' then`);
  L.push(`    ${V[9]}=${V[9]}+1`);
  L.push(`  end`);
  L.push(`end)`);
  L.push(`${V[8]}(function()`);
  L.push(`  if ${V[5]}(gcinfo)=='function' then`);
  L.push(`    local ${V[10]}=gcinfo()`);
  L.push(`    if ${V[5]}(${V[10]})=='number' then`);
  L.push(`      ${V[9]}=${V[9]}+1`);
  L.push(`    end`);
  L.push(`  end`);
  L.push(`end)`);
  L.push(`${V[8]}(function()`);
  L.push(`  if ${V[5]}(getmetatable)=='function' and getmetatable(_G)~=nil then`);
  L.push(`    ${V[9]}=${V[9]}-1`);
  L.push(`  end`);
  L.push(`end)`);
  L.push(`${V[8]}(function()`);
  L.push(`  if ${V[5]}(hookfunction)=='function' or ${V[5]}(newcclosure)=='function' or ${V[5]}(replaceclosure)=='function' then`);
  L.push(`    ${V[9]}=${V[9]}-1`);
  L.push(`  end`);
  L.push(`end)`);

  // Decimal -> original bytes.
  L.push(`local function ${V[11]}(${V[12]})`);
  L.push(`  if #${V[12]}%3~=0 then return nil end`);
  L.push(`  local ${V[13]}={}`);
  L.push(`  local ${V[14]}=1`);
  L.push(`  local ${V[15]}=1`);
  L.push(`  local ${V[16]}=1`);
  L.push(`  while ${V[15]}<=#${V[12]} do`);
  L.push(`    local ${V[17]}=${V[6]}.sub(${V[12]},${V[15]},${V[15]}+2)+0`);
  L.push(`    if ${V[17]}<0 or ${V[17]}>255 then return nil end`);
  L.push(`    local ${V[18]}=(((${V[2]}*${V[16]})%256)~=1) and nil or ${V[16]}`);
  L.push(`    if ${V[18]}==nil then return nil end`);
  L.push(`    local ${V[19]}=(((${V[17]}-${V[3]}-((${V[14]}-1)%251))%256)+256)%256`);
  L.push(`    ${V[13]}[${V[14]}]=${V[6]}.char(((${V[19]}*${V[16]})%256))`);
  L.push(`    ${V[14]}=${V[14]}+1`);
  L.push(`    ${V[15]}=${V[15]}+3`);
  L.push(`  end`);
  L.push(`  return ${V[7]}.concat(${V[13]})`);
  L.push(`end`);

  // Find modular inverse in Luau once. This is bounded to 128 odd candidates.
  L.push(`local ${V[16]}=1`);
  L.push(`while ((${V[2]}*${V[16]})%256)~=1 do ${V[16]}=${V[16]}+2 if ${V[16]}>255 then return end end`);

  // Join payload chunks without exposing source bytes.
  L.push(`local ${V[13]}=${V[7]}.concat(${V[0]})`);
  L.push(`if #${V[13]}~=${V[1]}*3 then return end`);
  L.push(`local ${V[14]}=${V[13]}`);
  L.push(`${V[13]}=nil`);

  // Decode directly, avoiding Unicode/symbol handling completely.
  L.push(`local ${V[17]}={}`);
  L.push(`local ${V[18]}=1`);
  L.push(`for ${V[19]}=1,#${V[14]},3 do`);
  L.push(`  local ${V[20]}=${V[6]}.sub(${V[14]},${V[19]},${V[19]}+2)+0`);
  L.push(`  local ${V[21]}=(((${V[20]}-${V[3]}-(((${V[18]}-1)%251)))%256)+256)%256`);
  L.push(`  ${V[17]}[${V[18]}]=${V[6]}.char(((${V[21]}*${V[16]})%256))`);
  L.push(`  ${V[18]}=${V[18]}+1`);
  L.push(`end`);
  L.push(`local ${V[22]}=${V[7]}.concat(${V[17]})`);
  L.push(`${V[17]}=nil`);
  L.push(`${V[14]}=nil`);

  // Arithmetic FNV-style integrity check.
  L.push(`local ${V[17]}=2166136261`);
  L.push(`for ${V[18]}=1,#${V[22]} do`);
  L.push(`  ${V[20]}=${V[6]}.byte(${V[22]},${V[18]})`);
  L.push(`  ${V[17]}=(${V[17]}*16777619+${V[20]}+97)%4294967296`);
  L.push(`end`);
  L.push(`if ${V[17]}~=${V[4]} then return end`);
  L.push(`if #${V[22]}~=${V[1]} then return end`);

  // Compile and execute. Support both Roblox's loadstring and environments
  // exposing load, without requiring collectgarbage or nonstandard APIs.
  L.push(`local ${V[17]}=loadstring or load`);
  L.push(`if ${V[5]}(${V[17]})~='function' then return end`);
  L.push(`local ${V[18]},${V[19]}=${V[8]}(${V[17]},${V[22]})`);
  L.push(`local ${V[20]}=${V[19]}`);
  L.push(`${V[22]}=nil`);
  L.push(`if not ${V[18]} or ${V[5]}(${V[20]})~='function' then return end`);
  L.push(`if ${V[5]}(${V[20]})~='function' then return end`);
  L.push(`return ${V[20]}(...)`);
  L.push('end)(...)');

  return L.join('\n');
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
