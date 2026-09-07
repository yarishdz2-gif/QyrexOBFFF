/**
 * QyrexObf 2.0.0
 * Payload: DECIMAL DIGITS ONLY (0-9)
 * Numeric transform only. Decimal payload.
 * Luau-compatible loader with numeric decoding + integrity checks.
 */
'use strict';

const crypto = require('crypto');
const VERSION = '2.0.0';
const MAX_SOURCE = 1_500_000;
const BLOCK_SIZE = 29;

const ri = (n) => crypto.randomInt(0, n);
const rb = (n) => crypto.randomBytes(n);

let uid = 0;
function rid() {
  uid += 1 + ri(3);
  return '_'.repeat(uid);
}

function rollingHash32(buf) {
  let h = 2166136261;
  for (const b of buf) {
    h = (Math.imul(h, 16777619) + b + 97) >>> 0;
  }
  return h >>> 0;
}

function decimalEncode(buffer, a, b) {
  const out = [];
  for (let i = 0; i < buffer.length; i++) {
    const x = buffer[i];
    // Odd a is invertible modulo 256. Arithmetic transform only.
    const y = ((Math.imul(a, x) + b + (i % 251)) % 256 + 256) % 256;
    out.push(String(y).padStart(3, '0'));
  }
  return out.join('');
}

function decimalDecode(buffer, a, b) {
  const inv = modInverse256(a);
  const out = Buffer.alloc(buffer.length / 3);
  for (let i = 0, j = 0; i + 2 < buffer.length; i += 3, j++) {
    const y = Number(buffer.slice(i, i + 3));
    const z = ((y - b - (j % 251)) % 256 + 256) % 256;
    out[j] = ((Math.imul(inv, z) % 256) + 256) % 256;
  }
  return out;
}

function modInverse256(a) {
  // For odd a, this small brute-force inverse is cheap and deterministic.
  for (let x = 1; x < 256; x += 2) {
    if (((a * x) % 256 + 256) % 256 === 1) return x;
  }
  throw new Error('Invalid numeric key');
}

function chunkDigits(s) {
  const out = [];
  const step = BLOCK_SIZE * (1 + ri(5));
  for (let i = 0; i < s.length; i += step) out.push(s.slice(i, i + step));
  return out;
}

function luaQuote(s) {
  return JSON.stringify(String(s));
}

function buildLoader(decimalPayload, a, b, expectedHash, sourceLen) {
  uid = 0;
  const V = Array.from({ length: 49 }, rid);
  const parts = chunkDigits(decimalPayload);
  const payloadTable = parts.map((p) => luaQuote(p)).join(',');

  const L = [];
  L.push('--[[ QyrexObf 2.0.0 | decimal payload | arithmetic numeric transform ]]');
  L.push(`return(function(...)`);

  // Numeric-only payload is kept in decimal strings. Everything outside this
  // payload is executable Luau syntax, which necessarily needs keywords/symbols.
  L.push(`local ${V[0]}=_G`);
  L.push(`local ${V[1]}={${payloadTable}}`);
  L.push(`local ${V[2]}=${sourceLen}`);
  L.push(`local ${V[3]}=${a}`);
  L.push(`local ${V[4]}=${b}`);
  L.push(`local ${V[5]}=${expectedHash}`);

  // Resolve standard functions without embedding the source payload in cleartext.
  L.push(`local ${V[6]}=string`);
  L.push(`local ${V[7]}=table`);
  L.push(`local ${V[8]}=math`);
  L.push(`local ${V[9]}=pcall`);
  L.push(`local ${V[10]}=type`);
  L.push(`local ${V[11]}=loadstring or load`);
  L.push(`local ${V[12]}=${V[6]}.sub`);
  L.push(`local ${V[13]}=${V[6]}.char`);
  L.push(`local ${V[14]}=${V[7]}.concat`);

  // Deterministic decimal parser.
  L.push(`local function ${V[15]}(s)`);
  L.push(`  local o={} local j=1 local p=1 local n=#s`);
  L.push(`  while p<=n do`);
  L.push(`    local y=(${V[12]}(s,p,p+2)+0)`);
  L.push(`    local x=0`);
  L.push(`    local inv=1`);
  L.push(`    while (((${V[3]}*inv)%256)~=1) do inv=inv+2 end`);
  L.push(`    x=(((y-${V[4]}-((j-1)%251))%256)+256)%256`);
  L.push(`    x=(x*inv)%256`);
  L.push(`    o[j]=${V[13]}(x)`);
  L.push(`    j=j+1 p=p+3`);
  L.push(`  end`);
  L.push(`  return ${V[14]}(o)`);
  L.push(`end`);

  // Lightweight 32-bit integrity check using arithmetic only.
  L.push(`local function ${V[16]}(s)`);
  L.push(`  local h=2166136261`);
  L.push(`  for i=1,#s do`);
  L.push(`    local c=${V[6]}.byte(s,i)`);
  L.push(`    h=(h*16777619+c+97)%4294967296`);
  L.push(`  end`);
  L.push(`  return h`);
  L.push(`end`);

  // Environment / hook sanity checks. These are intentionally soft: normal Roblox/clean Luau execution is not blocked.
  L.push(`local ${V[17]}=0`);
  L.push(`pcall(function() if ${V[10]}(${V[6]})=='table' then ${V[17]}=${V[17]}+1 end end)`);
  L.push(`pcall(function() if ${V[10]}(${V[12]})=='function' then ${V[17]}=${V[17]}+1 end end)`);
  L.push(`pcall(function() if ${V[10]}(${V[13]})=='function' then ${V[17]}=${V[17]}+1 end end)`);
  L.push(`pcall(function() if game and typeof and typeof(game)=='Instance' then ${V[17]}=${V[17]}+2 end end)`);
  L.push(`pcall(function() if _G and getmetatable and getmetatable(_G)~=nil then ${V[17]}=${V[17]}-1 end end)`);
  L.push(`pcall(function() if hookfunction or replaceclosure or newcclosure then ${V[17]}=${V[17]}-2 end end)`);
  L.push(`if ${V[17]}<2 then return end`);

  // Reassemble + decode. The payload itself contains digits only.
  L.push(`local ${V[18]}=${V[14]}(${V[1]})`);
  L.push(`if #${V[18]}~=${V[2]}*3 then return end`);
  L.push(`local ${V[19]}=${V[15]}(${V[18]})`);
  L.push(`if #${V[19]}~=${V[2]} then return end`);
  L.push(`if ${V[16]}(${V[19]})~=${V[5]} then return end`);

  // Clear packed data before loading the recovered source.
  L.push(`${V[1]}=nil ${V[18]}=nil`);
  L.push(`collectgarbage('collect')`);

  L.push(`local ${V[20]}=${V[11]}`);
  L.push(`if ${V[10]}(${V[20]})~='function' then return end`);
  L.push(`local ${V[21]},${V[22]}=${V[9]}(${V[20]},${V[19]})`);
  L.push(`${V[19]}=nil`);
  L.push(`if not ${V[21]} or ${V[10]}(${V[22]})~='function' then return end`);
  L.push(`return ${V[22]}(...)`);
  L.push(`end)(...)`);

  return L.join('\n');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const raw = Buffer.from(src, 'utf8');
  if (raw.length > MAX_SOURCE) throw new Error('Too large');

  // Random invertible affine transform using decimal arithmetic only.
  const odd = [1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83,85,87,89,91,93,95,97,99,101,103,105,107,109,111,113,115,117,119,121,123,125,127,129,131,133,135,137,139,141,143,145,147,149,151,153,155,157,159,161,163,165,167,169,171,173,175,177,179,181,183,185,187,189,191,193,195,197,199,201,203,205,207,209,211,213,215,217,219,221,223,225,227,229,231,233,235,237,239,241,243,245,247,249,251,253,255];
  const a = odd[ri(odd.length)];
  const b = ri(256);
  const decimal = decimalEncode(raw, a, b);
  const back = decimalDecode(decimal, a, b);
  if (!back.equals(raw)) throw new Error('numeric roundtrip failed');

  // Hard verification that the payload alphabet really is digits only.
  if (!/^\d+$/.test(decimal)) throw new Error('decimal payload violation');

  const expectedHash = rollingHash32(raw);
  const code = buildLoader(decimal, a, b, expectedHash, raw.length);

  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: `QyrexObf-${VERSION}`,
      layers: [
        'decimal-digits-only-payload',
        'affine-byte-transform',
        'numeric-integrity-check',
        'environment-sanity-checks',
        'payload-wipe-after-decode',
        'randomized-layout'
      ],
      verified: true,
      payloadAlphabet: '0123456789'
    }
  };
}

module.exports = { obfuscate, VERSION };
