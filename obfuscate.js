/**
 * QyrexObf 2.0.0
 * Payload: DECIMAL DIGITS ONLY (0-9)
 * Numeric transform only. Decimal payload.
 * Luau-compatible loader with numeric decoding + integrity checks.
 */
'use strict';

const crypto = require('crypto');
const VERSION = '2.1.0';
const MAX_SOURCE = 1_500_000;
const BLOCK_SIZE = 29;

// Segunda capa: cada dígito decimal se representa con uno de estos 10 símbolos.
// No aparecen 0-9 en el payload empaquetado.
const DIGIT_SYMBOLS = '!\"#$%&/()=';
const DIGIT_MAP = Object.fromEntries([...DIGIT_SYMBOLS].map((ch, i) => [ch, String(i)]));
const DIGIT_REVERSE = Array.from(DIGIT_SYMBOLS);

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
    h = (h * 65599 + b + 97) % 4294967296;
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

function symbolEncodeDigits(decimal) {
  let out = '';
  for (const ch of decimal) {
    if (ch < '0' || ch > '9') throw new Error('non-decimal payload');
    out += DIGIT_REVERSE[ch.charCodeAt(0) - 48];
  }
  return out;
}

function symbolDecodeDigits(symbols) {
  let out = '';
  for (const ch of symbols) {
    const digit = DIGIT_MAP[ch];
    if (digit === undefined) throw new Error('invalid symbol payload');
    out += digit;
  }
  return out;
}

function chunkSymbols(s) {
  const out = [];
  const step = BLOCK_SIZE * (1 + ri(5));
  for (let i = 0; i < s.length; i += step) out.push(s.slice(i, i + step));
  return out;
}

function luaQuote(s) {
  return JSON.stringify(String(s));
}

function buildLoader(symbolPayload, a, b, expectedHash, sourceLen) {
  uid = 0;
  const V = Array.from({ length: 31 }, rid);
  const parts = chunkSymbols(symbolPayload);
  const payloadTable = parts.map((p) => luaQuote(p)).join(',');
  const alphaLua = luaQuote(DIGIT_SYMBOLS);

  const L = [];
  L.push('-- QyrexObf by ikgmonxr qyrex.hopto.org 1.0.2');
  L.push(`return(function(...)`);

  L.push(`local ${V[0]}=_G`);
  L.push(`local ${V[1]}={${payloadTable}}`);
  L.push(`local ${V[2]}=${alphaLua}`);
  L.push(`local ${V[3]}=${sourceLen}`);
  L.push(`local ${V[4]}=${a}`);
  L.push(`local ${V[5]}=${b}`);
  L.push(`local ${V[6]}=${expectedHash}`);

  // Build symbol -> decimal digit lookup table using ASCII bytes only.
  L.push(`local ${V[7]}={}`);
  L.push(`${V[7]}[33]='0'`);
  L.push(`${V[7]}[34]='1'`);
  L.push(`${V[7]}[35]='2'`);
  L.push(`${V[7]}[36]='3'`);
  L.push(`${V[7]}[37]='4'`);
  L.push(`${V[7]}[38]='5'`);
  L.push(`${V[7]}[47]='6'`);
  L.push(`${V[7]}[40]='7'`);
  L.push(`${V[7]}[41]='8'`);
  L.push(`${V[7]}[61]='9'`);

  // Layer 1: symbols -> decimal digits. ASCII-only alphabet for Luau/Roblox.
  L.push(`local function ${V[9]}(s)`);
  L.push(`  local o={} local j=1`);
  L.push(`  for ${V[10]}=1,#s do`);
  L.push(`    local d=${V[7]}[string.byte(s,${V[10]})]`);
  L.push(`    if d==nil then return nil end`);
  L.push(`    o[j]=d j=j+1`);
  L.push(`  end`);
  L.push(`  return table.concat(o)`);
  L.push(`end`);

  // Layer 2: decimal digits -> original bytes.
  L.push(`local function ${V[11]}(s)`);
  L.push(`  local o={} local j=1 local p=1 local n=#s`);
  L.push(`  local inv=1 while (((${V[4]}*inv)%256)~=1) do inv=inv+2 end`);
  L.push(`  while p<=n do`);
  L.push(`    local y=(string.sub(s,p,p+2)+0)`);
  L.push(`    local x=(((y-${V[5]}-((j-1)%251))%256)+256)%256`);
  L.push(`    x=(x*inv)%256`);
  L.push(`    o[j]=string.char(x)`);
  L.push(`    j=j+1 p=p+3`);
  L.push(`  end`);
  L.push(`  return table.concat(o)`);
  L.push(`end`);

  // Arithmetic integrity check.
  L.push(`local function ${V[12]}(s)`);
  L.push(`  local h=2166136261`);
  L.push(`  for ${V[13]}=1,#s do`);
  L.push(`    local c=string.byte(s,${V[13]})`);
  L.push(`    h=(h*65599+c+97)%4294967296`);
  L.push(`  end`);
  L.push(`  return h`);
  L.push(`end`);

  // Soft environment / hook sanity checks.
  L.push(`local ${V[14]}=0`);
  L.push(`pcall(function() if type(string)=='table' then ${V[14]}=${V[14]}+1 end end)`);
  L.push(`pcall(function() if type(string.sub)=='function' then ${V[14]}=${V[14]}+1 end end)`);
  L.push(`pcall(function() if type(string.char)=='function' then ${V[14]}=${V[14]}+1 end end)`);
  L.push(`pcall(function() if game and typeof and typeof(game)=='Instance' then ${V[14]}=${V[14]}+2 end end)`);
  L.push(`pcall(function() if _G and getmetatable and getmetatable(_G)~=nil then ${V[14]}=${V[14]}-1 end end)`);
  L.push(`pcall(function() if hookfunction or replaceclosure or newcclosure then ${V[14]}=${V[14]}-2 end end)`);
  L.push(`if ${V[14]}<2 then return end`);

  // Symbols -> decimal.
  L.push(`local ${V[15]}={}`);
  L.push(`for ${V[16]}=1,#${V[1]} do`);
  L.push(`  local q=${V[9]}(${V[1]}[${V[16]}])`);
  L.push(`  if not q then return end`);
  L.push(`  ${V[15]}[${V[16]}]=q`);
  L.push(`end`);
  L.push(`local ${V[17]}=table.concat(${V[15]})`);
  L.push(`${V[15]}=nil ${V[1]}=nil`);

  // Decimal -> original bytes and verify before compiling.
  L.push(`if #${V[17]}~=${V[3]}*3 then return end`);
  L.push(`local ${V[18]}=${V[11]}(${V[17]})`);
  L.push(`${V[17]}=nil`);
  L.push(`if #${V[18]}~=${V[3]} then return end`);
  L.push(`if ${V[12]}(${V[18]})~=${V[6]} then return end`);

  L.push(`local ${V[19]}=loadstring or load`);
  L.push(`if type(${V[19]})~='function' then return end`);
  L.push(`local ${V[20]},${V[21]}=pcall(${V[19]},${V[18]})`);
  L.push(`${V[18]}=nil`);
  L.push(`if not ${V[20]} or type(${V[21]})~='function' then return end`);
  L.push(`collectgarbage('collect')`);
  L.push(`return ${V[21]}(...)`);
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
  const symbolized = symbolEncodeDigits(decimal);
  const back = decimalDecode(symbolDecodeDigits(symbolized), a, b);
  if (!back.equals(raw)) throw new Error('numeric roundtrip failed');

  // Hard verification that the payload alphabet really is digits only.
  if (!/^\d+$/.test(decimal)) throw new Error('decimal payload violation');
  if (/[0-9]/.test(symbolized)) throw new Error('symbol payload contains decimal digits');

  const expectedHash = rollingHash32(raw);
  const code = buildLoader(symbolized, a, b, expectedHash, raw.length);

  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: `QyrexObf-${VERSION}`,
      layers: [
        'symbolized-decimal-payload',
        'decimal-digits-after-symbol-decoding',
        'affine-byte-transform',
        'numeric-integrity-check',
        'environment-sanity-checks',
        'payload-wipe-after-decode',
        'randomized-layout'
      ],
      verified: true,
      payloadAlphabet: DIGIT_SYMBOLS,
      decimalLayer: true
    }
  };
}

module.exports = { obfuscate, VERSION };
