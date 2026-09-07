/**
 * QyrexObf 1.2.0
 * Roblox/Luau compatible numeric payload.
 * Visible payload alphabet: digits 0-9 only.
 * No Unicode payload symbols, XOR, or Base64.
 *
 * Hardening additions:
 * - dual affine byte transform
 * - per-byte two-state key schedule
 * - keyed chunk permutation with integrity metadata
 * - independent payload checksum
 * - randomized runtime identifiers/chunking
 * - best-effort memory wiping after decode
 */
'use strict';

const crypto = require('crypto');

const VERSION = '1.2.0';
const MAX_SOURCE = 1_500_000;
const CHUNK_SIZE_MIN = 72;
const CHUNK_SIZE_MAX = 156;
const PERM_MOD = 1000003;
const PRNG_MUL_A = 48271;
const PRNG_MUL_B = 69621;

const ri = (n) => crypto.randomInt(0, n);

const LUA_RESERVED = new Set([
  'and','break','do','else','elseif','end','false','for','function','goto','if','in','local','nil','not','or','repeat','return','then','true','until','while'
]);

function rid() {
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
  for (let x = 1; x < 256; x++) {
    if (((a * x) % 256 + 256) % 256 === 1) return x;
  }
  throw new Error('Invalid numeric key');
}

function nextState(state, mul, add) {
  return (state * mul + add) % PERM_MOD;
}

function decimalEncode(buf, a1, b1, a2, b2, seedA, seedB) {
  let out = '';
  let sa = seedA;
  let sb = seedB;
  for (let i = 0; i < buf.length; i++) {
    sa = nextState(sa, PRNG_MUL_A, 97 + (i % 251));
    sb = nextState(sb, PRNG_MUL_B, 193 + ((i * 17) % 251));
    const mask = (sa + 3 * sb + i * 29) % 256;
    const stage1 = (a1 * buf[i] + b1 + (i % 251) + mask) % 256;
    const stage2 = (a2 * stage1 + b2 + ((i * 7) % 251)) % 256;
    out += String(stage2).padStart(3, '0');
  }
  return out;
}

function decimalDecode(decimal, a1, b1, a2, b2, seedA, seedB) {
  const inv1 = modInverse256(a1);
  const inv2 = modInverse256(a2);
  if (decimal.length % 3 !== 0) throw new Error('Invalid decimal payload length');
  const out = Buffer.alloc(decimal.length / 3);
  let sa = seedA;
  let sb = seedB;
  for (let i = 0, j = 0; i < decimal.length; i += 3, j++) {
    sa = nextState(sa, PRNG_MUL_A, 97 + (j % 251));
    sb = nextState(sb, PRNG_MUL_B, 193 + ((j * 17) % 251));
    const mask = (sa + 3 * sb + j * 29) % 256;
    const y = Number(decimal.slice(i, i + 3));
    if (!Number.isInteger(y) || y < 0 || y > 255) throw new Error('Invalid decimal byte');
    const stage1 = ((inv2 * ((y - b2 - ((j * 7) % 251)) % 256 + 256) % 256)) % 256;
    const z = ((stage1 - b1 - (j % 251) - mask) % 256 + 256) % 256;
    out[j] = (inv1 * z) % 256;
  }
  return out;
}

function rollingHash32(buf) {
  let h = 216613;
  for (let i = 0; i < buf.length; i++) {
    h = (h * 257 + buf[i] + 97) % PERM_MOD;
  }
  return h;
}

function payloadHash(decimal) {
  let h = 811;
  for (let i = 0; i < decimal.length; i++) {
    h = (h * 131 + decimal.charCodeAt(i) - 48) % PERM_MOD;
  }
  return h;
}

function luaQuote(value) {
  return JSON.stringify(String(value));
}

function makeChunks(decimal) {
  const chunks = [];
  let p = 0;
  while (p < decimal.length) {
    const room = CHUNK_SIZE_MIN + ri(CHUNK_SIZE_MAX - CHUNK_SIZE_MIN + 1);
    const size = Math.max(3, room - (room % 3));
    chunks.push(decimal.slice(p, p + size));
    p += size;
  }
  return chunks;
}

function shuffleWithKey(arr, seed) {
  const out = arr.slice();
  let s = seed;
  for (let i = out.length - 1; i > 0; i--) {
    s = nextState(s, PRNG_MUL_B, 17 + i);
    const j = s % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function buildLoader(decimalPayload, params, expectedHash, sourceLen) {
  const V = Array.from({ length: 18 }, rid);
  const originalParts = makeChunks(decimalPayload);
  const orderSeed = params.orderSeed;
  const indexed = originalParts.map((chunk, index) => `${index + 1}:${chunk}`);
  const shuffled = shuffleWithKey(indexed, orderSeed);
  const payloadTable = shuffled.map(luaQuote).join(',');
  const L = [];

  L.push(`-- QyrexObf by ikgmonxr qyrex.hopto.org ${VERSION}\n`);
  L.push('return(function(...)');
  L.push(`local ${V[0]}={${payloadTable}};`);
  L.push(`local ${V[1]}=${sourceLen};local ${V[2]}=${params.a1};local ${V[3]}=${params.b1};local ${V[4]}=${params.a2};local ${V[5]}=${params.b2};`);
  L.push(`local ${V[6]}=${params.seedA};local ${V[7]}=${params.seedB};local ${V[8]}=${orderSeed};local ${V[9]}=${expectedHash};local ${V[10]}=${payloadHash(decimalPayload)};`);
  L.push(`local ${V[11]}=type;local ${V[12]}=string;local ${V[13]}=table;local ${V[14]}=pcall;`);

  L.push(`local ${V[15]}=0;${V[14]}(function()local ${V[16]}=${V[11]}(game);if ${V[16]}=='userdata' or ${V[16]}=='table' then ${V[15]}=${V[15]}+1 end;if ${V[11]}(_G)=='table' then ${V[15]}=${V[15]}+1 end end);`);

  // Rebuild the original chunk order from indexed entries, then discard the shuffled table.
  L.push(`local ${V[16]}={};for ${V[17]}=1,#${V[0]} do local ${V[6]}=${V[12]}.find(${V[0]}[${V[17]}],':',1,true);if not ${V[6]} then return end;local ${V[7]}=${V[12]}.sub(${V[0]}[${V[17]}],1,${V[6]}-1)+0;local ${V[8]}=${V[12]}.sub(${V[0]}[${V[17]}],${V[6]}+1);${V[16]}[${V[7]}]=${V[8]} end;`);
  L.push(`local ${V[0]}=${V[13]}.concat(${V[16]});${V[16]}=nil;`);

  // Payload checksum after reordering, before decode.
  L.push(`local ${V[16]}='';for ${V[17]}=1,#${V[0]} do ${V[16]}=${V[16]}..${V[0]}[${V[17]}] end;local ${V[0]}=${V[16]};${V[16]}=nil;if #${V[0]}~=${V[1]}*3 then return end;`);
  L.push(`local ${V[16]}=811;for ${V[17]}=1,#${V[0]} do ${V[16]}=(${V[16]}*131+(${V[12]}.byte(${V[0]},${V[17]})-48))%${PERM_MOD} end;if ${V[16]}~=${V[10]} then return end;`);

  // Decode the dual affine transform with the same two-state key schedule.
  L.push(`local ${V[16]}=1;while ((${V[2]}*${V[16]})%256)~=1 do ${V[16]}=${V[16]}+1;if ${V[16]}>255 then return end end;local ${V[17]}=1;while ((${V[4]}*${V[17]})%256)~=1 do ${V[17]}=${V[17]}+1;if ${V[17]}>255 then return end end;local ${V[6]}=${V[6]};local ${V[7]}=${V[7]};`);
  L.push(`local ${V[14]}={};local ${V[15]}=1;for ${V[8]}=1,#${V[0]},3 do local ${V[10]}=${V[12]}.sub(${V[0]},${V[8]},${V[8]}+2)+0;if ${V[10]}<0 or ${V[10]}>255 then return end;${V[6]}=(${V[6]}*${PRNG_MUL_A}+97+((${V[15]}-1)%251))%${PERM_MOD};${V[7]}=(${V[7]}*${PRNG_MUL_B}+193+((((${V[15]}-1)*17)%251)))%${PERM_MOD};local ${V[11]}=(${V[6]}+3*${V[7]}+((${V[15]}-1)*29))%256;local ${V[10]}=((${V[17]}*((${V[10]}-${V[5]}-((((${V[15]}-1)*7)%251)))%256+256)%256))%256;local ${V[10]}=(((${V[10]}-${V[3]}-(((${V[15]}-1)%251))-${V[11]})%256)+256)%256;${V[14]}[${V[15]}]=${V[12]}.char(((${V[16]}*${V[10]})%256));${V[15]}=${V[15]}+1 end;`);
  L.push(`local ${V[0]}=${V[13]}.concat(${V[14]});${V[14]}=nil;`);

  L.push(`local ${V[14]}=216613;for ${V[15]}=1,#${V[0]} do local ${V[10]}=${V[12]}.byte(${V[0]},${V[15]});${V[14]}=(${V[14]}*257+${V[10]}+97)%${PERM_MOD} end;if ${V[14]}~=${V[9]} or #${V[0]}~=${V[1]} then return end;`);

  // Best-effort wiping of intermediates before compilation.
  L.push(`${V[2]}=nil;${V[3]}=nil;${V[4]}=nil;${V[5]}=nil;${V[6]}=nil;${V[7]}=nil;${V[8]}=nil;${V[9]}=nil;${V[10]}=nil;`);
  L.push(`local ${V[14]}=loadstring;if ${V[11]}(${V[14]})~='function' then ${V[14]}=load end;if ${V[11]}(${V[14]})~='function' then return end;local ${V[15]},${V[16]}=${V[14]}(${V[0]});${V[0]}=nil;if not ${V[15]} or ${V[11]}(${V[16]})~='function' then return end;return ${V[16]}(...);`);
  L.push('end)(...)');
  return L.join('');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');

  const raw = Buffer.from(src, 'utf8');
  if (raw.length > MAX_SOURCE) throw new Error('Too large');

  const params = {
    a1: 1 + 2 * ri(128),
    b1: ri(256),
    a2: 1 + 2 * ri(128),
    b2: ri(256),
    seedA: 1 + ri(PERM_MOD - 1),
    seedB: 1 + ri(PERM_MOD - 1),
    orderSeed: 1 + ri(PERM_MOD - 1)
  };

  const decimal = decimalEncode(raw, params.a1, params.b1, params.a2, params.b2, params.seedA, params.seedB);
  if (!/^\d+$/.test(decimal)) throw new Error('decimal payload violation');
  if (decimal.length !== raw.length * 3) throw new Error('decimal length mismatch');

  const back = decimalDecode(decimal, params.a1, params.b1, params.a2, params.b2, params.seedA, params.seedB);
  if (!back.equals(raw)) throw new Error('numeric roundtrip failed');

  const expectedHash = rollingHash32(raw);
  const code = buildLoader(decimal, params, expectedHash, raw.length);

  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: `QyrexObf-${VERSION}`,
      layers: [
        'decimal-only-payload',
        'dual-randomized-affine-byte-transform',
        'per-byte-two-state-key-schedule',
        'keyed-chunk-permutation',
        'payload-integrity-check',
        'numeric-integrity-check',
        'luau-compatible-loader',
        'soft-environment-check',
        'best-effort-intermediate-wipe',
        'randomized-chunking'
      ],
      verified: true,
      payloadAlphabet: '0123456789',
      decimalLayer: true
    }
  };
}

module.exports = { obfuscate, VERSION };
