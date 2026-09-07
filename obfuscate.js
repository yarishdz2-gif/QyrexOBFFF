/**
 * QyrexObf 1.0.2 — anti-dump hardened (still Luau-safe)
 * Keeps working decimal payload + affine transform.
 * Adds: double-nest wrap, decoy loadstrings, delayed reconstruct,
 * soft AT, wipe locals, no long-lived clear source string.
 */
'use strict';

const crypto = require('crypto');
const VERSION = '1.0.2';
const MAX_SOURCE = 1_500_000;
const CHUNK_SIZE_MIN = 72;
const CHUNK_SIZE_MAX = 156;
const NEST_LEVELS = 2; // outer wraps inner loader → dumpers see intermediate first

const ri = (n) => crypto.randomInt(0, n);

const LUA_RESERVED = new Set([
  'and','break','do','else','elseif','end','false','for','function','goto','if','in',
  'local','nil','not','or','repeat','return','then','true','until','while',
]);

function rid() {
  const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let out = '';
  do {
    out = 'q';
    const len = 5 + ri(5);
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
  let h = 216613;
  for (let i = 0; i < buf.length; i++) {
    h = (h * 257 + buf[i] + 97) % 1000003;
  }
  return h;
}

function luaQuote(value) {
  return JSON.stringify(String(value));
}

function chunkDecimal(decimal) {
  const out = [];
  let p = 0;
  while (p < decimal.length) {
    const room = CHUNK_SIZE_MIN + ri(CHUNK_SIZE_MAX - CHUNK_SIZE_MIN + 1);
    const size = Math.max(3, room - (room % 3));
    out.push(decimal.slice(p, p + size));
    p += size;
  }
  return out;
}

/**
 * Build one loader level.
 * antiDump: if true, add decoys + no persistent source local before loadstring
 */
function buildLoader(decimalPayload, a, b, expectedHash, sourceLen, antiDump) {
  const V = Array.from({ length: 28 }, rid);
  const parts = chunkDecimal(decimalPayload);
  const payloadTable = parts.map(luaQuote).join(',');
  const L = [];

  L.push(`--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]]\n`);
  L.push('return(function(...)');
  L.push(`local ${V[0]}={${payloadTable}};`);
  L.push(`local ${V[1]}=${sourceLen};local ${V[2]}=${a};local ${V[3]}=${b};local ${V[4]}=${expectedHash};`);
  L.push(`local ${V[5]}=type;local ${V[6]}=string;local ${V[7]}=table;local ${V[8]}=pcall;`);
  L.push(`local ${V[9]}=0;`);

  /* soft AT — score only, never hard-kill clean Roblox */
  L.push(`${V[8]}(function()`);
  L.push(`local ${V[10]}=${V[5]}(game);if ${V[10]}=='userdata' or ${V[10]}=='table' then ${V[9]}=${V[9]}+1 end;`);
  L.push(`if ${V[5]}(_G)=='table' then ${V[9]}=${V[9]}+1 end;`);
  L.push(`if typeof and game~=nil and typeof(game)=='Instance' then ${V[9]}=${V[9]}+1 end;`);
  L.push(`if math and math.floor(3.9)==3 then ${V[9]}=${V[9]}+1 end;`);
  L.push(`if ${V[6]}.byte('A')==65 then ${V[9]}=${V[9]}+1 end;`);
  L.push(`end);`);
  L.push(`${V[8]}(function() if game and game.JobId=='00000000-0000-0000-0000-000000000000' then ${V[9]}=${V[9]}-5 end end);`);
  L.push(`${V[8]}(function() if game and (game.PlaceId==8916037983 or game.GameId==8916037983) then ${V[9]}=${V[9]}-5 end end);`);
  L.push(`${V[8]}(function() if getmetatable and getmetatable(_G)~=nil then ${V[9]}=${V[9]}-3 end end);`);
  L.push(`${V[8]}(function() if debug and debug.gethook then local ok,h=${V[8]}(debug.gethook);if ok and h~=nil then ${V[9]}=${V[9]}-4 end end end);`);
  L.push(`${V[8]}(function() local bad=false;local function has(k) local ok,v=${V[8]}(function() return rawget(_G,k) end);return ok and v~=nil end;`);
  L.push(`if has('process')or has('lune')or has('lute')or has('window')or has('document')or has('Buffer')then bad=true end;`);
  L.push(`if bad then ${V[9]}=${V[9]}-8 end end);`);

  /* modular inverse */
  L.push(`local ${V[11]}=1;while ((${V[2]}*${V[11]})%256)~=1 do ${V[11]}=${V[11]}+1;if ${V[11]}>255 then return end end;`);

  /* join decimal + decode to chars table (not one big clear string yet) */
  L.push(`local ${V[12]}=${V[7]}.concat(${V[0]});${V[0]}=nil;if #${V[12]}~=${V[1]}*3 then return end;`);
  L.push(`local ${V[13]}={};local ${V[14]}=1;`);
  L.push(`for ${V[15]}=1,#${V[12]},3 do`);
  L.push(`local ${V[16]}=${V[6]}.sub(${V[12]},${V[15]},${V[15]}+2)+0;`);
  L.push(`if ${V[16]}<0 or ${V[16]}>255 then return end;`);
  L.push(`local ${V[17]}=(((${V[16]}-${V[3]}-(((${V[14]}-1)%251)))%256)+256)%256;`);
  L.push(`${V[13]}[${V[14]}]=${V[6]}.char(((${V[17]}*${V[11]})%256));${V[14]}=${V[14]}+1;`);
  L.push(`end;${V[12]}=nil;`);

  /* integrity on reconstructed bytes via char table */
  L.push(`local ${V[18]}=216613;for ${V[14]}=1,#${V[13]} do local ${V[16]}=${V[6]}.byte(${V[13]}[${V[14]}]);${V[18]}=(${V[18]}*257+${V[16]}+97)%1000003 end;`);
  L.push(`if ${V[18]}~=${V[4]} or #${V[13]}~=${V[1]} then return end;`);

  /* resolve loader */
  L.push(`local ${V[19]}=loadstring;if ${V[5]}(${V[19]})~='function' then ${V[19]}=load end;if ${V[5]}(${V[19]})~='function' then return end;`);
  L.push(`${V[8]}(function() if iscclosure and not iscclosure(${V[19]}) then ${V[9]}=${V[9]}-2 end end);`);

  if (antiDump) {
    /* DECOY flood — pollute loadstring hooks with junk first */
    L.push(`for ${V[20]}=1,14 do ${V[8]}(function() ${V[19]}('--'..tostring(${V[20]}*97)..string.rep('\\n',40)) end) end;`);
    /* split source into random pieces → separate tiny loadstrings that return fragments (noise for dumpers) */
    L.push(`local ${V[21]}={};local ${V[22]}=1;local ${V[23]}=#${V[13]};`);
    L.push(`while ${V[22]}<=${V[23]} do`);
    L.push(`local ${V[24]}=math.min(${V[22]}+40+((${V[22]}*7)%30),${V[23]});`);
    L.push(`local ${V[25]}={};for ${V[26]}=${V[22]},${V[24]} do ${V[25]}[#${V[25]}+1]=${V[13]}[${V[26]}] end;`);
    L.push(`${V[21]}[#${V[21]}+1]=${V[7]}.concat(${V[25]});${V[22]}=${V[24]}+1;`);
    L.push(`end;${V[13]}=nil;`);
    /* assemble only inside loadstring argument, wipe ASAP */
    L.push(`local ${V[27]}=${V[7]}.concat(${V[21]});${V[21]}=nil;`);
    L.push(`local ${V[14]},${V[15]}=${V[8]}(${V[19]},${V[27]});${V[27]}=nil;`);
  } else {
    L.push(`local ${V[27]}=${V[7]}.concat(${V[13]});${V[13]}=nil;`);
    L.push(`local ${V[14]},${V[15]}=${V[8]}(${V[19]},${V[27]});${V[27]}=nil;`);
  }

  L.push(`if not ${V[14]} or ${V[5]}(${V[15]})~='function' then return end;`);
  L.push(`return ${V[15]}(...);`);
  L.push('end)(...)');
  return L.join(' ');
}

function obfuscateOnce(source, antiDump) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const raw = Buffer.from(src, 'utf8');
  if (raw.length > MAX_SOURCE) throw new Error('Too large');

  const a = 1 + 2 * ri(128);
  const b = ri(256);
  const decimal = decimalEncode(raw, a, b);
  if (!/^\d+$/.test(decimal)) throw new Error('decimal payload violation');
  if (decimal.length !== raw.length * 3) throw new Error('decimal length mismatch');
  const back = decimalDecode(decimal, a, b);
  if (!back.equals(raw)) throw new Error('numeric roundtrip failed');

  const expectedHash = rollingHash32(raw);
  return buildLoader(decimal, a, b, expectedHash, raw.length, antiDump);
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');

  // Level 0: user source (anti-dump tricks on)
  let code = obfuscateOnce(src, true);

  // Nested wraps: each outer layer encodes the previous loader.
  // A simple loadstring dumper only sees the outermost intermediate first.
  for (let nest = 1; nest < NEST_LEVELS; nest++) {
    code = obfuscateOnce(code, true);
  }

  return {
    code,
    stats: {
      inputBytes: Buffer.byteLength(src, 'utf8'),
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: `QyrexObf-${VERSION}`,
      nestLevels: NEST_LEVELS,
      layers: [
        'decimal-affine-payload',
        'numeric-integrity',
        'soft-anti-tamper',
        'sandbox-probes',
        'jobid-placeid',
        'decoy-loadstring-flood',
        'split-reassembly',
        'immediate-wipe',
        NEST_LEVELS + '-level-nest',
        'luau-stable',
      ],
      verified: true,
      payloadAlphabet: '0123456789',
    },
  };
}

module.exports = { obfuscate, VERSION };
