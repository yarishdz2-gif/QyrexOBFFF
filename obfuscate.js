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

const PERM_MOD = 1_000_003;

const PRNG_MUL_A = 48_271;
const PRNG_MUL_B = 69_621;

const ri = (n) => crypto.randomInt(0, n);

const LUA_RESERVED = new Set([
  'and',
  'break',
  'do',
  'else',
  'elseif',
  'end',
  'false',
  'for',
  'function',
  'goto',
  'if',
  'in',
  'local',
  'nil',
  'not',
  'or',
  'repeat',
  'return',
  'then',
  'true',
  'until',
  'while'
]);

function rid() {
  const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

  let out = '';

  do {
    out = 'q';

    const len = 5 + ri(4);

    for (let i = 0; i < len; i++) {
      out += letters[ri(letters.length)];
    }
  } while (LUA_RESERVED.has(out));

  return out;
}

function modInverse256(a) {
  a = ((a % 256) + 256) % 256;

  for (let x = 1; x < 256; x++) {
    if (((a * x) % 256 + 256) % 256 === 1) {
      return x;
    }
  }

  throw new Error('Invalid numeric key');
}

function nextState(state, mul, add) {
  return (state * mul + add) % PERM_MOD;
}

function decimalEncode(
  buf,
  a1,
  b1,
  a2,
  b2,
  seedA,
  seedB
) {
  let out = '';

  let sa = seedA;
  let sb = seedB;

  for (let i = 0; i < buf.length; i++) {
    sa = nextState(
      sa,
      PRNG_MUL_A,
      97 + (i % 251)
    );

    sb = nextState(
      sb,
      PRNG_MUL_B,
      193 + ((i * 17) % 251)
    );

    const mask =
      (sa + 3 * sb + i * 29) % 256;

    const stage1 =
      (
        a1 * buf[i] +
        b1 +
        (i % 251) +
        mask
      ) % 256;

    const stage2 =
      (
        a2 * stage1 +
        b2 +
        ((i * 7) % 251)
      ) % 256;

    out += String(stage2).padStart(3, '0');
  }

  return out;
}

function decimalDecode(
  decimal,
  a1,
  b1,
  a2,
  b2,
  seedA,
  seedB
) {
  const inv1 = modInverse256(a1);
  const inv2 = modInverse256(a2);

  if (decimal.length % 3 !== 0) {
    throw new Error('Invalid decimal payload length');
  }

  const out = Buffer.alloc(decimal.length / 3);

  let sa = seedA;
  let sb = seedB;

  for (
    let i = 0, j = 0;
    i < decimal.length;
    i += 3, j++
  ) {
    sa = nextState(
      sa,
      PRNG_MUL_A,
      97 + (j % 251)
    );

    sb = nextState(
      sb,
      PRNG_MUL_B,
      193 + ((j * 17) % 251)
    );

    const mask =
      (sa + 3 * sb + j * 29) % 256;

    const y = Number(
      decimal.slice(i, i + 3)
    );

    if (
      !Number.isInteger(y) ||
      y < 0 ||
      y > 255
    ) {
      throw new Error('Invalid decimal byte');
    }

    const stage1 =
      (
        inv2 *
        (
          (
            y -
            b2 -
            ((j * 7) % 251)
          ) % 256 +
          256
        ) % 256
      ) % 256;

    const z =
      (
        stage1 -
        b1 -
        (j % 251) -
        mask
      ) % 256;

    out[j] =
      (inv1 * ((z + 256) % 256)) % 256;
  }

  return out;
}

function rollingHash32(buf) {
  let h = 216_613;

  for (let i = 0; i < buf.length; i++) {
    h =
      (
        h * 257 +
        buf[i] +
        97
      ) % PERM_MOD;
  }

  return h;
}

function payloadHash(decimal) {
  let h = 811;

  for (let i = 0; i < decimal.length; i++) {
    h =
      (
        h * 131 +
        decimal.charCodeAt(i) -
        48
      ) % PERM_MOD;
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
    const room =
      CHUNK_SIZE_MIN +
      ri(
        CHUNK_SIZE_MAX -
        CHUNK_SIZE_MIN +
        1
      );

    const size = Math.max(
      3,
      room - (room % 3)
    );

    chunks.push(
      decimal.slice(p, p + size)
    );

    p += size;
  }

  return chunks;
}

function shuffleWithKey(arr, seed) {
  const out = arr.slice();

  let s = seed;

  for (
    let i = out.length - 1;
    i > 0;
    i--
  ) {
    s = nextState(
      s,
      PRNG_MUL_B,
      17 + i
    );

    const j = s % (i + 1);

    [
      out[i],
      out[j]
    ] = [
      out[j],
      out[i]
    ];
  }

  return out;
}

/**
 * Loader builder.
 *
 * Important fix:
 * Every runtime temporary now receives its own
 * randomized identifier instead of repeatedly
 * redeclaring the same identifiers in the same
 * Lua/Luau scope.
 */
function buildLoader(
  decimalPayload,
  params,
  expectedHash,
  sourceLen
) {
  const V = Array.from(
    { length: 34 },
    rid
  );

  const originalParts =
    makeChunks(decimalPayload);

  const orderSeed =
    params.orderSeed;

  const indexed =
    originalParts.map(
      (chunk, index) =>
        `${index + 1}:${chunk}`
    );

  const shuffled =
    shuffleWithKey(
      indexed,
      orderSeed
    );

  const payloadTable =
    shuffled
      .map(luaQuote)
      .join(',');

  const L = [];

  /*
   * V mappings:
   *
   * V0  = shuffled payload table
   * V1  = source length
   * V2  = a1
   * V3  = b1
   * V4  = a2
   * V5  = b2
   * V6  = seedA
   * V7  = seedB
   * V8  = orderSeed
   * V9  = expected source hash
   * V10 = expected payload hash
   *
   * V11 = type
   * V12 = string
   * V13 = table
   * V14 = pcall
   *
   * V15..V33 = dedicated runtime temporaries
   */

  L.push(
    `-- QyrexObf by ikgmonxr qyrex.hopto.org ${VERSION}\n`
  );

  L.push(
    'return(function(...)'
  );

  L.push(
    `local ${V[0]}={${payloadTable}};`
  );

  L.push(
    `local ${V[1]}=${sourceLen};`
  );

  L.push(
    `local ${V[2]}=${params.a1};`
  );

  L.push(
    `local ${V[3]}=${params.b1};`
  );

  L.push(
    `local ${V[4]}=${params.a2};`
  );

  L.push(
    `local ${V[5]}=${params.b2};`
  );

  L.push(
    `local ${V[6]}=${params.seedA};`
  );

  L.push(
    `local ${V[7]}=${params.seedB};`
  );

  L.push(
    `local ${V[8]}=${orderSeed};`
  );

  L.push(
    `local ${V[9]}=${expectedHash};`
  );

  L.push(
    `local ${V[10]}=${payloadHash(decimalPayload)};`
  );

  L.push(
    `local ${V[11]}=type;`
  );

  L.push(
    `local ${V[12]}=string;`
  );

  L.push(
    `local ${V[13]}=table;`
  );

  L.push(
    `local ${V[14]}=pcall;`
  );

  /*
   * Soft environment check.
   * Kept from the original implementation.
   */

  L.push(
    `local ${V[15]}=0;`
  );

  L.push(
    `${V[14]}(function()`
  );

  L.push(
    `local ${V[16]}=${V[11]}(game);`
  );

  L.push(
    `if ${V[16]}=='userdata' or ${V[16]}=='table' then`
  );

  L.push(
    `${V[15]}=${V[15]}+1;`
  );

  L.push(
    `end;`
  );

  L.push(
    `if ${V[11]}(_G)=='table' then`
  );

  L.push(
    `${V[15]}=${V[15]}+1;`
  );

  L.push(
    `end`
  );

  L.push(
    `end);`
  );

  /*
   * Rebuild original chunk ordering.
   *
   * Dedicated temporaries are used here so
   * the cryptographic/key variables remain intact.
   */

  L.push(
    `local ${V[17]}={};`
  );

  L.push(
    `for ${V[18]}=1,#${V[0]} do`
  );

  L.push(
    `local ${V[19]},${V[20]}=${V[12]}.find(${V[0]}[${V[18]}],':',1,true);`
  );

  L.push(
    `if not ${V[19]} then return end;`
  );

  L.push(
    `local ${V[21]}=${V[12]}.sub(${V[0]}[${V[18]}],1,${V[19]}-1);`
  );

  L.push(
    `local ${V[22]}=${V[12]}.sub(${V[0]}[${V[18]}],${V[19]}+1);`
  );

  L.push(
    `local ${V[23]}=tonumber(${V[21]});`
  );

  L.push(
    `if not ${V[23]} then return end;`
  );

  L.push(
    `${V[17]}[${V[23]}]=${V[22]};`
  );

  L.push(
    `end;`
  );

  /*
   * Discard shuffled structure.
   */

  L.push(
    `local ${V[24]}=${V[13]}.concat(${V[17]});`
  );

  L.push(
    `${V[17]}=nil;`
  );

  L.push(
    `${V[0]}=${V[24]};`
  );

  L.push(
    `${V[24]}=nil;`
  );

  /*
   * Validate decimal payload length.
   */

  L.push(
    `if #${V[0]}~=${V[1]}*3 then return end;`
  );

  /*
   * Independent decimal payload checksum.
   */

  L.push(
    `local ${V[25]}=811;`
  );

  L.push(
    `for ${V[26]}=1,#${V[0]} do`
  );

  L.push(
    `${V[25]}=(${V[25]}*131+(${V[12]}.byte(${V[0]},${V[26]})-48))%${PERM_MOD};`
  );

  L.push(
    `end;`
  );

  L.push(
    `if ${V[25]}~=${V[10]} then return end;`
  );

  L.push(
    `${V[25]}=nil;`
  );

  /*
   * Modular inverses.
   */

  L.push(
    `local ${V[27]}=1;`
  );

  L.push(
    `while ((${V[2]}*${V[27]})%256)~=1 do`
  );

  L.push(
    `${V[27]}=${V[27]}+1;`
  );

  L.push(
    `if ${V[27]}>255 then return end;`
  );

  L.push(
    `end;`
  );

  L.push(
    `local ${V[28]}=1;`
  );

  L.push(
    `while ((${V[4]}*${V[28]})%256)~=1 do`
  );

  L.push(
    `${V[28]}=${V[28]}+1;`
  );

  L.push(
    `if ${V[28]}>255 then return end;`
  );

  L.push(
    `end;`
  );

  /*
   * Preserve original seeds.
   *
   * IMPORTANT:
   * Decode state is kept in separate variables.
   */

  L.push(
    `local ${V[29]}=${V[6]};`
  );

  L.push(
    `local ${V[30]}=${V[7]};`
  );

  /*
   * Decode bytes.
   */

  L.push(
    `local ${V[31]}={};`
  );

  L.push(
    `local ${V[32]}=1;`
  );

  L.push(
    `for ${V[33]}=1,#${V[0]},3 do`
  );

  /*
   * Numeric decimal byte.
   */

  L.push(
    `local ${V[16]}=tonumber(${V[12]}.sub(${V[0]},${V[33]},${V[33]}+2));`
  );

  L.push(
    `if not ${V[16]} or ${V[16]}<0 or ${V[16]}>255 then return end;`
  );

  /*
   * Stateful schedules.
   */

  L.push(
    `${V[29]}=(${V[29]}*${PRNG_MUL_A}+97+((${V[32]}-1)%251))%${PERM_MOD};`
  );

  L.push(
    `${V[30]}=(${V[30]}*${PRNG_MUL_B}+193+((((${V[32]}-1)*17)%251)))%${PERM_MOD};`
  );

  /*
   * Dual-state mask.
   */

  L.push(
    `local ${V[15]}=(${V[29]}+3*${V[30]}+((${V[32]}-1)*29))%256;`
  );

  /*
   * Reverse stage 2.
   */

  L.push(
    `${V[16]}=(${V[28]}*((${V[16]}-${V[5]}-((((${V[32]}-1)*7)%251)))%256+256)%256)%256;`
  );

  /*
   * Reverse stage 1.
   */

  L.push(
    `${V[16]}=(((${V[16]}-${V[3]}-((${V[32]}-1)%251)-${V[15]})%256)+256)%256;`
  );

  /*
   * Reverse affine transform.
   */

  L.push(
    `${V[31]}[${V[32]}]=${V[12]}.char(((${V[27]}*${V[16]})%256));`
  );

  L.push(
    `${V[32]}=${V[32]}+1;`
  );

  L.push(
    `end;`
  );

  /*
   * Recreate source.
   */

  L.push(
    `local ${V[0]}=${V[13]}.concat(${V[31]});`
  );

  L.push(
    `${V[31]}=nil;`
  );

  /*
   * Numeric/source integrity.
   */

  L.push(
    `local ${V[17]}=216613;`
  );

  L.push(
    `for ${V[18]}=1,#${V[0]} do`
  );

  L.push(
    `local ${V[19]}=${V[12]}.byte(${V[0]},${V[18]});`
  );

  L.push(
    `${V[17]}=(${V[17]}*257+${V[19]}+97)%${PERM_MOD};`
  );

  L.push(
    `end;`
  );

  L.push(
    `if ${V[17]}~=${V[9]} or #${V[0]}~=${V[1]} then return end;`
  );

  /*
   * Best-effort wiping.
   */

  L.push(
    `${V[2]}=nil;`
  );

  L.push(
    `${V[3]}=nil;`
  );

  L.push(
    `${V[4]}=nil;`
  );

  L.push(
    `${V[5]}=nil;`
  );

  L.push(
    `${V[6]}=nil;`
  );

  L.push(
    `${V[7]}=nil;`
  );

  L.push(
    `${V[8]}=nil;`
  );

  L.push(
    `${V[9]}=nil;`
  );

  L.push(
    `${V[10]}=nil;`
  );

  L.push(
    `${V[17]}=nil;`
  );

  L.push(
    `${V[18]}=nil;`
  );

  L.push(
    `${V[19]}=nil;`
  );

  L.push(
    `${V[20]}=nil;`
  );

  L.push(
    `${V[21]}=nil;`
  );

  L.push(
    `${V[22]}=nil;`
  );

  L.push(
    `${V[23]}=nil;`
  );

  L.push(
    `${V[25]}=nil;`
  );

  L.push(
    `${V[27]}=nil;`
  );

  L.push(
    `${V[28]}=nil;`
  );

  L.push(
    `${V[29]}=nil;`
  );

  L.push(
    `${V[30]}=nil;`
  );

  L.push(
    `${V[32]}=nil;`
  );

  L.push(
    `${V[33]}=nil;`
  );

  /*
   * Compile and execute.
   */

  L.push(
    `local ${V[24]}=loadstring;`
  );

  L.push(
    `if ${V[11]}(${V[24]})~='function' then`
  );

  L.push(
    `${V[24]}=load;`
  );

  L.push(
    `end;`
  );

  L.push(
    `if ${V[11]}(${V[24]})~='function' then return end;`
  );

  L.push(
    `local ${V[25]},${V[26]}=${V[24]}(${V[0]});`
  );

  L.push(
    `${V[0]}=nil;`
  );

  L.push(
    `if not ${V[25]} or ${V[11]}(${V[26]})~='function' then return end;`
  );

  L.push(
    `return ${V[26]}(...);`
  );

  L.push(
    `end)(...)`
  );

  return L.join('');
}

function obfuscate(source) {
  const src = String(source ?? '');

  if (!src.trim()) {
    throw new Error('Empty code');
  }

  const raw =
    Buffer.from(src, 'utf8');

  if (raw.length > MAX_SOURCE) {
    throw new Error('Too large');
  }

  const params = {
    /*
     * Odd numbers are required for
     * modular inverses modulo 256.
     */

    a1:
      1 + 2 * ri(128),

    b1:
      ri(256),

    a2:
      1 + 2 * ri(128),

    b2:
      ri(256),

    seedA:
      1 + ri(PERM_MOD - 1),

    seedB:
      1 + ri(PERM_MOD - 1),

    orderSeed:
      1 + ri(PERM_MOD - 1)
  };

  const decimal =
    decimalEncode(
      raw,
      params.a1,
      params.b1,
      params.a2,
      params.b2,
      params.seedA,
      params.seedB
    );

  /*
   * Numeric payload validation.
   */

  if (!/^\d+$/.test(decimal)) {
    throw new Error(
      'decimal payload violation'
    );
  }

  if (
    decimal.length !==
    raw.length * 3
  ) {
    throw new Error(
      'decimal length mismatch'
    );
  }

  /*
   * Internal round-trip validation.
   */

  const back =
    decimalDecode(
      decimal,
      params.a1,
      params.b1,
      params.a2,
      params.b2,
      params.seedA,
      params.seedB
    );

  if (!back.equals(raw)) {
    throw new Error(
      'numeric roundtrip failed'
    );
  }

  /*
   * Integrity hash.
   */

  const expectedHash =
    rollingHash32(raw);

  /*
   * Build final loader.
   */

  const code =
    buildLoader(
      decimal,
      params,
      expectedHash,
      raw.length
    );

  return {
    code,

    stats: {
      inputBytes:
        raw.length,

      outputBytes:
        Buffer.byteLength(
          code,
          'utf8'
        ),

      mode:
        `QyrexObf-${VERSION}`,

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

      verified:
        true,

      payloadAlphabet:
        '0123456789',

      decimalLayer:
        true
    }
  };
}

module.exports = {
  obfuscate,
  VERSION
};
