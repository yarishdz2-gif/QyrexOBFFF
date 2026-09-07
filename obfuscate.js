```js
/**
 * QyrexObf 1.2.0
 * Roblox/Luau compatible numeric payload.
 * Visible payload alphabet: digits 0-9 only.
 * No Unicode payload symbols, XOR, or Base64.
 *
 * Hardening:
 * - dual affine byte transform
 * - per-byte two-state key schedule
 * - keyed chunk permutation
 * - payload checksum
 * - source checksum
 * - randomized identifiers
 * - randomized chunking
 * - best-effort memory wiping
 *
 * Luau compatibility:
 * - simple Lua/Luau syntax
 * - no bitwise operators
 * - no Lua 5.3-only syntax
 * - no unsupported standard-library dependencies
 * - loadstring preferred
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
  const letters =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

  let out;

  do {
    out = 'q';

    const len = 6 + ri(4);

    for (let i = 0; i < len; i++) {
      out += letters[ri(letters.length)];
    }
  } while (LUA_RESERVED.has(out));

  return out;
}

function modInverse256(a) {
  a = ((a % 256) + 256) % 256;

  for (let x = 1; x <= 255; x++) {
    if (((a * x) % 256) === 1) {
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
      (sa + (3 * sb) + (i * 29)) % 256;

    let stage1 =
      (
        (a1 * buf[i]) +
        b1 +
        (i % 251) +
        mask
      ) % 256;

    if (stage1 < 0) {
      stage1 += 256;
    }

    let stage2 =
      (
        (a2 * stage1) +
        b2 +
        ((i * 7) % 251)
      ) % 256;

    if (stage2 < 0) {
      stage2 += 256;
    }

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
  if (decimal.length % 3 !== 0) {
    throw new Error(
      'Invalid decimal payload length'
    );
  }

  const inv1 = modInverse256(a1);
  const inv2 = modInverse256(a2);

  const out = Buffer.alloc(
    decimal.length / 3
  );

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
      (sa + (3 * sb) + (j * 29)) % 256;

    const y = Number(
      decimal.slice(i, i + 3)
    );

    if (
      !Number.isInteger(y) ||
      y < 0 ||
      y > 255
    ) {
      throw new Error(
        'Invalid decimal byte'
      );
    }

    let t =
      (
        y -
        b2 -
        ((j * 7) % 251)
      ) % 256;

    if (t < 0) {
      t += 256;
    }

    let stage1 =
      (inv2 * t) % 256;

    if (stage1 < 0) {
      stage1 += 256;
    }

    let z =
      (
        stage1 -
        b1 -
        (j % 251) -
        mask
      ) % 256;

    if (z < 0) {
      z += 256;
    }

    out[j] =
      (inv1 * z) % 256;
  }

  return out;
}

function rollingHash32(buf) {
  let h = 216613;

  for (let i = 0; i < buf.length; i++) {
    h =
      (
        (h * 257) +
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
        (h * 131) +
        decimal.charCodeAt(i) -
        48
      ) % PERM_MOD;
  }

  return h;
}

function luaQuote(value) {
  return JSON.stringify(
    String(value)
  );
}

function makeChunks(decimal) {
  const chunks = [];

  let position = 0;

  while (position < decimal.length) {
    const randomRoom =
      CHUNK_SIZE_MIN +
      ri(
        CHUNK_SIZE_MAX -
        CHUNK_SIZE_MIN +
        1
      );

    let size =
      randomRoom -
      (randomRoom % 3);

    if (size < 3) {
      size = 3;
    }

    chunks.push(
      decimal.slice(
        position,
        position + size
      )
    );

    position += size;
  }

  return chunks;
}

function shuffleWithKey(arr, seed) {
  const out = arr.slice();

  let state = seed;

  for (
    let i = out.length - 1;
    i > 0;
    i--
  ) {
    state = nextState(
      state,
      PRNG_MUL_B,
      17 + i
    );

    const index =
      state % (i + 1);

    const tmp = out[i];

    out[i] = out[index];
    out[index] = tmp;
  }

  return out;
}

function buildLoader(
  decimalPayload,
  params,
  expectedHash,
  sourceLen
) {
  /*
   * Dedicated identifiers.
   *
   * 0  payload
   * 1  source length
   * 2  a1
   * 3  b1
   * 4  a2
   * 5  b2
   * 6  seedA
   * 7  seedB
   * 8  orderSeed
   * 9  source hash
   * 10 payload hash
   * 11 type
   * 12 string
   * 13 table
   * 14 pcall
   *
   * 15+ temporary variables
   */

  const V = Array.from(
    { length: 36 },
    () => rid()
  );

  const originalParts =
    makeChunks(decimalPayload);

  const indexed =
    originalParts.map(
      (chunk, index) => {
        return (
          String(index + 1) +
          ':' +
          chunk
        );
      }
    );

  const shuffled =
    shuffleWithKey(
      indexed,
      params.orderSeed
    );

  const payloadTable =
    shuffled
      .map(luaQuote)
      .join(',');

  const L = [];

  L.push(
    `-- QyrexObf by ikgmonxr qyrex.hopto.org ${VERSION}\n`
  );

  L.push(
    'return(function(...)'
  );

  /*
   * Constants / payload.
   */

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
    `local ${V[8]}=${params.orderSeed};`
  );

  L.push(
    `local ${V[9]}=${expectedHash};`
  );

  L.push(
    `local ${V[10]}=${payloadHash(decimalPayload)};`
  );

  /*
   * Native functions.
   */

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
   * Kept intentionally.
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
    `if ${V[16]}=='userdata' then`
  );

  L.push(
    `${V[15]}=${V[15]}+1;`
  );

  L.push(
    `elseif ${V[16]}=='table' then`
  );

  L.push(
    `${V[15]}=${V[15]}+1;`
  );

  L.push(
    `end;`
  );

  L.push(
    `local ${V[17]}=${V[11]}(_G);`
  );

  L.push(
    `if ${V[17]}=='table' then`
  );

  L.push(
    `${V[15]}=${V[15]}+1;`
  );

  L.push(
    `end;`
  );

  L.push(
    `end);`
  );

  /*
   * Reconstruct chunk ordering.
   */

  L.push(
    `local ${V[18]}={};`
  );

  L.push(
    `for ${V[19]}=1,#${V[0]} do`
  );

  L.push(
    `local ${V[20]},${V[21]}=${V[12]}.find(${V[0]}[${V[19]}],':',1,true);`
  );

  L.push(
    `if not ${V[20]} then return end;`
  );

  L.push(
    `local ${V[22]}=${V[12]}.sub(${V[0]}[${V[19]}],1,${V[20]}-1);`
  );

  L.push(
    `local ${V[23]}=${V[12]}.sub(${V[0]}[${V[19]}],${V[20]}+1);`
  );

  L.push(
    `local ${V[24]}=tonumber(${V[22]});`
  );

  L.push(
    `if not ${V[24]} then return end;`
  );

  L.push(
    `${V[18]}[${V[24]}]=${V[23]};`
  );

  L.push(
    `end;`
  );

  /*
   * Join payload.
   */

  L.push(
    `local ${V[25]}=${V[13]}.concat(${V[18]});`
  );

  L.push(
    `${V[18]}=nil;`
  );

  L.push(
    `${V[0]}=${V[25]};`
  );

  L.push(
    `${V[25]}=nil;`
  );

  /*
   * Payload length validation.
   */

  L.push(
    `if #${V[0]}~=${V[1]}*3 then return end;`
  );

  /*
   * Payload checksum.
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
   * Modular inverse #1.
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

  /*
   * Modular inverse #2.
   */

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
   * Decoder state.
   */

  L.push(
    `local ${V[29]}=${V[6]};`
  );

  L.push(
    `local ${V[30]}=${V[7]};`
  );

  L.push(
    `local ${V[31]}={};`
  );

  L.push(
    `local ${V[32]}=1;`
  );

  /*
   * Decode.
   */

  L.push(
    `for ${V[33]}=1,#${V[0]},3 do`
  );

  L.push(
    `local ${V[34]}=tonumber(${V[12]}.sub(${V[0]},${V[33]},${V[33]}+2));`
  );

  L.push(
    `if not ${V[34]} or ${V[34]}<0 or ${V[34]}>255 then return end;`
  );

  /*
   * Update state.
   */

  L.push(
    `${V[29]}=(${V[29]}*${PRNG_MUL_A}+97+((${V[32]}-1)%251))%${PERM_MOD};`
  );

  L.push(
    `${V[30]}=(${V[30]}*${PRNG_MUL_B}+193+((((${V[32]}-1)*17)%251)))%${PERM_MOD};`
  );

  /*
   * Mask.
   */

  L.push(
    `local ${V[35]}=(${V[29]}+3*${V[30]}+((${V[32]}-1)*29))%256;`
  );

  /*
   * Undo second affine stage.
   */

  L.push(
    `${V[34]}=(${V[34]}-${V[5]}-((((${V[32]}-1)*7)%251)))%256;`
  );

  L.push(
    `if ${V[34]}<0 then ${V[34]}=${V[34]}+256 end;`
  );

  L.push(
    `${V[34]}=(${V[28]}*${V[34]})%256;`
  );

  /*
   * Undo first affine stage.
   */

  L.push(
    `${V[34]}=(${V[34]}-${V[3]}-((${V[32]}-1)%251)-${V[35]})%256;`
  );

  L.push(
    `if ${V[34]}<0 then ${V[34]}=${V[34]}+256 end;`
  );

  /*
   * Restore original byte.
   */

  L.push(
    `${V[31]}[${V[32]}]=${V[12]}.char((${V[27]}*${V[34]})%256);`
  );

  L.push(
    `${V[32]}=${V[32]}+1;`
  );

  L.push(
    `end;`
  );

  /*
   * Rebuild source.
   */

  L.push(
    `local ${V[0]}=${V[13]}.concat(${V[31]});`
  );

  L.push(
    `${V[31]}=nil;`
  );

  /*
   * Source checksum.
   */

  L.push(
    `local ${V[25]}=216613;`
  );

  L.push(
    `for ${V[26]}=1,#${V[0]} do`
  );

  L.push(
    `local ${V[34]}=${V[12]}.byte(${V[0]},${V[26]});`
  );

  L.push(
    `${V[25]}=(${V[25]}*257+${V[34]}+97)%${PERM_MOD};`
  );

  L.push(
    `end;`
  );

  L.push(
    `if ${V[25]}~=${V[9]} then return end;`
  );

  L.push(
    `if #${V[0]}~=${V[1]} then return end;`
  );

  /*
   * Best-effort cleanup.
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
    `${V[18]}=nil;`
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

  /*
   * Compile.
   *
   * loadstring is preferred for Luau/executors.
   * load is only used when available.
   */

  L.push(
    `local ${V[31]}=loadstring;`
  );

  L.push(
    `if ${V[11]}(${V[31]})~='function' then`
  );

  L.push(
    `local ${V[25]}=load;`
  );

  L.push(
    `if ${V[11]}(${V[25]})~='function' then return end;`
  );

  L.push(
    `${V[31]}=${V[25]};`
  );

  L.push(
    `end;`
  );

  /*
   * Compile source.
   */

  L.push(
    `local ${V[25]},${V[26]}=${V[31]}(${V[0]});`
  );

  L.push(
    `${V[0]}=nil;`
  );

  L.push(
    `${V[31]}=nil;`
  );

  /*
   * Stop silently on compilation error.
   */

  L.push(
    `if ${V[11]}(${V[25]})~='function' then return end;`
  );

  /*
   * Execute.
   */

  L.push(
    `return ${V[25]}(...);`
  );

  L.push(
    'end)(...)'
  );

  return L.join('');
}

function obfuscate(source) {
  const src =
    String(source ?? '');

  if (!src.trim()) {
    throw new Error(
      'Empty code'
    );
  }

  const raw =
    Buffer.from(
      src,
      'utf8'
    );

  if (raw.length > MAX_SOURCE) {
    throw new Error(
      'Too large'
    );
  }

  /*
   * Odd numbers only so that an inverse
   * exists modulo 256.
   */

  const params = {
    a1: 1 + (2 * ri(128)),
    b1: ri(256),

    a2: 1 + (2 * ri(128)),
    b2: ri(256),

    seedA:
      1 + ri(PERM_MOD - 1),

    seedB:
      1 + ri(PERM_MOD - 1),

    orderSeed:
      1 + ri(PERM_MOD - 1)
  };

  /*
   * Encode.
   */

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
   * Decimal-only validation.
   */

  if (!/^[0-9]+$/.test(decimal)) {
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
   * Internal round-trip test.
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
   * Source integrity.
   */

  const expectedHash =
    rollingHash32(raw);

  /*
   * Final loader.
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
```

La diferencia importante es que **el código que sale de `obfuscate.js` ahora está pensado específicamente para Luau**, no para Lua genérico: usa `loadstring` como primera opción, evita sintaxis problemática, mantiene las operaciones `%`, `string.byte/char`, `string.find`, `table.concat` y separa completamente las variables del decoder.

También conserva tu `VERSION = '1.2.0'` y **no eliminé las capas existentes**.
