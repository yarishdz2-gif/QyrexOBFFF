/**
 * QyrexObf 1.2.0 - Render/Node + Luau safe
 * Numeric payload only. No Base64 and no XOR payload layer.
 * Keeps the existing affine/key-schedule/chunk/integrity design.
 */
'use strict';

const crypto = require('crypto');

const VERSION = '1.2.0';
const MAX_SOURCE = 1500000;
const CHUNK_SIZE_MIN = 72;
const CHUNK_SIZE_MAX = 156;
const PERM_MOD = 1000003;
const PRNG_MUL_A = 48271;
const PRNG_MUL_B = 69621;

/* Avoid crypto.randomInt so the module also works on older Node runtimes. */
function ri(n) {
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error('Invalid random range');
  }

  const bytes = crypto.randomBytes(4);
  const value = bytes.readUInt32BE(0);

  return value % n;
}

const LUA_RESERVED = new Set([
  'and','break','do','else','elseif','end','false','for','function','goto',
  'if','in','local','nil','not','or','repeat','return','then','true','until','while'
]);

function rid() {
  const letters =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

  let out = '';

  do {
    out = 'q';

    const len = 6 + ri(4);

    for (let i = 0; i < len; i++) {
      out += letters[ri(letters.length)];
    }
  } while (LUA_RESERVED.has(out));

  return out;
}

function nextState(state, mul, add) {
  return (state * mul + add) % PERM_MOD;
}

function modInverse256(a) {
  a = ((a % 256) + 256) % 256;

  for (let x = 1; x < 256; x++) {
    if (((a * x) % 256) === 1) {
      return x;
    }
  }

  throw new Error('Invalid numeric key');
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
  const parts = new Array(buf.length);

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

    let s1 =
      (
        a1 * buf[i] +
        b1 +
        (i % 251) +
        mask
      ) % 256;

    let s2 =
      (
        a2 * s1 +
        b2 +
        ((i * 7) % 251)
      ) % 256;

    if (s1 < 0) {
      s1 += 256;
    }

    if (s2 < 0) {
      s2 += 256;
    }

    parts[i] =
      String(s2).padStart(3, '0');
  }

  return parts.join('');
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

  const inv1 =
    modInverse256(a1);

  const inv2 =
    modInverse256(a2);

  const out =
    Buffer.alloc(
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
      (sa + 3 * sb + j * 29) % 256;

    const y =
      Number(
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

    let s1 =
      (
        y -
        b2 -
        ((j * 7) % 251)
      ) % 256;

    if (s1 < 0) {
      s1 += 256;
    }

    s1 =
      (inv2 * s1) % 256;

    let z =
      (
        s1 -
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

    const size =
      Math.max(
        3,
        room - (room % 3)
      );

    chunks.push(
      decimal.slice(
        p,
        p + size
      )
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

    const j =
      s % (i + 1);

    const t =
      out[i];

    out[i] =
      out[j];

    out[j] =
      t;
  }

  return out;
}

function luaQuote(s) {
  return JSON.stringify(
    String(s)
  );
}

function buildLoader(
  decimalPayload,
  params,
  expectedHash,
  sourceLen
) {
  const V =
    Array.from(
      { length: 24 },
      rid
    );

  const chunks =
    makeChunks(
      decimalPayload
    );

  const indexed =
    chunks.map(
      function (chunk, index) {
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

  const P = [];

  P.push(
    '-- QyrexObf by ikgmonxr qyrex.hopto.org ' +
    VERSION +
    '\n'
  );

  P.push(
    'return(function(...)'
  );

  P.push(
    'local ' +
    V[0] +
    '={' +
    payloadTable +
    '}'
  );

  P.push(
    'local ' +
    V[1] +
    '=' +
    sourceLen
  );

  P.push(
    'local ' +
    V[2] +
    '=' +
    params.a1
  );

  P.push(
    'local ' +
    V[3] +
    '=' +
    params.b1
  );

  P.push(
    'local ' +
    V[4] +
    '=' +
    params.a2
  );

  P.push(
    'local ' +
    V[5] +
    '=' +
    params.b2
  );

  P.push(
    'local ' +
    V[6] +
    '=' +
    params.seedA
  );

  P.push(
    'local ' +
    V[7] +
    '=' +
    params.seedB
  );

  P.push(
    'local ' +
    V[9] +
    '=' +
    expectedHash
  );

  P.push(
    'local ' +
    V[10] +
    '=' +
    payloadHash(decimalPayload)
  );

  P.push(
    'local ' +
    V[11] +
    '=string'
  );

  P.push(
    'local ' +
    V[12] +
    '=table'
  );

  P.push(
    'local ' +
    V[13] +
    '=type'
  );

  /* Rebuild original chunk order. */

  P.push(
    'local ' +
    V[14] +
    '={}'
  );

  P.push(
    'for ' +
    V[15] +
    '=1,#' +
    V[0] +
    ' do'
  );

  P.push(
    'local ' +
    V[16] +
    '=' +
    V[11] +
    '.find(' +
    V[0] +
    '[' +
    V[15] +
    '],":",1,true)'
  );

  P.push(
    'if not ' +
    V[16] +
    ' then return end'
  );

  P.push(
    'local ' +
    V[17] +
    '=tonumber(' +
    V[11] +
    '.sub(' +
    V[0] +
    '[' +
    V[15] +
    '],1,' +
    V[16] +
    '-1))'
  );

  P.push(
    'if not ' +
    V[17] +
    ' then return end'
  );

  P.push(
    'local ' +
    V[18] +
    '=' +
    V[11] +
    '.sub(' +
    V[0] +
    '[' +
    V[15] +
    '],' +
    V[16] +
    '+1)'
  );

  P.push(
    V[14] +
    '[' +
    V[17] +
    ']=' +
    V[18]
  );

  P.push(
    'end'
  );

  P.push(
    V[0] +
    '=' +
    V[12] +
    '.concat(' +
    V[14] +
    ')'
  );

  P.push(
    V[14] +
    '=nil'
  );

  /* Payload integrity. */

  P.push(
    'if #' +
    V[0] +
    '~=' +
    V[1] +
    '*3 then return end'
  );

  P.push(
    'local ' +
    V[19] +
    '=811'
  );

  P.push(
    'for ' +
    V[20] +
    '=1,#' +
    V[0] +
    ' do'
  );

  P.push(
    V[19] +
    '=('+V[19]+'*131+('+
    V[11]+
    '.byte('+
    V[0]+
    ','+
    V[20]+
    ')-48))%'+
    PERM_MOD
  );

  P.push(
    'end'
  );

  P.push(
    'if ' +
    V[19] +
    '~=' +
    V[10] +
    ' then return end'
  );

  /* Inverse a1. */

  P.push(
    'local ' +
    V[21] +
    '=1'
  );

  P.push(
    'while ((' +
    V[2] +
    '*' +
    V[21] +
    ')%256)~=1 do'
  );

  P.push(
    V[21] +
    '=' +
    V[21] +
    '+1'
  );

  P.push(
    'if ' +
    V[21] +
    '>255 then return end'
  );

  P.push(
    'end'
  );

  /* Inverse a2. */

  P.push(
    'local ' +
    V[22] +
    '=1'
  );

  P.push(
    'while ((' +
    V[4] +
    '*' +
    V[22] +
    ')%256)~=1 do'
  );

  P.push(
    V[22] +
    '=' +
    V[22] +
    '+1'
  );

  P.push(
    'if ' +
    V[22] +
    '>255 then return end'
  );

  P.push(
    'end'
  );

  /*
   * Decoder state.
   */

  P.push(
    'local ' +
    V[14] +
    '={}'
  );

  P.push(
    'local ' +
    V[15] +
    '=1'
  );

  P.push(
    'local ' +
    V[16] +
    '=' +
    V[6]
  );

  P.push(
    'local ' +
    V[17] +
    '=' +
    V[7]
  );

  P.push(
    'for ' +
    V[18] +
    '=1,#' +
    V[0] +
    ',3 do'
  );

  P.push(
    'local ' +
    V[19] +
    '=tonumber(' +
    V[11] +
    '.sub(' +
    V[0] +
    ',' +
    V[18] +
    ',' +
    V[18] +
    '+2))'
  );

  P.push(
    'if not ' +
    V[19] +
    ' or ' +
    V[19] +
    '<0 or ' +
    V[19] +
    '>255 then return end'
  );

  P.push(
    V[16] +
    '=(' +
    V[16] +
    '*' +
    PRNG_MUL_A +
    '+97+((' +
    V[15] +
    '-1)%251))%' +
    PERM_MOD
  );

  P.push(
    V[17] +
    '=(' +
    V[17] +
    '*' +
    PRNG_MUL_B +
    '+193+(((' +
    V[15] +
    '-1)*17)%251))%' +
    PERM_MOD
  );

  P.push(
    'local ' +
    V[20] +
    '=(' +
    V[16] +
    '+3*' +
    V[17] +
    '+(((' +
    V[15] +
    '-1)*29))%256'
  );

  P.push(
    V[19] +
    '=(' +
    V[19] +
    '-' +
    V[5] +
    '-(((' +
    V[15] +
    '-1)*7)%251))%256'
  );

  P.push(
    'if ' +
    V[19] +
    '<0 then ' +
    V[19] +
    '=' +
    V[19] +
    '+256 end'
  );

  P.push(
    V[19] +
    '=(' +
    V[22] +
    '*' +
    V[19] +
    ')%256'
  );

  P.push(
    V[19] +
    '=(' +
    V[19] +
    '-' +
    V[3] +
    '-(((' +
    V[15] +
    '-1)%251)-' +
    V[20] +
    ')%256'
  );

  P.push(
    'if ' +
    V[19] +
    '<0 then ' +
    V[19] +
    '=' +
    V[19] +
    '+256 end'
  );

  P.push(
    V[14] +
    '[' +
    V[15] +
    ']=' +
    V[11] +
    '.char((' +
    V[21] +
    '*' +
    V[19] +
    ')%256)'
  );

  P.push(
    V[15] +
    '=' +
    V[15] +
    '+1'
  );

  P.push(
    'end'
  );

  P.push(
    V[0] +
    '=' +
    V[12] +
    '.concat(' +
    V[14] +
    ')'
  );

  P.push(
    V[14] +
    '=nil'
  );

  /* Source integrity. */

  P.push(
    'local ' +
    V[19] +
    '=216613'
  );

  P.push(
    'for ' +
    V[20] +
    '=1,#' +
    V[0] +
    ' do'
  );

  P.push(
    'local ' +
    V[23] +
    '=' +
    V[11] +
    '.byte(' +
    V[0] +
    ',' +
    V[20] +
    ')'
  );

  P.push(
    V[19] +
    '=('+V[19]+'*257+'+
    V[23]+
    '+97)%'+
    PERM_MOD
  );

  P.push(
    'end'
  );

  P.push(
    'if ' +
    V[19] +
    '~=' +
    V[9] +
    ' or #' +
    V[0] +
    '~=' +
    V[1] +
    ' then return end'
  );

  /* Compile only after all validation. */

  P.push(
    V[2] +
    '=nil'
  );

  P.push(
    V[3] +
    '=nil'
  );

  P.push(
    V[4] +
    '=nil'
  );

  P.push(
    V[5] +
    '=nil'
  );

  P.push(
    V[6] +
    '=nil'
  );

  P.push(
    V[7] +
    '=nil'
  );

  P.push(
    V[9] +
    '=nil'
  );

  P.push(
    V[10] +
    '=nil'
  );

  /*
   * Luau loader boundary.
   */

  P.push(
    'local ' +
    V[21] +
    '=loadstring'
  );

  P.push(
    'if ' +
    V[13] +
    '(' +
    V[21] +
    ')~="function" then return end'
  );

  P.push(
    'local ' +
    V[22] +
    ',' +
    V[23] +
    '=' +
    V[21] +
    '(' +
    V[0] +
    ')'
  );

  P.push(
    V[0] +
    '=nil'
  );

  P.push(
    'if not ' +
    V[22] +
    ' or ' +
    V[13] +
    '(' +
    V[23] +
    ')~="function" then return end'
  );

  P.push(
    'return ' +
    V[22] +
    '(...)'
  );

  P.push(
    'end)(...)'
  );

  return P.join(';');
}

function obfuscate(source) {
  const src =
    String(
      source == null
        ? ''
        : source
    );

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
      'Too large (max 1.5 MB)'
    );
  }

  const params = {
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

  if (
    !/^[0-9]+$/.test(
      decimal
    )
  ) {
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

  if (
    !back.equals(raw)
  ) {
    throw new Error(
      'numeric roundtrip failed'
    );
  }

  const code =
    buildLoader(
      decimal,
      params,
      rollingHash32(raw),
      raw.length
    );

  return {
    code: code,

    stats: {
      inputBytes:
        raw.length,

      outputBytes:
        Buffer.byteLength(
          code,
          'utf8'
        ),

      mode:
        'QyrexObf-' +
        VERSION,

      layers: [
        'decimal-only-payload',
        'dual-randomized-affine-byte-transform',
        'per-byte-two-state-key-schedule',
        'keyed-chunk-permutation',
        'payload-integrity-check',
        'numeric-integrity-check',
        'luau-compatible-loader',
        'randomized-chunking',
        'render-safe-node-runtime'
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
  obfuscate: obfuscate,
  VERSION: VERSION
};
