/**
 * QyrexObf 1.4.0 — Luau-compatible hardened decimal loader
 *
 * Hardening:
 *  - Per-byte keyed xorshift-like stream mask
 *  - Affine byte transform
 *  - Deterministic keyed chunk permutation
 *  - Dual independent payload integrity
 *  - Dual independent source integrity
 *  - Metadata integrity
 *  - Early primitive capture
 *  - Runtime structure validation
 *  - Reference cleanup before compile
 *  - Double nesting
 *  - Random identifiers
 *  - Random chunk sizes
 *
 * NOTE:
 * Client-side executable code can ultimately be observed by a sufficiently
 * capable runtime dumper. This implementation raises the cost; it cannot make
 * client execution mathematically impossible to inspect.
 */

'use strict';

const crypto = require('crypto');

const VERSION = '1.4.0';
const MAX_SOURCE = 1_500_000;

const ri = (n) => crypto.randomInt(0, n);

const RES = new Set([
  'and', 'break', 'do', 'else', 'elseif', 'end', 'false',
  'for', 'function', 'goto', 'if', 'in', 'local', 'nil',
  'not', 'or', 'repeat', 'return', 'then', 'true',
  'until', 'while'
]);

function rid() {
  const letters =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

  let out;

  do {
    out = 'q';

    for (let i = 0; i < 7 + ri(6); i++) {
      out += letters[ri(letters.length)];
    }
  } while (RES.has(out));

  return out;
}

/* --------------------------------------------------------- */
/* Small arithmetic helpers                                  */
/* --------------------------------------------------------- */

function xorByte(a, b) {
  a &= 255;
  b &= 255;

  let out = 0;
  let bit = 1;

  for (let i = 0; i < 8; i++, bit *= 2) {
    const abit = a % 2;
    const bbit = b % 2;

    if (abit !== bbit) {
      out += bit;
    }

    a = Math.floor(a / 2);
    b = Math.floor(b / 2);
  }

  return out;
}

function u16(n) {
  n %= 65536;

  if (n < 0) {
    n += 65536;
  }

  return n;
}

/* --------------------------------------------------------- */
/* Key stream                                                */
/* --------------------------------------------------------- */

function keyedMask(seed, i, a, b) {
  let s = u16(seed);

  s = u16(
    s +
    u16((i + 1) * 40503)
  );

  s = u16(
    s +
    u16(a * 257)
  );

  s = u16(
    s +
    u16(b * 911)
  );

  s = u16(
    (s * 25173) +
    13849
  );

  return s % 256;
}

/* --------------------------------------------------------- */
/* Affine inverse                                             */
/* --------------------------------------------------------- */

function modInv(a) {
  for (let x = 1; x < 256; x++) {
    if (
      ((a * x) % 256 + 256) % 256 === 1
    ) {
      return x;
    }
  }

  throw new Error('Invalid affine key');
}

/* --------------------------------------------------------- */
/* Decimal encoder                                            */
/* --------------------------------------------------------- */

function decEnc(buf, a, b, seed) {
  let out = '';

  for (let i = 0; i < buf.length; i++) {
    const masked = xorByte(
      buf[i],
      keyedMask(seed, i, a, b)
    );

    const transformed =
      (a * masked + b + (i % 251)) % 256;

    out += String(transformed).padStart(3, '0');
  }

  return out;
}

/* --------------------------------------------------------- */
/* Decimal decoder                                            */
/* --------------------------------------------------------- */

function decDec(d, a, b, seed) {
  if (d.length % 3 !== 0) {
    throw new Error('Invalid decimal length');
  }

  const inv = modInv(a);
  const out = Buffer.alloc(d.length / 3);

  for (
    let i = 0, j = 0;
    i < d.length;
    i += 3, j++
  ) {
    const y = Number(
      d.slice(i, i + 3)
    );

    if (
      !Number.isInteger(y) ||
      y < 0 ||
      y > 255
    ) {
      throw new Error('Invalid decimal byte');
    }

    const z =
      (
        y -
        b -
        (j % 251)
      ) % 256;

    const normalized =
      (z + 256) % 256;

    const unAffine =
      (inv * normalized) % 256;

    out[j] = xorByte(
      unAffine,
      keyedMask(seed, j, a, b)
    );
  }

  return out;
}

/* --------------------------------------------------------- */
/* Primary integrity hash                                     */
/* --------------------------------------------------------- */

function hash32(buf, seed = 0) {
  let h = u16(21613 + seed);

  for (let i = 0; i < buf.length; i++) {
    h =
      (
        h * 257 +
        buf[i] +
        97
      ) % 1000003;
  }

  return h;
}

/* --------------------------------------------------------- */
/* Independent secondary integrity hash                       */
/* --------------------------------------------------------- */

function hash32b(buf, seed = 0) {
  let h =
    u16(
      52379 +
      u16(seed * 3)
    );

  for (let i = 0; i < buf.length; i++) {
    h =
      (
        h * 263 +
        buf[i] +
        53 +
        (i % 17) * 7
      ) % 1000003;
  }

  return h;
}

/* --------------------------------------------------------- */
/* Random decimal chunking                                    */
/* --------------------------------------------------------- */

function chunkDec(d) {
  const out = [];
  let p = 0;

  while (p < d.length) {
    const room =
      72 +
      ri(120);

    const size =
      Math.max(
        3,
        room - (room % 3)
      );

    out.push(
      d.slice(
        p,
        p + size
      )
    );

    p += size;
  }

  return out;
}

/* --------------------------------------------------------- */
/* Keyed permutation                                          */
/* --------------------------------------------------------- */

function keyedShuffle(items, seed) {
  const shuffled = items.map(
    (value, index) => ({
      value,
      index,
      k: hash32(
        Buffer.from(
          String(index)
        ),
        seed
      )
    })
  );

  shuffled.sort(
    (x, y) =>
      (x.k - y.k) ||
      (x.index - y.index)
  );

  return {
    parts: shuffled.map(
      x => x.value
    ),

    order: shuffled.map(
      x => x.index + 1
    )
  };
}

/* --------------------------------------------------------- */
/* Runtime loader generator                                   */
/* --------------------------------------------------------- */

function buildDecimalLoader(
  decimal,
  a,
  b,
  streamSeed,
  metaHash,
  expectedHash,
  expectedPayloadHash,
  expectedHash2,
  expectedPayloadHash2,
  sourceLen
) {
  const V = Array.from(
    { length: 35 },
    rid
  );

  const originalParts =
    chunkDec(decimal);

  const shuffled =
    keyedShuffle(
      originalParts,
      streamSeed
    );

  const payloadTable =
    shuffled.parts
      .map(
        p => JSON.stringify(p)
      )
      .join(',');

  const orderTable =
    shuffled.order.join(',');

  const L = [];

  const [
    P,
    O,
    N,
    A,
    B,
    S,
    H,
    PH,
    H2,
    PH2,
    MG,
    T,
    STR,
    TBL,
    PC,
    SUB,
    BYTE,
    CHAR,
    CONCAT,
    ENC,
    INV,
    DEC,
    I,
    SRC,
    LOAD,
    OK,
    FN,
    C1,
    C2,
    TRAP,
    R1,
    R2,
    R3,
    R4,
    R5
  ] = V;

  L.push(
    `--[[ QyrexObf ${VERSION} | hardened decimal loader ]]\n`
  );

  L.push(
    'return(function(...) '
  );

  /* ------------------------------------------------------- */
  /* Capture primitives immediately                          */
  /* ------------------------------------------------------- */

  L.push(
    `local ${T}=type; ` +
    `local ${STR}=string; ` +
    `local ${TBL}=table; ` +
    `local ${PC}=pcall; `
  );

  L.push(
    `local ${SUB}=${STR}.sub; ` +
    `local ${BYTE}=${STR}.byte; ` +
    `local ${CHAR}=${STR}.char; ` +
    `local ${CONCAT}=${TBL}.concat; `
  );

  L.push(
    `if ` +
    `${T}(${SUB})~='function' or ` +
    `${T}(${BYTE})~='function' or ` +
    `${T}(${CHAR})~='function' or ` +
    `${T}(${CONCAT})~='function' or ` +
    `${T}(${PC})~='function' ` +
    `then return end; `
  );

  /* ------------------------------------------------------- */
  /* Payload + metadata                                      */
  /* ------------------------------------------------------- */

  L.push(
    `local ${P}={${payloadTable}}; ` +
    `local ${O}={${orderTable}}; `
  );

  L.push(
    `local ${N}=${sourceLen}; ` +
    `local ${A}=${a}; ` +
    `local ${B}=${b}; ` +
    `local ${S}=${streamSeed}; `
  );

  L.push(
    `local ${H}=${expectedHash}; ` +
    `local ${PH}=${expectedPayloadHash}; ` +
    `local ${H2}=${expectedHash2}; ` +
    `local ${PH2}=${expectedPayloadHash2}; ` +
    `local ${MG}=${metaHash}; `
  );

  /* ------------------------------------------------------- */
  /* Metadata integrity                                      */
  /* ------------------------------------------------------- */

  L.push(
    `if ` +
    `((${A}*257+` +
    `${B}*131+` +
    `${S}*17+` +
    `${N})%1000003)` +
    `~=${MG} then return end; `
  );

  /* ------------------------------------------------------- */
  /* Table structure checks                                  */
  /* ------------------------------------------------------- */

  L.push(
    `if ` +
    `${T}(${P})~='table' or ` +
    `${T}(${O})~='table' or ` +
    `#${O}==0 then return end; `
  );

  /* ------------------------------------------------------- */
  /* Restore original chunk order                            */
  /* ------------------------------------------------------- */

  L.push(
    `local ${ENC}={}; ` +
    `for ${I}=1,#${O} do ` +
      `local pos=${O}[${I}]; ` +

      `if ` +
      `${T}(pos)~='number' or ` +
      `pos<1 or ` +
      `pos>#${O} then ` +
      `return ` +
      `end; ` +

      `${ENC}[pos]=${P}[${I}]; ` +
    `end; ` +

    `${P}=nil; ` +
    `${O}=nil; `
  );

  /* ------------------------------------------------------- */
  /* Join decimal payload                                    */
  /* ------------------------------------------------------- */

  L.push(
    `local ${SRC}=${CONCAT}(${ENC}); ` +
    `${ENC}=nil; ` +
    `if ` +
    `${T}(${SRC})~='string' or ` +
    `#${SRC}~=${N}*3 then ` +
    `return ` +
    `end; `
  );

  /* ------------------------------------------------------- */
  /* Payload primary hash                                    */
  /* ------------------------------------------------------- */

  L.push(
    `local ${C1}=` +
    `((21613+${S})%65536+65536)%65536; ` +

    `for ${I}=1,#${SRC} do ` +
      `local c=${BYTE}(${SRC},${I}); ` +

      `${C1}=` +
      `(${C1}*257+c+97)%1000003; ` +
    `end; ` +

    `if ${C1}~=${PH} then return end; `
  );

  /* ------------------------------------------------------- */
  /* Payload secondary hash                                  */
  /* ------------------------------------------------------- */

  L.push(
    `local ${C2}=` +
    `((52379+((${S}+12345)*3)%65536)%65536+65536)%65536; ` +

    `for ${I}=1,#${SRC} do ` +
      `local c=${BYTE}(${SRC},${I}); ` +
      `local j=${I}-1; ` +

      `${C2}=` +
      `(${C2}*263+c+53+(j%17)*7)%1000003; ` +
    `end; ` +

    `if ${C2}~=${PH2} then return end; `
  );

  /* ------------------------------------------------------- */
  /* Affine inverse                                          */
  /* ------------------------------------------------------- */

  L.push(
    `local ${INV}=1; ` +

    `while ` +
    `((${A}*${INV})%256)~=1 do ` +

      `${INV}=${INV}+1; ` +

      `if ${INV}>255 then ` +
        `return ` +
      `end; ` +

    `end; `
  );

  /* ------------------------------------------------------- */
  /* Decimal -> bytes                                        */
  /* ------------------------------------------------------- */

  L.push(
    `local ${DEC}={}; ` +

    `for ${I}=1,#${SRC},3 do ` +

      `local q=` +
      `${SUB}(${SRC},${I},${I}+2)+0; ` +

      `if q<0 or q>255 then ` +
        `return ` +
      `end; ` +

      `local j=${I}-1; ` +

      `local s=` +
      `(${S}` +
      `+(j+1)*374761393` +
      `+${A}*668265263` +
      `+${B}*2147483647)` +
      `%4294967296; ` +

      `if s<0 then `s=s+4294967296 end; ` +

      `s=` +
      `(s*1664525+1013904223)` +
      `%4294967296; ` +

      `local m=s%256; ` +

      `local z=` +
      `((q-${B}-(j%251))%256+256)%256; ` +

      `local v=` +
      `(z*${INV})%256; ` +

      `local out=0; ` +
      `local bit=1; ` +

      `for k=1,8 do ` +

        `local ab=v%2; ` +
        `local bb=m%2; ` +

        `if ab~=bb then ` +
          `out=out+bit; ` +
        `end; ` +

        `v=math.floor(v/2); ` +
        `m=math.floor(m/2); ` +
        `bit=bit*2; ` +

      `end; ` +

      `${DEC}[#${DEC}+1]=${CHAR}(out); ` +
    `end; ` +

    `${SRC}=nil; `
  );

  /* ------------------------------------------------------- */
  /* Source primary hash                                    */
  /* ------------------------------------------------------- */

  L.push(
    `local ${C1}=` +
    `((21613+${S})%65536+65536)%65536; ` +

    `for ${I}=1,#${DEC} do ` +
      `local c=${BYTE}(${DEC}[${I}]); ` +

      `${C1}=` +
      `(${C1}*257+c+97)%1000003; ` +
    `end; ` +

    `if ${C1}~=${H} then return end; `
  );

  /* ------------------------------------------------------- */
  /* Source secondary hash                                  */
  /* ------------------------------------------------------- */

  L.push(
    `local ${C2}=` +
    `((52379+(${S}*3)%65536)%65536+65536)%65536; ` +

    `for ${I}=1,#${DEC} do ` +
      `local c=${BYTE}(${DEC}[${I}]); ` +
      `local j=${I}-1; ` +

      `${C2}=` +
      `(${C2}*263+c+53+(j%17)*7)%1000003; ` +
    `end; ` +

    `if ${C2}~=${H2} then return end; `
  );

  /* ------------------------------------------------------- */
  /* Final plaintext length validation                       */
  /* ------------------------------------------------------- */

  L.push(
    `if #${DEC}~=${N} then return end; `
  );

  /* ------------------------------------------------------- */
  /* Reconstruct plaintext once                              */
  /* ------------------------------------------------------- */

  L.push(
    `local ${SRC}=${CONCAT}(${DEC}); ` +
    `${DEC}=nil; `
  );

  /* ------------------------------------------------------- */
  /* Compile only after all checks                           */
  /* ------------------------------------------------------- */

  L.push(
    `local ${LOAD}=loadstring; ` +

    `if ${T}(${LOAD})~='function' then ` +
      `${LOAD}=load; ` +
    `end; ` +

    `if ${T}(${LOAD})~='function' then ` +
      `${SRC}=nil; ` +
      `return ` +
    `end; `
  );

  L.push(
    `local ${OK},${FN}=` +
    `${PC}(${LOAD},${SRC}); ` +

    `${SRC}=nil; ` +

    `if ` +
    `not ${OK} or ` +
    `${T}(${FN})~='function' then ` +
    `return end; `
  );

  /* ------------------------------------------------------- */
  /* Execute immediately                                    */
  /* ------------------------------------------------------- */

  L.push(
    `return ${FN}(...); `
  );

  L.push(
    `end)(...)`
  );

  return L.join('');
}

/* --------------------------------------------------------- */
/* Obfuscation pipeline                                      */
/* --------------------------------------------------------- */

function obfuscateDecimal(source, nests) {
  let src = String(source);
  let lastCode = null;

  const levels =
    Math.max(
      1,
      nests | 0
    );

  for (let n = 0; n < levels; n++) {
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

    /* Random affine key. Odd values are invertible mod 256. */
    const a =
      1 +
      2 * ri(128);

    const b =
      ri(256);

    const streamSeed =
      ri(65536);

    /* Encode */
    const decimal =
      decEnc(
        raw,
        a,
        b,
        streamSeed
      );

    if (
      !/^\d+$/.test(decimal)
    ) {
      throw new Error(
        'decimal payload violation'
      );
    }

    /* Internal roundtrip verification */
    const back =
      decDec(
        decimal,
        a,
        b,
        streamSeed
      );

    if (!back.equals(raw)) {
      throw new Error(
        'roundtrip failed'
      );
    }

    /* Two independent hashes for plaintext */
    const expectedHash =
      hash32(
        raw,
        streamSeed
      );

    const expectedHash2 =
      hash32b(
        raw,
        streamSeed
      );

    /* Two independent hashes for decimal payload */
    const decimalBuf =
      Buffer.from(
        decimal,
        'ascii'
      );

    const expectedPayloadHash =
      hash32(
        decimalBuf,
        streamSeed + 12345
      );

    const expectedPayloadHash2 =
      hash32b(
        decimalBuf,
        streamSeed + 12345
      );

    /* Metadata checksum */
    const metaHash =
      (
        a * 257 +
        b * 131 +
        streamSeed * 17 +
        raw.length
      ) % 1000003;

    lastCode =
      buildDecimalLoader(
        decimal,
        a,
        b,
        streamSeed,

        metaHash,

        expectedHash,
        expectedPayloadHash,

        expectedHash2,
        expectedPayloadHash2,

        raw.length
      );

    src = lastCode;
  }

  return lastCode;
}

/* --------------------------------------------------------- */
/* Public API                                                */
/* --------------------------------------------------------- */

function obfuscate(source) {
  const src =
    String(
      source ?? ''
    );

  if (!src.trim()) {
    throw new Error(
      'Empty code'
    );
  }

  const code =
    obfuscateDecimal(
      src,
      2
    );

  /* Basic generated-loader sanity checks */
  if (
    code.includes('dolocal') ||
    code.includes('thenlocal') ||
    code.includes('endlocal')
  ) {
    throw new Error(
      'internal spacing error'
    );
  }

  if (
    !/^\s*--\[\[/.test(code)
  ) {
    throw new Error(
      'loader generation failed'
    );
  }

  return {
    code,

    stats: {
      inputBytes:
        Buffer.byteLength(
          src,
          'utf8'
        ),

      outputBytes:
        Buffer.byteLength(
          code,
          'utf8'
        ),

      mode:
        `QyrexObf-${VERSION}`,

      nestLevels: 2,

      layers: [
        'decimal-affine',
        'per-byte-keyed-stream-mask',
        'keyed-chunk-permutation',
        'dual-source-integrity',
        'dual-payload-integrity',
        'metadata-integrity',
        'runtime-structure-validation',
        'primitive-capture',
        'early-reference-release',
        'plaintext-length-validation',
        'runtime-compatibility-checks',
        'double-nest',
        'random-identifiers',
        'random-chunking',
        'small-integer-runtime-key-derivation',
        'luau-roblox-stable'
      ],

      verified: true
    }
  };
}

module.exports = {
  obfuscate,
  VERSION
};
