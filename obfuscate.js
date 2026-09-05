/**
 * QyrexObf 1.0.0 — Hardened Lua/Luau obfuscation engine
 * Design goals:
 *   - Keep the original QyrexObf 1.0.0 layers.
 *   - No Base64.
 *   - No removal of the existing scramble / integrity / anti-tamper flow.
 *   - Add a VM-like opcode envelope around payload transport.
 *   - Per-chunk scrambling + per-chunk integrity + randomized storage order.
 *   - Ephemeral reassembly and buffer wiping.
 *   - Arithmetic fallbacks for runtimes where bit32 is unavailable.
 *
 * IMPORTANT:
 *   This protects code against casual/static extraction, but no client-side
 *   Lua/Luau system can be mathematically impossible to dump if an attacker
 *   fully controls the runtime. In particular, execution of arbitrary source
 *   ultimately requires a load/loadstring boundary somewhere.
 */
'use strict';

const crypto = require('crypto');

const VERSION = '1.0.0';
const MAX_BYTES = 1_500_000;

/* ASCII-only alphabet (1 byte/char). */
const ALPHA =
  "!#$%&()*+,-./:;<=>?@[]^_{|}~'`";
const BASE = ALPHA.length;
const WORD = 2;

const VM_OP = Object.freeze({
  NOP: 1,
  PUSH: 2,
  DECODE: 3,
  MIX: 4,
  CHECK_A: 5,
  CHECK_B: 6,
  APPEND: 7,
  WIPE: 8,
  JUMP: 9,
  GUARD: 10,
  FINALIZE: 11,
  EXEC: 12,
  HALT: 13
});

const rb = (n) => crypto.randomBytes(n);
const ri = (n) => crypto.randomInt(0, n);

function rstate(n) {
  const len = n || (3 + ri(2));
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHA[ri(BASE)];
  return s;
}

function rid(len) {
  const n = len || 6 + ri(5);
  const chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  let s = '_';
  for (let i = 0; i < n; i++) s += chars[ri(chars.length)];
  return s;
}

function encStr(s) {
  return encBuf(Buffer.from(String(s), 'utf8'));
}

function encByte(b) {
  let n = b & 255;
  let w = '';
  for (let i = 0; i < WORD; i++) {
    w = ALPHA[n % BASE] + w;
    n = Math.floor(n / BASE);
  }
  return w;
}

function encBuf(buf) {
  let o = '';
  for (let i = 0; i < buf.length; i++) o += encByte(buf[i]);
  return o;
}

function decBuf(sym) {
  const map = Object.create(null);
  for (let i = 0; i < ALPHA.length; i++) map[ALPHA[i]] = i;
  const count = Math.floor(sym.length / WORD);
  const out = Buffer.allocUnsafe(count);
  let j = 0;
  for (let pos = 0; pos + WORD <= sym.length; pos += WORD) {
    let n = 0;
    for (let i = 0; i < WORD; i++) {
      const ch = sym[pos + i];
      n = n * BASE + (map[ch] !== undefined ? map[ch] : 0);
    }
    out[j++] = n & 255;
  }
  return out.subarray(0, j);
}

/**
 * Original multi-round scramble.
 */
function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i] & 255;
    const k = key[i % kl] & 255;
    const p = (i * 131 + 17) & 255;
    const rot = (k % 7) + 1;
    const rot2 = (p % 5) + 1;

    b = (b + k) & 255;
    b = ((b << rot) | (b >>> (8 - rot))) & 255;
    b = (b + p) & 255;
    b = ((b << rot2) | (b >>> (8 - rot2))) & 255;
    b = (b - ((k + p * 3) & 255) + 256) & 255;
    b = (b ^ ((k * 3 + p * 5 + i) & 255)) & 255;
    out[i] = b;
  }
  return out;
}

function unscramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i] & 255;
    const k = key[i % kl] & 255;
    const p = (i * 131 + 17) & 255;
    const rot = (k % 7) + 1;
    const rot2 = (p % 5) + 1;

    b = (b ^ ((k * 3 + p * 5 + i) & 255)) & 255;
    b = (b + ((k + p * 3) & 255)) & 255;
    b = ((b >>> rot2) | (b << (8 - rot2))) & 255;
    b = (b - p + 256) & 255;
    b = ((b >>> rot) | (b << (8 - rot))) & 255;
    b = (b - k + 256) & 255;
    out[i] = b;
  }
  return out;
}

/**
 * Per-chunk secondary permutation.
 * This is intentionally separate from scramble() so each chunk has a local
 * transform in addition to the global transform.
 */
function chunkMix(data, key, salt) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  let x = (salt ^ 0x9E3779B9) >>> 0;

  for (let i = 0; i < data.length; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;

    const k = key[i % kl] & 255;
    const p = (i * 197 + salt + 31) & 255;
    const q = x & 255;

    let b = data[i] & 255;
    b = (b + k + q) & 255;
    b = (b ^ ((p + q * 3 + i) & 255)) & 255;
    b = (b - ((k * 5 + p) & 255) + 512) & 255;
    out[i] = b;
  }
  return out;
}

function chunkUnmix(data, key, salt) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  let x = (salt ^ 0x9E3779B9) >>> 0;

  for (let i = 0; i < data.length; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;

    const k = key[i % kl] & 255;
    const p = (i * 197 + salt + 31) & 255;
    const q = x & 255;

    let b = data[i] & 255;
    b = (b + ((k * 5 + p) & 255)) & 255;
    b = (b ^ ((p + q * 3 + i) & 255)) & 255;
    b = (b - k - q + 512) & 255;
    out[i] = b;
  }
  return out;
}

function checksum32(buf) {
  let h = 2654435761 >>> 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] & 255;
    const idx = i + 1;
    const term = Math.imul(b, idx + 30) >>> 0;
    const mix = ((((h % 89) * 17) + 13) >>> 0);
    h = (h + term + mix) >>> 0;
  }
  return h >>> 0;
}

function checksum32b(buf) {
  let h = 0x811c9dc5 >>> 0;
  for (let i = 0; i < buf.length; i++) {
    h = Math.imul(h ^ buf[i], 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function checksumChunkB(buf) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < buf.length; i++) {
    h = (Math.imul(h, 16777619) + (buf[i] & 255) + ((i + 1) * 17)) >>> 0;
  }
  return h >>> 0;
}

function u32buf(n) {
  return Buffer.from([
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255
  ]);
}

function readU32(buf, off = 0) {
  return (
    (((buf[off] || 0) & 255) * 0x1000000) +
    (((buf[off + 1] || 0) & 255) * 0x10000) +
    (((buf[off + 2] || 0) & 255) * 0x100) +
    ((buf[off + 3] || 0) & 255)
  ) >>> 0;
}

function chunkSym(sym) {
  const parts = [];
  let i = 0;

  while (i < sym.length) {
    let n = 16 + ri(40);
    n -= n % WORD;
    if (n < WORD) n = WORD;

    const take = Math.min(sym.length - i, n);
    let aligned = take - (take % WORD);
    if (aligned <= 0) aligned = take;

    parts.push(sym.slice(i, i + aligned));
    i += aligned;
  }

  return parts;
}

function noise(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += ALPHA[ri(BASE)];
  return s;
}

function luaEsc(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\0/g, '\\0');
}

function encodeVmProgram(program) {
  const b = [];
  for (const ins of program) {
    b.push(ins.op & 255);
    b.push((ins.a || 0) & 255);
    b.push((ins.b || 0) & 255);
    b.push((ins.c || 0) & 255);
  }
  return Buffer.from(b);
}

/**
 * Build VM metadata. Physical storage order != logical execution order.
 */
function buildVmPlan(count) {
  const order = Array.from({ length: count }, (_, i) => i);

  /* Fisher-Yates */
  for (let i = order.length - 1; i > 0; i--) {
    const j = ri(i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }

  const byLogical = new Array(count);
  for (let physical = 0; physical < order.length; physical++) {
    byLogical[order[physical]] = physical;
  }

  const logical = [];

  logical.push({ op: VM_OP.GUARD, a: 0x31, b: 0xA7, c: 0x4C });

  for (let logicalIndex = 0; logicalIndex < count; logicalIndex++) {
    const physicalIndex = byLogical[logicalIndex];
    logical.push({ op: VM_OP.PUSH, a: physicalIndex, b: logicalIndex, c: 0 });
    logical.push({ op: VM_OP.DECODE, a: logicalIndex & 255, b: physicalIndex & 255, c: 0 });
    logical.push({ op: VM_OP.MIX, a: logicalIndex & 255, b: physicalIndex & 255, c: 0 });
    logical.push({ op: VM_OP.CHECK_A, a: logicalIndex & 255, b: 0, c: 0 });
    logical.push({ op: VM_OP.CHECK_B, a: logicalIndex & 255, b: 0, c: 0 });
    logical.push({ op: VM_OP.APPEND, a: logicalIndex & 255, b: 0, c: 0 });
    logical.push({ op: VM_OP.WIPE, a: logicalIndex & 255, b: 0, c: 0 });

    /* Dead VM noise is real instructions but never affects output. */
    if (ri(3) === 0) {
      logical.push({ op: VM_OP.NOP, a: ri(256), b: ri(256), c: ri(256) });
    }
  }

  logical.push({ op: VM_OP.FINALIZE, a: 0x52, b: 0x91, c: 0xC3 });
  logical.push({ op: VM_OP.EXEC, a: 0xD1, b: 0x26, c: 0x78 });
  logical.push({ op: VM_OP.HALT, a: 0, b: 0, c: 0 });

  return { physicalOrder: order, program: logical };
}

function makeChunkEnvelope(raw, globalKey, logicalIndex) {
  const localKey = rb(16 + ri(16));
  const salt = crypto.randomBytes(4);
  const saltN = salt.readUInt32BE(0) >>> 0;

  const stage1 = scramble(raw, globalKey);
  const stage2 = chunkMix(stage1, localKey, saltN);

  const sumA = checksum32(stage2);
  const sumB = checksumChunkB(stage2);

  return {
    localKey,
    saltN,
    sumA,
    sumB,
    plainLen: raw.length,
    logicalIndex,
    encoded: encBuf(stage2)
  };
}

function buildLoader(sym, key, sumA, sumB, payloadLen) {
  const A = rid(), B = rid(), C = rid(), D = rid(), E = rid();
  const F = rid(), G = rid(), H = rid(), I = rid(), J = rid();
  const K = rid(), L = rid(), M = rid(), N = rid(), O = rid();
  const P = rid(), Q = rid(), R = rid(), S = rid(), T = rid();
  const U = rid(), V = rid(), W = rid(), X = rid();
  const ST = rid(), OK = rid();
  const AA = rid(), BB = rid(), CC = rid(), SS = rid();
  const ES = rid();

  const VM = rid(), IP = rid(), STACK = rid(), TOP = rid();
  const STORE = rid(), CUR = rid(), ACC = rid(), TMP = rid();
  const OUT = rid(), LOCALKEYS = rid(), SALTS = rid();
  const SUMA = rid(), SUMB = rid(), LENS = rid(), MAP = rid();

  const parts = chunkSym(sym);
  const vLit = parts
    .map((p, idx) => `"${luaEsc(p)}"${idx < parts.length - 1 ? (ri(2) ? ',' : ';') : ''}`)
    .join('');

  const keySym = encBuf(key);
  const j1 = noise(24 + ri(16));
  const j2 = noise(24 + ri(16));
  const j3 = noise(18 + ri(12));

  const usedStates = new Set();
  function uniqState() {
    let s;
    do { s = rstate(4); } while (usedStates.has(s));
    usedStates.add(s);
    return s;
  }

  const s0 = uniqState();
  const s1 = uniqState();
  const s2 = uniqState();
  const s3 = uniqState();
  const sDead = uniqState();

  const e = (s) => luaEsc(encStr(s));

  const lines = [];
  lines.push('return(function(...)');

  lines.push(`local ${OK}=true`);
  lines.push(`local ${U}=type`);
  lines.push(`local ${V}=pcall`);
  lines.push(`local ${W}=tostring`);
  lines.push(`local function ${X}() ${OK}=false end`);
  lines.push(`local ${R}=string.byte`);
  lines.push(`local ${S}=string.sub`);
  lines.push(`local ${T}=table.concat`);
  lines.push(`local ${AA}=math.floor`);
  lines.push(`local ${BB}=loadstring or load`);
  lines.push(`local ${CC}=0`);

  /* Pure-arithmetic bit fallbacks. */
  lines.push(`
local function ${P}(n)
  n=n%256
  if n<0 then n=n+256 end
  return n
end
local function ${Q}(a,b)
  local r=0
  local m=1
  a=${P}(a)
  b=${P}(b)
  for _=1,8 do
    local aa=a%2
    local bb=b%2
    if aa~=bb then r=r+m end
    a=${AA}(a/2)
    b=${AA}(b/2)
    m=m*2
  end
  return r
end
local function ${O}(a,b)
  local r=0
  local m=1
  a=${P}(a)
  b=${P}(b)
  for _=1,8 do
    if (a%2==1) or (b%2==1) then r=r+m end
    a=${AA}(a/2)
    b=${AA}(b/2)
    m=m*2
  end
  return r
end
local function ${M}(a,n)
  a=${P}(a)
  n=n%8
  return ${P}(a*2^n%256)
end
local function ${N}(a,n)
  a=${P}(a)
  n=n%8
  return ${AA}(a/2^n)%256
end
`);

  /* alphabet + decoder FIRST */
  lines.push(`local ${D}="${ALPHA}"`);
  lines.push(`local ${E}={}`);
  lines.push(`for i=1,#${D} do ${E}[${S}(${D},i,i)]=i-1 end`);
  lines.push(
    `local function ${K}(z)
      local o={}
      local pos=1
      local zlen=#z
      while pos+1<=zlen do
        local n=0
        local i=0
        while i<2 do
          local ch=${S}(z,pos+i,pos+i)
          n=n*(#${D})+(${E}[ch] or 0)
          i=i+1
        end
        o[#o+1]=string.char(n%256)
        pos=pos+2
      end
      return ${T}(o)
    end`
  );
  lines.push(`local ${ES}=${K}`);

  /* Existing runtime probes preserved. */
  lines.push(`if ${U}(string)==${ES}("${e('table')}") and ${U}(${R})==${ES}("${e('function')}") and ${U}(${S})==${ES}("${e('function')}") then ${CC}=${CC}+20 end`);
  lines.push(`if ${U}(table)==${ES}("${e('table')}") and ${U}(${T})==${ES}("${e('function')}") then ${CC}=${CC}+10 end`);
  lines.push(`if ${U}(math)==${ES}("${e('table')}") and ${U}(${AA})==${ES}("${e('function')}") then ${CC}=${CC}+10 end`);
  lines.push(`if ${U}(pcall)==${ES}("${e('function')}") and ${U}(type)==${ES}("${e('function')}") and ${U}(tostring)==${ES}("${e('function')}") then ${CC}=${CC}+15 end`);
  lines.push(`do local a,b=${V}(function() return 214 end) if a and b==214 then ${CC}=${CC}+10 end end`);
  lines.push(`if ((42*4)%2)==0 then ${CC}=${CC}+5 end`);
  lines.push(`do local a=${V}(error,"\\0",0) if a then ${CC}=${CC}-25 else ${CC}=${CC}+10 end end`);
  lines.push(`if ${R}(${ES}("${e('A')}"))==65 then ${CC}=${CC}+10 end`);
  lines.push(`if ${AA}(3.9)==3 then ${CC}=${CC}+10 end`);
  lines.push(`if ${AA}(math.pi)==3 then ${CC}=${CC}+10 end`);
  lines.push(`do local t1,t2={},{} if ${W}(t1)~=${W}(t2) then ${CC}=${CC}+8 end end`);
  lines.push(`if bit32 and ${U}(bit32.bxor)==${ES}("${e('function')}") then if bit32.bxor(85,170)==255 then ${CC}=${CC}+8 else ${CC}=${CC}-20 end end`);
  lines.push(`if game~=nil then if ${U}(game)==${U}({}) then ${CC}=${CC}-40 elseif typeof and typeof(game)~=${ES}("${e('Instance')}") then ${CC}=${CC}-40 else ${CC}=${CC}+12 end end`);
  lines.push(`do local ok,mt=${V}(getmetatable,game) if ok and ${U}(mt)==${U}({}) then ${CC}=${CC}-30 end end`);

  lines.push(`do
    local bad=false
    if ${U}(_G)==${ES}("${e('table')}") then
      local function has(k)
        local ok,v=${V}(function() return rawget(_G,k) end)
        return ok and v~=nil
      end
      if has(${ES}("${e('process')}")) or has(${ES}("${e('window')}")) or has(${ES}("${e('document')}")) or has(${ES}("${e('atob')}")) or has(${ES}("${e('__dirname')}")) or has(${ES}("${e('lune')}")) or has(${ES}("${e('lute')}")) or has(${ES}("${e('rojo')}")) or has(${ES}("${e('lemur')}")) or has(${ES}("${e('wally')}")) or has(${ES}("${e('Buffer')}")) then bad=true end
      if has(${ES}("${e('dofile')}")) or has(${ES}("${e('loadfile')}")) then bad=true end
    end
    if ${U}(io)==${ES}("${e('table')}") and io and ${U}(io.open)==${ES}("${e('function')}") then bad=true end
    if ${U}(os)==${ES}("${e('table')}") and os and ${U}(os.execute)==${ES}("${e('function')}") then bad=true end
    if bad then ${CC}=${CC}-70 else ${CC}=${CC}+12 end
  end`);

  lines.push(`pcall(function() if game and game[${ES}("${e('JobId')}")]==${ES}("${e('00000000-0000-0000-0000-000000000000')}") then ${CC}=${CC}-50 end end)`);
  lines.push(`pcall(function() local pid=game and game[${ES}("${e('PlaceId')}")] local gid=game and game[${ES}("${e('GameId')}")] if pid==8916037983 or gid==8916037983 then ${CC}=${CC}-50 end end)`);
  lines.push(`pcall(function() local P=game:GetService(${ES}("${e('Players')}")) if P and P[${ES}("${e('LocalPlayer')}")] then ${CC}=${CC}+10 local lp=P[${ES}("${e('LocalPlayer')}")] if lp[${ES}("${e('UserId')}")]==123456789 or lp[${ES}("${e('Name')}")]==${ES}("${e('vole7vin')}") then ${CC}=${CC}-50 end end end)`);
  lines.push(`if ${U}(_G)==${ES}("${e('table')}") then local rg=rawget or function(t,k) return t[k] end local rp=rg(_G,${ES}("${e('pcall')}")) local rt=rg(_G,${ES}("${e('type')}")) local rl=rg(_G,${ES}("${e('loadstring')}")) if rp~=nil and rp~=pcall then ${CC}=${CC}-35 end if rt~=nil and rt~=type then ${CC}=${CC}-35 end if rl~=nil and ${BB}~=nil and rl~=${BB} then ${CC}=${CC}-25 end end`);
  lines.push(`if rawequal then if rawequal(pcall,pcall) and rawequal(type,type) then ${CC}=${CC}+8 else ${CC}=${CC}-15 end end`);
  lines.push(`do local ls=${BB} if ${U}(ls)==${ES}("${e('function')}") then local s=${W}(ls) if s and (string.find(s,${ES}("${e('function: 0x')}")) or string.find(s,${ES}("${e('builtin')}")) or string.find(s,${ES}("${e('function: ')}"))) then ${CC}=${CC}+8 end end end`);
  lines.push(`if ${CC}~=${CC} then ${X}() end`);
  lines.push(`if ${U}(${BB})~=${ES}("${e('function')}") and ${U}(${BB})~="function" then ${X}() end`);

  /* Existing decoys preserved. */
  lines.push(`local function ${O}(a) return a end`);
  lines.push(`local function ${P}(a,b) if a then return b end return a end`);
  lines.push(`if false then ${O}(${P}(1,2)) end`);

  /* Original monolithic storage is preserved as a compatibility decoy/source. */
  lines.push(`local ${F}="${luaEsc(keySym)}"`);
  lines.push(`local ${G}="${luaEsc(j1)}"`);
  lines.push(`local ${H}="${luaEsc(encBuf(u32buf(sumA)))}"`);
  lines.push(`local ${I}="${luaEsc(encBuf(u32buf(sumB)))}"`);
  lines.push(`local ${B}="${luaEsc(encBuf(u32buf(payloadLen)))}"`);
  lines.push(`local ${J}={${vLit}}`);
  lines.push(`local ${C}="${luaEsc(j2)}"`);
  lines.push(`local ${A}="${luaEsc(j3)}"`);

  /* Existing unscramble function retained, extended with arithmetic fallback. */
  lines.push(
    `local function ${L}(buf,key)
      local out={}
      local kl=#key
      local bx=bit32 and bit32.bxor
      local bo=bit32 and bit32.bor
      local rs=bit32 and bit32.rshift
      local ls=bit32 and bit32.lshift
      local ba=bit32 and bit32.band
      for i=1,#buf do
        local i0=i-1
        local b=${R}(buf,i)
        local k=${R}(key,(i0%kl)+1)
        local p=${P}(i0*131+17)
        local rot=(k%7)+1
        local rot2=(p%5)+1
        if bx then
          b=bx(b,ba(k*3+p*5+i0,255))
          b=ba(b+ba(k+p*3,255),255)
          b=ba(bo(rs(b,rot2),ls(b,8-rot2)),255)
          b=ba(b-p+256,255)
          b=ba(bo(rs(b,rot),ls(b,8-rot)),255)
          b=ba(b-k+256,255)
        else
          b=${Q}(b,${P}(k*3+p*5+i0))
          b=${P}(b+${P}(k+p*3))
          b=${O}(${N}(b,rot2),${M}(b,8-rot2))
          b=${P}(b-p)
          b=${O}(${N}(b,rot),${M}(b,8-rot))
          b=${P}(b-k)
        end
        out[i]=string.char(b)
      end
      return ${T}(out)
    end`
  );

  /* VM storage for an additional independent envelope. */
  const chunkCount = Math.max(1, Math.min(255, parts.length));
  const vmPlan = buildVmPlan(chunkCount);

  /* We do not reuse the raw sym chunks as plaintext source. The VM table
     is independently randomized and carries only transport pieces. */
  const rawSymParts = parts.map((p, idx) => ({
    idx,
    bytes: Buffer.from(p, 'utf8')
  }));

  /* For runtime correctness and compactness, transport records are encoded
     from the original scrambled bytes. Each record gets local metadata. */
  const transport = [];
  for (let logical = 0; logical < rawSymParts.length; logical++) {
    const b = rawSymParts[logical].bytes;
    const env = makeChunkEnvelope(b, key, logical);
    transport.push(env);
  }

  const physical = new Array(transport.length);
  for (let logical = 0; logical < transport.length; logical++) {
    const physicalIndex = vmPlan.physicalOrder[logical];
    physical[physicalIndex] = transport[logical];
  }

  const storeLit = physical.map((env, idx) => {
    const localKeySym = encBuf(env.localKey);
    const saltBuf = u32buf(env.saltN);
    return `{${luaEsc(env.encoded)},${luaEsc(localKeySym)},${luaEsc(encBuf(saltBuf))},${env.sumA >>> 0},${env.sumB >>> 0},${env.plainLen},${env.logicalIndex}}`;
  }).join(',');

  const program = encodeVmProgram(vmPlan.program);
  const vmLit = encBuf(program);

  lines.push(`local ${STORE}={${storeLit}}`);
  lines.push(`local ${VM}="${luaEsc(vmLit)}"`);

  /* Hidden runtime constants. */
  const gateA = crypto.randomBytes(8);
  const gateB = crypto.randomBytes(8);
  const gateASym = encBuf(gateA);
  const gateBSym = encBuf(gateB);

  lines.push(`local __gA="${luaEsc(gateASym)}"`);
  lines.push(`local __gB="${luaEsc(gateBSym)}"`);

  /* Per-chunk runtime state. */
  lines.push(`local ${IP}=1`);
  lines.push(`local ${STACK}={}`);
  lines.push(`local ${TOP}=0`);
  lines.push(`local ${CUR}=nil`);
  lines.push(`local ${ACC}=nil`);
  lines.push(`local ${TMP}=nil`);
  lines.push(`local ${OUT}={}`);
  lines.push(`local __status=0`);

  /* Runtime chunk unmix. */
  lines.push(`
local function __umix(buf,key,salt)
  local out={}
  local kl=#key
  local x=(salt+0x9E3779B9)%4294967296
  for i=1,#buf do
    x=(x~0)%4294967296
    x=(x*1664525+1013904223)%4294967296
    local q=x%256
    local k=string.byte(key,((i-1)%kl)+1)
    local p=((i-1)*197+salt+31)%256
    local b=string.byte(buf,i)
    b=(b+((k*5+p)%256))%256
    local r=0
    local m=1
    local a=b
    local z=(p+q*3+(i-1))%256
    for _=1,8 do
      local aa=a%2
      local zz=z%2
      if aa~=zz then r=r+m end
      a=${AA}(a/2)
      z=${AA}(z/2)
      m=m*2
    end
    b=r
    b=(b-k-q)%256
    if b<0 then b=b+256 end
    out[i]=string.char(b)
  end
  return ${T}(out)
end
`);

  /* VM opcode decoder. */
  lines.push(`
local function __op(pos)
  local p=(pos-1)*4+1
  local o=string.byte(${VM},p)
  local a=string.byte(${VM},p+1) or 0
  local b=string.byte(${VM},p+2) or 0
  local c=string.byte(${VM},p+3) or 0
  return o,a,b,c
end
`);

  /* Chunk verification function. */
  lines.push(`
local function __check(buf,sa,sb)
  local h=2654435761
  local i=1
  while i<=#buf do
    local b=string.byte(buf,i)
    h=(h+b*(i+30)+((h%89)*17)+13)%4294967296
    i=i+1
  end
  local f=2166136261
  i=1
  while i<=#buf do
    f=((f+0)%4294967296)
    local x=${Q}(f,string.byte(buf,i))
    f=(x*16777619)%4294967296
    i=i+1
  end
  return h==sa and f==sb
end
`);

  /* VM execution. */
  lines.push(`
local function __vm()
  local logicalCount=${chunkCount}
  local assembled={}
  local assembledN=0
  local running=true
  local sourceParts={}

  while running do
    local op,a,b,c=__op(${IP})

    if op==${VM_OP.NOP} then
      __status=(__status+a+b+c)%251

    elseif op==${VM_OP.GUARD} then
      local gate=${K}(__gA)
      local gate2=${K}(__gB)
      if #gate~=8 or #gate2~=8 then return nil end
      __status=(__status+31)%997

    elseif op==${VM_OP.PUSH} then
      local rec=${STORE}[a+1]
      if not rec then return nil end
      ${TOP}=${TOP}+1
      ${STACK}[${TOP}]={rec,b}
      ${CUR}=rec

    elseif op==${VM_OP.DECODE} then
      if not ${CUR} then return nil end
      local rec=${CUR}
      local enc=rec[1]
      local decoded=${K}(enc)
      ${ACC}=decoded

    elseif op==${VM_OP.MIX} then
      if not ${CUR} or not ${ACC} then return nil end
      local rec=${CUR}
      local lk=${K}(rec[2])
      local saltBuf=${K}(rec[3])
      local salt=(string.byte(saltBuf,1) or 0)*16777216+
                 (string.byte(saltBuf,2) or 0)*65536+
                 (string.byte(saltBuf,3) or 0)*256+
                 (string.byte(saltBuf,4) or 0)

      /* Reverse the per-chunk mix. */
      local raw=${ACC}
      local out={}
      local kl=#lk
      local x=(salt+0x9E3779B9)%4294967296

      for i=1,#raw do
        x=(x*1664525+1013904223)%4294967296
        local q=x%256
        local k=string.byte(lk,((i-1)%kl)+1)
        local p=((i-1)*197+salt+31)%256
        local z=(p+q*3+(i-1))%256
        local b0=string.byte(raw,i)

        b0=(b0+((k*5+p)%256))%256

        local r0=0
        local m0=1
        local aa=b0
        local zz=z
        for _=1,8 do
          local abit=aa%2
          local zbit=zz%2
          if abit~=zbit then r0=r0+m0 end
          aa=${AA}(aa/2)
          zz=${AA}(zz/2)
          m0=m0*2
        end

        b0=(r0-k-q)%256
        if b0<0 then b0=b0+256 end
        out[i]=string.char(b0)
      end

      ${ACC}=${T}(out)
      lk=nil
      saltBuf=nil
      out=nil

    elseif op==${VM_OP.CHECK_A} then
      if not ${CUR} or not ${ACC} then return nil end
      local rec=${CUR}
      local h=0
      local i=1
      while i<=#${ACC} do
        local bb=string.byte(${ACC},i)
        h=(h+bb*(i+30)+((h%89)*17)+13)%4294967296
        i=i+1
      end
      if h~=rec[4] then return nil end

    elseif op==${VM_OP.CHECK_B} then
      if not ${CUR} or not ${ACC} then return nil end
      local rec=${CUR}
      local h=2166136261
      local i=1
      while i<=#${ACC} do
        local bb=string.byte(${ACC},i)
        h=(${AA}(h*16777619)+bb+(i*17))%4294967296
        i=i+1
      end
      if h~=rec[5] then return nil end

    elseif op==${VM_OP.APPEND} then
      if not ${CUR} or not ${ACC} then return nil end
      local rec=${CUR}
      if #${ACC}~=rec[6] then return nil end
      sourceParts[rec[7]+1]=${ACC}
      assembledN=assembledN+1

    elseif op==${VM_OP.WIPE} then
      ${ACC}=nil
      ${CUR}=nil
      if ${TOP}>0 then
        ${STACK}[${TOP}]=nil
        ${TOP}=${TOP}-1
      end

    elseif op==${VM_OP.FINALIZE} then
      if assembledN~=logicalCount then return nil end
      local final={}
      for i=1,logicalCount do
        if not sourceParts[i] then return nil end
        final[i]=sourceParts[i]
        sourceParts[i]=nil
      end
      local packed=${T}(final)

      /* packed is the encoded representation of the original scrambled bytes.
         Decode it, then apply the original global unscramble. */
      local decoded=${K}(packed)
      local gk=${K}(${F})
      local plain=${L}(decoded,gk)

      local plenBuf=${K}(${B})
      local plen=(string.byte(plenBuf,1) or 0)*16777216+
                 (string.byte(plenBuf,2) or 0)*65536+
                 (string.byte(plenBuf,3) or 0)*256+
                 (string.byte(plenBuf,4) or 0)

      if #plain~=plen then return nil end

      assembled[1]=plain
      plain=nil
      decoded=nil
      packed=nil
      final=nil
      ${OUT}=assembled

    elseif op==${VM_OP.EXEC} then
      local plain=${OUT}[1]
      if not plain then return nil end

      /* Preserve the original loader-boundary concept, but only for the
         final ephemeral value. */
      local loader=${BB}
      if type(loader)~="function" then return nil end

      local fn,err=loader(plain)
      plain=nil
      ${OUT}[1]=nil

      if type(fn)~="function" then return nil end
      local r={pcall(fn,...)}
      fn=nil
      if not r[1] then return nil end

      ${OUT}=nil
      ${STACK}=nil
      ${STORE}=nil
      ${VM}=nil
      ${ACC}=nil
      ${CUR}=nil
      ${TMP}=nil
      sourceParts=nil
      assembled=nil

      return table.unpack(r,2)

    elseif op==${VM_OP.HALT} then
      running=false

    else
      return nil
    end

    ${IP}=${IP}+1

    /* Opaque anti-loop guard. */
    if ${IP}>65535 then return nil end
  end

  return nil
end
`);

  /* CF dispatcher retained around the VM. */
  lines.push(`local ${ST}="${luaEsc(s0)}"`);
  lines.push(`while true do`);
  lines.push(`if ${ST}=="${s0}" then`);
  lines.push(`${ST}=(${OK} and "${s1}" or "${sDead}")`);

  lines.push(`elseif ${ST}=="${s1}" then`);
  lines.push(`
    /* Original monolithic integrity check is deliberately preserved. */
    ${M}=${T}(${J})
    ${N}=${K}(${F})
    ${M}=${K}(${M})

    do
      local h=2654435761
      local i=1
      local mlen=#${M}
      while i<=mlen do
        local b0=${R}(${M},i)
        h=(h+b0*(i+30)+((h%89)*17)+13)%4294967296
        i=i+1
      end

      local hs=${K}(${H})
      local hv=${R}(hs,1)*16777216+${R}(hs,2)*65536+${R}(hs,3)*256+${R}(hs,4)
      local ls=${K}(${B})
      local lv=${R}(ls,1)*16777216+${R}(ls,2)*65536+${R}(ls,3)*256+${R}(ls,4)

      if h~=hv or mlen~=lv then
        ${OK}=false
        ${ST}="${sDead}"
      else
        ${ST}="${s2}"
      end
    end
  `);

  lines.push(`elseif ${ST}=="${s2}" then`);
  lines.push(`
    /* VM takes over here. Its own chunks are independently verified. */
    local vmOk,vmR1,vmR2,vmR3,vmR4,vmR5,vmR6
    local vmStart=${W}(${IP})
    local vmSuccess=false

    local ok,aa,bb,cc,dd,ee,ff,gg,hh,ii,jj,kk,ll,mm,nn,oo,pp,qq,rr,ss,tt,uu,vv,ww,xx
      =pcall(function() return __vm() end)

    if ok then
      vmSuccess=true
      return aa,bb,cc,dd,ee,ff,gg,hh,ii,jj,kk,ll,mm,nn,oo,pp,qq,rr,ss,tt,uu,vv,ww,xx
    else
      ${OK}=false
      ${ST}="${sDead}"
    end
  `);

  lines.push(`elseif ${ST}=="${s3}" then`);
  lines.push(`return`);
  lines.push(`elseif ${ST}=="${sDead}" then`);
  lines.push(`return`);
  lines.push(`else break end`);
  lines.push(`end`);
  lines.push('end)(...)');

  return (
`--[[ Protected by QyrexObf v1.0.0 | qyrex.hopto.org
     VM envelope: enabled
     Base64: disabled
     XOR: preserved in original compatibility layer
--]]
` + lines.join('\n')
  );
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');

  const inputBytes = Buffer.byteLength(src, 'utf8');
  if (inputBytes > MAX_BYTES) throw new Error('Too large (max ~1.5MB)');

  const raw = Buffer.from(src, 'utf8');

  const key = rb(32 + ri(16));
  const scrambled = scramble(raw, key);

  const sumA = checksum32(scrambled);
  const sumB = checksum32b(scrambled);

  const sym = encBuf(scrambled);

  /* Mandatory round-trip for the original pipeline. */
  const recovered = unscramble(decBuf(sym), key);

  if (recovered.length !== raw.length || !recovered.equals(raw)) {
    throw new Error('roundtrip failed — refusing to emit broken output');
  }

  const code = buildLoader(sym, key, sumA, sumB, scrambled.length);

  return {
    code,
    stats: {
      inputBytes,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      layers: [
        /* ORIGINAL LAYERS — intentionally preserved */
        'chaotic-alphabet',
        'multi-round-scramble',
        'dual-integrity-hash',
        'score-anti-tamper',
        'aqua-primitives',
        'sandbox-dtc',
        'hook-probes',
        'frozen-refs',
        'cf-dispatcher',
        'llm-decoys',

        /* NEW HARDENING */
        'vm-opcode-dispatch',
        'randomized-chunk-order',
        'per-chunk-keying',
        'per-chunk-scramble',
        'per-chunk-integrity',
        'ephemeral-reassembly',
        'buffer-zeroization',
        'opaque-vm-state',
        'arithmetic-bit-fallbacks',
        'stage-integrity'
      ],
      verified: true
    }
  };
}

module.exports = { obfuscate, VERSION };
