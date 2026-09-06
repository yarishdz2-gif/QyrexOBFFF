/**
 * QyrexObf 2.0.0 — Opcode VM Engine (Luau/Roblox)
 * Source is compiled to encrypted bytecode. Runtime is a register VM.
 * Plaintext source is never stored as one clear Lua string in the loader.
 */
'use strict';

const crypto = require('crypto');

const VERSION = '2.0.0';
const MAX_BYTES = 1_500_000;

/* Single-byte alphabet only (Luau string.sub is byte-based) */
const ALPHA = "!#$%&()*+,-./:;<=>?@[]^_{|}~'`";
const BASE = ALPHA.length;
const WORD = 2;

const rb = (n) => crypto.randomBytes(n);
const ri = (n) => crypto.randomInt(0, n);

function rid(len) {
  const n = len || 6 + ri(5);
  const chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  let s = '_';
  for (let i = 0; i < n; i++) s += chars[ri(chars.length)];
  return s;
}

function rstate(n) {
  const len = n || (3 + ri(2));
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHA[ri(BASE)];
  return s;
}

function encByte(b) {
  let n = b & 255;
  let w = '';
  for (let i = 0; i < WORD; i++) {
    w = ALPHA[n % BASE] + w;
    n = (n / BASE) | 0;
  }
  return w;
}

function encBuf(buf) {
  let s = '';
  for (let i = 0; i < buf.length; i++) s += encByte(buf[i]);
  return s;
}

function encStr(s) {
  return encBuf(Buffer.from(String(s), 'utf8'));
}

function decBuf(sym) {
  const map = Object.create(null);
  for (let i = 0; i < BASE; i++) map[ALPHA[i]] = i;
  const out = Buffer.alloc((sym.length / WORD) | 0);
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

function luaEsc(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\0/g, '\\0');
}

function noise(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += ALPHA[ri(BASE)];
  return s;
}

function chunkSym(sym, size) {
  const out = [];
  const step = size || 180 + ri(40);
  for (let i = 0; i < sym.length; i += step) out.push(sym.slice(i, i + step));
  return out;
}

/* ─── Opcodes ─── */
const OP = {
  MOVE: 1,
  LOADK: 2,
  LOADNIL: 3,
  LOADBOOL: 4,
  GETGLOBAL: 5,
  SETGLOBAL: 6,
  GETTABLE: 7,
  SETTABLE: 8,
  NEWTABLE: 9,
  ADD: 10,
  SUB: 11,
  MUL: 12,
  DIV: 13,
  MOD: 14,
  POW: 15,
  UNM: 16,
  NOT: 17,
  LEN: 18,
  CONCAT: 19,
  JMP: 20,
  EQ: 21,
  LT: 22,
  LE: 23,
  TEST: 24,
  CALL: 25,
  RETURN: 26,
  FORPREP: 27,
  FORLOOP: 28,
  CLOSURE: 29,
  SETLIST: 30,
  VARARG: 31,
  SELF: 32,
  /* custom */
  LOADBYTES: 40,  /* R[A] = byte-table from K[Bx] (encrypted const) */
  TOSTRING: 41,   /* R[A] = string.char of all values in table R[B] */
  LOADSTR: 42,    /* R[A] = loadstring(R[B]) or load(R[B]) */
  CHECK: 43,      /* anti-tamper probe */
  DEAD: 44,       /* noop / trap */
  XORK: 45,       /* R[A] = xor decode buffer R[B] with key K[C] */
  NOP: 46,
};

function pack(op, a, b, c) {
  a = a & 255;
  b = b & 255;
  c = c & 255;
  return ((op & 255) << 24) | (a << 16) | (b << 8) | c;
}

function packBx(op, a, bx) {
  a = a & 255;
  bx = bx & 0xffff;
  return ((op & 255) << 24) | (a << 16) | bx;
}

/**
 * Compile arbitrary Lua source into VM bytecode.
 * Strategy: store source bytes encrypted in K; VM reconstructs + loadstring + call.
 * Extra noise ops + CHECK ops raise analysis cost massively.
 */
function compile(source) {
  const srcBuf = Buffer.from(source, 'utf8');
  const xorKey = rb(16 + ri(16));

  /* encrypt source bytes */
  const enc = Buffer.alloc(srcBuf.length);
  for (let i = 0; i < srcBuf.length; i++) {
    enc[i] = srcBuf[i] ^ xorKey[i % xorKey.length] ^ ((i * 131 + 17) & 255);
  }

  const K = [];
  /* K indices */
  const K_LOADSTRING = 0;
  const K_LOAD = 1;
  const K_TYPE = 2;
  const K_FUNCTION = 3;
  const K_STRING = 4;
  const K_CHAR = 5;
  const K_CONCAT = 6;
  const K_BYTE = 7;
  const K_PCALL = 8;
  const K_G = 9;
  const K_SRC = 10;      /* encrypted source bytes as raw buffer stored separately */
  const K_KEY = 11;      /* xor key bytes */
  const K_FAKE1 = 12;
  const K_FAKE2 = 13;

  K[K_LOADSTRING] = 'loadstring';
  K[K_LOAD] = 'load';
  K[K_TYPE] = 'type';
  K[K_FUNCTION] = 'function';
  K[K_STRING] = 'string';
  K[K_CHAR] = 'char';
  K[K_CONCAT] = 'concat';
  K[K_BYTE] = 'byte';
  K[K_PCALL] = 'pcall';
  K[K_G] = '_G';
  K[K_SRC] = enc; /* Buffer */
  K[K_KEY] = xorKey;
  K[K_FAKE1] = Buffer.from(noise(40));
  K[K_FAKE2] = 'table';

  const code = [];
  const R = {
    loader: 0,
    srcEnc: 1,
    key: 2,
    decoded: 3,
    fn: 4,
    tmp: 5,
    env: 6,
    strlib: 7,
    tfn: 8,
    ret: 9,
    ok: 10,
  };

  /* noise prologue */
  for (let i = 0; i < 8 + ri(8); i++) {
    code.push(pack(OP.NOP, ri(8), ri(8), ri(8)));
    if (i % 3 === 0) code.push(pack(OP.CHECK, 0, 0, 0));
    if (i % 5 === 0) code.push(pack(OP.DEAD, ri(4), ri(4), 0));
  }

  /* R.env = _G */
  code.push(packBx(OP.GETGLOBAL, R.env, K_G));
  /* R.loader = loadstring or load */
  code.push(packBx(OP.GETGLOBAL, R.loader, K_LOADSTRING));
  code.push(packBx(OP.LOADK, R.tmp, K_TYPE));
  code.push(packBx(OP.GETGLOBAL, R.tfn, K_TYPE));
  /* if type(loadstring) ~= function then loader = load */
  /* simplified: also fetch load into tmp and TEST */
  code.push(packBx(OP.GETGLOBAL, R.tmp, K_LOAD));
  /* Prefer loadstring: if nil, use load — emitted as runtime preference in LOADSTR op */

  /* R.srcEnc = K_SRC bytes as table */
  code.push(packBx(OP.LOADBYTES, R.srcEnc, K_SRC));
  /* R.key = K_KEY bytes as table */
  code.push(packBx(OP.LOADBYTES, R.key, K_KEY));
  /* R.decoded = xor decode */
  code.push(pack(OP.XORK, R.decoded, R.srcEnc, R.key));
  /* CHECK mid */
  code.push(pack(OP.CHECK, 1, 0, 0));
  /* R.fn = loadstring(R.decoded) */
  code.push(pack(OP.LOADSTR, R.fn, R.decoded, 0));
  /* wipe decoded */
  code.push(pack(OP.LOADNIL, R.decoded, 0, 0));
  code.push(pack(OP.LOADNIL, R.srcEnc, 0, 0));
  /* CALL R.fn() */
  code.push(pack(OP.CALL, R.fn, 1, 2)); /* B=1 no args, C=2 want 1 ret */
  code.push(pack(OP.RETURN, R.fn, 2, 0)); /* return R[fn].. */

  /* dead tail */
  for (let i = 0; i < 5 + ri(5); i++) {
    code.push(pack(OP.DEAD, ri(8), ri(8), 0));
    code.push(pack(OP.NOP, 0, 0, 0));
  }

  return { code, K, xorKey, srcLen: srcBuf.length };
}

/**
 * Serialize bytecode + constants into encrypted symbol stream for embedding.
 */
function serializeProgram(prog) {
  const { code, K } = prog;
  const parts = [];

  /* header: magic, ncode, nk */
  const hdr = Buffer.alloc(12);
  hdr.writeUInt32LE(0x51524d56, 0); /* QRMV */
  hdr.writeUInt32LE(code.length, 4);
  hdr.writeUInt32LE(K.length, 8);
  parts.push(hdr);

  /* code as uint32 LE */
  const codeBuf = Buffer.alloc(code.length * 4);
  for (let i = 0; i < code.length; i++) codeBuf.writeUInt32LE(code[i] >>> 0, i * 4);
  parts.push(codeBuf);

  /* constants: type-tagged */
  for (let i = 0; i < K.length; i++) {
    const v = K[i];
    if (typeof v === 'string') {
      const b = Buffer.from(v, 'utf8');
      const t = Buffer.alloc(5);
      t[0] = 1; /* string */
      t.writeUInt32LE(b.length, 1);
      parts.push(t, b);
    } else if (Buffer.isBuffer(v)) {
      const t = Buffer.alloc(5);
      t[0] = 2; /* bytes */
      t.writeUInt32LE(v.length, 1);
      parts.push(t, v);
    } else if (typeof v === 'number') {
      const t = Buffer.alloc(9);
      t[0] = 3;
      t.writeDoubleLE(v, 1);
      parts.push(t);
    } else {
      const t = Buffer.alloc(5);
      t[0] = 0;
      t.writeUInt32LE(0, 1);
      parts.push(t);
    }
  }

  const raw = Buffer.concat(parts);
  /* outer transport xor */
  const transportKey = rb(24 + ri(8));
  const xored = Buffer.alloc(raw.length);
  for (let i = 0; i < raw.length; i++) {
    xored[i] = raw[i] ^ transportKey[i % transportKey.length] ^ ((i * 17 + 91) & 255);
  }
  return { blob: xored, transportKey, rawLen: raw.length };
}

function buildVmLoader(blob, transportKey, rawLen) {
  const A = rid(), B = rid(), C = rid(), D = rid(), E = rid();
  const F = rid(), G = rid(), H = rid(), I = rid(), J = rid();
  const K = rid(), L = rid(), M = rid(), N = rid(), O = rid();
  const P = rid(), Q = rid(), R = rid(), S = rid(), T = rid();
  const U = rid(), V = rid(), W = rid(), X = rid();
  const PC = rid(), OPV = rid(), RA = rid(), RB = rid(), RC = rid();
  const REG = rid(), KT = rid(), CODE = rid(), OK = rid(), CC = rid();
  const ES = rid(), ST = rid();

  const parts = chunkSym(encBuf(blob));
  const vLit = parts.map((p, idx) => `"${luaEsc(p)}"${idx < parts.length - 1 ? ',' : ''}`).join('\n');
  const keySym = encBuf(transportKey);
  const e = (s) => luaEsc(encStr(s));

  const lines = [];
  lines.push('return(function(...)');
  lines.push(`local ${OK}=true`);
  lines.push(`local ${U}=type`);
  lines.push(`local ${V}=pcall`);
  lines.push(`local ${W}=tostring`);
  lines.push(`local ${S}=string.sub`);
  lines.push(`local ${R}=string.byte`);
  lines.push(`local ${T}=table.concat`);
  lines.push(`local ${CC}=0`);

  /* alphabet + decoder */
  lines.push(`local ${D}="${ALPHA}"`);
  lines.push(`local ${E}={}`);
  lines.push(`for i=1,#${D} do ${E}[${S}(${D},i,i)]=i-1 end`);
  lines.push(`local function ${K}(z) local o={} local pos=1 local zlen=#z while pos+1<=zlen do local n=0 local i=0 while i<2 do local ch=${S}(z,pos+i,pos+i) n=n*(#${D})+(${E}[ch] or 0) i=i+1 end o[#o+1]=string.char(n%256) pos=pos+2 end return ${T}(o) end`);
  lines.push(`local ${ES}=${K}`);

  /* light anti-tamper */
  lines.push(`if ${U}(string)==${ES}("${e('table')}") then ${CC}=${CC}+10 end`);
  lines.push(`if ${U}(table)==${ES}("${e('table')}") then ${CC}=${CC}+10 end`);
  lines.push(`if ${U}(pcall)==${ES}("${e('function')}") then ${CC}=${CC}+10 end`);
  lines.push(`if string.byte(${ES}("${e('A')}"))==65 then ${CC}=${CC}+10 end`);
  lines.push(`if math.floor(3.9)==3 then ${CC}=${CC}+10 end`);
  lines.push(`if math.floor(math.pi)==3 then ${CC}=${CC}+8 end`);
  lines.push(`do local a=${V}(error,"\\0",0) if not a then ${CC}=${CC}+8 end end`);
  lines.push(`if game~=nil and typeof and typeof(game)==${ES}("${e('Instance')}") then ${CC}=${CC}+10 end`);
  lines.push(`do local bad=false if ${U}(_G)==${ES}("${e('table')}") then local function has(k) local ok,v=${V}(function() return rawget(_G,k) end) return ok and v~=nil end if has(${ES}("${e('process')}")) or has(${ES}("${e('lune')}")) or has(${ES}("${e('window')}")) or has(${ES}("${e('document')}")) then bad=true end end if bad then ${CC}=${CC}-40 else ${CC}=${CC}+8 end end`);
  lines.push(`pcall(function() if game and game[${ES}("${e('JobId')}")]==${ES}("${e('00000000-0000-0000-0000-000000000000')}") then ${CC}=${CC}-30 end end)`);

  /* decode blob */
  lines.push(`local ${J}={${vLit}}`);
  lines.push(`local ${F}="${luaEsc(keySym)}"`);
  lines.push(`local ${M}=${K}(${T}(${J}))`);
  lines.push(`local ${N}=${K}(${F})`);
  /* transport xor decode M with N */
  lines.push(`do local out={} local kl=#${N} for i=1,#${M} do local b=${R}(${M},i) local k=${R}(${N},((i-1)%kl)+1) out[i]=string.char(bit32.bxor(b,k,bit32.band((i-1)*17+91,255))) end ${M}=${T}(out) end`);

  /* parse header + code + K */
  lines.push(`local function ${L}(u32,i) return ${R}(${M},i)+${R}(${M},i+1)*256+${R}(${M},i+2)*65536+${R}(${M},i+3)*16777216 end`);
  lines.push(`local magic=${L}(${M},1)`);
  lines.push(`if magic~=${0x51524d56} then return end`);
  lines.push(`local ncode=${L}(${M},5)`);
  lines.push(`local nk=${L}(${M},9)`);
  lines.push(`local pos=13`);
  lines.push(`local ${CODE}={}`);
  lines.push(`for i=1,ncode do ${CODE}[i]=${L}(${M},pos) pos=pos+4 end`);
  lines.push(`local ${KT}={}`);
  lines.push(`for i=1,nk do local tag=${R}(${M},pos) pos=pos+1 local len=${L}(${M},pos) pos=pos+4 if tag==1 or tag==2 then local bytes={} for j=1,len do bytes[j]=${R}(${M},pos) pos=pos+1 end if tag==1 then local cs={} for j=1,len do cs[j]=string.char(bytes[j]) end ${KT}[i-1]=${T}(cs) else ${KT}[i-1]=bytes end elseif tag==3 then ${KT}[i-1]=0 pos=pos+8 else ${KT}[i-1]=nil end end`);

  /* free blob */
  lines.push(`${M}=nil ${J}=nil`);

  /* registers */
  lines.push(`local ${REG}={}`);
  lines.push(`for i=0,255 do ${REG}[i]=nil end`);
  lines.push(`local ${PC}=1`);
  lines.push(`local ${OK}=true`);

  /* helpers used by VM */
  lines.push(`local function getg(name) local g=(type(getfenv)=="function" and getfenv()) or _G local v=g[name] if v~=nil then return v end local n1=string.char(108,111,97,100,115,116,114,105,110,103) local n2=string.char(108,111,97,100) local ls=rawget(g,n1) local ld=rawget(g,n2) if ls==nil then ls=_G and rawget(_G,n1) end if ld==nil then ld=_G and rawget(_G,n2) end if name==n1 then return ls or ld end if name==n2 then return ld or ls end return v or ls or ld end`);

  /* VM dispatch */
  lines.push(`while ${OK} and ${PC}>=1 and ${PC}<=#${CODE} do`);
  lines.push(`local ins=${CODE}[${PC}]`);
  lines.push(`local op=bit32.rshift(ins,24)`);
  lines.push(`local a=bit32.band(bit32.rshift(ins,16),255)`);
  lines.push(`local b=bit32.band(bit32.rshift(ins,8),255)`);
  lines.push(`local c=bit32.band(ins,255)`);
  lines.push(`local bx=bit32.band(ins,65535)`);
  lines.push(`${PC}=${PC}+1`);

  /* NOP / DEAD */
  lines.push(`if op==46 or op==44 then`);
  lines.push(`elseif op==43 then`); /* CHECK */
  lines.push(`if string.byte("A")~=65 then ${OK}=false end`);
  lines.push(`if ${CC}<5 then ${OK}=false end`);

  lines.push(`elseif op==2 then`); /* LOADK */
  lines.push(`${REG}[a]=${KT}[bx]`);

  lines.push(`elseif op==1 then`); /* MOVE */
  lines.push(`${REG}[a]=${REG}[b]`);

  lines.push(`elseif op==3 then`); /* LOADNIL */
  lines.push(`${REG}[a]=nil`);

  lines.push(`elseif op==5 then`); /* GETGLOBAL */
  lines.push(`${REG}[a]=getg(${KT}[bx])`);

  lines.push(`elseif op==40 then`); /* LOADBYTES — already table of numbers in K */
  lines.push(`${REG}[a]=${KT}[bx]`);

  lines.push(`elseif op==45 then`); /* XORK R[a] = xor decode byte-table R[b] with key-table R[c] */
  lines.push(`do local src=${REG}[b] local key=${REG}[c] if ${U}(src)~="table" or ${U}(key)~="table" then ${OK}=false else local out={} local kl=#key for i=1,#src do local bv=src[i] local kv=key[((i-1)%kl)+1] out[i]=bit32.bxor(bv,kv,bit32.band((i-1)*131+17,255)) end local cs={} for i=1,#out do cs[i]=string.char(out[i]) end ${REG}[a]=${T}(cs) end end`);

  lines.push(`elseif op==42 then`); /* LOADSTR R[a]=loadstring(R[b]) */
  lines.push(`do local src=${REG}[b] local loader=getg(string.char(108,111,97,100,115,116,114,105,110,103)) or getg(string.char(108,111,97,100))`);
  /* anti-hook */
  lines.push(`if iscclosure and loader and not iscclosure(loader) then loader=getg(string.char(108,111,97,100)) or loader end`);
  /* decoy flood */
  lines.push(`pcall(function() for di=1,8 do local decoy=string.rep("--"..tostring(di*31).."\\n",70) if #decoy>1000 and loader then loader(decoy) end end end)`);
  lines.push(`if ${U}(src)=="string" and ${U}(loader)=="function" then`);
  /* build via char chunks to frustrate naive dumps */
  lines.push(`local bytes={} for i=1,#src do bytes[i]=string.byte(src,i) end`);
  lines.push(`local parts={} local buf={} local bi=0`);
  lines.push(`for i=1,#bytes do bi=bi+1 buf[bi]=string.char(bytes[i]) if bi>=700 then parts[#parts+1]=table.concat(buf) buf={} bi=0 end end`);
  lines.push(`if bi>0 then parts[#parts+1]=table.concat(buf) end`);
  lines.push(`local built=table.concat(parts) parts=nil buf=nil bytes=nil`);
  lines.push(`${REG}[a]=loader(built) built=nil`);
  lines.push(`else ${REG}[a]=nil end end`);

  lines.push(`elseif op==25 then`); /* CALL A B C — simplified: R[A] = R[A](args) */
  lines.push(`do local fn=${REG}[a] if ${U}(fn)~="function" then ${OK}=false else`);
  lines.push(`if b<=1 then local ret=fn() if c~=1 then ${REG}[a]=ret end`);
  lines.push(`else local args={} for i=1,b-1 do args[i]=${REG}[a+i] end local up=table.unpack or unpack local ret=fn(up(args)) if c~=1 then ${REG}[a]=ret end end end end`);

  lines.push(`elseif op==26 then`); /* RETURN */
  lines.push(`do local v=${REG}[a] return v end`);

  lines.push(`elseif op==20 then`); /* JMP */
  lines.push(`${PC}=${PC}+b-c`); /* rough */

  lines.push(`else`); /* unknown = nop */
  lines.push(`end`);
  lines.push(`end`); /* while */

  lines.push(`end)(...)`);

  return (
    `--[[ Protected by QyrexObf VM v${VERSION} | qyrex.hopto.org ]]\n` +
    lines.join('\n')
  );
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const inputBytes = Buffer.byteLength(src, 'utf8');
  if (inputBytes > MAX_BYTES) throw new Error('Too large (max ~1.5MB)');

  const prog = compile(src);
  const ser = serializeProgram(prog);

  /* verify transport roundtrip */
  const check = Buffer.alloc(ser.blob.length);
  for (let i = 0; i < ser.blob.length; i++) {
    check[i] =
      ser.blob[i] ^
      ser.transportKey[i % ser.transportKey.length] ^
      ((i * 17 + 91) & 255);
  }
  if (check.readUInt32LE(0) !== 0x51524d56) {
    throw new Error('VM serialize roundtrip failed');
  }

  const code = buildVmLoader(ser.blob, ser.transportKey, ser.rawLen);
  return {
    code,
    stats: {
      inputBytes,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-VM-' + VERSION,
      layers: [
        'opcode-vm',
        'encrypted-bytecode',
        'register-machine',
        'xor-const-pool',
        'transport-cipher',
        'symbol-alphabet',
        'anti-hook',
        'decoy-flood',
        'chunk-reassembly',
        'score-anti-tamper',
        'sandbox-probes',
      ],
      opcodes: Object.keys(OP).length,
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION, OP };
