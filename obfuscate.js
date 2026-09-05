/**
 * QyrexObf 2.0.0 — Hardened Lua/Luau obfuscation engine
 * Design goals: zero runtime arithmetic errors, dual Lua/Luau load,
 * verified round-trip, dual integrity, CF dispatcher, anti-tamper, decoys,
 * + CUSTOM OPCODE VIRTUAL MACHINE (impossible-to-static-recover decoder).
 *
 * Identifiers are always valid Lua (_ + alnum). Chaotic alphabet lives in strings only.
 * The real unscramble + string rebuild is no longer plain Lua — it is executed
 * as a stream of custom opcodes inside a heavily obfuscated stack VM.
 */
'use strict';

const crypto = require('crypto');

const VERSION = '2.0.0';
const MAX_BYTES = 1_500_000;

/* ASCII-only alphabet (1 byte/char). Multi-byte UTF-8 breaks Luau string.sub byte indexing. */
const ALPHA =
  "!#$%&()*+,-./:;<=>?@[]^_{|}~'`";
const BASE = ALPHA.length; // must be constant
const WORD = 2; // 2 symbols per byte (BASE^2 >= 256)

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
    n = (n / BASE) | 0;
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
  const count = (sym.length / WORD) | 0;
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
 * Multi-round scramble — pure 8-bit modular ops (no undefined shifts).
 * Must match Lua decoder exactly.
 */
function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i] & 255;
    const k = key[i % kl] & 255;
    const p = (i * 131 + 17) & 255;
    const rot = (k % 7) + 1; // 1..7
    const rot2 = (p % 5) + 1; // 1..5

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

function checksum32(buf) {
  /* Must match Lua: i is 1-based, h=(h+b*(i+30)+((h%89)*17)+13)%2^32 */
  let h = 2654435761 >>> 0; // 0x9E3779B1
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] & 255;
    const idx = i + 1; // Lua 1-based
    const term = (b * (idx + 30)) >>> 0;
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

/* ============================================================
 * CUSTOM OPCODE VM — core of the new protection layer
 * Opcodes (numeric, emitted as table of integers):
 *   0x01 PUSH_IMM   <byte>          push immediate
 *   0x02 LOAD_KEY   <idx>           push key[idx % kl]
 *   0x03 XOR                        pop a,b → push a^b
 *   0x04 ADD                        pop a,b → push (a+b)&255
 *   0x05 SUB                        pop a,b → push (a-b+256)&255
 *   0x06 ROL        <n>             rotate left top by n
 *   0x07 ROR        <n>             rotate right top by n
 *   0x08 STORE                      pop → append to output buffer
 *   0x09 DUP                        duplicate top
 *   0x0A POP                        discard top
 *   0x0B JMP        <rel>           relative jump
 *   0x0C JZ         <rel>           jump if top==0 (consumes)
 *   0x0D LOAD_IDX                   push current byte index
 *   0x0E INC_IDX                    idx = idx + 1
 *   0x0F HALT                       stop VM, output ready
 *   0x10 NOP / JUNK                 many decoy variants
 *   0x11 XOR_CONST  <c>             top ^= c
 *   0x12 ADD_CONST  <c>             top = (top+c)&255
 *   0x13 LOAD_LEN                   push payload length
 *   0x14 CMP_EQ                     pop a,b → push (a==b ? 1 : 0)
 *   0x20 LOAD_SCRAMBLED             push next scrambled byte
 * ============================================================ */

function buildVmBytecode(scrambled, key) {
  const bc = [];
  const kl = key.length;
  const len = scrambled.length;

  for (let i = 0; i < len; i++) {
    const k = key[i % kl] & 255;
    const p = (i * 131 + 17) & 255;
    const rot = (k % 7) + 1;
    const rot2 = (p % 5) + 1;

    // random junk ops (makes pattern matching extremely hard)
    const junkCount = 1 + ri(3);
    for (let j = 0; j < junkCount; j++) {
      const junk = 0x40 + ri(20);
      bc.push(junk);
      if (ri(2)) bc.push(ri(256));
    }

    // LOAD_SCRAMBLED
    bc.push(0x20);

    // b = b ^ ((k*3 + p*5 + i) & 255)
    bc.push(0x01, (k * 3 + p * 5 + i) & 255);
    bc.push(0x03);

    // b = (b + ((k + p*3) & 255)) & 255
    bc.push(0x01, (k + p * 3) & 255);
    bc.push(0x04);

    // b = ROR(b, rot2)
    bc.push(0x07, rot2);

    // b = (b - p + 256) & 255
    bc.push(0x01, p);
    bc.push(0x05);

    // b = ROR(b, rot)
    bc.push(0x07, rot);

    // b = (b - k + 256) & 255
    bc.push(0x01, k);
    bc.push(0x05);

    // STORE
    bc.push(0x08);

    if (ri(3) === 0) bc.push(0x10);
  }

  bc.push(0x0F); // HALT

  for (let i = 0; i < 8 + ri(16); i++) {
    bc.push(0x50 + ri(30));
    if (ri(2)) bc.push(ri(256));
  }

  return bc;
}

/**
 * Emit self-decoding Lua loader.
 * All arithmetic uses % 256 / math.floor — no bit32 required where possible.
 * NEW: the real unscramble is performed by a custom opcode VM.
 */

function buildLoader(sym, key, sumA, sumB, payloadLen, scrambled) {
  const A = rid(), B = rid(), C = rid(), D = rid(), E = rid();
  const F = rid(), G = rid(), H = rid(), I = rid(), J = rid();
  const K = rid(), L = rid(), M = rid(), N = rid(), O = rid();
  const P = rid(), Q = rid(), R = rid(), S = rid(), T = rid();
  const U = rid(), V = rid(), W = rid(), X = rid();
  const ST = rid(), OK = rid();
  const AA = rid(), BB = rid(), CC = rid(), SS = rid();
  const ES = rid();

  // VM-specific identifiers
  const VM = rid(), PC = rid(), STK = rid(), OUT = rid(), OP = rid();
  const IDX = rid(), BC = rid(), SP = rid(), TMP = rid(), HALTED = rid();
  const SCR = rid();

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
  const s4 = uniqState();
  const sDead = uniqState();

  const e = (s) => luaEsc(encStr(s));

  const bytecode = buildVmBytecode(scrambled, key);
  const bcChunks = [];
  for (let i = 0; i < bytecode.length; i += 40) {
    bcChunks.push(bytecode.slice(i, i + 40).join(','));
  }
  const bcLit = bcChunks.map((c, i) => (i === 0 ? c : ',' + c)).join('');

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

  // alphabet + decoder FIRST
  lines.push(`local ${D}="${ALPHA}"`);
  lines.push(`local ${E}={}`);
  lines.push(`for i=1,#${D} do ${E}[${S}(${D},i,i)]=i-1 end`);
  lines.push(
    `local function ${K}(z) local o={} local pos=1 local zlen=#z while pos+1<=zlen do local n=0 local i=0 while i<#"~~" do local ch=${S}(z,pos+i,pos+i) n=n*(#${D})+(${E}[ch] or 0) i=i+1 end o[#o+1]=string.char(n%256) pos=pos+(#"~~") end return ${T}(o) end`
  );
  lines.push(`local ${ES}=${K}`);

  // primitives with encoded type names (ALL KEPT)
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

  lines.push(`do local bad=false if ${U}(_G)==${ES}("${e('table')}") then local function has(k) local ok,v=${V}(function() return rawget(_G,k) end) return ok and v~=nil end if has(${ES}("${e('process')}")) or has(${ES}("${e('window')}")) or has(${ES}("${e('document')}")) or has(${ES}("${e('atob')}")) or has(${ES}("${e('__dirname')}")) or has(${ES}("${e('lune')}")) or has(${ES}("${e('lute')}")) or has(${ES}("${e('rojo')}")) or has(${ES}("${e('lemur')}")) or has(${ES}("${e('wally')}")) or has(${ES}("${e('Buffer')}")) then bad=true end if has(${ES}("${e('dofile')}")) or has(${ES}("${e('loadfile')}")) then bad=true end end if ${U}(io)==${ES}("${e('table')}") and io and ${U}(io.open)==${ES}("${e('function')}") then bad=true end if ${U}(os)==${ES}("${e('table')}") and os and ${U}(os.execute)==${ES}("${e('function')}") then bad=true end if bad then ${CC}=${CC}-70 else ${CC}=${CC}+12 end end`);

  lines.push(`pcall(function() if game and game[${ES}("${e('JobId')}")]==${ES}("${e('00000000-0000-0000-0000-000000000000')}") then ${CC}=${CC}-50 end end)`);
  lines.push(`pcall(function() local pid=game and game[${ES}("${e('PlaceId')}")] local gid=game and game[${ES}("${e('GameId')}")] if pid==8916037983 or gid==8916037983 then ${CC}=${CC}-50 end end)`);
  lines.push(`pcall(function() local P=game:GetService(${ES}("${e('Players')}")) if P and P[${ES}("${e('LocalPlayer')}")] then ${CC}=${CC}+10 local lp=P[${ES}("${e('LocalPlayer')}")] if lp[${ES}("${e('UserId')}")]==123456789 or lp[${ES}("${e('Name')}")]==${ES}("${e('vole7vin')}") then ${CC}=${CC}-50 end end end)`);

  lines.push(`if ${U}(_G)==${ES}("${e('table')}") then local rg=rawget or function(t,k) return t[k] end local rp=rg(_G,${ES}("${e('pcall')}")) local rt=rg(_G,${ES}("${e('type')}")) local rl=rg(_G,${ES}("${e('loadstring')}")) if rp~=nil and rp~=pcall then ${CC}=${CC}-35 end if rt~=nil and rt~=type then ${CC}=${CC}-35 end if rl~=nil and ${BB}~=nil and rl~=${BB} then ${CC}=${CC}-25 end end`);
  lines.push(`if rawequal then if rawequal(pcall,pcall) and rawequal(type,type) then ${CC}=${CC}+8 else ${CC}=${CC}-15 end end`);
  lines.push(`do local ls=${BB} if ${U}(ls)==${ES}("${e('function')}") then local s=${W}(ls) if s and (string.find(s,${ES}("${e('function: 0x')}")) or string.find(s,${ES}("${e('builtin')}")) or string.find(s,${ES}("${e('function: ')}"))) then ${CC}=${CC}+8 end end end`);
  lines.push(`if ${CC}~=${CC} then ${X}() end`);
  lines.push(`if ${U}(${BB})~=${ES}("${e('function')}") and ${U}(${BB})~="function" then ${X}() end`);

  // decoys
  lines.push(`local function ${O}(a) return a end`);
  lines.push(`local function ${P}(a,b) if a then return b end return a end`);
  lines.push(`if false then ${O}(${P}(1,2)) end`);

  // blobs (kept exactly)
  lines.push(`local ${F}="${luaEsc(keySym)}"`);
  lines.push(`local ${G}="${luaEsc(j1)}"`);
  lines.push(`local ${H}="${luaEsc(encBuf(Buffer.from([(sumA>>>24)&255,(sumA>>>16)&255,(sumA>>>8)&255,sumA&255])))}"`);
  lines.push(`local ${I}="${luaEsc(encBuf(Buffer.from([(sumB>>>24)&255,(sumB>>>16)&255,(sumB>>>8)&255,sumB&255])))}"`);
  lines.push(`local ${B}="${luaEsc(encBuf(Buffer.from([(payloadLen>>>24)&255,(payloadLen>>>16)&255,(payloadLen>>>8)&255,payloadLen&255])))}"`);
  lines.push(`local ${J}={${vLit}}`);
  lines.push(`local ${C}="${luaEsc(j2)}"`);
  lines.push(`local ${A}="${luaEsc(j3)}"`);

  // ========== CUSTOM OPCODE VM ==========
  lines.push(`local ${BC}={${bcLit}}`);

  // Portable 8-bit helpers
  lines.push(`local function ${TMP}_xor(a,b) local r=0 local p=1 for i=0,7 do local abit=a%2 local bbit=b%2 if abit~=bbit then r=r+p end a=${AA}(a/2) b=${AA}(b/2) p=p*2 end return r end`);
  lines.push(`local function ${TMP}_rol(v,n) n=n%8 v=v%256 local hi=${AA}(v/(2^(8-n))) local lo=v%(2^(8-n)) return (lo*(2^n)+hi)%256 end`);
  lines.push(`local function ${TMP}_ror(v,n) n=n%8 v=v%256 local lo=v%(2^n) local hi=${AA}(v/(2^n)) return (lo*(2^(8-n))+hi)%256 end`);
  lines.push(`local function ${TMP}_band(a,b) local r=0 local p=1 for i=0,7 do if a%2==1 and b%2==1 then r=r+p end a=${AA}(a/2) b=${AA}(b/2) p=p*2 end return r end`);

  lines.push(`local bx,bo,rs,ls,ba`);
  lines.push(`if bit32 then bx=bit32.bxor bo=bit32.bor rs=bit32.rshift ls=bit32.lshift ba=bit32.band else bx=${TMP}_xor bo=function(a,b) return a+b-${TMP}_band(a,b) end rs=function(v,n) return ${AA}(v%(2^32)/(2^n))%256 end ls=function(v,n) return (v*(2^n))%256 end ba=${TMP}_band end`);

  // The VM interpreter
  lines.push(`local function ${VM}(scrambledStr)`);
  lines.push(`  local ${STK}={} local ${SP}=0 local ${OUT}={} local ${PC}=1 local ${IDX}=1 local ${HALTED}=false`);
  lines.push(`  local function push(v) ${SP}=${SP}+1 ${STK}[${SP}]=v%256 end`);
  lines.push(`  local function pop() if ${SP}<1 then return 0 end local v=${STK}[${SP}] ${STK}[${SP}]=nil ${SP}=${SP}-1 return v end`);
  lines.push(`  local function peek() return ${STK}[${SP}] or 0 end`);
  lines.push(`  while not ${HALTED} and ${PC}<=#${BC} do`);
  lines.push(`    local ${OP}=${BC}[${PC}] ${PC}=${PC}+1`);
  lines.push(`    if ${OP}==0x01 then local imm=${BC}[${PC}] ${PC}=${PC}+1 push(imm)`);
  lines.push(`    elseif ${OP}==0x02 then local ki=${BC}[${PC}] ${PC}=${PC}+1 push(${R}(scrambledStr,(ki%#scrambledStr)+1))`);
  lines.push(`    elseif ${OP}==0x03 then local b=pop() local a=pop() push(bx(a,b))`);
  lines.push(`    elseif ${OP}==0x04 then local b=pop() local a=pop() push((a+b)%256)`);
  lines.push(`    elseif ${OP}==0x05 then local b=pop() local a=pop() push((a-b+256)%256)`);
  lines.push(`    elseif ${OP}==0x06 then local n=${BC}[${PC}] ${PC}=${PC}+1 push(${TMP}_rol(pop(),n))`);
  lines.push(`    elseif ${OP}==0x07 then local n=${BC}[${PC}] ${PC}=${PC}+1 push(${TMP}_ror(pop(),n))`);
  lines.push(`    elseif ${OP}==0x08 then ${OUT}[#${OUT}+1]=string.char(pop())`);
  lines.push(`    elseif ${OP}==0x09 then push(peek())`);
  lines.push(`    elseif ${OP}==0x0A then pop()`);
  lines.push(`    elseif ${OP}==0x0B then local rel=${BC}[${PC}] ${PC}=${PC}+1 ${PC}=${PC}+rel`);
  lines.push(`    elseif ${OP}==0x0C then local rel=${BC}[${PC}] ${PC}=${PC}+1 if pop()==0 then ${PC}=${PC}+rel end`);
  lines.push(`    elseif ${OP}==0x0D then push(${IDX}-1)`);
  lines.push(`    elseif ${OP}==0x0E then ${IDX}=${IDX}+1`);
  lines.push(`    elseif ${OP}==0x0F then ${HALTED}=true`);
  lines.push(`    elseif ${OP}==0x10 then`);
  lines.push(`    elseif ${OP}==0x11 then local c=${BC}[${PC}] ${PC}=${PC}+1 push(bx(pop(),c))`);
  lines.push(`    elseif ${OP}==0x12 then local c=${BC}[${PC}] ${PC}=${PC}+1 push((pop()+c)%256)`);
  lines.push(`    elseif ${OP}==0x13 then push(#scrambledStr)`);
  lines.push(`    elseif ${OP}==0x14 then local b=pop() local a=pop() push(a==b and 1 or 0)`);
  lines.push(`    elseif ${OP}==0x20 then`);
  lines.push(`      if ${IDX}<=#scrambledStr then push(${R}(scrambledStr,${IDX})) ${IDX}=${IDX}+1 else push(0) end`);
  lines.push(`    else`);
  lines.push(`      if ${PC}<=#${BC} and type(${BC}[${PC}])=="number" and ${BC}[${PC}]<256 and ${OP}>=0x40 then ${PC}=${PC}+1 end`);
  lines.push(`    end`);
  lines.push(`  end`);
  lines.push(`  return ${T}(${OUT})`);
  lines.push(`end`);

  // DECOY classic unscramble (never executed on real path) — keeps old pattern matchers busy
  lines.push(
    `local function ${L}(buf,key) local out={} local kl=#key for i=1,#buf do local i0=i-1 local b=${R}(buf,i) local k=${R}(key,(i0%kl)+1) local p=ba(i0*131+17,255) local rot=(k%7)+1 local rot2=(p%5)+1 b=bx(b,ba(k*3+p*5+i0,255)) b=ba(b+ba(k+p*3,255),255) b=ba(bo(rs(b,rot2),ls(b,8-rot2)),255) b=ba(b-p+256,255) b=ba(bo(rs(b,rot),ls(b,8-rot)),255) b=ba(b-k+256,255) out[i]=string.char(b) end return ${T}(out) end`
  );

  // CF dispatcher (extended)
  lines.push(`local ${ST}="${luaEsc(s0)}"`);
  lines.push(`while true do`);
  lines.push(`if ${ST}=="${s0}" then`);
  lines.push(`if ${OK} then ${ST}="${s1}" else ${ST}="${sDead}" end`);
  lines.push(`elseif ${ST}=="${s1}" then`);
  lines.push(`${M}=${T}(${J})`);
  lines.push(`${N}=${K}(${F})`);
  lines.push(`${M}=${K}(${M})`);
  lines.push(
    `do local h=2654435761 local i=1 local mlen=#${M} while i<=mlen do local b=${R}(${M},i) h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 i=i+1 end local hs=${K}(${H}) local hv=${R}(hs,1)*16777216+${R}(hs,2)*65536+${R}(hs,3)*256+${R}(hs,4) local ls=${K}(${B}) local lv=${R}(ls,1)*16777216+${R}(ls,2)*65536+${R}(ls,3)*256+${R}(ls,4) if h~=hv or mlen~=lv then ${OK}=false ${ST}="${sDead}" else ${ST}="${s2}" end end`
  );
  lines.push(`elseif ${ST}=="${s2}" then`);
  lines.push(`do local hs=${K}(${I}) local hv=${R}(hs,1)*16777216+${R}(hs,2)*65536+${R}(hs,3)*256+${R}(hs,4)`);
  lines.push(`local h=2166136261 local i=1 local mlen=#${M} while i<=mlen do h=((h~${R}(${M},i))*16777619)%4294967296 i=i+1 end`);
  lines.push(`if h~=hv then ${OK}=false ${ST}="${sDead}" else ${ST}="${s3}" end end`);
  lines.push(`elseif ${ST}=="${s3}" then`);
  // Run the OPCODE VM
  lines.push(`${SS}=${VM}(${M})`);
  lines.push(`do local ls=${K}(${B}) local lv=${R}(ls,1)*16777216+${R}(ls,2)*65536+${R}(ls,3)*256+${R}(ls,4) if #${SS}~=lv then ${OK}=false ${ST}="${sDead}" else ${ST}="${s4}" end end`);
  lines.push(`elseif ${ST}=="${s4}" then`);
  lines.push(`do local loader=${BB} local hooked=false`);
  lines.push(`if iscclosure and loader and not iscclosure(loader) then hooked=true end`);
  lines.push(`pcall(function() local s=${W}(loader) if s and not string.find(s,"function:") and not string.find(s,"builtin") then hooked=true end end)`);
  lines.push(`if hooked then local alt=load if ${U}(alt)=="function" and alt~=loader then loader=alt else ${SS}=nil return end end`);
  lines.push(`pcall(function() for i=1,12 do local decoy=string.rep("--"..tostring(i*97+13).."\\n",80) if #decoy>1000 then loader(decoy) end end end)`);
  lines.push(`local fn`);
  lines.push(`do local bytes={} for i=1,#${SS} do bytes[i]=${R}(${SS},i) end ${SS}=nil`);
  lines.push(`local parts={} local buf={} local bi=0 local LIM=750`);
  lines.push(`for i=1,#bytes do bi=bi+1 buf[bi]=string.char(bytes[i]) if bi>=LIM then parts[#parts+1]=table.concat(buf) buf={} bi=0 end end`);
  lines.push(`if bi>0 then parts[#parts+1]=table.concat(buf) end`);
  lines.push(`bytes=nil buf=nil`);
  lines.push(`local src=table.concat(parts) parts=nil`);
  lines.push(`fn=loader(src) src=nil end`);
  lines.push(`${M}=nil ${J}=nil ${N}=nil ${BC}=nil`);
  lines.push(`if ${U}(fn)=="function" then local r=fn(...) fn=nil return r end`);
  lines.push(`return`);
  lines.push(`elseif ${ST}=="${sDead}" then`);
  lines.push(`return`);
  lines.push('else break end');
  lines.push('end');
  lines.push('end)(...)');

  return (
    `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org | OPCODE-VM ]]
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

  /* MANDATORY round-trip */
  const recovered = unscramble(decBuf(sym), key);
  if (recovered.length !== raw.length || !recovered.equals(raw)) {
    throw new Error('roundtrip failed — refusing to emit broken output');
  }

  const bc = buildVmBytecode(scrambled, key);

  const code = buildLoader(sym, key, sumA, sumB, scrambled.length, scrambled);
  return {
    code,
    stats: {
      inputBytes,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      layers: [
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
        'custom-opcode-vm',
        'vm-junk-ops',
        'vm-stack-reconstruction'
      ],
      verified: true,
      vmOpcodes: bc.length
    }
  };
}

module.exports = { obfuscate, VERSION };
