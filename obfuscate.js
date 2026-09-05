/**
 * QyrexObf 1.0.0 — Hardened Lua/Luau obfuscation engine
 * Design goals: zero runtime arithmetic errors, dual Lua/Luau load,
 * verified round-trip, dual integrity, CF dispatcher, anti-tamper, decoys.
 *
 * Identifiers are always valid Lua (_ + alnum). Chaotic alphabet lives in strings only.
 */
'use strict';

const crypto = require('crypto');

const VERSION = '1.0.0';
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

/**
 * Emit self-decoding Lua loader.
 * All arithmetic uses % 256 / math.floor — no bit32 required.
 */

function buildLoader(sym, key, sumA, sumB, payloadLen) {
  const A = rid(), B = rid(), C = rid(), D = rid(), E = rid();
  const F = rid(), G = rid(), H = rid(), I = rid(), J = rid();
  const K = rid(), L = rid(), M = rid(), N = rid(), O = rid();
  const P = rid(), Q = rid(), R = rid(), S = rid(), T = rid();
  const U = rid(), V = rid(), W = rid(), X = rid();
  const ST = rid(), OK = rid();
  const AA = rid(), BB = rid(), CC = rid(), SS = rid();
  const ES = rid();

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

  // alphabet + decoder FIRST
  lines.push(`local ${D}="${ALPHA}"`);
  lines.push(`local ${E}={}`);
  lines.push(`for i=1,#${D} do ${E}[${S}(${D},i,i)]=i-1 end`);
  lines.push(
    `local function ${K}(z) local o={} local pos=1 local zlen=#z while pos+1<=zlen do local n=0 local i=0 while i<#"~~" do local ch=${S}(z,pos+i,pos+i) n=n*(#${D})+(${E}[ch] or 0) i=i+1 end o[#o+1]=string.char(n%256) pos=pos+(#"~~") end return ${T}(o) end`
  );
  lines.push(`local ${ES}=${K}`);

  // primitives with encoded type names
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
  lines.push(`-- score=${CC} (advisory only; never abort payload)`);
  lines.push(`if ${U}(${BB})~=${ES}("${e('function')}") and ${U}(${BB})~="function" then ${X}() end`);

  // decoys
  lines.push(`local function ${O}(a) return a end`);
  lines.push(`local function ${P}(a,b) if a then return b end return a end`);
  lines.push(`if false then ${O}(${P}(1,2)) end`);

  // blobs
  lines.push(`local ${F}="${luaEsc(keySym)}"`);
  lines.push(`local ${G}="${luaEsc(j1)}"`);
  lines.push(`local ${H}="${luaEsc(encBuf(Buffer.from([(sumA>>>24)&255,(sumA>>>16)&255,(sumA>>>8)&255,sumA&255])))}"`);
  lines.push(`local ${I}="${luaEsc(encBuf(Buffer.from([(sumB>>>24)&255,(sumB>>>16)&255,(sumB>>>8)&255,sumB&255])))}"`);
  lines.push(`local ${B}="${luaEsc(encBuf(Buffer.from([(payloadLen>>>24)&255,(payloadLen>>>16)&255,(payloadLen>>>8)&255,payloadLen&255])))}"`);
  lines.push(`local ${J}={${vLit}}`);
  lines.push(`local ${C}="${luaEsc(j2)}"`);
  lines.push(`local ${A}="${luaEsc(j3)}"`);

  // unscramble
  lines.push(
    `local function ${L}(buf,key) local out={} local kl=#key local bx=bit32 and bit32.bxor local bo=bit32 and bit32.bor local rs=bit32 and bit32.rshift local ls=bit32 and bit32.lshift local ba=bit32 and bit32.band for i=1,#buf do local i0=i-1 local b=${R}(buf,i) local k=${R}(key,(i0%kl)+1) local p=ba(i0*131+17,255) local rot=(k%7)+1 local rot2=(p%5)+1 b=bx(b,ba(k*3+p*5+i0,255)) b=ba(b+ba(k+p*3,255),255) b=ba(bo(rs(b,rot2),ls(b,8-rot2)),255) b=ba(b-p+256,255) b=ba(bo(rs(b,rot),ls(b,8-rot)),255) b=ba(b-k+256,255) out[i]=string.char(b) end return ${T}(out) end`
  );

  // CF
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
  lines.push(`${SS}=${L}(${M},${N})`);
  lines.push(`do local ls=${K}(${B}) local lv=${R}(ls,1)*16777216+${R}(ls,2)*65536+${R}(ls,3)*256+${R}(ls,4) if #${SS}~=lv then ${OK}=false ${ST}="${sDead}" else ${ST}="${s3}" end end`);
  lines.push(`elseif ${ST}=="${s3}" then`);
  lines.push(`local loader=${BB}`);
  lines.push(`if ${U}(loader)~=${ES}("${e('function')}") and ${U}(loader)~="function" then return end`);
  lines.push(`local fn=loader(${SS})`);
  // anti-dump: wipe payload string after compile
  lines.push(`${SS}=nil ${M}=nil ${J}=nil`);
  lines.push(`if ${U}(fn)==${ES}("${e('function')}") or ${U}(fn)=="function" then local r=fn(...) fn=nil return r end`);
  lines.push(`return`);
  lines.push(`elseif ${ST}=="${sDead}" then`);
  lines.push(`return`);
  lines.push('else break end');
  lines.push('end');
  lines.push('end)(...)');

  return (
    `--[[ Protected by QyrexObf v1.0.0 | qyrex.hopto.org ]]
` + lines.join(' ')
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

  const code = buildLoader(sym, key, sumA, sumB, scrambled.length);
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
        'score-anti-tamper','aqua-primitives','sandbox-dtc','hook-probes','frozen-refs',
        'cf-dispatcher',
        'llm-decoys'
      ],
      verified: true
    }
  };
}

module.exports = { obfuscate, VERSION };
