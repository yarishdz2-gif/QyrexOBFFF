/**
 * QyrexObf 1.0.0 — single-line, symbol-alphabet payload, anti-tamper
 * Version MUST remain 1.0.0
 */
'use strict';
const crypto = require('crypto');

const VERSION = '1.0.0';
const MAX_BYTES = 1_500_000;

/* User alphabet — symbols only, single-byte ASCII (Luau-safe) */
const ALPHA = "!#$%&()*+,-./:;<=>?@[]^_{|}~'`";
const BASE = ALPHA.length;
const WORD = 2;

const rb = (n) => crypto.randomBytes(n);
const ri = (n) => crypto.randomInt(0, n);

function rid() {
  const n = 5 + ri(4);
  const c = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  let s = '_';
  for (let i = 0; i < n; i++) s += c[ri(c.length)];
  return s;
}

function encByte(b) {
  let n = b & 255, w = '';
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
    for (let i = 0; i < WORD; i++) n = n * BASE + (map[sym[pos + i]] || 0);
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
function chunkSym(sym) {
  const out = [];
  const step = 160 + ri(50);
  for (let i = 0; i < sym.length; i += step) out.push(sym.slice(i, i + step));
  return out;
}

/* scramble matching Lua decoder exactly (bit32 ops) */
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
function checksum32(buf) {
  let h = 2654435761 >>> 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] & 255;
    const idx = i + 1;
    h = (h + ((b * (idx + 30)) >>> 0) + ((((h % 89) * 17) + 13) >>> 0)) >>> 0;
  }
  return h >>> 0;
}

function u32sym(n) {
  return encBuf(Buffer.from([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]));
}

function buildLoader(sym, key, sumA, payloadLen) {
  const A = rid(), B = rid(), C = rid(), D = rid(), E = rid();
  const F = rid(), G = rid(), H = rid(), I = rid(), J = rid();
  const K = rid(), L = rid(), M = rid(), N = rid(), O = rid();
  const P = rid(), Q = rid(), R = rid(), S = rid(), T = rid();
  const U = rid(), V = rid(), W = rid(), X = rid();
  const OK = rid(), CC = rid(), SS = rid(), ES = rid();
  const ST = rid();
  const s0 = noise(4), s1 = noise(4), s2 = noise(4), s3 = noise(4), sDead = noise(4);

  const e = (s) => luaEsc(encStr(s));
  const parts = chunkSym(sym);
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');
  const keySym = encBuf(key);

  const LN = [];
  LN.push('return(function(...)');
  LN.push(`local ${OK}=true`);
  LN.push(`local ${U}=type`);
  LN.push(`local ${V}=pcall`);
  LN.push(`local ${W}=tostring`);
  LN.push(`local ${R}=string.byte`);
  LN.push(`local ${S}=string.sub`);
  LN.push(`local ${T}=table.concat`);
  LN.push(`local ${CC}=0`);
  LN.push(`local ${D}="${ALPHA}"`);
  LN.push(`local ${E}={}`);
  LN.push(`for i=1,#${D} do ${E}[${S}(${D},i,i)]=i-1 end`);
  LN.push(`local function ${K}(z)local o={}local pos=1 local zlen=#z while pos+1<=zlen do local n=0 local i=0 while i<2 do local ch=${S}(z,pos+i,pos+i)n=n*(#${D})+(${E}[ch] or 0)i=i+1 end o[#o+1]=string.char(n%256)pos=pos+2 end return ${T}(o)end`);
  LN.push(`local ${ES}=${K}`);

  /* anti-tamper — all sensitive strings via ES */
  LN.push(`if ${U}(string)==${ES}("${e('table')}")and ${U}(${R})==${ES}("${e('function')}")then ${CC}=${CC}+15 end`);
  LN.push(`if ${U}(table)==${ES}("${e('table')}")then ${CC}=${CC}+10 end`);
  LN.push(`if ${U}(math)==${ES}("${e('table')}")then ${CC}=${CC}+10 end`);
  LN.push(`if ${U}(pcall)==${ES}("${e('function')}")and ${U}(type)==${ES}("${e('function')}")then ${CC}=${CC}+12 end`);
  LN.push(`if ${R}(${ES}("${e('A')}"))==65 then ${CC}=${CC}+10 end`);
  LN.push(`if math.floor(3.9)==3 then ${CC}=${CC}+8 end`);
  LN.push(`if math.floor(math.pi)==3 then ${CC}=${CC}+8 end`);
  LN.push(`do local a=${V}(error,"\\0",0)if not a then ${CC}=${CC}+8 end end`);
  LN.push(`if game~=nil then if typeof and typeof(game)==${ES}("${e('Instance')}")then ${CC}=${CC}+10 else if ${U}(game)==${U}({})then ${CC}=${CC}-35 end end end`);
  LN.push(`do local bad=false if ${U}(_G)==${ES}("${e('table')}")then local function has(k)local ok,v=${V}(function()return rawget(_G,k)end)return ok and v~=nil end if has(${ES}("${e('process')}"))or has(${ES}("${e('window')}"))or has(${ES}("${e('document')}"))or has(${ES}("${e('lune')}"))or has(${ES}("${e('lute')}"))or has(${ES}("${e('rojo')}"))or has(${ES}("${e('Buffer')}"))then bad=true end end if bad then ${CC}=${CC}-50 else ${CC}=${CC}+8 end end`);
  LN.push(`pcall(function()if game and game[${ES}("${e('JobId')}")]==${ES}("${e('00000000-0000-0000-0000-000000000000')}")then ${CC}=${CC}-40 end end)`);
  LN.push(`pcall(function()if game and(game[${ES}("${e('PlaceId')}"]==8916037983 or game[${ES}("${e('GameId')}")]==8916037983)then ${CC}=${CC}-40 end end)`);
  LN.push(`if ${U}(_G)==${ES}("${e('table')}")then local rg=rawget or function(t,k)return t[k]end local rp=rg(_G,${ES}("${e('pcall')}"))if rp~=nil and rp~=pcall then ${CC}=${CC}-30 end end`);
  LN.push(`if rawequal and rawequal(pcall,pcall)then ${CC}=${CC}+6 end`);
  /* score advisory only — never blocks */
  LN.push(`if ${CC}~=${CC} then ${OK}=false end`);

  LN.push(`local ${F}="${luaEsc(keySym)}"`);
  LN.push(`local ${H}="${luaEsc(u32sym(sumA))}"`);
  LN.push(`local ${B}="${luaEsc(u32sym(payloadLen))}"`);
  LN.push(`local ${J}={${vLit}}`);

  /* unscramble = Node algorithm via bit32 */
  LN.push(`local function ${L}(buf,key)local out={}local kl=#key local bx,bo,rs,ls,ba=bit32.bxor,bit32.bor,bit32.rshift,bit32.lshift,bit32.band for i=1,#buf do local i0=i-1 local b=${R}(buf,i)local k=${R}(key,(i0%kl)+1)local p=ba(i0*131+17,255)local rot=(k%7)+1 local rot2=(p%5)+1 b=bx(b,ba(k*3+p*5+i0,255))b=ba(b+ba(k+p*3,255),255)b=ba(bo(rs(b,rot2),ls(b,8-rot2)),255)b=ba(b-p+256,255)b=ba(bo(rs(b,rot),ls(b,8-rot)),255)b=ba(b-k+256,255)out[i]=string.char(b)end return ${T}(out)end`);

  LN.push(`local ${ST}="${luaEsc(s0)}"`);
  LN.push(`while true do`);
  LN.push(`if ${ST}=="${luaEsc(s0)}"then`);
  LN.push(`if ${OK} then ${ST}="${luaEsc(s1)}"else ${ST}="${luaEsc(sDead)}"end`);
  LN.push(`elseif ${ST}=="${luaEsc(s1)}"then`);
  LN.push(`local ${M}=${K}(${T}(${J}))`);
  LN.push(`local ${N}=${K}(${F})`);
  LN.push(`do local h=2654435761 local i=1 local mlen=#${M} while i<=mlen do local b=${R}(${M},i)h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 i=i+1 end local hs=${K}(${H})local hv=${R}(hs,1)*16777216+${R}(hs,2)*65536+${R}(hs,3)*256+${R}(hs,4)local ls=${K}(${B})local lv=${R}(ls,1)*16777216+${R}(ls,2)*65536+${R}(ls,3)*256+${R}(ls,4)if h~=hv or mlen~=lv then ${OK}=false ${ST}="${luaEsc(sDead)}"else ${ST}="${luaEsc(s2)}"end end`);
  LN.push(`elseif ${ST}=="${luaEsc(s2)}"then`);
  LN.push(`${SS}=${L}(${M},${N})`);
  LN.push(`do local ls=${K}(${B})local lv=${R}(ls,1)*16777216+${R}(ls,2)*65536+${R}(ls,3)*256+${R}(ls,4)if #${SS}~=lv then ${OK}=false ${ST}="${luaEsc(sDead)}"else ${ST}="${luaEsc(s3)}"end end`);
  LN.push(`elseif ${ST}=="${luaEsc(s3)}"then`);
  LN.push(`local loader=(rawget(_G,string.char(108,111,97,100,115,116,114,105,110,103))or rawget(_G,string.char(108,111,97,100)))`);
  LN.push(`if iscclosure and loader and not iscclosure(loader)then loader=rawget(_G,string.char(108,111,97,100))or loader end`);
  LN.push(`pcall(function()for di=1,10 do local d=string.rep("--"..tostring(di*41).."\\n",80)if #d>1000 and loader then loader(d)end end end)`);
  /* reconstruct via char table so static file has no plaintext payload */
  LN.push(`do local bytes={}for i=1,#${SS} do bytes[i]=${R}(${SS},i)end ${SS}=nil local parts={}local buf={}local bi=0 for i=1,#bytes do bi=bi+1 buf[bi]=string.char(bytes[i])if bi>=600 then parts[#parts+1]=${T}(buf)buf={}bi=0 end end if bi>0 then parts[#parts+1]=${T}(buf)end local src=${T}(parts)parts=nil buf=nil bytes=nil local fn=loader(src)src=nil ${M}=nil ${J}=nil if ${U}(fn)=="function"then local r=fn(...)fn=nil return r end end`);
  LN.push(`return`);
  LN.push(`elseif ${ST}=="${luaEsc(sDead)}"then return`);
  LN.push(`else break end end`);
  LN.push(`end)(...)`);

  /* SINGLE LINE body after header */
  const header = `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]]\n`;
  return header + LN.join(' ');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const inputBytes = Buffer.byteLength(src, 'utf8');
  if (inputBytes > MAX_BYTES) throw new Error('Too large');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(32 + ri(16));
  const scrambled = scramble(raw, key);
  const sumA = checksum32(scrambled);
  const sym = encBuf(scrambled);

  const recovered = unscramble(decBuf(sym), key);
  if (recovered.length !== raw.length || !recovered.equals(raw)) {
    throw new Error('roundtrip failed');
  }

  const code = buildLoader(sym, key, sumA, scrambled.length);
  return {
    code,
    stats: {
      inputBytes,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      layers: [
        'symbol-alphabet',
        'multi-round-scramble',
        'integrity-hash',
        'cf-dispatcher',
        'encoded-anti-tamper',
        'anti-hook',
        'decoy-flood',
        'char-reassembly',
        'single-line',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
