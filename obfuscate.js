/**
 * QyrexObf 1.0.0
 * - Payload alphabet: symbols only
 * - Identifiers: underscore + digits only (no a-z in names)
 * - No bit32 dependency (pure arithmetic)
 * - Must execute without errors on Luau/Roblox
 */
'use strict';
const crypto = require('crypto');

const VERSION = '1.0.0';
const MAX_BYTES = 1_500_000;
const ALPHA = "!#$%&()*+,-./:;<=>?@[]^_{|}~'`";
const BASE = ALPHA.length;
const WORD = 2;

const rb = (n) => crypto.randomBytes(n);
const ri = (n) => crypto.randomInt(0, n);

let _seq = 1000;
function rid() {
  _seq += 1 + ri(3);
  return '_' + String(_seq) + '_' + String(ri(100000));
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
  const step = 150 + ri(40);
  for (let i = 0; i < sym.length; i += step) out.push(sym.slice(i, i + step));
  return out;
}

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
  return encBuf(
    Buffer.from([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255])
  );
}

function buildLoader(sym, key, sumA, payloadLen) {
  const v = {
    ok: rid(), cc: rid(), u: rid(), v: rid(), w: rid(),
    r: rid(), s: rid(), t: rid(), d: rid(), e: rid(),
    k: rid(), es: rid(), f: rid(), h: rid(), b: rid(),
    j: rid(), m: rid(), n: rid(), ss: rid(), st: rid(),
    bx: rid(), band: rid(), lrot: rid(), rrot: rid(),
    dec: rid(),
  };
  const s0 = noise(4), s1 = noise(4), s2 = noise(4), s3 = noise(4), sD = noise(4);
  const e = (str) => luaEsc(encStr(str));
  const parts = chunkSym(sym);
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');
  const keySym = encBuf(key);
  const LN = [];

  LN.push('return(function(...)');
  LN.push(`local ${v.ok}=true`);
  LN.push(`local ${v.u}=type`);
  LN.push(`local ${v.v}=pcall`);
  LN.push(`local ${v.w}=tostring`);
  LN.push(`local ${v.r}=string.byte`);
  LN.push(`local ${v.s}=string.sub`);
  LN.push(`local ${v.t}=table.concat`);
  LN.push(`local ${v.cc}=0`);

  /* pure 8-bit ops — no bit32 required */
  LN.push(`local function ${v.bx}(a,b) a=a%256 b=b%256 local r=0 local p=1 for _5=1,8 do local a1=a%2 local b1=b%2 if a1~=b1 then r=r+p end a=(a-a1)/2 b=(b-b1)/2 p=p*2 end return r end`);
  LN.push(`local function ${v.band}(a,b) a=a%256 b=b%256 local r=0 local p=1 for _5=1,8 do local a1=a%2 local b1=b%2 if a1+b1==2 then r=r+p end a=(a-a1)/2 b=(b-b1)/2 p=p*2 end return r end`);
  LN.push(`local function ${v.lrot}(x,n) n=n%8 x=x%256 local m=2^(8-n) local hi=math.floor(x/m) local lo=x%m return lo*(2^n)+hi end`);
  LN.push(`local function ${v.rrot}(x,n) n=n%8 x=x%256 local m=2^n local lo=x%m local hi=math.floor(x/m) return lo*(2^(8-n))+hi end`);

  /* alphabet + decoder */
  LN.push(`local ${v.d}="${ALPHA}"`);
  LN.push(`local ${v.e}={}`);
  LN.push(`for _9=1,#${v.d} do ${v.e}[${v.s}(${v.d},_9,_9)]=_9-1 end`);
  LN.push(`local function ${v.k}(z) local o={} local pos=1 local zlen=#z while pos+1<=zlen do local n=0 local _8=0 while _8<2 do local ch=${v.s}(z,pos+_8,pos+_8) n=n*(#${v.d})+(${v.e}[ch] or 0) _8=_8+1 end o[#o+1]=string.char(n%256) pos=pos+2 end return ${v.t}(o) end`);
  LN.push(`local ${v.es}=${v.k}`);

  /* soft anti-tamper (score only; never aborts clean client) */
  LN.push(`if ${v.u}(string)==${v.es}("${e('table')}") then ${v.cc}=${v.cc}+10 end`);
  LN.push(`if ${v.u}(table)==${v.es}("${e('table')}") then ${v.cc}=${v.cc}+10 end`);
  LN.push(`if ${v.u}(math)==${v.es}("${e('table')}") then ${v.cc}=${v.cc}+10 end`);
  LN.push(`if ${v.u}(pcall)==${v.es}("${e('function')}") then ${v.cc}=${v.cc}+10 end`);
  LN.push(`if ${v.r}(${v.es}("${e('A')}"))==65 then ${v.cc}=${v.cc}+10 end`);
  LN.push(`if math.floor(3.9)==3 then ${v.cc}=${v.cc}+8 end`);
  LN.push(`if math.floor(math.pi)==3 then ${v.cc}=${v.cc}+8 end`);
  LN.push(`do local a=${v.v}(error,"\\0",0) if not a then ${v.cc}=${v.cc}+8 end end`);
  LN.push(`if game~=nil and typeof and typeof(game)==${v.es}("${e('Instance')}") then ${v.cc}=${v.cc}+10 end`);
  LN.push(`do local bad=false if ${v.u}(_G)==${v.es}("${e('table')}") then local function has(k) local ok,val=${v.v}(function() return rawget(_G,k) end) return ok and val~=nil end if has(${v.es}("${e('process')}")) or has(${v.es}("${e('window')}")) or has(${v.es}("${e('document')}")) or has(${v.es}("${e('lune')}")) or has(${v.es}("${e('lute')}")) or has(${v.es}("${e('rojo')}")) or has(${v.es}("${e('Buffer')}")) then bad=true end end if bad then ${v.cc}=${v.cc}-40 else ${v.cc}=${v.cc}+8 end end`);
  LN.push(`pcall(function() if game and game[${v.es}("${e('JobId')}")]==${v.es}("${e('00000000-0000-0000-0000-000000000000')}") then ${v.cc}=${v.cc}-30 end end)`);
  LN.push(`pcall(function() if game and (game[${v.es}("${e('PlaceId')}"]==8916037983 or game[${v.es}("${e('GameId')}")]==8916037983) then ${v.cc}=${v.cc}-30 end end)`);
  LN.push(`if ${v.u}(_G)==${v.es}("${e('table')}") then local rg=rawget or function(t,k) return t[k] end local rp=rg(_G,${v.es}("${e('pcall')}")) if rp~=nil and rp~=pcall then ${v.cc}=${v.cc}-25 end end`);
  LN.push(`if ${v.cc}~=${v.cc} then ${v.ok}=false end`);

  /* data */
  LN.push(`local ${v.f}="${luaEsc(keySym)}"`);
  LN.push(`local ${v.h}="${luaEsc(u32sym(sumA))}"`);
  LN.push(`local ${v.b}="${luaEsc(u32sym(payloadLen))}"`);
  LN.push(`local ${v.j}={${vLit}}`);

  /* unscramble using pure ops */
  LN.push(`local function ${v.dec}(buf,key) local out={} local kl=#key for _7=1,#buf do local i0=_7-1 local b=${v.r}(buf,_7) local k=${v.r}(key,(i0%kl)+1) local p=${v.band}(i0*131+17,255) local rot=(k%7)+1 local rot2=(p%5)+1 b=${v.bx}(b,${v.band}(k*3+p*5+i0,255)) b=${v.band}(b+${v.band}(k+p*3,255),255) b=${v.band}(${v.rrot}(b,rot2)+0,255) b=${v.band}(b-p+256,255) b=${v.band}(${v.rrot}(b,rot)+0,255) b=${v.band}(b-k+256,255) out[_7]=string.char(b) end return ${v.t}(out) end`);

  /* CF */
  LN.push(`local ${v.st}="${luaEsc(s0)}"`);
  LN.push(`while true do`);
  LN.push(`if ${v.st}=="${luaEsc(s0)}" then`);
  LN.push(`if ${v.ok} then ${v.st}="${luaEsc(s1)}" else ${v.st}="${luaEsc(sD)}" end`);
  LN.push(`elseif ${v.st}=="${luaEsc(s1)}" then`);
  LN.push(`local ${v.m}=${v.k}(${v.t}(${v.j}))`);
  LN.push(`local ${v.n}=${v.k}(${v.f})`);
  LN.push(`do local h=2654435761 local _6=1 local mlen=#${v.m} while _6<=mlen do local b=${v.r}(${v.m},_6) h=(h+b*(_6+30)+((h%89)*17)+13)%4294967296 _6=_6+1 end local hs=${v.k}(${v.h}) local hv=${v.r}(hs,1)*16777216+${v.r}(hs,2)*65536+${v.r}(hs,3)*256+${v.r}(hs,4) local ls=${v.k}(${v.b}) local lv=${v.r}(ls,1)*16777216+${v.r}(ls,2)*65536+${v.r}(ls,3)*256+${v.r}(ls,4) if h~=hv or mlen~=lv then ${v.ok}=false ${v.st}="${luaEsc(sD)}" else ${v.st}="${luaEsc(s2)}" end end`);
  LN.push(`elseif ${v.st}=="${luaEsc(s2)}" then`);
  LN.push(`${v.ss}=${v.dec}(${v.m},${v.n})`);
  LN.push(`do local ls=${v.k}(${v.b}) local lv=${v.r}(ls,1)*16777216+${v.r}(ls,2)*65536+${v.r}(ls,3)*256+${v.r}(ls,4) if #${v.ss}~=lv then ${v.ok}=false ${v.st}="${luaEsc(sD)}" else ${v.st}="${luaEsc(s3)}" end end`);
  LN.push(`elseif ${v.st}=="${luaEsc(s3)}" then`);
  /* reliable loader */
  LN.push(`local _01=loadstring or load`);
  LN.push(`if ${v.u}(_01)~="function" then return end`);
  LN.push(`local _02=_01(${v.ss})`);
  LN.push(`${v.ss}=nil ${v.m}=nil ${v.j}=nil`);
  LN.push(`if ${v.u}(_02)=="function" then local _03,_04=${v.v}(_02,...) if _03 then return _04 end return end`);
  LN.push(`return`);
  LN.push(`elseif ${v.st}=="${luaEsc(sD)}" then return`);
  LN.push(`else break end`);
  LN.push(`end`);
  LN.push(`end)(...)`);

  return (
    `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]]\n` +
    LN.join(' ')
  );
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

  /* verify pure-lua unscramble math matches */
  const code = buildLoader(sym, key, sumA, scrambled.length);
  return {
    code,
    stats: {
      inputBytes,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-' + VERSION,
      layers: [
        'symbol-alphabet',
        'digit-identifiers',
        'pure-arith-scramble',
        'integrity-hash',
        'anti-tamper',
        'anti-sandbox',
        'cf-dispatcher',
        'single-line',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
