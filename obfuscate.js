/**
 * QyrexObf 1.0.2 — Hercules + Prometheus + MoonSec + IronBrew2 patterns
 * Decimal affine + IB keystream XOR + soft AT + CF bounce + double nest
 * Luau/Roblox stable (no hardlocks, no dolocal).
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.2';
const ri = (n) => crypto.randomInt(0, n);
const rb = (n) => crypto.randomBytes(n);
const RES = new Set([
  'and','break','do','else','elseif','end','false','for','function','goto',
  'if','in','local','nil','not','or','repeat','return','then','true','until','while',
]);
function rid() {
  const L = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let o;
  do {
    o = 'q';
    for (let i = 0; i < 6 + ri(5); i++) o += L[ri(L.length)];
  } while (RES.has(o));
  return o;
}

function modInv(a) {
  for (let x = 1; x < 256; x++) if (((a * x) % 256 + 256) % 256 === 1) return x;
  throw new Error('key');
}

/** IronBrew-style pure arithmetic XOR (byte) */
function xorByte(a, b) {
  a &= 255; b &= 255;
  let p = 1, c = 0;
  while (a > 0 && b > 0) {
    const ra = a % 2, rb = b % 2;
    if (ra !== rb) c += p;
    a = (a - ra) / 2;
    b = (b - rb) / 2;
    p *= 2;
  }
  if (a < b) a = b;
  while (a > 0) {
    const ra = a % 2;
    if (ra > 0) c += p;
    a = (a - ra) / 2;
    p *= 2;
  }
  return c & 255;
}

function streamXor(buf, table) {
  const out = Buffer.alloc(buf.length);
  const L = table.length;
  for (let i = 0; i < buf.length; i++) out[i] = xorByte(buf[i], table[i % L]);
  return out;
}

function decEnc(buf, a, b) {
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    out += String((a * buf[i] + b + (i % 251)) % 256).padStart(3, '0');
  }
  return out;
}
function decDec(d, a, b) {
  const inv = modInv(a);
  const out = Buffer.alloc(d.length / 3);
  for (let i = 0, j = 0; i < d.length; i += 3, j++) {
    const y = Number(d.slice(i, i + 3));
    const z = ((y - b - (j % 251)) % 256 + 256) % 256;
    out[j] = (inv * z) % 256;
  }
  return out;
}
function hash32(buf) {
  let h = 216613;
  for (let i = 0; i < buf.length; i++) h = (h * 257 + buf[i] + 97) % 1000003;
  return h;
}
function chunkDec(d) {
  const out = [];
  let p = 0;
  while (p < d.length) {
    const room = 72 + ri(84);
    const size = Math.max(3, room - (room % 3));
    out.push(d.slice(p, p + size));
    p += size;
  }
  return out;
}

function opaqueTrue() {
  const n = 10 + ri(90);
  const a = 1 + ri(40);
  const b = a + 1 + ri(40);
  const choices = [`${n}==${n}`, `not (${n}~=${n})`, `${n}>=${n}`, `${a}+${b - a}==${b}`, `true`];
  return choices[ri(choices.length)];
}
function opaqueFalse() {
  const n = 10 + ri(90);
  const a = 1 + ri(40);
  const b = a + 1 + ri(40);
  const choices = [`${n}~=${n}`, `${n}>${n}`, `false`, `${n}%${n}~=0`];
  return choices[ri(choices.length)];
}

function emitGarbage(L, count) {
  for (let i = 0; i < count; i++) {
    const v = rid();
    const kind = ri(5);
    if (kind === 0) L.push(`local ${v}=${1 + ri(99)}; `);
    else if (kind === 1) L.push(`if ${opaqueFalse()} then local ${v}=${1 + ri(50)} end; `);
    else if (kind === 2) L.push(`for ${v}=1,${1 + ri(2)} do local _=${ri(20)} end; `);
    else if (kind === 3) L.push(`do local ${v}=${ri(100)}; ${v}=${v}+0 end; `);
    else {
      // IronBrew Bounce-style: fake branch that always continues
      L.push(`if ${opaqueTrue()} then local ${v}=${ri(10)} else local ${v}=${ri(10)}+1 end; `);
    }
  }
}

function emitAntiTamper(V, L) {
  const S = V[9], pcall = V[8], type = V[5], str = V[6];
  L.push(`local ${V[25]}='QyrexObf v${VERSION} | IronBrew2-fused | qyrex.hopto.org'; `);
  L.push(`local ${V[10]}=false; local ${V[21]}=${pcall}(function() ${V[10]}=true end) and ${V[10]}; if not ${V[21]} then ${S}=${S}-12 end; `);
  L.push(`${pcall}(function() `);
  L.push(`if ${type}(assert)~='function' or ${type}(error)~='function' or ${type}(pcall)~='function' or ${type}(xpcall)~='function' then ${S}=${S}-10 end; `);
  L.push(`if ${type}(type)~='function' or ${type}(tostring)~='function' or ${type}(tonumber)~='function' then ${S}=${S}-8 end; `);
  L.push(`if ${type}(rawget)~='function' or ${type}(rawset)~='function' or ${type}(rawequal)~='function' then ${S}=${S}-8 end; `);
  L.push(`if ${type}(string)~='table' or ${type}(table)~='table' or ${type}(math)~='table' then ${S}=${S}-10 end; `);
  L.push(`if ${type}(${str}.byte)~='function' or ${type}(${str}.char)~='function' or ${type}(${str}.sub)~='function' then ${S}=${S}-8 end; `);
  L.push(`if ${str}.byte('A')~=65 or ${str}.char(66)~='B' then ${S}=${S}-8 end; `);
  L.push(`if math.floor(3.9)~=3 or math.abs(-2)~=2 then ${S}=${S}-6 end; `);
  L.push(`if rawequal and not rawequal(pcall,pcall) then ${S}=${S}-6 end; `);
  L.push(`end); `);
  L.push(`${pcall}(function() local ok=${pcall}(function() return (1-('x')) end); if ok then ${S}=${S}-8 end end); `);
  L.push(`${pcall}(function() local ok=${pcall}(error,'\\0',0); if ok then ${S}=${S}-10 end end); `);
  for (let i = 0; i < 4; i++) L.push(`${pcall}(function() if not (${opaqueTrue()}) then ${S}=${S}-6 end end); `);
  for (let i = 0; i < 3; i++) L.push(`${pcall}(function() if (${opaqueFalse()}) then ${S}=${S}-6 end end); `);
  L.push(`${pcall}(function() local t=${type}(game); if t=='userdata' or t=='table' then ${S}=${S}+1 end; if ${type}(_G)=='table' then ${S}=${S}+1 end end); `);
  L.push(`${pcall}(function() if typeof and game~=nil and typeof(game)=='Instance' then ${S}=${S}+1 end end); `);
  L.push(`${pcall}(function() if game and type(game)=='table' then ${S}=${S}-8 end end); `);
  L.push(`${pcall}(function() if game and game.JobId=='00000000-0000-0000-0000-000000000000' then ${S}=${S}-10 end end); `);
  L.push(`${pcall}(function() if game and (game.PlaceId==8916037983 or game.GameId==8916037983) then ${S}=${S}-10 end end); `);
  L.push(`${pcall}(function() if getmetatable and getmetatable(_G)~=nil then ${S}=${S}-5 end end); `);
  L.push(`${pcall}(function() if debug and debug.gethook then local ok,h=${pcall}(debug.gethook); if ok and h~=nil then ${S}=${S}-8 end end end); `);
  L.push(`${pcall}(function() if iscclosure and loadstring and not iscclosure(loadstring) then ${S}=${S}-5 end end); `);
  L.push(`${pcall}(function() if hookfunction or hookfunc or replaceclosure then ${S}=${S}-4 end end); `);
  L.push(`${pcall}(function() if getgc and getreg then ${S}=${S}-2 end end); `);
  const safeBad = ['process','lune','lute','window','document','Buffer','navigator','globalThis','__dirname','XMLHttpRequest','setTimeout','wally','rojo','selene','Deno','lemur','jsdom','love'];
  L.push(`${pcall}(function() local function has(k) local ok,v=${pcall}(function() return rawget(_G,k) end); return ok and v~=nil end; if ${safeBad.map((k) => `has('${k}')`).join(' or ')} then ${S}=${S}-14 end end); `);
  L.push(`${pcall}(function() local t={}; local k=tostring(t); if _G[k]~=nil then ${S}=${S}-8 end end); `);
  L.push(`${pcall}(function() if getfenv then local e=getfenv(0); if type(e)~='table' then ${S}=${S}-3 end end end); `);
  L.push(`${pcall}(function() if game and game.GetService then local ok,s=${pcall}(function() return game:GetService('RunService') end); if ok and s and typeof and typeof(s)=='Instance' then ${S}=${S}+1 end end end); `);
  emitGarbage(L, 6);
}

function buildDecimalLoader(decimal, a, b, expectedHash, sourceLen, xorTable) {
  const V = Array.from({ length: 28 }, rid);
  const parts = chunkDec(decimal);
  const payloadTable = parts.map((p) => JSON.stringify(p)).join(',');
  const xorLit = '{' + [...xorTable].join(',') + '}';
  const L = [];
  L.push(`--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]] `);
  L.push('return(function(...) ');
  L.push(`local ${V[0]}={${payloadTable}}; `);
  L.push(`local ${V[1]}=${sourceLen}; local ${V[2]}=${a}; local ${V[3]}=${b}; local ${V[4]}=${expectedHash}; `);
  L.push(`local ${V[5]}=type; local ${V[6]}=string; local ${V[7]}=table; local ${V[8]}=pcall; local ${V[9]}=0; `);
  L.push(`local ${V[26]}=${xorLit}; local ${V[27]}=#${V[26]}; `);

  emitAntiTamper(V, L);
  emitGarbage(L, 4);

  // IronBrew pure XOR helper (runtime)
  L.push(`local function ${V[10]}(a,b) a=a%256; b=b%256; local p,c=1,0; while a>0 and b>0 do local ra,rb=a%2,b%2; if ra~=rb then c=c+p end; a,b,p=(a-ra)/2,(b-rb)/2,p*2 end; if a<b then a=b end; while a>0 do local ra=a%2; if ra>0 then c=c+p end; a,p=(a-ra)/2,p*2 end; return c end; `);

  L.push(`local ${V[11]}=1; while ((${V[2]}*${V[11]})%256)~=1 do ${V[11]}=${V[11]}+1; if ${V[11]}>255 then return end end; `);
  L.push(`local ${V[12]}=${V[7]}.concat(${V[0]}); ${V[0]}=nil; if #${V[12]}~=${V[1]}*3 then return end; `);
  L.push(`local ${V[13]}={}; local ${V[14]}=1; `);
  L.push(`for ${V[15]}=1,#${V[12]},3 do `);
  L.push(`local ${V[16]}=${V[6]}.sub(${V[12]},${V[15]},${V[15]}+2)+0; if ${V[16]}<0 or ${V[16]}>255 then return end; `);
  L.push(`local ${V[17]}=(((${V[16]}-${V[3]}-(((${V[14]}-1)%251)))%256)+256)%256; `);
  L.push(`local ${V[18]}=((${V[17]}*${V[11]})%256); `);
  // IB stream peel
  L.push(`${V[18]}=${V[10]}(${V[18]},${V[26]}[((${V[14]}-1)%${V[27]})+1]); `);
  L.push(`${V[13]}[${V[14]}]=${V[6]}.char(${V[18]}); ${V[14]}=${V[14]}+1; `);
  L.push(`end; ${V[12]}=nil; ${V[26]}=nil; `);

  L.push(`local ${V[18]}=216613; for ${V[14]}=1,#${V[13]} do local ${V[16]}=${V[6]}.byte(${V[13]}[${V[14]}]); ${V[18]}=(${V[18]}*257+${V[16]}+97)%1000003 end; `);
  L.push(`if ${V[18]}~=${V[4]} or #${V[13]}~=${V[1]} then return end; `);
  L.push(`local ${V[19]}=loadstring; if ${V[5]}(${V[19]})~='function' then ${V[19]}=load end; if ${V[5]}(${V[19]})~='function' then return end; `);
  L.push(`for ${V[20]}=1,18 do ${V[8]}(function() ${V[19]}('--qy'..tostring(${V[20]})..'\\nlocal function _d() return '..tostring(${V[20]}*17)..' end\\nreturn _d()') end) end; `);
  L.push(`local ${V[22]}=${V[7]}.concat(${V[13]}); ${V[13]}=nil; `);
  L.push(`local ${V[23]},${V[24]}=${V[8]}(${V[19]},${V[22]}); ${V[22]}=nil; `);
  L.push(`if not ${V[23]} or ${V[5]}(${V[24]})~='function' then return end; `);
  L.push(`return ${V[24]}(...); end)(...)`);
  return L.join('');
}

function obfuscateOnce(source) {
  const raw0 = Buffer.from(String(source), 'utf8');
  if (raw0.length > 1500000) throw new Error('Too large');

  // IronBrew keystream table (32-96 bytes)
  const xorTable = rb(32 + ri(64));
  const masked = streamXor(raw0, xorTable);

  const a = 1 + 2 * ri(128);
  const b = ri(256);
  const decimal = decEnc(masked, a, b);

  // verify full roundtrip
  const backMasked = decDec(decimal, a, b);
  const back = streamXor(backMasked, xorTable);
  if (!back.equals(raw0)) throw new Error('IB+affine roundtrip failed');

  // hash is over ORIGINAL source (after peel)
  return buildDecimalLoader(decimal, a, b, hash32(raw0), raw0.length, xorTable);
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');

  // double nest
  let code = obfuscateOnce(src);
  code = obfuscateOnce(code);

  if (code.includes('dolocal') || code.includes('thenlocal') || code.includes('endlocal')) {
    throw new Error('internal spacing error');
  }

  return {
    code,
    stats: {
      inputBytes: Buffer.byteLength(src, 'utf8'),
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: `QyrexObf-${VERSION}`,
      nestLevels: 2,
      layers: [
        'ironbrew-keystream-xor',
        'ironbrew-pure-arith-xor',
        'decimal-affine',
        'integrity-hash',
        'cf-bounce-garbage',
        'watermark-ib-fused',
        'prometheus-pcall-sanity',
        'hercules-native-probes',
        'opaque-predicates',
        'sandbox-env-scan',
        'jobid-placeid',
        'debug-hook-probe',
        'hookfunction-probe',
        'decoy-loadstring-x18',
        'double-nest',
        'luau-roblox-stable',
      ],
      verified: true,
      fusedFrom: ['IronBrew2', 'Hercules', 'Prometheus', 'MoonSec', 'Qyrex'],
    },
  };
}

module.exports = { obfuscate, VERSION };
