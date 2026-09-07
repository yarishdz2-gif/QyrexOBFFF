/**
 * QyrexObf 1.0.2 — fused protections from:
 * Hercules · Prometheus · MoonSec patterns · Qyrex decimal core
 * Soft anti-tamper (does not kill clean Roblox). Double nest + decoys.
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.2';
const ri = (n) => crypto.randomInt(0, n);
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

/** Soft fused AT block — Prometheus sanity + Hercules natives + sandbox (score only) */
function emitAntiTamper(V, L) {
  const S = V[9]; // score local already declared as 0
  const pcall = V[8];
  const type = V[5];
  const str = V[6];

  // --- Prometheus-style pcall integrity ---
  L.push(`local ${V[10]}=false; local ${V[21]}=${pcall}(function() ${V[10]}=true end) and ${V[10]}; if not ${V[21]} then ${S}=${S}-10 end; `);

  // --- Hercules-style native type probes (Luau-safe subset) ---
  L.push(`${pcall}(function() `);
  L.push(`if ${type}(assert)~='function' or ${type}(error)~='function' or ${type}(pcall)~='function' then ${S}=${S}-8 end; `);
  L.push(`if ${type}(type)~='function' or ${type}(tostring)~='function' or ${type}(tonumber)~='function' then ${S}=${S}-6 end; `);
  L.push(`if ${type}(rawget)~='function' or ${type}(rawset)~='function' or ${type}(rawequal)~='function' then ${S}=${S}-6 end; `);
  L.push(`if ${type}(string)~='table' or ${type}(table)~='table' or ${type}(math)~='table' then ${S}=${S}-8 end; `);
  L.push(`if ${str}.byte('A')~=65 or ${str}.char(66)~='B' then ${S}=${S}-8 end; `);
  L.push(`if math.floor(3.9)~=3 or math.abs(-2)~=2 then ${S}=${S}-5 end; `);
  L.push(`end); `);

  // --- Prometheus arithmetic / pcall message sanity (soft) ---
  L.push(`${pcall}(function() `);
  L.push(`local ok,err=${pcall}(function() return (1-("x")) end); `);
  L.push(`if ok then ${S}=${S}-6 end; `);
  L.push(`end); `);

  // --- Opaque predicates (always true on real VM) ---
  L.push(`${pcall}(function() local x=7; if x~=x or (x*0)~=0 or (x==x and false) then ${S}=${S}-10 end end); `);
  L.push(`${pcall}(function() local a=1; local b=2; if not (a+b==3) then ${S}=${S}-5 end end); `);

  // --- Environment / Roblox fingerprints ---
  L.push(`${pcall}(function() local t=${type}(game); if t=='userdata' or t=='table' then ${S}=${S}+1 end; if ${type}(_G)=='table' then ${S}=${S}+1 end end); `);
  L.push(`${pcall}(function() if typeof and game~=nil and typeof(game)=='Instance' then ${S}=${S}+1 end end); `);
  L.push(`${pcall}(function() if game and game.JobId=='00000000-0000-0000-0000-000000000000' then ${S}=${S}-8 end end); `);
  L.push(`${pcall}(function() if game and (game.PlaceId==8916037983 or game.GameId==8916037983) then ${S}=${S}-8 end end); `);
  L.push(`${pcall}(function() if getmetatable and getmetatable(_G)~=nil then ${S}=${S}-4 end end); `);

  // --- Debug hook (Prometheus/Hercules) ---
  L.push(`${pcall}(function() if debug and debug.gethook then local ok,h=${pcall}(debug.gethook); if ok and h~=nil then ${S}=${S}-6 end end end); `);
  L.push(`${pcall}(function() if debug and debug.getinfo and debug.getinfo(pcall) then local i=debug.getinfo(pcall); if i and i.what and i.what~='C' and i.what~='Lua' then end end end); `);

  // --- Sandbox pollution (Lune/Node/browser) ---
  L.push(`${pcall}(function() local function has(k) local ok,v=${pcall}(function() return rawget(_G,k) end); return ok and v~=nil end; `);
  L.push(`if has('process')or has('lune')or has('lute')or has('window')or has('document')or has('Buffer')or has('navigator')or has('globalThis')or has('__dirname')or has('XMLHttpRequest')or has('setTimeout')or has('wally')or has('rojo')or has('selene') then ${S}=${S}-12 end end); `);

  // --- tostring table probe (anti-proxy _G) ---
  L.push(`${pcall}(function() local t={}; local k=tostring(t); if _G[k]~=nil then ${S}=${S}-6 end end); `);

  // --- error must fail ---
  L.push(`${pcall}(function() local ok=${pcall}(error,'\\0',0); if ok then ${S}=${S}-8 end end); `);

  // --- iscclosure on loadstring when available ---
  L.push(`${pcall}(function() if iscclosure and loadstring and not iscclosure(loadstring) then ${S}=${S}-4 end end); `);
}

function buildDecimalLoader(decimal, a, b, expectedHash, sourceLen) {
  const V = Array.from({ length: 28 }, rid);
  const parts = chunkDec(decimal);
  const payloadTable = parts.map((p) => JSON.stringify(p)).join(',');
  const L = [];
  L.push(`--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]] `);
  L.push('return(function(...) ');
  L.push(`local ${V[0]}={${payloadTable}}; `);
  L.push(`local ${V[1]}=${sourceLen}; local ${V[2]}=${a}; local ${V[3]}=${b}; local ${V[4]}=${expectedHash}; `);
  L.push(`local ${V[5]}=type; local ${V[6]}=string; local ${V[7]}=table; local ${V[8]}=pcall; local ${V[9]}=0; `);

  emitAntiTamper(V, L);

  // modular inverse
  L.push(`local ${V[11]}=1; while ((${V[2]}*${V[11]})%256)~=1 do ${V[11]}=${V[11]}+1; if ${V[11]}>255 then return end end; `);
  // decode
  L.push(`local ${V[12]}=${V[7]}.concat(${V[0]}); ${V[0]}=nil; if #${V[12]}~=${V[1]}*3 then return end; `);
  L.push(`local ${V[13]}={}; local ${V[14]}=1; `);
  L.push(`for ${V[15]}=1,#${V[12]},3 do `);
  L.push(`local ${V[16]}=${V[6]}.sub(${V[12]},${V[15]},${V[15]}+2)+0; if ${V[16]}<0 or ${V[16]}>255 then return end; `);
  L.push(`local ${V[17]}=(((${V[16]}-${V[3]}-(((${V[14]}-1)%251)))%256)+256)%256; `);
  L.push(`${V[13]}[${V[14]}]=${V[6]}.char(((${V[17]}*${V[11]})%256)); ${V[14]}=${V[14]}+1; `);
  L.push(`end; ${V[12]}=nil; `);
  // integrity
  L.push(`local ${V[18]}=216613; for ${V[14]}=1,#${V[13]} do local ${V[16]}=${V[6]}.byte(${V[13]}[${V[14]}]); ${V[18]}=(${V[18]}*257+${V[16]}+97)%1000003 end; `);
  L.push(`if ${V[18]}~=${V[4]} or #${V[13]}~=${V[1]} then return end; `);
  // load + decoys (MoonSec/Prometheus style noise)
  L.push(`local ${V[19]}=loadstring; if ${V[5]}(${V[19]})~='function' then ${V[19]}=load end; if ${V[5]}(${V[19]})~='function' then return end; `);
  L.push(`for ${V[20]}=1,16 do ${V[8]}(function() ${V[19]}('--qy'..tostring(${V[20]})..'\\nlocal function _d() return '..tostring(${V[20]}*17)..' end\\nreturn _d()') end) end; `);
  L.push(`local ${V[22]}=${V[7]}.concat(${V[13]}); ${V[13]}=nil; `);
  L.push(`local ${V[23]},${V[24]}=${V[8]}(${V[19]},${V[22]}); ${V[22]}=nil; `);
  L.push(`if not ${V[23]} or ${V[5]}(${V[24]})~='function' then return end; `);
  L.push(`return ${V[24]}(...); end)(...)`);
  return L.join('');
}

function obfuscateDecimal(source, nests) {
  let src = String(source);
  let lastCode = null;
  const levels = Math.max(1, nests | 0);
  for (let n = 0; n < levels; n++) {
    const raw = Buffer.from(src, 'utf8');
    if (raw.length > 1500000) throw new Error('Too large');
    const a = 1 + 2 * ri(128);
    const b = ri(256);
    const decimal = decEnc(raw, a, b);
    if (!decDec(decimal, a, b).equals(raw)) throw new Error('roundtrip failed');
    lastCode = buildDecimalLoader(decimal, a, b, hash32(raw), raw.length);
    src = lastCode;
  }
  return lastCode;
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  const code = obfuscateDecimal(src, 2);
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
        'decimal-affine',
        'integrity-hash',
        'prometheus-pcall-sanity',
        'hercules-native-probes',
        'opaque-predicates',
        'sandbox-env-scan',
        'jobid-placeid',
        'metatable-g-check',
        'debug-hook-probe',
        'tostring-proxy-probe',
        'error-integrity',
        'iscclosure-probe',
        'decoy-loadstring-flood',
        'double-nest',
        'luau-roblox-stable',
      ],
      verified: true,
      fusedFrom: ['Hercules', 'Prometheus', 'MoonSec-patterns', 'Qyrex'],
    },
  };
}

module.exports = { obfuscate, VERSION };
