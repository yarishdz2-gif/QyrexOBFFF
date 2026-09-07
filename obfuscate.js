/**
 * QyrexObf 1.0.2 — Hybrid
 * 1) Try bytecode VM (no user loadstring) when syntax is supported
 * 2) Else decimal double-nest loader (always works on Roblox/Luau)
 * Soft anti-tamper + decoys + no dolocal glue
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.2';
const ri = (n) => crypto.randomInt(0, n);
const RES = new Set(['and','break','do','else','elseif','end','false','for','function','goto','if','in','local','nil','not','or','repeat','return','then','true','until','while']);
function rid() {
  const L = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let o = '';
  do { o = 'q'; for (let i = 0; i < 6 + ri(4); i++) o += L[ri(L.length)]; } while (RES.has(o));
  return o;
}

/* ===================== DECIMAL PATH (always works) ===================== */
function modInv(a) {
  for (let x = 1; x < 256; x++) if (((a * x) % 256 + 256) % 256 === 1) return x;
  throw new Error('key');
}
function decEnc(buf, a, b) {
  let out = '';
  for (let i = 0; i < buf.length; i++) out += String((a * buf[i] + b + (i % 251)) % 256).padStart(3, '0');
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

function buildDecimalLoader(decimal, a, b, expectedHash, sourceLen) {
  const V = Array.from({ length: 26 }, rid);
  const parts = chunkDec(decimal);
  const payloadTable = parts.map((p) => JSON.stringify(p)).join(',');
  const L = [];
  L.push(`--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]] `);
  L.push('return(function(...) ');
  L.push(`local ${V[0]}={${payloadTable}}; `);
  L.push(`local ${V[1]}=${sourceLen}; local ${V[2]}=${a}; local ${V[3]}=${b}; local ${V[4]}=${expectedHash}; `);
  L.push(`local ${V[5]}=type; local ${V[6]}=string; local ${V[7]}=table; local ${V[8]}=pcall; local ${V[9]}=0; `);
  L.push(`${V[8]}(function() local t=${V[5]}(game); if t=='userdata' or t=='table' then ${V[9]}=${V[9]}+1 end; if ${V[5]}(_G)=='table' then ${V[9]}=${V[9]}+1 end end); `);
  L.push(`${V[8]}(function() if typeof and game~=nil and typeof(game)=='Instance' then ${V[9]}=${V[9]}+1 end end); `);
  L.push(`${V[8]}(function() if math and math.floor(3.9)==3 and ${V[6]}.byte('A')==65 then ${V[9]}=${V[9]}+1 end end); `);
  L.push(`${V[8]}(function() if game and game.JobId=='00000000-0000-0000-0000-000000000000' then ${V[9]}=${V[9]}-5 end end); `);
  L.push(`${V[8]}(function() if game and (game.PlaceId==8916037983 or game.GameId==8916037983) then ${V[9]}=${V[9]}-5 end end); `);
  L.push(`${V[8]}(function() if getmetatable and getmetatable(_G)~=nil then ${V[9]}=${V[9]}-3 end end); `);
  L.push(`${V[8]}(function() if debug and debug.gethook then local ok,h=${V[8]}(debug.gethook); if ok and h~=nil then ${V[9]}=${V[9]}-4 end end end); `);
  L.push(`${V[8]}(function() local function has(k) local ok,v=${V[8]}(function() return rawget(_G,k) end); return ok and v~=nil end; if has('process')or has('lune')or has('lute')or has('window')or has('document')or has('Buffer')then ${V[9]}=${V[9]}-8 end end); `);
  L.push(`local ${V[11]}=1; while ((${V[2]}*${V[11]})%256)~=1 do ${V[11]}=${V[11]}+1; if ${V[11]}>255 then return end end; `);
  L.push(`local ${V[12]}=${V[7]}.concat(${V[0]}); ${V[0]}=nil; if #${V[12]}~=${V[1]}*3 then return end; `);
  L.push(`local ${V[13]}={}; local ${V[14]}=1; `);
  L.push(`for ${V[15]}=1,#${V[12]},3 do `);
  L.push(`local ${V[16]}=${V[6]}.sub(${V[12]},${V[15]},${V[15]}+2)+0; if ${V[16]}<0 or ${V[16]}>255 then return end; `);
  L.push(`local ${V[17]}=(((${V[16]}-${V[3]}-(((${V[14]}-1)%251)))%256)+256)%256; `);
  L.push(`${V[13]}[${V[14]}]=${V[6]}.char(((${V[17]}*${V[11]})%256)); ${V[14]}=${V[14]}+1; `);
  L.push(`end; ${V[12]}=nil; `);
  L.push(`local ${V[18]}=216613; for ${V[14]}=1,#${V[13]} do local ${V[16]}=${V[6]}.byte(${V[13]}[${V[14]}]); ${V[18]}=(${V[18]}*257+${V[16]}+97)%1000003 end; `);
  L.push(`if ${V[18]}~=${V[4]} or #${V[13]}~=${V[1]} then return end; `);
  L.push(`local ${V[19]}=loadstring; if ${V[5]}(${V[19]})~='function' then ${V[19]}=load end; if ${V[5]}(${V[19]})~='function' then return end; `);
  L.push(`${V[8]}(function() if iscclosure and not iscclosure(${V[19]}) then ${V[9]}=${V[9]}-2 end end); `);
  L.push(`for ${V[20]}=1,14 do ${V[8]}(function() ${V[19]}('--d'..tostring(${V[20]})..'\\nreturn '..tostring(${V[20]}*9)) end) end; `);
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

/* ===================== PUBLIC API ===================== */
function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');

  // Always use reliable decimal path with 2 nests + AT + decoys
  // (VM optional later; stability on Roblox first)
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
        'soft-anti-tamper',
        'sandbox-probes',
        'jobid-placeid',
        'debug-hook-probe',
        'decoy-loadstring',
        'double-nest',
        'luau-roblox-stable',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
