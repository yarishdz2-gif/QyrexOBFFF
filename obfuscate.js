'use strict';
/**
 * QyrexOBF Pure Node — 100% Node.js Lua/Luau obfuscator
 * No external binaries, no lua, no tar, no PACK_B64.
 * Layers inspired by Prometheus / IronBrew2 / Hercules / MoonSec techniques.
 * Compatible with Roblox executors (Lua 5.1 style).
 */

const crypto = require('crypto');

// ─────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────
function rnd(n) {
  return crypto.randomBytes(4).readUInt32BE(0) % (n || 0xffffffff);
}
function rndInt(min, max) {
  return min + (rnd(max - min + 1));
}
function rndIdent(len) {
  const chars = 'OIl10abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let s = chars[rndInt(10, chars.length - 1)]; // no digit start
  for (let i = 1; i < (len || rndInt(6, 14)); i++) s += chars[rndInt(0, chars.length - 1)];
  return '_' + s;
}
function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = rndInt(0, i);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// ─────────────────────────────────────────────
// Layer 1 — AntiTamper v3 (Lua 5.1 safe)
// ─────────────────────────────────────────────
function buildAntiTamper() {
  function posKeyEncode(str, key) {
    const t = [];
    for (let i = 0; i < str.length; i++) {
      const idx = i + 1;
      const ki = (key * ((idx % 11) + 1) + idx * 7 + (key % 31)) % 256;
      t.push((str.charCodeAt(i) + ki) % 256);
    }
    return t;
  }
  function rndKey() { return 17 + rndInt(0, 216); }
  const stopKey = rndKey();
  const markerKey = rndKey();
  const stopBytes = posKeyEncode('stop skidding', stopKey);
  const markerBytes = posKeyEncode('AT3_OK_' + rndInt(10000, 99999), markerKey);

  return [
    'do',
    'local function _pk_dec(t,k) local r={} for i=1,#t do local ki=(k*((i%11)+1)+i*7+(k%31))%256 r[i]=string.char((t[i]-ki+512)%256) end return table.concat(r) end',
    'local _stop=_pk_dec({' + stopBytes.join(',') + '},' + stopKey + ')',
    'local function _crash() local t while true do t={t} end end',
    'local _type,_pcall,_error,_select=type,pcall,error,select',
    'local _find,_tostring,_tonumber=string.find,tostring,tonumber',
    'local _floor,_random,_abs=math.floor,math.random,math.abs',
    'local _unpack=table.unpack or unpack',
    'local _rawget,_rawset=rawget,rawset',
    'local _getfenv,_setfenv=getfenv,setfenv',
    'do local G=_G or getfenv and getfenv(0) or {}',
    'local S={"lune","lute","wally","rojo","selene","darklua","remodel","tarmac","stylua","lemur","busted","process","window","document","navigator","localStorage","globalThis","__dirname","__filename","js","SYN","is_synapse_function","is_protosmasher_closure","is_sirhurt_closure","secure_call","hookfunction","hookmetamethod","getrawmetatable","setreadonly","checkcaller","getcallingscript","getnamecallmethod","newcclosure","islclosure","isexecutorclosure","getgenv","getrenv","getsenv","getreg","getgc","getinstances","getnilinstances","getscripts","getloadedmodules","getconnections","firesignal","fireclickdetector","fireproximityprompt","sethiddenproperty","gethiddenproperty","setsimulationradius","getsimulationradius","Drawing","crypt","base64","http","syn","KRNL","Fluxus","ScriptWare","Electron","Valyse","Delta","Codex","Solara","Wave","Xeno","Arceus","Potassium"}',
    'for i=1,#S do if _rawget(G,S[i])~=nil then _crash() end end',
    'if _type(G.process)=="table" and (G.process.env or G.process.platform) then _crash() end',
    'if _type(G.js)=="table" or _type(G.JS)=="table" then _crash() end end',
    'if _type(game)~="userdata" or _type(Enum)~="userdata" then _crash() end',
    'if string.byte("A")~=65 or math.floor(3.9)~=3 or math.floor(math.pi)~=3 then _crash() end',
    'if _type(string)~="table" or _type(math)~="table" or _type(table)~="table" then _crash() end',
    'do local okE=_pcall(_error,"\\\\0",0) if okE then _crash() end end',
    'if _type(game)==_type({}) then _crash() end',
    'if _type(typeof)=="function" and typeof(game)=="table" then _crash() end',
    'do local okMt,mt=_pcall(getmetatable,game) if okMt and _type(mt)==_type({}) then _crash() end end',
    'do local n=0/0 if n==n then _crash() end end',
    'do local a,b=1,1 if a+b~=2 or a*b~=1 then _crash() end end',
    'local function _sg(o,k) local ok,v=_pcall(function() return o[k] end) return ok,v end',
    'do local ok,j=_sg(game,"JobId") if ok and (j=="00000000-0000-0000-0000-000000000000" or j=="" or j==nil) then _crash() end end',
    'do local ok,p=_sg(game,"PlaceId") if ok and (p==0 or p==8916037983 or p==nil) then _crash() end end',
    'do local ok,g=_sg(game,"GameId") if ok and (g==0 or g==8916037983) then _crash() end end',
    'local okPl,Players=_pcall(function() return game:GetService("Players") end)',
    'if not okPl or Players==nil then _crash() end',
    'local LP do local ok,v=_sg(Players,"LocalPlayer") if ok then LP=v end end',
    'if LP==nil then _crash() end',
    'do local ok,uid=_sg(LP,"UserId") if ok and (uid==0 or uid==123456789 or uid==nil) then _crash() end end',
    'do local ok,nm=_sg(LP,"Name") if ok and (nm=="vole7vin" or nm=="Player" or nm=="") then _crash() end end',
    'do local okSt,Stats=_pcall(function() return game:GetService("Stats") end)',
    'if not okSt or not Stats then _crash() end',
    'local okNet,Net=_sg(Stats,"Network") if not okNet or not Net then _crash() end',
    'local okSSI,SSI=_sg(Net,"ServerStatsItem") if not okSSI or not SSI then _crash() end',
    'local okDP,DP=_sg(SSI,"Data Ping") if not okDP or not DP then _crash() end',
    'local okGV,gv=_sg(DP,"GetValue") if not okGV or _type(gv)~="function" then _crash() end',
    'local okPing,pv=_pcall(gv,DP) if not okPing or pv==nil or pv=="" or pv==0 then _crash() end',
    'if _floor(_tonumber(pv) or 0)==0 then _crash() end end',
    'do local okC,CG=_pcall(function() return game:GetService("CoreGui") end)',
    'if not okC or not CG then _crash() end',
    'local okR,RG=_pcall(function() return CG:FindFirstChild("RobloxGui") end)',
    'if not okR or not RG then _crash() end end',
    'do local okRS,RS=_pcall(function() return game:GetService("RunService") end)',
    'if not okRS or not RS then _crash() end',
    'local okHB,hb=_sg(RS,"Heartbeat") if not okHB or not hb then _crash() end end',
    'local _marker=_pk_dec({' + markerBytes.join(',') + '},' + markerKey + ')',
    'local function _probe(fn) local ok,err=_pcall(fn) if _type(err)~="string" then return false end return _find(err,_marker,1,true)~=nil end',
    'for _=1,7 do if not _probe(function() _error(_marker) end) then _crash() end end',
    'do local valid=true local intact2=false local intact=_pcall(function() intact2=true end) and intact2',
    'if not intact then _crash() end',
    'local acc1,acc2,len=0,0,64',
    'for i=1,len do',
    'local n2=i%256 local pos=i%len+1 local shouldErr=(i%2==0)',
    'local eMsg="E#".._tostring(i)',
    'local arr={_pcall(function()',
    'if shouldErr then _error(eMsg,0) end',
    'local res={} for j=1,len do res[j]=_random(0,255) end res[pos]=n2',
    'return _unpack(res)',
    'end)}',
    'if shouldErr then valid=valid and arr[1]==false else valid=valid and arr[1] acc1=(acc1+(arr[pos+1] or 0))%256 acc2=(acc2+n2)%256 end',
    'end',
    'if not (valid and acc1==acc2) then _crash() end end',
    'do local okF=_pcall(function() if _getfenv then local e=_getfenv(0) if e~=_G and e~=nil then _crash() end end end) if not okF then _crash() end end',
    'end',
    ''
  ].join('\n');
}

// ─────────────────────────────────────────────
// Layer 2 — String encryption + constant array
// ─────────────────────────────────────────────
function encryptStrings(source) {
  const strings = [];
  const key = rndInt(17, 233);

  // Match long strings "..." and '...' (simple, non-nested)
  const re = /(["'])(?:(?!\1)[^\\]|\\.)*\1/g;
  let code = source.replace(re, (match) => {
    if (match.length < 4) return match; // skip tiny
    const quote = match[0];
    let raw;
    try {
      // naive unescape for common cases
      raw = match.slice(1, -1)
        .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
        .replace(/\\'/g, "'").replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    } catch {
      return match;
    }
    if (raw.length < 2) return match;
    const bytes = [];
    for (let i = 0; i < raw.length; i++) {
      const ki = (key * ((i % 11) + 1) + (i + 1) * 7 + (key % 31)) % 256;
      bytes.push((raw.charCodeAt(i) + ki) % 256);
    }
    const idx = strings.length;
    strings.push(bytes);
    return `_S[${idx + 1}]`;
  });

  if (strings.length === 0) return source;

  const decFn = rndIdent(8);
  const arrName = '_S';
  const parts = [];
  parts.push(`local ${arrName}={}`);
  for (let i = 0; i < strings.length; i++) {
    parts.push(`${arrName}[${i + 1}]={${strings[i].join(',')}}`);
  }
  parts.push(`local function ${decFn}(t,k)`);
  parts.push(`local r={} for i=1,#t do local ki=(k*((i%11)+1)+i*7+(k%31))%256 r[i]=string.char((t[i]-ki+512)%256) end return table.concat(r) end`);
  for (let i = 0; i < strings.length; i++) {
    parts.push(`${arrName}[${i + 1}]=${decFn}(${arrName}[${i + 1}],${key})`);
  }
  return parts.join('\n') + '\n' + code;
}

// ─────────────────────────────────────────────
// Layer 3 — Number to expression
// ─────────────────────────────────────────────
function numbersToExpressions(source) {
  return source.replace(/\b(\d{2,})\b/g, (m, num) => {
    const n = parseInt(num, 10);
    if (n < 10 || n > 999999) return m;
    if (rndInt(0, 2) !== 0) return m; // only ~33% to keep size down
    const a = rndInt(1, Math.min(n - 1, 97));
    const b = n - a;
    if (rndInt(0, 1) === 0) {
      return `(${a}+${b})`;
    }
    const c = rndInt(2, 9);
    if (n % c === 0) return `(${n / c}*${c})`;
    return `(${a}+${b})`;
  });
}

// ─────────────────────────────────────────────
// Layer 4 — Simple name mangling (locals)
// ─────────────────────────────────────────────
function mangleLocals(source) {
  // Very conservative: only rename obvious local x = ... patterns that look user-defined
  const map = new Map();
  const reserved = new Set([
    'and','break','do','else','elseif','end','false','for','function','goto','if','in',
    'local','nil','not','or','repeat','return','then','true','until','while',
    'game','workspace','script','shared','plugin','Enum','typeof','pairs','ipairs',
    'next','type','tonumber','tostring','pcall','xpcall','error','assert','select',
    'unpack','rawget','rawset','rawequal','setmetatable','getmetatable','require',
    'print','warn','tick','wait','spawn','delay','task','Instance','Vector3','CFrame',
    'Color3','UDim2','Ray','Region3','TweenInfo','BrickColor','NumberSequence',
    'string','table','math','bit32','coroutine','debug','os','utf8','buffer'
  ]);

  // collect local names
  const localRe = /\blocal\s+([a-zA-Z_][a-zA-Z0-9_]*)\b/g;
  let m;
  while ((m = localRe.exec(source)) !== null) {
    const name = m[1];
    if (reserved.has(name) || name.startsWith('_') || name.length < 3) continue;
    if (!map.has(name)) map.set(name, rndIdent(rndInt(7, 12)));
  }

  if (map.size === 0) return source;

  // replace whole-word
  let out = source;
  for (const [orig, neu] of map) {
    const re = new RegExp('\\b' + orig.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'g');
    out = out.replace(re, neu);
  }
  return out;
}

// ─────────────────────────────────────────────
// Layer 5 — Opaque predicates + junk
// ─────────────────────────────────────────────
function injectOpaqueAndJunk(source) {
  const junkSnippets = [
    () => {
      const a = rndIdent(5), b = rndIdent(5);
      return `do local ${a}=${rndInt(1, 50)} local ${b}=${a}*${a}+${rndInt(1, 9)} if ${b}<0 then error("x") end end`;
    },
    () => {
      const t = rndIdent(6);
      return `do local ${t}={${rndInt(1, 9)},${rndInt(1, 9)},${rndInt(1, 9)}} if #${t}~=3 then while true do end end end`;
    },
    () => {
      const x = rndIdent(5);
      return `do local ${x}=pcall(function() return ${rndInt(1, 99)} end) if not ${x} then return end end`;
    }
  ];

  const lines = source.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    out.push(lines[i]);
    if (lines[i].trim() && rndInt(0, 8) === 0) {
      out.push(junkSnippets[rndInt(0, junkSnippets.length - 1)]());
    }
  }
  return out.join('\n');
}

// ─────────────────────────────────────────────
// Layer 6 — Control-flow flattening (basic blocks)
// ─────────────────────────────────────────────
function flattenControlFlow(source) {
  // Wrap whole script in a state machine for max mode
  // Keep it simple and Lua 5.1 safe
  const stateVar = rndIdent(8);
  const blocks = source.split(/\n(?=function\s|local\s+function\s)/);
  if (blocks.length < 2) {
    // single block → simple wrapper
    const s = rndIdent(7);
    return [
      `do`,
      `local ${s}=1`,
      `while ${s} do`,
      `if ${s}==1 then`,
      source,
      `${s}=nil`,
      `end`,
      `end`,
      `end`
    ].join('\n');
  }

  // multi-ish: wrap everything
  const s = rndIdent(7);
  return [
    `do`,
    `local ${s}=1`,
    `while ${s} do`,
    `if ${s}==1 then`,
    source,
    `${s}=nil`,
    `elseif ${s}==2 then`,
    `error("cf")`,
    `else`,
    `${s}=nil`,
    `end`,
    `end`,
    `end`
  ].join('\n');
}

// ─────────────────────────────────────────────
// Layer 7 — Wrap in function + proxy
// ─────────────────────────────────────────────
function wrapInFunction(source) {
  const fn = rndIdent(9);
  const env = rndIdent(7);
  return [
    `local function ${fn}(...)`,
    `local ${env}=getfenv and getfenv() or _G`,
    source,
    `end`,
    `return ${fn}()`
  ].join('\n');
}

// ─────────────────────────────────────────────
// Layer 8 — Minify / whitespace
// ─────────────────────────────────────────────
function minify(source) {
  return source
    .replace(/--\[\[[\s\S]*?\]\]/g, '')
    .replace(/--[^\n]*/g, '')
    .replace(/\n\s*\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n /g, '\n')
    .trim();
}

// ─────────────────────────────────────────────
// Main pipeline
// ─────────────────────────────────────────────
function obfuscate(source, opts) {
  opts = opts || {};
  const mode = String(opts.mode || 'max').toLowerCase();
  const wantAT = opts.antiTamper !== false;
  const steps = [];
  let code = String(source || '');

  if (!code.trim()) {
    return { code: '', engine: 'QyrexOBF-PureNode', steps: ['empty'], antiTamper: false, mode };
  }

  // 1. AntiTamper
  if (wantAT) {
    try {
      code = buildAntiTamper() + '\n' + code;
      steps.push('AntiTamper:v3');
    } catch (e) {
      steps.push('AntiTamper:skip');
    }
  }

  // 2. String encryption (always on max/strong)
  if (mode === 'max' || mode === 'strong' || mode === 'strings') {
    try {
      code = encryptStrings(code);
      steps.push('StringEncrypt');
    } catch (e) {
      steps.push('StringEncrypt:skip');
    }
  }

  // 3. Numbers
  if (mode === 'max' || mode === 'strong') {
    try {
      code = numbersToExpressions(code);
      steps.push('NumbersToExpr');
    } catch (e) {
      steps.push('NumbersToExpr:skip');
    }
  }

  // 4. Mangle locals
  if (mode === 'max' || mode === 'strong' || mode === 'mangle') {
    try {
      code = mangleLocals(code);
      steps.push('NameMangle');
    } catch (e) {
      steps.push('NameMangle:skip');
    }
  }

  // 5. Junk / opaque
  if (mode === 'max') {
    try {
      code = injectOpaqueAndJunk(code);
      steps.push('OpaqueJunk');
    } catch (e) {
      steps.push('OpaqueJunk:skip');
    }
  }

  // 6. Control flow
  if (mode === 'max') {
    try {
      code = flattenControlFlow(code);
      steps.push('ControlFlow');
    } catch (e) {
      steps.push('ControlFlow:skip');
    }
  }

  // 7. Wrap
  if (mode === 'max' || mode === 'strong') {
    try {
      code = wrapInFunction(code);
      steps.push('WrapFn');
    } catch (e) {
      steps.push('WrapFn:skip');
    }
  }

  // 8. Minify
  if (opts.minify !== false) {
    try {
      code = minify(code);
      steps.push('Minify');
    } catch (e) {
      steps.push('Minify:skip');
    }
  }

  const header = '--QyrexObf PureNode v3 [qyrex.hopto.org]\n';
  if (!code.startsWith('--QyrexObf')) {
    code = header + code;
  }

  return {
    code,
    engine: 'QyrexOBF-PureNode',
    steps,
    antiTamper: wantAT && steps.includes('AntiTamper:v3'),
    mode
  };
}

// Stubs so the old server API does not break
function getRoot() { return process.cwd(); }
function findLua() { return null; }
function findLua54() { return null; }
function findLuac() { return null; }
function runPrometheus() { throw new Error('Pure Node build: external engines disabled'); }
function runHercules() { throw new Error('Pure Node build: external engines disabled'); }
function runIB2() { throw new Error('Pure Node build: external engines disabled'); }

module.exports = {
  obfuscate,
  getRoot,
  findLua,
  findLua54,
  findLuac,
  runPrometheus,
  runHercules,
  runIB2,
  buildAntiTamper
};
