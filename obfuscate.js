'use strict';
/**
 * QyrexOBF Pure Node — XOR pack + AntiTamper (from your engines)
 * Must work on Roblox executors. No lua binaries.
 */

const crypto = require('crypto');

function rndInt(a, b) {
  const n = crypto.randomBytes(4).readUInt32BE(0);
  return a + (n % (b - a + 1));
}
function rndHexName() {
  const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz';
  return a[rndInt(0, a.length - 1)] + a[rndInt(0, a.length - 1)];
}

// ── XOR encode/decode (1-based position key, matches Lua) ──
function xorEncode(str, key) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    const I = i + 1;
    const k = (key * ((I % 11) + 1) + I * 7 + (key % 31)) % 256;
    out.push(str.charCodeAt(i) ^ k);
  }
  return out;
}

function minifyLua(s) {
  return String(s)
    .replace(/--\[\[[\s\S]*?\]\]/g, '')
    .replace(/--[^\n]*/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n[ \t]+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// ── Full AntiTamper (from your Qyrex / Hercules / MoonSec style checks) ──
function buildAntiTamper() {
  function posKeyEncode(str, key) {
    const t = [];
    for (let i = 0; i < str.length; i++) {
      const I = i + 1;
      const ki = (key * ((I % 11) + 1) + I * 7 + (key % 31)) % 256;
      t.push((str.charCodeAt(i) + ki) % 256);
    }
    return t;
  }
  const stopKey = rndInt(17, 233);
  const markerKey = rndInt(17, 233);
  const stopBytes = posKeyEncode('stop skidding', stopKey);
  const markerBytes = posKeyEncode('AT3_OK_' + rndInt(10000, 99999), markerKey);

  return [
    'do',
    'local function _pk_dec(t,k) local r={} for i=1,#t do local ki=(k*((i%11)+1)+i*7+(k%31))%256 r[i]=string.char((t[i]-ki+512)%256) end return table.concat(r) end',
    'local _stop=_pk_dec({' + stopBytes.join(',') + '},' + stopKey + ')',
    'local function _crash() local t while true do t={t} end end',
    'local _type,_pcall,_error=type,pcall,error',
    'local _find,_tostring,_tonumber=string.find,tostring,tonumber',
    'local _floor,_random=math.floor,math.random',
    'local _unpack=table.unpack or unpack',
    'local _rawget=rawget',
    'local _getfenv=getfenv',
    // executor / tool names
    'do local G=_G or (_getfenv and _getfenv(0)) or {}',
    'local S={"lune","lute","wally","rojo","selene","darklua","remodel","tarmac","stylua","lemur","busted","process","window","document","navigator","localStorage","globalThis","__dirname","__filename","js","SYN","is_synapse_function","is_protosmasher_closure","is_sirhurt_closure","secure_call","hookfunction","hookmetamethod","getrawmetatable","setreadonly","checkcaller","getcallingscript","getnamecallmethod","newcclosure","islclosure","isexecutorclosure","getgenv","getrenv","getsenv","getreg","getgc","getinstances","getnilinstances","getscripts","getloadedmodules","getconnections","firesignal","fireclickdetector","fireproximityprompt","sethiddenproperty","gethiddenproperty","Drawing","crypt","base64","http","syn","KRNL","Fluxus","ScriptWare","Electron","Valyse","Delta","Codex","Solara","Wave","Xeno","Arceus","Potassium"}',
    'for i=1,#S do if _rawget(G,S[i])~=nil then _crash() end end',
    'if _type(G.process)=="table" and (G.process.env or G.process.platform) then _crash() end end',
    // primitives
    'if _type(game)~="userdata" or _type(Enum)~="userdata" then _crash() end',
    'if string.byte("A")~=65 or math.floor(3.9)~=3 or math.floor(math.pi)~=3 then _crash() end',
    'if _type(string)~="table" or _type(math)~="table" or _type(table)~="table" then _crash() end',
    'do local okE=_pcall(_error,"\\0",0) if okE then _crash() end end',
    'if _type(game)==_type({}) then _crash() end',
    'if _type(typeof)=="function" and typeof(game)=="table" then _crash() end',
    'do local okMt,mt=_pcall(getmetatable,game) if okMt and _type(mt)==_type({}) then _crash() end end',
    'do local n=0/0 if n==n then _crash() end end',
    // sandbox fingerprints
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
    // network ping
    'do local okSt,Stats=_pcall(function() return game:GetService("Stats") end)',
    'if not okSt or not Stats then _crash() end',
    'local okNet,Net=_sg(Stats,"Network") if not okNet or not Net then _crash() end',
    'local okSSI,SSI=_sg(Net,"ServerStatsItem") if not okSSI or not SSI then _crash() end',
    'local okDP,DP=_sg(SSI,"Data Ping") if not okDP or not DP then _crash() end',
    'local okGV,gv=_sg(DP,"GetValue") if not okGV or _type(gv)~="function" then _crash() end',
    'local okPing,pv=_pcall(gv,DP) if not okPing or pv==nil or pv=="" or pv==0 then _crash() end',
    'if _floor(_tonumber(pv) or 0)==0 then _crash() end end',
    // coregui
    'do local okC,CG=_pcall(function() return game:GetService("CoreGui") end)',
    'if not okC or not CG then _crash() end',
    'local okR,RG=_pcall(function() return CG:FindFirstChild("RobloxGui") end)',
    'if not okR or not RG then _crash() end end',
    // runservice
    'do local okRS,RS=_pcall(function() return game:GetService("RunService") end)',
    'if not okRS or not RS then _crash() end',
    'local okHB,hb=_sg(RS,"Heartbeat") if not okHB or not hb then _crash() end end',
    // marker probe
    'local _marker=_pk_dec({' + markerBytes.join(',') + '},' + markerKey + ')',
    'local function _probe(fn) local ok,err=_pcall(fn) if _type(err)~="string" then return false end return _find(err,_marker,1,true)~=nil end',
    'for _=1,7 do if not _probe(function() _error(_marker) end) then _crash() end end',
    // accumulator
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
    'end',
    ''
  ].join('\n');
}

// ── Build final script: watermark + XOR VM-style return ──
function buildPacked(source) {
  const key = rndInt(17, 240);
  const bytes = xorEncode(source, key);

  // split into chunks for IB2-like look
  const chunkSize = rndInt(12, 20);
  const chunks = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    chunks.push(bytes.slice(i, i + chunkSize));
  }

  const N = {
    dec: rndHexName(),
    run: rndHexName(),
    rot: rndHexName(),
    set: rndHexName(),
    get: rndHexName(),
    load: rndHexName(),
    ep: rndHexName(),
    wrap: rndHexName()
  };

  const parts = [];

  // style ops
  parts.push(
    `${N.rot}=bit32 and bit32.rrotate or function(a,b)b=b%32 local c=4294967296 a=a%c local d=2^b return((a-a%d)/d+(a*2^(32-b))%c)%c end`
  );
  // XOR decrypt
  parts.push(
    `${N.dec}=function(y,C,f)local bxor=bit32 and bit32.bxor or function(a,b)local r,v=0,1 while a>0 or b>0 do local ab,bb=a%2,b%2 if ab~=bb then r=r+v end a,b,v=(a-ab)/2,(b-bb)/2,v*2 end return r end local l={}for I=1,#C do local M=(f*((I%11)+1)+I*7+(f%31))%256 l[I]=string.char(bxor(C[I],M))end return table.concat(l)end`
  );
  parts.push(`${N.set}=function(y,y,C,f)y[C]=C-f end`);
  parts.push(
    `${N.get}=function(y,C,f,l,I,M)local c if M<=0X5f then if not(M<0x5f)then else end else c,C,f,l=y.${N.wrap}(M,I,f,l,C) if c==${rndInt(20000, 50000)} then return C,l,${rndInt(10000, 40000)},f else if c~=${rndInt(10000, 40000)} then else return C,l,${rndInt(10000, 40000)},f end end end return C,l,nil,f end`
  );
  parts.push(
    `${N.load}=function(y,y,C,f,l)(C[${rndInt(1, 9)}])[f+1]=(y)l=${rndInt(0x40, 0xff)} return l end`
  );
  parts.push(`${N.ep}=function(y,y,C)y=C[${rndInt(20, 45)}]() return y end`);

  const chunkNames = [];
  for (let i = 0; i < chunks.length; i++) {
    const cn = rndHexName() + i;
    chunkNames.push(cn);
    parts.push(`${cn}={${chunks[i].join(',')}}`);
  }

  const loops = chunkNames
    .map((cn) => `for I=1,#y.${cn} do C[#C+1]=y.${cn}[I] end`)
    .join(' ');

  // run: decrypt with XOR, loadstring, setfenv, execute
  parts.push(
    `${N.run}=function(y)local C={}local f=${key} ${loops} local l=y.${N.dec}(y,C,f)local I=loadstring or load local M=I(l)if not M then error("protected")end if setfenv and getfenv then pcall(setfenv,M,getfenv(0))end return M()end`
  );
  parts.push(`${N.wrap}=function(y,C,f,l,I)return ${rndInt(10000, 50000)},C,f,l end`);
  parts.push(`x=function(y)return y.${N.run}(y)end`);

  const watermark =
    '-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]';

  return watermark + '\n' + `return({${parts.join(',')}})["x"]()`;
}

function obfuscate(source, opts) {
  opts = opts || {};
  const mode = String(opts.mode || 'max').toLowerCase();
  const wantAT = opts.antiTamper !== false;
  const steps = [];
  let src = minifyLua(String(source || ''));

  if (!src) {
    return {
      code:
        '-- This file was protected using Qyrex Obfuscator v11.2 [https://qyrex.hopto.org/]\nreturn({x=function()end})["x"]()',
      engine: 'QyrexOBF-PureNode',
      steps: ['empty'],
      antiTamper: false,
      mode
    };
  }

  // AntiTamper goes INSIDE the encrypted payload so it runs after decrypt
  if (wantAT && mode !== 'light') {
    src = buildAntiTamper() + '\n' + src;
    steps.push('AntiTamper');
  }

  const code = buildPacked(src);
  steps.push('XOR', 'VM-Pack', 'DenseReturn');

  return {
    code,
    engine: 'QyrexOBF-PureNode',
    steps,
    antiTamper: wantAT && steps.includes('AntiTamper'),
    mode
  };
}

function getRoot() { return process.cwd(); }
function findLua() { return null; }
function findLua54() { return null; }
function findLuac() { return null; }
function runPrometheus() { throw new Error('Pure Node'); }
function runHercules() { throw new Error('Pure Node'); }
function runIB2() { throw new Error('Pure Node'); }

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
