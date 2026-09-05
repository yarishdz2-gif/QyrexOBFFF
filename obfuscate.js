/**
 * Symbolic Overload v4 — hardened anti-tamper stack
 * Payload: arithmetic scramble + custom alphabet (NO XOR, NO std Base64)
 * Anti-tamper: fused from Aqua / env-injection / hook / integrity samples
 * Fail mode: silent return (no infinite lock on legit clients)
 */
'use strict';
const crypto = require('crypto');

const MAX = 1_000_000;
const ALPHA =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' +
  '!#$%&/()=?¡°_>:;X+*~@[]{}|^';
const BASE = ALPHA.length;
const WORD = 2;

const rb = n => crypto.randomBytes(n);
const ri = n => rb(1)[0] % n;

function rid(n) {
  n = n || (5 + ri(4));
  const A = 'IlOabcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  let s = '';
  const b = rb(n);
  for (let i = 0; i < n; i++) s += A[b[i] % A.length];
  return s + String(10 + ri(89));
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
  let o = '';
  for (let i = 0; i < buf.length; i++) o += encByte(buf[i]);
  return o;
}

function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    const k = key[i % kl];
    const p = (i * 131 + 17) & 255;
    const q = (i * 47 + k * 3) & 255;
    b = (b + k + p) & 255;
    const rot = (k % 7) + 1;
    b = ((b << rot) | (b >>> (8 - rot))) & 255;
    let m = ((k | 1) * 5) & 255;
    if (!m) m = 1;
    b = (b * m + q) & 255;
    b = (b - ((p * 3 + k) & 255) + 256) & 255;
    out[i] = b;
  }
  return out;
}

function invTable() {
  const t = new Array(256);
  for (let kk = 0; kk < 256; kk++) {
    let m = ((kk | 1) * 5) & 255;
    if (!m) m = 1;
    let inv = 1;
    for (let x = 1; x < 256; x++) if (((m * x) & 255) === 1) { inv = x; break; }
    t[kk] = inv;
  }
  return t;
}

function checksum(buf) {
  let h = 0x9e3779b1 >>> 0;
  for (let i = 0; i < buf.length; i++)
    h = (h + buf[i] * (i + 31) + ((h % 89) * 17) + 13) >>> 0;
  return h >>> 0;
}

function chunks(sym) {
  const parts = [];
  let i = 0;
  while (i < sym.length) {
    let n = 10 + ri(22);
    n -= n % WORD;
    if (n < WORD) n = WORD;
    const take = Math.min(sym.length - i, n);
    const aligned = take - (take % WORD) || take;
    parts.push(sym.slice(i, i + aligned));
    i += aligned;
  }
  return parts;
}

/** Fused anti-tamper bootstrap — conservative, Roblox-safe */
function antiTamperBlock(id) {
  const L = [];
  L.push(`local ${id.safe}=1`);
  L.push(`local ${id.T}=type`);
  L.push(`local ${id.R}=rawget`);
  L.push(`local ${id.P}=pcall`);
  L.push(`do`);

  // --- primitive integrity ---
  L.push(`if ${id.T}(pcall)~="function" then ${id.safe}=0 end`);
  L.push(`if ${id.T}(string)~="table" and ${id.T}(string)~="userdata" then ${id.safe}=0 end`);
  L.push(`if ${id.T}(table)~="table" and ${id.T}(table)~="userdata" then ${id.safe}=0 end`);
  L.push(`if ${id.T}(math)~="table" and ${id.T}(math)~="userdata" then ${id.safe}=0 end`);
  L.push(`if ${id.T}(loadstring)~="function" and ${id.T}(load)~="function" then ${id.safe}=0 end`);
  L.push(`if ${id.T}(rawget)~="function" or ${id.T}(rawset)~="function" then ${id.safe}=0 end`);
  L.push(`if ${id.T}(setmetatable)~="function" then ${id.safe}=0 end`);
  L.push(`if string.byte("A")~=65 then ${id.safe}=0 end`);
  L.push(`if math.floor(3.9)~=3 then ${id.safe}=0 end`);
  L.push(`if math.floor(math.pi)~=3 then ${id.safe}=0 end`);

  // --- error must throw ---
  L.push(`do local ok=${id.P}(error,"\\0",0) if ok then ${id.safe}=0 end end`);

  // --- env / injection ---
  L.push(`local ${id.ok},${id.env}=${id.P}(function() return (getfenv and getfenv(0)) or _G end)`);
  L.push(`if not ${id.ok} or ${id.T}(${id.env})~="table" then ${id.safe}=0 end`);
  L.push(`if ${id.R} and ${id.env} then`);
  L.push(`  if ${id.R}(${id.env},"__builtins__")~=nil then ${id.safe}=0 end`);
  L.push(`  if ${id.R}(${id.env},"__name__")~=nil then ${id.safe}=0 end`);
  L.push(`  for _,k in ipairs({"fenv","_fenv","__fenv","genv","globalenv","_env","rawenv","hookenv","scriptenv"}) do`);
  L.push(`    if ${id.R}(${id.env},k)~=nil then ${id.safe}=0 end`);
  L.push(`  end`);
  L.push(`end`);

  // --- game/typeof sanity (Roblox) ---
  L.push(`if game~=nil then`);
  L.push(`  if ${id.T}(game)==${id.T}({}) then ${id.safe}=0 end`);
  L.push(`  if ${id.T}(typeof)=="function" and typeof(game)=="table" then ${id.safe}=0 end`);
  L.push(`  local om,mt=${id.P}(getmetatable,game)`);
  L.push(`  if om and ${id.T}(mt)==${id.T}({}) then ${id.safe}=0 end`);
  L.push(`end`);

  // --- sandbox fingerprints (Aqua-style, safe pcalls) ---
  L.push(`if game~=nil and ${id.P} then`);
  L.push(`  local oj,jid=${id.P}(function() return game.JobId end)`);
  L.push(`  if oj and jid=="00000000-0000-0000-0000-000000000000" then ${id.safe}=0 end`);
  L.push(`  local op,pid=${id.P}(function() return game.PlaceId end)`);
  L.push(`  if op and pid==8916037983 then ${id.safe}=0 end`);
  L.push(`  local og,gid=${id.P}(function() return game.GameId end)`);
  L.push(`  if og and gid==8916037983 then ${id.safe}=0 end`);
  L.push(`  local oPl,Pl=${id.P}(function() return game:GetService("Players") end)`);
  L.push(`  if oPl and Pl then`);
  L.push(`    local oLP,LP=${id.P}(function() return Pl.LocalPlayer end)`);
  L.push(`    if oLP and LP then`);
  L.push(`      local ou,uid=${id.P}(function() return LP.UserId end)`);
  L.push(`      if ou and uid==123456789 then ${id.safe}=0 end`);
  L.push(`      local on,nm=${id.P}(function() return LP.Name end)`);
  L.push(`      if on and nm=="vole7vin" then ${id.safe}=0 end`);
  L.push(`    end`);
  L.push(`  end`);
  L.push(`  local oL,Lg=${id.P}(function() return game:GetService("Lighting") end)`);
  L.push(`  if oL and Lg then`);
  L.push(`    local ola,lat=${id.P}(function() return Lg.GeographicLatitude end)`);
  L.push(`    local ofg,fog=${id.P}(function() return Lg.FogEnd end)`);
  L.push(`    if ola and ofg and lat==41.7 and fog==100000 then ${id.safe}=0 end`);
  L.push(`  end`);
  L.push(`end`);

  // --- timing / debug lag ---
  L.push(`local t0=(os and os.clock and os.clock()) or 0`);
  L.push(`for ${id.i}=1,60 do ${id.P}(function() return ${id.i}*${id.i}+11 end) end`);
  L.push(`local t1=(os and os.clock and os.clock()) or 0`);
  L.push(`if t1>0 and t0>0 and (t1-t0)>0.45 then ${id.safe}=0 end`);

  // --- opaque always-true ---
  L.push(`if ((${12 + ri(18) * 2}*${2 + ri(5)})%2)~=0 then ${id.safe}=0 end`);
  L.push(`local w=7 if w~=w or w*0~=0 or w<0 then ${id.safe}=0 end`);

  L.push(`end`);
  L.push(`if ${id.safe}~=1 then return function() end end`);
  return L.join('\n');
}

function build(sym, key, sum, len) {
  const id = {};
  for (const k of 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('')) {
    id[k] = rid();
  }
  id.safe = rid();
  id.ok = rid();
  id.env = rid();
  id.i = rid();
  id.T = rid();
  id.R = rid();
  id.P = rid();

  const parts = chunks(sym);
  const vLit = parts.map((p, i) => {
    const sep = i < parts.length - 1 ? (ri(4) === 0 ? ';' : ',') : '';
    return `"${p}"${sep}`;
  }).join('');

  const keySym = encBuf(key);
  const inv = invTable().join(',');
  const alphaLit = [...ALPHA].map(c => `"${c}"`).join(',');

  const fakeOps = [];
  for (let i = 0; i < 10; i++) {
    const name = rid(3);
    const n1 = 10 + ri(120);
    const n2 = 10 + ri(120);
    fakeOps.push(
      `${name}=function(${id.A},${id.B},${id.C},${id.D})` +
      `if ${id.D}<=${n1} then return ${n2},${id.B},${id.C}+1,${id.A};` +
      `else return ${n1 + 3},${id.C},${id.B},${id.D};end;end`
    );
  }

  const L = [];
  L.push(`return(function(...)`);
  L.push(antiTamperBlock(id));

  L.push(`local ${id.V}=setmetatable({`);
  L.push(fakeOps.join(','));
  L.push(`,[${40 + ri(30)}]=string.char,[${70 + ri(20)}]=string.byte,[${90 + ri(20)}]=string.sub`);
  L.push(`,RA={["|"]="Y/6&[",[" "]="?vZ*F",["#"]="9G)Iq",["!"]="2G+fq",["{"]="+JX",["~"]="olc",["}"]="KN4",y="+'fx",z="6^?6"}`);
  L.push(`,nH="°!#$%&/()=?¡",aH=":(%d+)"`);
  L.push(`},{__metatable="°!#$%&/()=?¡"})`);

  L.push(`local ${id.M}={${vLit}}`);
  L.push(`local ${id.Q}={${alphaLit}}`);
  L.push(`local ${id.R}={}`);
  L.push(`for ${id.i}=1,#${id.Q} do ${id.R}[${id.Q}[${id.i}]]=${id.i}-1 end`);
  L.push(`local ${id.K}="${keySym}"`);
  L.push(`local ${id.H}=${sum}`);
  L.push(`local ${id.I}={${inv}}`);
  L.push(`local ${id.S}=table.concat(${id.M})`);

  L.push(`local function ${id.G}(z)`);
  L.push(`local o,pos={},1`);
  L.push(`while pos<=#z do local n=0`);
  L.push(`for ${id.i}=0,${WORD - 1} do local ch=string.sub(z,pos+${id.i},pos+${id.i}) n=n*${BASE}+(${id.R}[ch] or 0) end`);
  L.push(`o[#o+1]=string.char(n%256) pos=pos+${WORD} end`);
  L.push(`return table.concat(o) end`);

  L.push(`local function ${id.U}(data,key)`);
  L.push(`local o,kl={},#key`);
  L.push(`for ${id.i}=1,#data do`);
  L.push(`local b=string.byte(data,${id.i})`);
  L.push(`local k=string.byte(key,((${id.i}-1)%kl)+1)`);
  L.push(`local p=((${id.i}-1)*131+17)%256`);
  L.push(`local q=(((${id.i}-1)*47)+(k*3))%256`);
  L.push(`b=(b+((p*3+k)%256))%256`);
  L.push(`local m=((k%2==0 and k+1 or k)*5)%256 if m==0 then m=1 end`);
  L.push(`b=((b-q+256)*${id.I}[k+1])%256`);
  L.push(`local rot=(k%7)+1 local hi=math.floor(b/(2^rot)) local lo=b%(2^rot)`);
  L.push(`b=(lo*(2^(8-rot))+hi)%256`);
  L.push(`b=(b-k-p+512)%256`);
  L.push(`o[${id.i}]=string.char(b) end`);
  L.push(`return table.concat(o) end`);

  L.push(`local ${id.W}=${id.G}(${id.S})`);
  L.push(`local ${id.X}=${id.G}(${id.K})`);

  L.push(`do local h=2654435761`);
  L.push(`for ${id.i}=1,#${id.W} do local b=string.byte(${id.W},${id.i}) h=(h+b*(${id.i}+30)+((h%89)*17)+13)%4294967296 end`);
  L.push(`if h~=${id.H} or #${id.W}~=${len} then return function()end end end`);

  // second integrity pass after decode (anti mid-flight patch)
  L.push(`local ${id.Y}=${id.U}(${id.W},${id.X})`);
  L.push(`if #${id.Y}~=${len} then return function()end end`);
  L.push(`local ${id.Z}=(loadstring or load)(${id.Y})`);
  L.push(`if type(${id.Z})~="function" then return function()end end`);
  L.push(`return ${id.Z}(...)`);
  L.push(`end)(...)`);

  return L.join('\n');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  if (Buffer.byteLength(src, 'utf8') > MAX) throw new Error('Too large');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(32 + ri(12));
  const scrambled = scramble(raw, key);
  const sum = checksum(scrambled);
  const sym = encBuf(scrambled);
  const code = build(sym, key, sum, scrambled.length);

  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'symbolic-hardened-v4',
      encoding: 'arith-scramble + custom-alphabet (NO xor)',
      antiTamper: 'aqua+env+hooks+integrity+timing'
    }
  };
}

module.exports = { obfuscate };
