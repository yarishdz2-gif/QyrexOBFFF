/**
 * QyrexObf 1.6.7
 * Outer layer: ONLY header + symbol soup + minimal decode/load
 * Anti-tamper is PREPENDED to source before scramble (invisible outside)
 * Alphabet: 0-9A-Za-z!#$%&/()=?@_:;+*~[]{}
 * NO XOR · NO Base64
 */
'use strict';
const crypto = require('crypto');

const MAX_BYTES = 1_000_000;
const ALPHA =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
  '!#$%&/()=?@_:;+*~[]{}';
const BASE = ALPHA.length;
const WORD = 2;

const rb = n => crypto.randomBytes(n);
const ri = n => rb(1)[0] % n;

function rid(n) {
  n = n || (4 + ri(3));
  const pool = 'IlOQabcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  let s = '_';
  const b = rb(n);
  for (let i = 0; i < n; i++) s += pool[b[i] % pool.length];
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
  let o = '';
  for (let i = 0; i < buf.length; i++) o += encByte(buf[i]);
  return o;
}
function decBuf(sym) {
  const map = Object.create(null);
  for (let i = 0; i < ALPHA.length; i++) map[ALPHA[i]] = i;
  const out = Buffer.allocUnsafe(sym.length / WORD);
  let j = 0;
  for (let pos = 0; pos < sym.length; pos += WORD) {
    let n = 0;
    for (let i = 0; i < WORD; i++) n = n * BASE + (map[sym[pos + i]] || 0);
    out[j++] = n & 255;
  }
  return out;
}

function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    const k = key[i % kl];
    const p = (i * 131 + 17) & 255;
    b = (b + k) & 255;
    const rot = (k % 7) + 1;
    b = ((b << rot) | (b >>> (8 - rot))) & 255;
    b = (b + p) & 255;
    const rot2 = (p % 5) + 1;
    b = ((b << rot2) | (b >>> (8 - rot2))) & 255;
    b = (b - ((k + p * 3) & 255) + 256) & 255;
    out[i] = b;
  }
  return out;
}

function unscramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    let b = data[i];
    const k = key[i % kl];
    const p = (i * 131 + 17) & 255;
    const rot = (k % 7) + 1;
    const rot2 = (p % 5) + 1;
    b = (b + ((k + p * 3) & 255)) & 255;
    b = ((b >>> rot2) | (b << (8 - rot2))) & 255;
    b = (b - p + 256) & 255;
    b = ((b >>> rot) | (b << (8 - rot))) & 255;
    b = (b - k + 256) & 255;
    out[i] = b;
  }
  return out;
}

function checksum(buf) {
  let h = 0x9e3779b1 >>> 0;
  for (let i = 0; i < buf.length; i++)
    h = (h + buf[i] * (i + 31) + ((h % 89) * 17) + 13) >>> 0;
  return h >>> 0;
}

function noise(n) {
  const b = rb(n);
  let s = '';
  for (let i = 0; i < n; i++) s += ALPHA[b[i] % BASE];
  return s;
}

function chunks(sym) {
  const parts = [];
  let i = 0;
  while (i < sym.length) {
    let n = 18 + ri(40);
    n -= n % WORD;
    if (n < WORD) n = WORD;
    const take = Math.min(sym.length - i, n);
    const aligned = take - (take % WORD) || take;
    parts.push(sym.slice(i, i + aligned));
    i += aligned;
  }
  return parts;
}

/** Anti-tamper injected INTO the encrypted payload (not visible outside) */
function antiTamperPrefix() {
  return `
do
  local _ok=1
  local _t=type
  local _r=rawget
  local _p=pcall
  if _t(pcall)~="function" then _ok=0 end
  if _t(string)~="table" and _t(string)~="userdata" then _ok=0 end
  if _t(table)~="table" and _t(table)~="userdata" then _ok=0 end
  if _t(math)~="table" and _t(math)~="userdata" then _ok=0 end
  if _t(loadstring)~="function" and _t(load)~="function" then _ok=0 end
  if string.byte("A")~=65 then _ok=0 end
  if math.floor(3.9)~=3 then _ok=0 end
  do local a=_p(function() error("x") end) if a then _ok=0 end end
  local w=7 if w~=w or w*0~=0 or w<0 then _ok=0 end
  local eok,env=_p(function() return (getfenv and getfenv(0)) or _G end)
  if not eok or _t(env)~="table" then _ok=0 end
  if _r and env then
    if _r(env,"__builtins__")~=nil then _ok=0 end
    if _r(env,"__name__")~=nil then _ok=0 end
    for _,k in ipairs({"fenv","genv","hookenv","lune","lute","process","window","document"}) do
      if _r(env,k)~=nil then _ok=0 end
    end
  end
  do local G=_G or {}
    for _,k in ipairs({"lune","lute","wally","rojo","process","window","document","navigator","__dirname","atob","btoa","setTimeout","Buffer","console"}) do
      if rawget(G,k)~=nil then _ok=0 end
    end
    if G.process and (G.process.env or G.process.platform or G.process.exit) then _ok=0 end
  end
  if game~=nil then
    if _t(game)=="table" then _ok=0 end
    if _t(typeof)=="function" and typeof(game)~="Instance" then _ok=0 end
    local oj,jid=_p(function() return game.JobId end)
    if oj and jid=="00000000-0000-0000-0000-000000000000" then _ok=0 end
    local op,pid=_p(function() return game.PlaceId end)
    if op and pid==8916037983 then _ok=0 end
    local oPl,Pl=_p(function() return game:GetService("Players") end)
    if oPl and Pl then
      local oLP,LP=_p(function() return Pl.LocalPlayer end)
      if oLP and LP then
        local ou,uid=_p(function() return LP.UserId end)
        if ou and uid==123456789 then _ok=0 end
        local on,nm=_p(function() return LP.Name end)
        if on and nm=="vole7vin" then _ok=0 end
      end
    end
  end
  do local dbg=((getfenv and getfenv()) or _G).debug
    if dbg and dbg.gethook then local a,h=_p(dbg.gethook) if a and h~=nil then _ok=0 end end
  end
  do local bad=false local ts=tostring
    _p(function() local e=(getfenv and getfenv()) or _G if e[ts({})]~=nil then bad=true end if _G and _G[ts({})]~=nil then bad=true end end)
    if bad then _ok=0 end
  end
  do if getgenv and debug and debug.getinfo then
    local ge=getgenv()
    local mt=getmetatable(ge)
    if mt and (mt.__index or mt.__newindex or mt.__metatable) then _ok=0 end
    local info=debug.getinfo(getgenv)
    if not info or info.what~="C" or info.source~="=[C]" then _ok=0 end
    if iscclosure and not iscclosure(getgenv) then _ok=0 end
    local gu=debug.getupvalue or debug.getupvalues
    if gu then local a,uv=_p(gu,getgenv,1) if a and uv~=nil then _ok=0 end end
  end end
  if _ok~=1 then return end
end
`;
}

/**
 * Outer shell: commercial look — header + dense string tables + tiny decoder
 * NO readable anti-tamper keywords on the outside
 */
function buildOuter(sym, key, sum, len) {
  const a = rid(), b = rid(), c = rid(), d = rid(), e = rid();
  const f = rid(), g = rid(), h = rid(), i = rid(), j = rid();
  const k = rid(), m = rid(), n = rid(), o = rid(), p = rid();
  const q = rid(), r = rid(), s = rid();

  const parts = chunks(sym);
  // Luraph-like mixed separators
  const vLit = parts.map((p, idx) => {
    const sep = idx < parts.length - 1 ? (ri(2) ? ';' : ',') : '';
    return `"${p}"${sep}`;
  }).join('');

  // Extra pure-noise tables (dead)
  const dead = [];
  for (let t = 0; t < 8; t++) {
    const segs = [];
    for (let s = 0; s < 6 + ri(5); s++) segs.push(`"${noise(60 + ri(80))}"`);
    dead.push(`local ${rid()}={${segs.join(',')}}`);
  }
  for (let t = 0; t < 5; t++) {
    dead.push(`local ${rid()}="${noise(2000 + ri(2000))}"`);
  }

  const keySym = encBuf(key);
  const alphaLit = ALPHA;

  const L = [];
  L.push(`-- This file was protected using Qyrex Obfuscator v1.6.7[https://qyrex.hopto.org/]`);
  L.push(`return(function(...)`);
  for (const line of dead) L.push(line);
  L.push(`local ${a}={${vLit}}`);
  L.push(`local ${b}="${noise(40 + ri(40))}"`);
  L.push(`local ${c}="${alphaLit}"`);
  L.push(`local ${d}={}`);
  L.push(`for ${e}=1,#${c} do ${d}[string.sub(${c},${e},${e})]=${e}-1 end`);
  L.push(`local ${f}="${keySym}"`);
  L.push(`local ${g}=${sum}`);
  L.push(`local ${h}=table.concat(${a})`);
  L.push(`local function ${i}(z)`);
  L.push(`local o,pos={},1`);
  L.push(`while pos<=#z do local n=0`);
  L.push(`for i=0,1 do local ch=string.sub(z,pos+i,pos+i) n=n*${BASE}+(${d}[ch] or 0) end`);
  L.push(`o[#o+1]=string.char(n%256) pos=pos+2 end`);
  L.push(`return table.concat(o) end`);
  L.push(`local function ${j}(data,key)`);
  L.push(`local o,kl={},#key`);
  L.push(`for i=1,#data do`);
  L.push(`local b=string.byte(data,i)`);
  L.push(`local k=string.byte(key,((i-1)%kl)+1)`);
  L.push(`local p=((i-1)*131+17)%256`);
  L.push(`local rot=(k%7)+1 local rot2=(p%5)+1`);
  L.push(`b=(b+((k+p*3)%256))%256`);
  L.push(`local hi=math.floor(b/(2^rot2)) local lo=b%(2^rot2) b=(lo*(2^(8-rot2))+hi)%256`);
  L.push(`b=(b-p+256)%256`);
  L.push(`hi=math.floor(b/(2^rot)) lo=b%(2^rot) b=(lo*(2^(8-rot))+hi)%256`);
  L.push(`b=(b-k+256)%256`);
  L.push(`o[i]=string.char(b) end`);
  L.push(`return table.concat(o) end`);
  L.push(`local ${k}=${i}(${h})`);
  L.push(`local ${m}=${i}(${f})`);
  L.push(`do local h=2654435761`);
  L.push(`for i=1,#${k} do local b=string.byte(${k},i) h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 end`);
  L.push(`if h~=${g} or #${k}~=${len} then return end end`);
  L.push(`local ${n}=${j}(${k},${m})`);
  L.push(`if #${n}~=${len} then return end`);
  L.push(`local ${o}=(loadstring or load)(${n})`);
  L.push(`if type(${o})~="function" then return end`);
  L.push(`return ${o}(...)`);
  L.push(`end)(...)`);

  return L.join('\n');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');

  // Anti-tamper hidden inside encrypted payload
  const wrapped = antiTamperPrefix() + '\n' + src;
  if (Buffer.byteLength(wrapped, 'utf8') > MAX_BYTES) throw new Error('Too large');

  const raw = Buffer.from(wrapped, 'utf8');
  const key = rb(36 + ri(12));
  const scrambled = scramble(raw, key);
  const sum = checksum(scrambled);
  const sym = encBuf(scrambled);

  const back = unscramble(decBuf(sym), key);
  if (!back.equals(raw)) throw new Error('roundtrip failed');

  const code = buildOuter(sym, key, sum, scrambled.length);
  return {
    code,
    stats: {
      inputBytes: Buffer.byteLength(src, 'utf8'),
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-1.6.7',
      encoding: 'outer-symbol-soup · AT-tamper-inside',
      verified: true
    }
  };
}

module.exports = { obfuscate };
