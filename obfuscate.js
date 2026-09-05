/**
 * QyrexObf 1.6.7 — Symbolic Chaos Generator
 * ---------------------------------------------------------------
 * Generator (Node) that emits a self-decoding Luau script.
 *
 * Layers:
 *  1) Extended ASCII symbol alphabet (Luau-safe, byte-indexed)
 *  2) Reversible scramble: add → rotL → add → rotL → sub
 *     (NO XOR, NO Base64)
 *  3) Integrity checksum (32-bit rolling hash) before load
 *  4) Anti-tamper stack (env / sandbox / Obscura / getgenv)
 *  5) Isolated do-block + random local ids
 *
 * Usage:
 *   const { obfuscate } = require('./obfuscate');
 *   const { code } = obfuscate(sourceString);
 */
'use strict';
const crypto = require('crypto');

const MAX_BYTES = 1_000_000;

/* ------------------------------------------------------------------
 * 1) Extended chaotic alphabet (ASCII only — Luau string.sub is
 *    byte-based; multi-byte UTF-8 would break decoding)
 * ------------------------------------------------------------------ */
const ALPHA =
  '0123456789' +
  'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
  'abcdefghijklmnopqrstuvwxyz' +
  '!#$%&/()=?@_:;+*~[]{}|^<>';
const BASE = ALPHA.length; // 88
const WORD = 2;            // BASE^2 = 7744 > 255

const rb = n => crypto.randomBytes(n);
const ri = n => rb(1)[0] % n;

/** Random local identifier */
function rid(len) {
  len = len || (5 + ri(4));
  const pool = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  let s = '_';
  const b = rb(len);
  for (let i = 0; i < len; i++) s += pool[b[i] % pool.length];
  return s;
}

/* ------------------------------------------------------------------
 * Symbol encode / decode (base-BASE digit pairs)
 * ------------------------------------------------------------------ */
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
  let out = '';
  for (let i = 0; i < buf.length; i++) out += encByte(buf[i]);
  return out;
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

/* ------------------------------------------------------------------
 * 2) Reversible scramble — add / rotate / sub only (NO XOR)
 * ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------
 * 3) Integrity hash (32-bit rolling)
 * ------------------------------------------------------------------ */
function checksum(buf) {
  let h = 0x9e3779b1 >>> 0;
  for (let i = 0; i < buf.length; i++) {
    h = (h + buf[i] * (i + 31) + ((h % 89) * 17) + 13) >>> 0;
  }
  return h >>> 0;
}

function chunkPayload(sym) {
  const parts = [];
  let i = 0;
  while (i < sym.length) {
    let n = 12 + ri(24);
    n -= n % WORD;
    if (n < WORD) n = WORD;
    const take = Math.min(sym.length - i, n);
    const aligned = take - (take % WORD) || take;
    parts.push(sym.slice(i, i + aligned));
    i += aligned;
  }
  return parts;
}

function junk() {
  const pool = '!#$%&/()=?@_:;+*~[]{}|^<>0123456789abcdefghijk';
  let s = '';
  const n = 18 + ri(28);
  const b = rb(n);
  for (let i = 0; i < n; i++) s += pool[b[i] % pool.length];
  return s;
}

/* ------------------------------------------------------------------
 * 4–5) Emit Luau loader (multi-line, isolated, anti-tamper)
 * ------------------------------------------------------------------ */
function buildLuau(sym, key, sum, len) {
  const id = {};
  for (const c of 'ABCDEFGHIJKLMNOPQRSTUV') id[c] = rid();

  const parts = chunkPayload(sym);
  const vLit = parts.map((p, i) => {
    const sep = i < parts.length - 1 ? (ri(3) ? ',' : ';') : '';
    return `"${p}"${sep}`;
  }).join('');

  const keySym = encBuf(key);
  const alphaLit = ALPHA.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const j1 = junk();
  const j2 = junk();

  const L = [];
  L.push(`-- Protect by QyrexObf 1.6.7`);
  L.push(`return(function(...)`);
  L.push(`do`);

  /* ---- native existence + anti-tamper ---- */
  L.push(`local ${id.A}=1`);
  L.push(`local ${id.B}=type`);
  L.push(`local ${id.C}=rawget`);
  L.push(`local ${id.D}=pcall`);
  L.push(`if ${id.B}(pcall)~="function" then ${id.A}=0 end`);
  L.push(`if ${id.B}(string)~="table" and ${id.B}(string)~="userdata" then ${id.A}=0 end`);
  L.push(`if ${id.B}(table)~="table" and ${id.B}(table)~="userdata" then ${id.A}=0 end`);
  L.push(`if ${id.B}(math)~="table" and ${id.B}(math)~="userdata" then ${id.A}=0 end`);
  L.push(`if ${id.B}(loadstring)~="function" and ${id.B}(load)~="function" then ${id.A}=0 end`);
  L.push(`if ${id.B}(rawget)~="function" or ${id.B}(rawset)~="function" then ${id.A}=0 end`);
  L.push(`if string.byte("A")~=65 then ${id.A}=0 end`);
  L.push(`if math.floor(3.9)~=3 then ${id.A}=0 end`);
  L.push(`if math.floor(math.pi)~=3 then ${id.A}=0 end`);
  L.push(`do local ok=${id.D}(function() error("x") end) if ok then ${id.A}=0 end end`);
  L.push(`local w=7 if w~=w or w*0~=0 or w<0 then ${id.A}=0 end`);

  /* env / injection */
  L.push(`local ${id.E},${id.F}=${id.D}(function() return (getfenv and getfenv(0)) or _G end)`);
  L.push(`if not ${id.E} or ${id.B}(${id.F})~="table" then ${id.A}=0 end`);
  L.push(`if ${id.C} and ${id.F} then`);
  L.push(`if ${id.C}(${id.F},"__builtins__")~=nil then ${id.A}=0 end`);
  L.push(`if ${id.C}(${id.F},"__name__")~=nil then ${id.A}=0 end`);
  L.push(`for _,k in ipairs({"fenv","genv","hookenv","lune","lute","process","window","document"}) do`);
  L.push(`if ${id.C}(${id.F},k)~=nil then ${id.A}=0 end end`);
  L.push(`end`);

  /* offline sandbox tool globals */
  L.push(`do local G=_G or {}`);
  L.push(`for _,k in ipairs({"lune","lute","wally","rojo","process","window","document","navigator","__dirname","atob","btoa","setTimeout","Buffer","console"}) do`);
  L.push(`if rawget(G,k)~=nil then ${id.A}=0 end end`);
  L.push(`if G.process and (G.process.env or G.process.platform or G.process.exit) then ${id.A}=0 end`);
  L.push(`end`);

  /* Roblox / Aqua fingerprints */
  L.push(`if game~=nil then`);
  L.push(`if ${id.B}(game)==${id.B}({}) or ${id.B}(game)=="table" then ${id.A}=0 end`);
  L.push(`if ${id.B}(typeof)=="function" and typeof(game)~="Instance" then ${id.A}=0 end`);
  L.push(`local om,mt=${id.D}(getmetatable,game)`);
  L.push(`if om and ${id.B}(mt)==${id.B}({}) then ${id.A}=0 end`);
  L.push(`local oj,jid=${id.D}(function() return game.JobId end)`);
  L.push(`if oj and jid=="00000000-0000-0000-0000-000000000000" then ${id.A}=0 end`);
  L.push(`local op,pid=${id.D}(function() return game.PlaceId end)`);
  L.push(`if op and pid==8916037983 then ${id.A}=0 end`);
  L.push(`local og,gid=${id.D}(function() return game.GameId end)`);
  L.push(`if og and gid==8916037983 then ${id.A}=0 end`);
  L.push(`local oPl,Pl=${id.D}(function() return game:GetService("Players") end)`);
  L.push(`if oPl and Pl then`);
  L.push(`local oLP,LP=${id.D}(function() return Pl.LocalPlayer end)`);
  L.push(`if oLP and LP then`);
  L.push(`local ou,uid=${id.D}(function() return LP.UserId end)`);
  L.push(`if ou and uid==123456789 then ${id.A}=0 end`);
  L.push(`local on,nm=${id.D}(function() return LP.Name end)`);
  L.push(`if on and nm=="vole7vin" then ${id.A}=0 end`);
  L.push(`end end`);
  L.push(`local oL,Lg=${id.D}(function() return game:GetService("Lighting") end)`);
  L.push(`if oL and Lg then`);
  L.push(`local ola,lat=${id.D}(function() return Lg.GeographicLatitude end)`);
  L.push(`local ofg,fog=${id.D}(function() return Lg.FogEnd end)`);
  L.push(`if ola and ofg and lat==41.7 and fog==100000 then ${id.A}=0 end`);
  L.push(`end`);
  L.push(`end`);

  /* Obscura-style hooks */
  L.push(`do local dbg=((getfenv and getfenv()) or _G).debug`);
  L.push(`if dbg and dbg.gethook then local ok,h=${id.D}(dbg.gethook) if ok and h~=nil then ${id.A}=0 end end`);
  L.push(`end`);
  L.push(`do local bad=false local ts=tostring`);
  L.push(`${id.D}(function() local e=(getfenv and getfenv()) or _G if e[ts({})]~=nil then bad=true end if _G and _G[ts({})]~=nil then bad=true end end)`);
  L.push(`if bad then ${id.A}=0 end end`);
  L.push(`do local env=(getfenv and getfenv()) or _G`);
  L.push(`local hc=env and env.isfunctionhooked`);
  L.push(`if hc and rawget then`);
  L.push(`local rf=rawget(env,"request") or rawget(env,"http_request")`);
  L.push(`if rf then local ok,h=${id.D}(hc,rf) if ok and h==true then ${id.A}=0 end end`);
  L.push(`local ls=rawget(env,"loadstring")`);
  L.push(`if ls then local ok,h=${id.D}(hc,ls) if ok and h==true then ${id.A}=0 end end`);
  L.push(`end end`);
  L.push(`do if getgenv and debug and debug.getinfo then`);
  L.push(`local ge=getgenv()`);
  L.push(`local mt=getmetatable(ge)`);
  L.push(`if mt and (mt.__index or mt.__newindex or mt.__metatable) then ${id.A}=0 end`);
  L.push(`local info=debug.getinfo(getgenv)`);
  L.push(`if not info or info.what~="C" or info.source~="=[C]" then ${id.A}=0 end`);
  L.push(`if iscclosure and not iscclosure(getgenv) then ${id.A}=0 end`);
  L.push(`local gu=debug.getupvalue or debug.getupvalues`);
  L.push(`if gu then local ok,uv=${id.D}(gu,getgenv,1) if ok and uv~=nil then ${id.A}=0 end end`);
  L.push(`local x="_t" ge[x]=1 if rawget(ge,x)~=1 then ${id.A}=0 end ge[x]=nil`);
  L.push(`end end`);

  /* opaque always-true */
  L.push(`if ((${12 + ri(10) * 2}*${2 + ri(4)})%2)~=0 then ${id.A}=0 end`);
  L.push(`if ${id.A}~=1 then return function() end end`);

  /* ---- payload table (symbol noise) ---- */
  L.push(`local ${id.G}={${vLit}}`);
  L.push(`local ${id.H}="${j1}"`);
  L.push(`local ${id.I}="${j2}"`);
  L.push(`local ${id.J}="${alphaLit}"`);
  L.push(`local ${id.K}={}`);
  L.push(`for ${id.L}=1,#${id.J} do ${id.K}[string.sub(${id.J},${id.L},${id.L})]=${id.L}-1 end`);
  L.push(`local ${id.M}="${keySym}"`);
  L.push(`local ${id.N}=${sum}`);
  L.push(`local ${id.O}=table.concat(${id.G})`);

  /* decode symbols → bytes */
  L.push(`local function ${id.P}(z)`);
  L.push(`local o,pos={},1`);
  L.push(`while pos<=#z do`);
  L.push(`local n=0`);
  L.push(`for i=0,${WORD - 1} do`);
  L.push(`local ch=string.sub(z,pos+i,pos+i)`);
  L.push(`n=n*${BASE}+(${id.K}[ch] or 0)`);
  L.push(`end`);
  L.push(`o[#o+1]=string.char(n%256)`);
  L.push(`pos=pos+${WORD}`);
  L.push(`end`);
  L.push(`return table.concat(o)`);
  L.push(`end`);

  /* unscramble (mirror of Node scramble) */
  L.push(`local function ${id.Q}(data,key)`);
  L.push(`local o,kl={},#key`);
  L.push(`for i=1,#data do`);
  L.push(`local b=string.byte(data,i)`);
  L.push(`local k=string.byte(key,((i-1)%kl)+1)`);
  L.push(`local p=((i-1)*131+17)%256`);
  L.push(`local rot=(k%7)+1`);
  L.push(`local rot2=(p%5)+1`);
  L.push(`b=(b+((k+p*3)%256))%256`);
  L.push(`local hi=math.floor(b/(2^rot2)) local lo=b%(2^rot2)`);
  L.push(`b=(lo*(2^(8-rot2))+hi)%256`);
  L.push(`b=(b-p+256)%256`);
  L.push(`hi=math.floor(b/(2^rot)) lo=b%(2^rot)`);
  L.push(`b=(lo*(2^(8-rot))+hi)%256`);
  L.push(`b=(b-k+256)%256`);
  L.push(`o[i]=string.char(b)`);
  L.push(`end`);
  L.push(`return table.concat(o)`);
  L.push(`end`);

  /* integrity + load */
  L.push(`local ${id.R}=${id.P}(${id.O})`);
  L.push(`local ${id.S}=${id.P}(${id.M})`);
  L.push(`do local h=2654435761`);
  L.push(`for i=1,#${id.R} do local b=string.byte(${id.R},i) h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 end`);
  L.push(`if h~=${id.N} or #${id.R}~=${len} then return function() end end`);
  L.push(`end`);
  L.push(`local ${id.T}=${id.Q}(${id.R},${id.S})`);
  L.push(`if #${id.T}~=${len} then return function() end end`);
  L.push(`local ${id.U}=(loadstring or load)(${id.T})`);
  L.push(`if type(${id.U})~="function" then return function() end end`);
  L.push(`return ${id.U}(...)`);
  L.push(`end`);
  L.push(`end)(...)`);

  return L.join('\n');
}

/**
 * Public API
 * @param {string} source  plain Luau/Lua source
 * @returns {{ code: string, stats: object }}
 */
function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  if (Buffer.byteLength(src, 'utf8') > MAX_BYTES) throw new Error('Too large');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(32 + ri(8));
  const scrambled = scramble(raw, key);
  const sum = checksum(scrambled);
  const sym = encBuf(scrambled);

  // hard verify before emit
  const round = unscramble(decBuf(sym), key);
  if (!round.equals(raw)) throw new Error('Internal roundtrip failure');

  const code = buildLuau(sym, key, sum, scrambled.length);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-1.6.7',
      alphabetSize: BASE,
      encoding: 'symbol-base + add/rot/sub (NO xor, NO base64)',
      antiTamper: true,
      verified: true
    }
  };
}

module.exports = { obfuscate };
