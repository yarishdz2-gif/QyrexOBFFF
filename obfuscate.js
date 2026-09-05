/**
 * QyrexObf 1.6.7 — dense Luraph-style visual + working packer
 * Label: 1.6.7 | Engine: add/rot/sub (NO xor) | ASCII alphabet for Luau bytes
 */
'use strict';
const crypto = require('crypto');

const MAX = 1_000_000;
const ALPHA =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
  '!#$%&/()=?@_:;+*~[]{}|^<>';
const BASE = ALPHA.length;
const WORD = 2;

const rb = n => crypto.randomBytes(n);
const ri = n => rb(1)[0] % n;

function rid(n) {
  n = n || (3 + ri(2));
  const A = 'IlOQZabcdefghjkmnpqrstuvwxyz';
  let s = '_';
  const b = rb(n);
  for (let i = 0; i < n; i++) s += A[b[i] % A.length];
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

function chunks(sym) {
  const parts = [];
  let i = 0;
  while (i < sym.length) {
    let n = 16 + ri(32);
    n -= n % WORD;
    if (n < WORD) n = WORD;
    const take = Math.min(sym.length - i, n);
    const aligned = take - (take % WORD) || take;
    parts.push(sym.slice(i, i + aligned));
    i += aligned;
  }
  return parts;
}

/** visual junk — pure symbol noise (not decoded) */
function junkStr() {
  const pool = '!#$%&/()=?@_:;+*~[]{}|^<>0123456789abcdefghijklmnopqrstuvwxyz';
  let s = '';
  const n = 24 + ri(40);
  const b = rb(n);
  for (let i = 0; i < n; i++) s += pool[b[i] % pool.length];
  return s;
}

function build(sym, key, sum, len) {
  // ultra short noise ids
  const a=rid(),b=rid(),c=rid(),d=rid(),e=rid(),f=rid(),g=rid(),h=rid();
  const i=rid(),j=rid(),k=rid(),m=rid(),n=rid(),o=rid(),p=rid(),q=rid();
  const r=rid(),s=rid(),t=rid(),u=rid(),v=rid(),w=rid(),x=rid(),y=rid(),z=rid();

  const parts = chunks(sym);
  // Luraph-like separators ; and ,
  const vLit = parts.map((p, idx) => {
    const sep = idx < parts.length - 1 ? (ri(2) ? ';' : ',') : '';
    return `"${p}"${sep}`;
  }).join('');

  const keySym = encBuf(key);
  const alphaLit = ALPHA.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const j1 = junkStr(), j2 = junkStr(), j3 = junkStr();

  // Compact Luraph-ish shell — minimal readable surface
  // anti-tamper kept but compressed
  const code =
`-- Protect by QyrexObf 1.6.7
return(function(...)local ${a}=1;local ${b}=type;local ${c}=rawget;local ${d}=pcall;do if ${b}(pcall)~="function"then ${a}=0 end;if ${b}(string)~="table"and ${b}(string)~="userdata"then ${a}=0 end;if ${b}(table)~="table"and ${b}(table)~="userdata"then ${a}=0 end;if ${b}(math)~="table"and ${b}(math)~="userdata"then ${a}=0 end;if ${b}(loadstring)~="function"and ${b}(load)~="function"then ${a}=0 end;if string.byte("A")~=65 then ${a}=0 end;if math.floor(3.9)~=3 then ${a}=0 end;do local ${e}=${d}(error,"x",0)if ${e} then ${a}=0 end end;local ${f},${g}=${d}(function()return(getfenv and getfenv(0))or _G end)if not ${f}or ${b}(${g})~="table"then ${a}=0 end;if ${c}and ${g}then if ${c}(${g},"__builtins__")~=nil then ${a}=0 end;if ${c}(${g},"__name__")~=nil then ${a}=0 end end;do local G=_G or{};for _,k in ipairs({"lune","lute","process","window","document","navigator","__dirname","atob","btoa"})do if rawget(G,k)~=nil then ${a}=0 end end end;if game~=nil then if ${b}(game)==${b}({})then ${a}=0 end;local oj,jid=${d}(function()return game.JobId end)if oj and jid=="00000000-0000-0000-0000-000000000000"then ${a}=0 end;local op,pid=${d}(function()return game.PlaceId end)if op and pid==8916037983 then ${a}=0 end;local oPl,Pl=${d}(function()return game:GetService("Players")end)if oPl and Pl then local oLP,LP=${d}(function()return Pl.LocalPlayer end)if oLP and LP then local ou,uid=${d}(function()return LP.UserId end)if ou and uid==123456789 then ${a}=0 end end end end end;if ${a}~=1 then return function()end end;local ${h}={${vLit}};local ${i}="${j1}";local ${j}="${j2}";local ${k}="${j3}";local ${m}="${alphaLit}";local ${n}={};for ${o}=1,#${m} do ${n}[string.sub(${m},${o},${o})]=${o}-1 end;local ${p}="${keySym}";local ${q}=${sum};local ${r}=table.concat(${h});local function ${s}(z)local o,pos={},1;while pos<=#z do local n=0;for i=0,1 do local ch=string.sub(z,pos+i,pos+i);n=n*${BASE}+(${n}[ch]or 0)end;o[#o+1]=string.char(n%256);pos=pos+2 end;return table.concat(o)end;local function ${t}(data,key)local o,kl={},#key;for i=1,#data do local b=string.byte(data,i);local k=string.byte(key,((i-1)%kl)+1);local p=((i-1)*131+17)%256;local rot=(k%7)+1;local rot2=(p%5)+1;b=(b+((k+p*3)%256))%256;local hi=math.floor(b/(2^rot2));local lo=b%(2^rot2);b=(lo*(2^(8-rot2))+hi)%256;b=(b-p+256)%256;hi=math.floor(b/(2^rot));lo=b%(2^rot);b=(lo*(2^(8-rot))+hi)%256;b=(b-k+256)%256;o[i]=string.char(b)end;return table.concat(o)end;local ${u}=${s}(${r});local ${v}=${s}(${p});do local h=2654435761;for i=1,#${u} do local b=string.byte(${u},i);h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 end;if h~=${q} or #${u}~=${len} then return function()end end end;local ${w}=${t}(${u},${v});if #${w}~=${len} then return function()end end;local ${x}=(loadstring or load)(${w});if type(${x})~="function"then return function()end end;return ${x}(...)end)(...)`;

  return code;
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  if (Buffer.byteLength(src, 'utf8') > MAX) throw new Error('Too large');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(32 + ri(8));
  const scrambled = scramble(raw, key);
  const sum = checksum(scrambled);
  const sym = encBuf(scrambled);

  const back = unscramble(decBuf(sym), key);
  if (!back.equals(raw)) throw new Error('roundtrip failed');

  const code = build(sym, key, sum, scrambled.length);
  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-1.6.7',
      encoding: 'add+rot+sub (NO xor) + dense symbol payload',
      verified: true
    }
  };
}

module.exports = { obfuscate };
