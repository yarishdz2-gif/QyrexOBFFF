/**
 * Symbolic Overload v5 — single-line max density
 * Output: ONE LINE · payload is pure symbol soup · minimal bootstrap
 * NO XOR · NO std Base64 · arithmetic scramble only
 */
'use strict';
const crypto = require('crypto');

const MAX = 1_000_000;
// Dense alphabet — symbols the user asked for
const ALPHA =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
  '!#$%&/()=?¡°@_:;+*~[]{}|^<>';
const BASE = ALPHA.length;
const WORD = 2;

const rb = n => crypto.randomBytes(n);
const ri = n => rb(1)[0] % n;

function rid(n) {
  n = n || (4 + ri(3));
  // look like noise: mix letters that look random
  const A = 'IlOQZabcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYabcdefgh';
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
    let n = 14 + ri(28);
    n -= n % WORD;
    if (n < WORD) n = WORD;
    const take = Math.min(sym.length - i, n);
    const aligned = take - (take % WORD) || take;
    parts.push(sym.slice(i, i + aligned));
    i += aligned;
  }
  return parts;
}

function build(sym, key, sum, len) {
  // ultra-short ids
  const a = rid(5), b = rid(5), c = rid(5), d = rid(5), e = rid(5);
  const f = rid(5), g = rid(5), h = rid(5), i = rid(5), j = rid(5);
  const k = rid(5), m = rid(5), n = rid(5), o = rid(5), p = rid(5);
  const q = rid(5), r = rid(5), s = rid(5), t = rid(5), u = rid(5);
  const v = rid(5), w = rid(5), x = rid(5), y = rid(5), z = rid(5);

  const parts = chunks(sym);
  // dense table: only symbols/digits inside strings
  const vLit = parts.map((p, idx) => {
    const sep = idx < parts.length - 1 ? (ri(3) ? ',' : ';') : '';
    return `"${p}"${sep}`;
  }).join('');

  const keySym = encBuf(key);
  const inv = invTable().join(',');
  // alphabet as pure string then split at runtime to avoid readable char list
  const alphaStr = ALPHA.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

  // SINGLE LINE — everything compacted
  // anti-tamper kept but minified
  const code =
`return(function(...)local ${a}=1;local ${b}=type;local ${c}=rawget;local ${d}=pcall;do if ${b}(pcall)~="function"then ${a}=0 end;if ${b}(string)~="table"and ${b}(string)~="userdata"then ${a}=0 end;if ${b}(table)~="table"and ${b}(table)~="userdata"then ${a}=0 end;if ${b}(math)~="table"and ${b}(math)~="userdata"then ${a}=0 end;if ${b}(loadstring)~="function"and ${b}(load)~="function"then ${a}=0 end;if ${b}(rawget)~="function"or ${b}(rawset)~="function"then ${a}=0 end;if string.byte("A")~=65 then ${a}=0 end;if math.floor(3.9)~=3 then ${a}=0 end;if math.floor(math.pi)~=3 then ${a}=0 end;do local ${e}=${d}(error,"\\0",0)if ${e} then ${a}=0 end end;local ${f},${g}=${d}(function()return(getfenv and getfenv(0))or _G end)if not ${f} or ${b}(${g})~="table"then ${a}=0 end;if ${c} and ${g} then if ${c}(${g},"__builtins__")~=nil then ${a}=0 end;if ${c}(${g},"__name__")~=nil then ${a}=0 end;for _,${h} in ipairs({"fenv","_fenv","genv","hookenv","_env"})do if ${c}(${g},${h})~=nil then ${a}=0 end end end;if game~=nil then if ${b}(game)==${b}({})then ${a}=0 end;if ${b}(typeof)=="function"and typeof(game)=="table"then ${a}=0 end;local ${i},${j}=${d}(getmetatable,game)if ${i} and ${b}(${j})==${b}({})then ${a}=0 end;local ${k},${m}=${d}(function()return game.JobId end)if ${k} and ${m}=="00000000-0000-0000-0000-000000000000"then ${a}=0 end;local ${n},${o}=${d}(function()return game.PlaceId end)if ${n} and ${o}==8916037983 then ${a}=0 end;local ${p},${q}=${d}(function()return game:GetService("Players")end)if ${p} and ${q} then local ${r},${s}=${d}(function()return ${q}.LocalPlayer end)if ${r} and ${s} then local ${t},${u}=${d}(function()return ${s}.UserId end)if ${t} and ${u}==123456789 then ${a}=0 end end end end;local ${v}=(os and os.clock and os.clock())or 0;for ${w}=1,55 do ${d}(function()return ${w}*${w}+9 end)end;local ${x}=(os and os.clock and os.clock())or 0;if ${x}>0 and ${v}>0 and(${x}-${v})>0.45 then ${a}=0 end;if((${14+ri(10)*2}*${2+ri(4)})%2)~=0 then ${a}=0 end end;if ${a}~=1 then return function()end end;local ${y}={${vLit}};local ${rid()}="°!".."#$%&/()=?¡°!".."#$%&/()=?@@@";local ${rid()}=":slkas:s_".."!#$%&/()=?¡";local ${z}="${alphaStr}";local ${rid()}={};local ${rid(4)}=1;local _A={};for _B=1,#${z} do _A[string.sub(${z},_B,_B)]=_B-1 end;local _C="${keySym}";local _D=${sum};local _E={${inv}};local _F=table.concat(${y});local function _G(z)local o,pos={},1;while pos<=#z do local n=0;for i=0,${WORD-1} do local ch=string.sub(z,pos+i,pos+i);n=n*${BASE}+(_A[ch]or 0)end;o[#o+1]=string.char(n%256);pos=pos+${WORD} end;return table.concat(o)end;local function _H(data,key)local o,kl={},#key;for i=1,#data do local b=string.byte(data,i);local k=string.byte(key,((i-1)%kl)+1);local p=((i-1)*131+17)%256;local q=(((i-1)*47)+(k*3))%256;b=(b+((p*3+k)%256))%256;local m=((k%2==0 and k+1 or k)*5)%256;if m==0 then m=1 end;b=((b-q+256)*_E[k+1])%256;local rot=(k%7)+1;local hi=math.floor(b/(2^rot));local lo=b%(2^rot);b=(lo*(2^(8-rot))+hi)%256;b=(b-k-p+512)%256;o[i]=string.char(b)end;return table.concat(o)end;local _I=_G(_F);local _J=_G(_C);do local h=2654435761;for i=1,#_I do local b=string.byte(_I,i);h=(h+b*(i+30)+((h%89)*17)+13)%4294967296 end;if h~=_D or #_I~=${len} then return function()end end end;local _K=_H(_I,_J);if #_K~=${len} then return function()end end;local _L=(loadstring or load)(_K);if type(_L)~="function"then return function()end end;return _L(...)end)(...)`;

  // force single line (strip any accidental newlines)
  return code.replace(/\s*\n\s*/g, ' ').replace(/\s+/g, ' ').trim();
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');
  if (Buffer.byteLength(src, 'utf8') > MAX) throw new Error('Too large');

  const raw = Buffer.from(src, 'utf8');
  const key = rb(36 + ri(16));
  const scrambled = scramble(raw, key);
  const sum = checksum(scrambled);
  const sym = encBuf(scrambled);
  const code = build(sym, key, sum, scrambled.length);

  return {
    code,
    stats: {
      inputBytes: raw.length,
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'symbolic-oneline-v5',
      encoding: 'arith-scramble + dense-alphabet (NO xor)',
      lines: 1
    }
  };
}

module.exports = { obfuscate };
