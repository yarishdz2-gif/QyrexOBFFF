/**
 * Symbolic Overload v3 — dense setmetatable shell
 * Style target: return setmetatable({...handlers...},{__call=...})(...)
 * NO XOR · NO standard Base64 · arithmetic scramble only
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

function build(sym, key, sum, len) {
  const id = {
    A: rid(), B: rid(), C: rid(), D: rid(), E: rid(),
    F: rid(), G: rid(), H: rid(), I: rid(), J: rid(),
    K: rid(), L: rid(), M: rid(), N: rid(), O: rid(),
    P: rid(), Q: rid(), R: rid(), S: rid(), T: rid(),
    U: rid(), V: rid(), W: rid(), X: rid(), Y: rid(),
    Z: rid(), safe: rid(), go: rid()
  };

  const parts = chunks(sym);
  const vLit = parts.map((p, i) => {
    const sep = i < parts.length - 1 ? (ri(4) === 0 ? ';' : ',') : '';
    return `"${p}"${sep}`;
  }).join('');

  const keySym = encBuf(key);
  const inv = invTable().join(',');
  const alphaLit = [...ALPHA].map(c => `"${c}"`).join(',');

  // Fake opcode handlers for visual density (never executed meaningfully)
  const fakeOps = [];
  for (let i = 0; i < 8; i++) {
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

  // --- anti-tamper block (clean, no XOR, no infinite hang on legit) ---
  L.push(`local ${id.safe}=1`);
  L.push(`do`);
  L.push(`local ${id.A}=type`);
  L.push(`if ${id.A}(pcall)~="function" then ${id.safe}=0 end`);
  L.push(`if ${id.A}(string)~="table" and ${id.A}(string)~="userdata" then ${id.safe}=0 end`);
  L.push(`if ${id.A}(table)~="table" and ${id.A}(table)~="userdata" then ${id.safe}=0 end`);
  L.push(`if ${id.A}(loadstring)~="function" and ${id.A}(load)~="function" then ${id.safe}=0 end`);
  L.push(`local ${id.B},${id.C}=pcall(function()return(getfenv and getfenv(0))or _G end)`);
  L.push(`if not ${id.B} or ${id.A}(${id.C})~="table" then ${id.safe}=0 end`);
  L.push(`if rawget and ${id.C} and rawget(${id.C},"__builtins__")~=nil then ${id.safe}=0 end`);
  L.push(`if rawget and ${id.C} and rawget(${id.C},"__name__")~=nil then ${id.safe}=0 end`);
  // timing probe
  L.push(`local ${id.D}=(os and os.clock and os.clock())or 0`);
  L.push(`for ${id.E}=1,50 do pcall(function()return ${id.E}*${id.E}+7 end) end`);
  L.push(`local ${id.F}=(os and os.clock and os.clock())or 0`);
  L.push(`if ${id.F}>0 and ${id.D}>0 and (${id.F}-${id.D})>0.4 then ${id.safe}=0 end`);
  // opaque always-true
  L.push(`if ((${12 + ri(20) * 2}*${2 + ri(6)})%2)~=0 then ${id.safe}=0 end`);
  L.push(`end`);
  L.push(`if ${id.safe}~=1 then return function()end end`);

  // dense handler table (looks like VM)
  L.push(`local ${id.V}=setmetatable({`);
  L.push(fakeOps.join(','));
  L.push(`,[${44 + ri(20)}]=string.char`);
  L.push(`,[${60 + ri(20)}]=string.byte`);
  L.push(`,[${80 + ri(20)}]=string.sub`);
  L.push(`,[${100 + ri(20)}]=table.concat`);
  L.push(`,RA={["|"]="Y/6&[",[" "]="?vZ*F",["#"]="9G)Iq",["!"]="2G+fq",["{"]="+JX",["~"]="olc",["}"]="KN4",y="+'fx",z="6^?6"}`);
  L.push(`,nH="?",aH=":(%d+)"`);
  L.push(`},{__index=function(t,k)return t end,__metatable="°!#$%&/()=?¡"})`);

  // payload table
  L.push(`local ${id.P}={${vLit}}`);
  L.push(`local ${id.Q}={${alphaLit}}`);
  L.push(`local ${id.R}={}`);
  L.push(`for ${id.E}=1,#${id.Q} do ${id.R}[${id.Q}[${id.E}]]=${id.E}-1 end`);
  L.push(`local ${id.K}="${keySym}"`);
  L.push(`local ${id.H}=${sum}`);
  L.push(`local ${id.I}={${inv}}`);
  L.push(`local ${id.T}=table.concat(${id.P})`);

  // decode
  L.push(`local function ${id.go}(z)`);
  L.push(`local o,pos={},1`);
  L.push(`while pos<=#z do local n=0`);
  L.push(`for ${id.E}=0,${WORD - 1} do local ch=string.sub(z,pos+${id.E},pos+${id.E}) n=n*${BASE}+(${id.R}[ch] or 0) end`);
  L.push(`o[#o+1]=string.char(n%256) pos=pos+${WORD} end`);
  L.push(`return table.concat(o) end`);

  // unscramble (arithmetic inverse only)
  L.push(`local function ${id.U}(data,key)`);
  L.push(`local o,kl={},#key`);
  L.push(`for ${id.E}=1,#data do`);
  L.push(`local b=string.byte(data,${id.E})`);
  L.push(`local k=string.byte(key,((${id.E}-1)%kl)+1)`);
  L.push(`local p=((${id.E}-1)*131+17)%256`);
  L.push(`local q=(((${id.E}-1)*47)+(k*3))%256`);
  L.push(`b=(b+((p*3+k)%256))%256`);
  L.push(`local m=((k%2==0 and k+1 or k)*5)%256 if m==0 then m=1 end`);
  L.push(`b=((b-q+256)*${id.I}[k+1])%256`);
  L.push(`local rot=(k%7)+1 local hi=math.floor(b/(2^rot)) local lo=b%(2^rot)`);
  L.push(`b=(lo*(2^(8-rot))+hi)%256`);
  L.push(`b=(b-k-p+512)%256`);
  L.push(`o[${id.E}]=string.char(b) end`);
  L.push(`return table.concat(o) end`);

  L.push(`local ${id.W}=${id.go}(${id.T})`);
  L.push(`local ${id.X}=${id.go}(${id.K})`);

  // integrity
  L.push(`do local h=2654435761`);
  L.push(`for ${id.E}=1,#${id.W} do local b=string.byte(${id.W},${id.E}) h=(h+b*(${id.E}+30)+((h%89)*17)+13)%4294967296 end`);
  L.push(`if h~=${id.H} or #${id.W}~=${len} then return function()end end end`);

  L.push(`local ${id.Y}=${id.U}(${id.W},${id.X})`);
  L.push(`local ${id.Z}=(loadstring or load)(${id.Y})`);
  L.push(`if type(${id.Z})=="function" then return ${id.Z}(...) end`);
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
      mode: 'symbolic-mt-v3',
      encoding: 'arith-scramble + custom-alphabet (NO xor / NO std base64)',
      antiTamper: true
    }
  };
}

module.exports = { obfuscate };
