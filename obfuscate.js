'use strict';

/**
 * Lightweight Lua/Luau obfuscator (pure JS, no luac required).
 * Layers: minify-ish strip, string encrypt, number encode,
 * name mangle, junk injection, control-flow wrappers.
 */

const KEYWORDS = new Set([
  'and','break','do','else','elseif','end','false','for','function','goto','if',
  'in','local','nil','not','or','repeat','return','then','true','until','while',
  // Luau / Roblox common
  'continue','type','export','typeof'
]);

const BUILTINS = new Set([
  'print','warn','error','assert','type','typeof','tostring','tonumber','pairs','ipairs',
  'next','select','unpack','pcall','xpcall','getfenv','setfenv','rawget','rawset','rawequal',
  'setmetatable','getmetatable','require','loadstring','load','collectgarbage',
  'game','workspace','script','shared','_G','getgenv','getrenv','getsenv',
  'Instance','Vector3','Vector2','CFrame','Color3','UDim2','UDim','BrickColor','Ray',
  'Enum','task','tick','wait','spawn','delay','time','os','math','string','table','bit32',
  'utf8','buffer','debug','coroutine','proxy','newproxy'
]);

function randInt(a, b) {
  return a + Math.floor(Math.random() * (b - a + 1));
}

function randIdent(len) {
  const chars = 'IlO01';
  let s = '_';
  for (let i = 0; i < len; i++) s += chars[randInt(0, chars.length - 1)];
  return s + randInt(10, 99);
}

function xorEncrypt(str, key) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    out.push(str.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return out;
}

function encodeNumber(n) {
  if (!Number.isFinite(n) || Math.abs(n) > 1e12) return String(n);
  const styles = [
    () => {
      const a = randInt(2, 40);
      const b = n - a;
      return `(${a}+${b})`;
    },
    () => {
      const a = randInt(2, 30);
      return `(${n * a}/${a})`;
    },
    () => {
      if (n === 0) return '(#{})';
      const a = randInt(3, 20);
      return `(${n + a}-${a})`;
    },
    () => String(n)
  ];
  return styles[randInt(0, styles.length - 1)]();
}

function stripCommentsAndStrings(src) {
  // Extract strings & comments so we don't touch them during rename
  const parts = [];
  let i = 0;
  let out = '';
  while (i < src.length) {
    // long comment --[[ ]]
    if (src[i] === '-' && src[i + 1] === '-' && src[i + 2] === '[' && src[i + 3] === '[') {
      let j = i + 4;
      while (j < src.length - 1 && !(src[j] === ']' && src[j + 1] === ']')) j++;
      j += 2;
      out += ' ';
      i = j;
      continue;
    }
    // line comment
    if (src[i] === '-' && src[i + 1] === '-') {
      let j = i + 2;
      while (j < src.length && src[j] !== '\n') j++;
      out += ' ';
      i = j;
      continue;
    }
    // long string [[ ]]
    if (src[i] === '[' && src[i + 1] === '[') {
      let j = i + 2;
      while (j < src.length - 1 && !(src[j] === ']' && src[j + 1] === ']')) j++;
      j += 2;
      const raw = src.slice(i + 2, j - 2);
      const id = parts.length;
      parts.push({ type: 'long', value: raw });
      out += `__STR${id}__`;
      i = j;
      continue;
    }
    // quoted string
    if (src[i] === '"' || src[i] === "'") {
      const q = src[i];
      let j = i + 1;
      let val = '';
      while (j < src.length) {
        if (src[j] === '\\' && j + 1 < src.length) {
          val += src[j] + src[j + 1];
          j += 2;
          continue;
        }
        if (src[j] === q) break;
        val += src[j];
        j++;
      }
      j++;
      const id = parts.length;
      parts.push({ type: 'quote', quote: q, value: val });
      out += `__STR${id}__`;
      i = j;
      continue;
    }
    out += src[i];
    i++;
  }
  return { code: out, strings: parts };
}

function restoreStrings(code, strings, encrypt) {
  const key = String.fromCharCode(
    randInt(40, 90), randInt(40, 90), randInt(40, 90),
    randInt(40, 90), randInt(40, 90), randInt(40, 90)
  );

  const decryptFn = randIdent(6);
  let header = '';

  if (encrypt) {
    header += `local function ${decryptFn}(t,k)local r={}for i=1,#t do r[i]=string.char(bit32.bxor(t[i],string.byte(k,(i-1)%#k+1)))end return table.concat(r)end\n`;
  }

  for (let i = 0; i < strings.length; i++) {
    const s = strings[i];
    let replacement;
    if (encrypt && s.value.length > 0 && s.value.length < 400) {
      const bytes = xorEncrypt(s.value, key);
      const tableLit = '{' + bytes.join(',') + '}';
      replacement = `${decryptFn}(${tableLit},"${key}")`;
    } else if (s.type === 'long') {
      replacement = '[[' + s.value + ']]';
    } else {
      // escape
      const esc = s.value
        .replace(/\\/g, '\\\\')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t');
      const q = s.quote || '"';
      const inner = q === '"' ? esc.replace(/"/g, '\\"') : esc.replace(/'/g, "\\'");
      replacement = q + inner + q;
    }
    code = code.split(`__STR${i}__`).join(replacement);
  }
  return header + code;
}

function collectLocals(code) {
  const names = new Set();
  // local x, y = ...
  const re1 = /\blocal\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)/g;
  let m;
  while ((m = re1.exec(code))) {
    m[1].split(',').forEach(p => {
      const n = p.trim();
      if (n && !KEYWORDS.has(n) && !BUILTINS.has(n)) names.add(n);
    });
  }
  // function name(...) or local function name
  const re2 = /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)/g;
  while ((m = re2.exec(code))) {
    if (!KEYWORDS.has(m[1]) && !BUILTINS.has(m[1])) names.add(m[1]);
  }
  // for i, v in / for i =
  const re3 = /\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|,)/g;
  while ((m = re3.exec(code))) {
    if (!KEYWORDS.has(m[1])) names.add(m[1]);
  }
  return [...names];
}

function mangleNames(code, names) {
  const map = new Map();
  // longer first to avoid partial replaces
  names.sort((a, b) => b.length - a.length);
  for (const n of names) {
    let neu;
    do {
      neu = randIdent(randInt(5, 9));
    } while ([...map.values()].includes(neu));
    map.set(n, neu);
  }
  for (const [old, neu] of map) {
    const re = new RegExp('\\b' + old.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'g');
    code = code.replace(re, neu);
  }
  return code;
}

function obfuscateNumbers(code) {
  return code.replace(/\b(\d+(?:\.\d+)?)\b/g, (match, num, offset, full) => {
    // skip if part of identifier context already handled; avoid version-like
    const before = full[offset - 1];
    if (before && /[A-Za-z_0-9.]/.test(before)) return match;
    const after = full[offset + match.length];
    if (after && /[A-Za-z_0-9.]/.test(after)) return match;
    const n = Number(num);
    if (!Number.isFinite(n) || num.length > 10) return match;
    if (Math.random() > 0.55) return match;
    return encodeNumber(n);
  });
}

function injectJunk(code) {
  const junkSnippets = [
    () => `local ${randIdent(5)}=nil;`,
    () => `if ${randInt(2, 9)}>${randInt(10, 20)} then local ${randIdent(4)}=${randInt(1, 99)} end;`,
    () => `do local ${randIdent(5)}=${randInt(1, 50)};${randIdent(5)}=nil end;`,
    () => `local ${randIdent(6)}=(function()return ${randInt(0, 1)}end)();`,
  ];
  const lines = code.split('\n');
  const out = [];
  for (const line of lines) {
    out.push(line);
    if (line.trim() && Math.random() < 0.12) {
      out.push(junkSnippets[randInt(0, junkSnippets.length - 1)]());
    }
  }
  return out.join('\n');
}

function wrapControlFlow(code) {
  const flag = randIdent(7);
  const decoy = randIdent(6);
  return [
    `local ${flag}=true`,
    `local ${decoy}=function()end`,
    `if ${flag} then`,
    code,
    `else`,
    `${decoy}()`,
    `end`
  ].join('\n');
}

function compactWhitespace(code) {
  return code
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/ *\n */g, '\n')
    .trim();
}

/**
 * @param {string} source
 * @param {object} options
 * @returns {string}
 */
function obfuscate(source, options = {}) {
  const opts = {
    encryptStrings: options.encryptStrings !== false,
    mangleNames: options.mangleNames !== false,
    encodeNumbers: options.encodeNumbers !== false,
    junkCode: options.junkCode !== false,
    controlFlow: options.controlFlow !== false,
    minify: options.minify !== false,
    watermark: options.watermark !== false,
    ...options
  };

  let src = String(source || '');
  if (src.length < 2) throw new Error('Empty source');

  // Normalize newlines
  src = src.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  const { code: stripped, strings } = stripCommentsAndStrings(src);
  let code = stripped;

  if (opts.mangleNames) {
    const locals = collectLocals(code);
    // don't mangle very short or single-letter sometimes used as loops - still mangle most
    const toMangle = locals.filter(n => n.length >= 2 || Math.random() > 0.3);
    code = mangleNames(code, toMangle);
  }

  if (opts.encodeNumbers) {
    code = obfuscateNumbers(code);
  }

  code = restoreStrings(code, strings, opts.encryptStrings);

  if (opts.junkCode) {
    code = injectJunk(code);
  }

  if (opts.controlFlow) {
    code = wrapControlFlow(code);
  }

  if (opts.minify) {
    code = compactWhitespace(code);
  }

  const header = opts.watermark
    ? `--[ obfuscated · pure-js ]\n`
    : '';

  return header + code;
}

module.exports = { obfuscate };
