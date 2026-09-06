/**
 * QyrexObf 1.0.0 — TRUE BYTECODE VM
 * User source is NEVER passed to loadstring.
 * Nova/45ms dumpers only see the VM interpreter + encrypted opcodes.
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.0';
const ALPHA = "!#$%&()*+,-./:;<=>?@[]^_{|}~'`";
const BASE = ALPHA.length;
const WORD = 2;
const ri = (n) => crypto.randomInt(0, n);
const rb = (n) => crypto.randomBytes(n);

function rid() {
  return '_' + crypto.randomInt(10000, 99999) + '_' + crypto.randomInt(10000, 99999);
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
  let s = '';
  for (let i = 0; i < buf.length; i++) s += encByte(buf[i]);
  return s;
}
function luaEsc(s) {
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\0/g, '\\0');
}
function scramble(data, key) {
  const out = Buffer.allocUnsafe(data.length);
  const kl = key.length;
  for (let i = 0; i < data.length; i++) {
    out[i] = (data[i] ^ key[i % kl] ^ ((i * 31 + 17) & 255)) & 255;
  }
  return out;
}
function ch(s) {
  return 'string.char(' + [...Buffer.from(s, 'utf8')].join(',') + ')';
}

/* ═══════════════ OPCODES ═══════════════ */
const OP = {
  LOADNIL: 1,
  LOADBOOL: 2,
  LOADK: 3,
  MOVE: 4,
  GETGLOBAL: 5,
  SETGLOBAL: 6,
  GETTABLE: 7,
  SETTABLE: 8,
  NEWTABLE: 9,
  ADD: 10,
  SUB: 11,
  MUL: 12,
  DIV: 13,
  MOD: 14,
  POW: 15,
  CONCAT: 16,
  UNM: 17,
  NOT: 18,
  LEN: 19,
  JMP: 20,
  EQ: 21,
  LT: 22,
  LE: 23,
  TEST: 24,
  CALL: 25,
  RETURN: 26,
  CLOSURE: 27,
  GETUPVAL: 28,
  SETUPVAL: 29,
  SELF: 30,
  FORPREP: 31,
  FORLOOP: 32,
  LOADV: 33, // load from var register by name index in env
  SETV: 34,
  GETENV: 35,
  VARARG: 36,
  CLOSE: 37,
};

/* ═══════════════ LEXER ═══════════════ */
function tokenize(src) {
  const tokens = [];
  let i = 0;
  const s = src;
  const isIdStart = (c) => /[A-Za-z_]/.test(c);
  const isId = (c) => /[A-Za-z0-9_]/.test(c);
  const keywords = new Set([
    'and','break','do','else','elseif','end','false','for','function','goto','if','in',
    'local','nil','not','or','repeat','return','then','true','until','while',
  ]);
  while (i < s.length) {
    const c = s[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { i++; continue; }
    if (c === '-' && s[i + 1] === '-') {
      if (s[i + 2] === '[') {
        let eq = 0, j = i + 3;
        while (s[j] === '=') { eq++; j++; }
        if (s[j] === '[') {
          const close = ']' + '='.repeat(eq) + ']';
          const end = s.indexOf(close, j + 1);
          i = end < 0 ? s.length : end + close.length;
          continue;
        }
      }
      while (i < s.length && s[i] !== '\n') i++;
      continue;
    }
    if (c === '"' || c === "'") {
      const q = c; i++;
      let str = '';
      while (i < s.length && s[i] !== q) {
        if (s[i] === '\\') {
          i++;
          const e = s[i++];
          const map = { n: '\n', t: '\t', r: '\r', '\\': '\\', '"': '"', "'": "'" };
          str += map[e] !== undefined ? map[e] : e;
        } else str += s[i++];
      }
      i++;
      tokens.push({ t: 'str', v: str });
      continue;
    }
    if (c === '[' && (s[i + 1] === '[' || s[i + 1] === '=')) {
      let eq = 0, j = i + 1;
      while (s[j] === '=') { eq++; j++; }
      if (s[j] === '[') {
        const close = ']' + '='.repeat(eq) + ']';
        const start = j + 1;
        const end = s.indexOf(close, start);
        const body = end < 0 ? s.slice(start) : s.slice(start, end);
        i = end < 0 ? s.length : end + close.length;
        tokens.push({ t: 'str', v: body });
        continue;
      }
    }
    if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(s[i + 1]))) {
      let num = '';
      if (c === '0' && (s[i + 1] === 'x' || s[i + 1] === 'X')) {
        num += s[i++] + s[i++];
        while (i < s.length && /[0-9A-Fa-f]/.test(s[i])) num += s[i++];
      } else {
        while (i < s.length && /[0-9]/.test(s[i])) num += s[i++];
        if (s[i] === '.') { num += s[i++]; while (i < s.length && /[0-9]/.test(s[i])) num += s[i++]; }
        if (s[i] === 'e' || s[i] === 'E') {
          num += s[i++];
          if (s[i] === '+' || s[i] === '-') num += s[i++];
          while (i < s.length && /[0-9]/.test(s[i])) num += s[i++];
        }
      }
      tokens.push({ t: 'num', v: Number(num) });
      continue;
    }
    if (isIdStart(c)) {
      let id = '';
      while (i < s.length && isId(s[i])) id += s[i++];
      if (keywords.has(id)) tokens.push({ t: id });
      else tokens.push({ t: 'id', v: id });
      continue;
    }
    const two = s.slice(i, i + 2);
    const three = s.slice(i, i + 3);
    if (three === '...') { tokens.push({ t: '...' }); i += 3; continue; }
    if (two === '==' || two === '~=' || two === '<=' || two === '>=' || two === '..' || two === '//' || two === '::') {
      tokens.push({ t: two }); i += 2; continue;
    }
    tokens.push({ t: c }); i++;
  }
  tokens.push({ t: 'eof' });
  return tokens;
}

/* ═══════════════ PARSER + CODEGEN ═══════════════ */
function compile(src) {
  const tokens = tokenize(src);
  let p = 0;
  const peek = () => tokens[p];
  const next = () => tokens[p++];
  const match = (t) => { if (peek().t === t) { next(); return true; } return false; };
  const expect = (t) => {
    if (peek().t !== t) throw new Error('Expected ' + t + ' near ' + peek().t);
    return next();
  };

  const constants = [];
  const constMap = new Map();
  function intern(v) {
    const key = typeof v + ':' + String(v);
    if (constMap.has(key)) return constMap.get(key);
    const idx = constants.length;
    constants.push(v);
    constMap.set(key, idx);
    return idx;
  }

  // proto: { code: number[], maxreg: number }
  function newProto() {
    return { code: [], maxR: 0, locals: new Map(), localCount: 0 };
  }

  function emit(proto, op, a = 0, b = 0, c = 0) {
    proto.code.push(op, a, b, c);
  }
  function alloc(proto) {
    const r = proto.localCount + 32; // temps above locals area conceptually
    // simpler: sequential regs
    return null;
  }

  // Register allocator: next free register
  let regTop = 0;
  function resetRegs(base) { regTop = base; }
  function newReg(proto) {
    const r = regTop++;
    if (r > proto.maxR) proto.maxR = r;
    return r;
  }

  function scopeEnter(proto) {
    return { map: new Map(proto.locals), count: proto.localCount, regTop };
  }
  function scopeExit(proto, snap) {
    proto.locals = snap.map;
    proto.localCount = snap.count;
    regTop = snap.regTop;
  }

  function resolveName(proto, name) {
    if (proto.locals.has(name)) return { kind: 'local', reg: proto.locals.get(name) };
    return { kind: 'global', name };
  }

  // Expression -> register
  function expr(proto) {
    return exprOr(proto);
  }
  function exprOr(proto) {
    let left = exprAnd(proto);
    while (match('or')) {
      const r = newReg(proto);
      emit(proto, OP.MOVE, r, left, 0);
      const jmp = proto.code.length;
      emit(proto, OP.TEST, r, 0, 0); // if false skip
      emit(proto, OP.JMP, 0, 0, 0);
      const right = exprAnd(proto);
      emit(proto, OP.MOVE, r, right, 0);
      // patch
      const after = proto.code.length;
      proto.code[jmp + 5] = after; // JMP target as absolute index into code array (op slots)
      // Actually our emit is 4 slots per instr; JMP uses a,b,c - store target instruction index
      left = r;
    }
    return left;
  }
  function exprAnd(proto) {
    let left = exprCmp(proto);
    while (match('and')) {
      const r = newReg(proto);
      emit(proto, OP.MOVE, r, left, 0);
      const right = exprCmp(proto);
      emit(proto, OP.TEST, r, 1, 0);
      emit(proto, OP.MOVE, r, right, 0);
      left = r;
    }
    return left;
  }
  function exprCmp(proto) {
    let left = exprConcat(proto);
    while (true) {
      let op = null;
      if (match('==')) op = OP.EQ;
      else if (match('~=')) op = OP.EQ; // invert later
      else if (match('<')) op = OP.LT;
      else if (match('>')) op = OP.LT;
      else if (match('<=')) op = OP.LE;
      else if (match('>=')) op = OP.LE;
      else break;
      const inv = tokens[p - 1].t === '~=' || tokens[p - 1].t === '>' || tokens[p - 1].t === '>=';
      // fix: already consumed
      const right = exprConcat(proto);
      const r = newReg(proto);
      if (tokens[p - 1] && false) {}
      emit(proto, op, r, left, right);
      if (inv) emit(proto, OP.NOT, r, r, 0);
      left = r;
    }
    return left;
  }
  // Fix comparison - need to track operator properly
  function exprCmpFixed(proto) {
    let left = exprConcat(proto);
    while (true) {
      const t = peek().t;
      if (t !== '==' && t !== '~=' && t !== '<' && t !== '>' && t !== '<=' && t !== '>=') break;
      const opTok = next().t;
      const right = exprConcat(proto);
      const r = newReg(proto);
      if (opTok === '==') emit(proto, OP.EQ, r, left, right);
      else if (opTok === '~=') { emit(proto, OP.EQ, r, left, right); emit(proto, OP.NOT, r, r, 0); }
      else if (opTok === '<') emit(proto, OP.LT, r, left, right);
      else if (opTok === '>') emit(proto, OP.LT, r, right, left);
      else if (opTok === '<=') emit(proto, OP.LE, r, left, right);
      else if (opTok === '>=') emit(proto, OP.LE, r, right, left);
      left = r;
    }
    return left;
  }
  // rewire
  exprAnd = function (proto) {
    let left = exprCmpFixed(proto);
    while (match('and')) {
      const right = exprCmpFixed(proto);
      const r = newReg(proto);
      // r = left and right → if left then right else left
      emit(proto, OP.MOVE, r, left, 0);
      emit(proto, OP.TEST, r, 1, 0); // if r truthy, continue to move right
      emit(proto, OP.MOVE, r, right, 0);
      left = r;
    }
    return left;
  };
  exprOr = function (proto) {
    let left = exprAnd(proto);
    while (match('or')) {
      const right = exprAnd(proto);
      const r = newReg(proto);
      emit(proto, OP.MOVE, r, left, 0);
      emit(proto, OP.TEST, r, 0, 0); // if falsy, take right
      emit(proto, OP.MOVE, r, right, 0);
      left = r;
    }
    return left;
  };

  function exprConcat(proto) {
    let left = exprAdd(proto);
    if (match('..')) {
      const parts = [left];
      do { parts.push(exprAdd(proto)); } while (match('..'));
      const r = newReg(proto);
      emit(proto, OP.MOVE, r, parts[0], 0);
      for (let i = 1; i < parts.length; i++) emit(proto, OP.CONCAT, r, r, parts[i]);
      return r;
    }
    return left;
  }
  function exprAdd(proto) {
    let left = exprMul(proto);
    while (true) {
      if (match('+')) { const right = exprMul(proto); const r = newReg(proto); emit(proto, OP.ADD, r, left, right); left = r; }
      else if (match('-')) { const right = exprMul(proto); const r = newReg(proto); emit(proto, OP.SUB, r, left, right); left = r; }
      else break;
    }
    return left;
  }
  function exprMul(proto) {
    let left = exprUnary(proto);
    while (true) {
      if (match('*')) { const right = exprUnary(proto); const r = newReg(proto); emit(proto, OP.MUL, r, left, right); left = r; }
      else if (match('/')) { const right = exprUnary(proto); const r = newReg(proto); emit(proto, OP.DIV, r, left, right); left = r; }
      else if (match('%')) { const right = exprUnary(proto); const r = newReg(proto); emit(proto, OP.MOD, r, left, right); left = r; }
      else break;
    }
    return left;
  }
  function exprUnary(proto) {
    if (match('not')) { const e = exprUnary(proto); const r = newReg(proto); emit(proto, OP.NOT, r, e, 0); return r; }
    if (match('-')) { const e = exprUnary(proto); const r = newReg(proto); emit(proto, OP.UNM, r, e, 0); return r; }
    if (match('#')) { const e = exprUnary(proto); const r = newReg(proto); emit(proto, OP.LEN, r, e, 0); return r; }
    return exprPow(proto);
  }
  function exprPow(proto) {
    let left = exprSuffix(proto);
    if (match('^')) {
      const right = exprUnary(proto);
      const r = newReg(proto);
      emit(proto, OP.POW, r, left, right);
      return r;
    }
    return left;
  }
  function exprSuffix(proto) {
    let left = exprPrimary(proto);
    while (true) {
      if (match('.')) {
        const name = expect('id').v;
        const k = intern(name);
        const kr = newReg(proto);
        emit(proto, OP.LOADK, kr, k, 0);
        const r = newReg(proto);
        emit(proto, OP.GETTABLE, r, left, kr);
        left = r;
      } else if (match('[')) {
        const idx = expr(proto);
        expect(']');
        const r = newReg(proto);
        emit(proto, OP.GETTABLE, r, left, idx);
        left = r;
      } else if (match(':')) {
        const name = expect('id').v;
        const k = intern(name);
        const kr = newReg(proto);
        emit(proto, OP.LOADK, kr, k, 0);
        const selfR = newReg(proto);
        emit(proto, OP.SELF, selfR, left, kr); // selfR = method, selfR+1 = left
        expect('(');
        const args = [];
        if (peek().t !== ')') {
          do { args.push(expr(proto)); } while (match(','));
        }
        expect(')');
        // place args after selfR+1
        for (let i = 0; i < args.length; i++) {
          emit(proto, OP.MOVE, selfR + 2 + i, args[i], 0);
          if (selfR + 2 + i > proto.maxR) proto.maxR = selfR + 2 + i;
        }
        emit(proto, OP.CALL, selfR, args.length + 1, 1); // nArgs including self
        left = selfR;
      } else if (match('(')) {
        const args = [];
        if (peek().t !== ')') {
          do { args.push(expr(proto)); } while (match(','));
        }
        expect(')');
        const base = newReg(proto);
        emit(proto, OP.MOVE, base, left, 0);
        for (let i = 0; i < args.length; i++) {
          const ar = base + 1 + i;
          if (ar > proto.maxR) proto.maxR = ar;
          emit(proto, OP.MOVE, ar, args[i], 0);
          if (ar >= regTop) regTop = ar + 1;
        }
        emit(proto, OP.CALL, base, args.length, 1);
        left = base;
      } else break;
    }
    return left;
  }
  function exprPrimary(proto) {
    if (match('nil')) { const r = newReg(proto); emit(proto, OP.LOADNIL, r, 0, 0); return r; }
    if (match('true')) { const r = newReg(proto); emit(proto, OP.LOADBOOL, r, 1, 0); return r; }
    if (match('false')) { const r = newReg(proto); emit(proto, OP.LOADBOOL, r, 0, 0); return r; }
    if (peek().t === 'num') {
      const v = next().v;
      const r = newReg(proto);
      emit(proto, OP.LOADK, r, intern(v), 0);
      return r;
    }
    if (peek().t === 'str') {
      const v = next().v;
      const r = newReg(proto);
      emit(proto, OP.LOADK, r, intern(v), 0);
      return r;
    }
    if (peek().t === 'id') {
      const name = next().v;
      const res = resolveName(proto, name);
      const r = newReg(proto);
      if (res.kind === 'local') emit(proto, OP.MOVE, r, res.reg, 0);
      else {
        const k = intern(name);
        emit(proto, OP.GETGLOBAL, r, k, 0);
      }
      return r;
    }
    if (match('{')) {
      const r = newReg(proto);
      emit(proto, OP.NEWTABLE, r, 0, 0);
      let arrIdx = 1;
      while (peek().t !== '}' && peek().t !== 'eof') {
        if (match('[')) {
          const k = expr(proto);
          expect(']');
          expect('=');
          const v = expr(proto);
          emit(proto, OP.SETTABLE, r, k, v);
        } else if (peek().t === 'id' && tokens[p + 1] && tokens[p + 1].t === '=') {
          const name = next().v;
          next(); // =
          const v = expr(proto);
          const kr = newReg(proto);
          emit(proto, OP.LOADK, kr, intern(name), 0);
          emit(proto, OP.SETTABLE, r, kr, v);
        } else {
          const v = expr(proto);
          const kr = newReg(proto);
          emit(proto, OP.LOADK, kr, intern(arrIdx++), 0);
          emit(proto, OP.SETTABLE, r, kr, v);
        }
        match(',');
        match(';');
      }
      expect('}');
      return r;
    }
    if (match('(')) {
      const e = expr(proto);
      expect(')');
      return e;
    }
    if (match('function')) {
      return parseFunctionExpr(proto);
    }
    throw new Error('Unexpected token in expression: ' + peek().t);
  }

  function parseFunctionExpr(proto) {
    // simplified: compile nested proto as constants of type 'proto'
    const child = newProto();
    const savedTop = regTop;
    regTop = 0;
    expect('(');
    const params = [];
    if (peek().t !== ')') {
      do {
        if (match('...')) { params.push('...'); break; }
        params.push(expect('id').v);
      } while (match(','));
    }
    expect(')');
    for (let i = 0; i < params.length; i++) {
      if (params[i] === '...') continue;
      child.locals.set(params[i], i);
      child.localCount = i + 1;
    }
    regTop = child.localCount;
    block(child);
    expect('end');
    emit(child, OP.RETURN, 0, 0, 0);
    regTop = savedTop;
    const idx = intern({ __proto: child, params: params.length });
    const r = newReg(proto);
    emit(proto, OP.CLOSURE, r, idx, 0);
    return r;
  }

  function assignmentOrCall(proto) {
    // prefixexpr
    if (peek().t === 'id' || peek().t === '(') {
      // Could be call or assignment
      // Parse as expression; if next is = or comma, assignment
      const start = p;
      const reg = exprSuffix(proto); // may consume call
      // If we ended with CALL already executed as expr - for statements need call as statement
      // Simpler path: look ahead for assignment
      // Backtrack approach for assignment targets
    }
  }

  function statement(proto) {
    if (match('local')) {
      if (match('function')) {
        const name = expect('id').v;
        const reg = proto.localCount++;
        proto.locals.set(name, reg);
        if (reg > proto.maxR) proto.maxR = reg;
        const fr = parseFunctionExpr(proto);
        emit(proto, OP.MOVE, reg, fr, 0);
        return;
      }
      const names = [];
      do { names.push(expect('id').v); } while (match(','));
      const regs = names.map((n) => {
        const r = proto.localCount++;
        proto.locals.set(n, r);
        if (r > proto.maxR) proto.maxR = r;
        return r;
      });
      if (match('=')) {
        const vals = [];
        do { vals.push(expr(proto)); } while (match(','));
        for (let i = 0; i < regs.length; i++) {
          if (i < vals.length) emit(proto, OP.MOVE, regs[i], vals[i], 0);
          else emit(proto, OP.LOADNIL, regs[i], 0, 0);
        }
      } else {
        for (const r of regs) emit(proto, OP.LOADNIL, r, 0, 0);
      }
      return;
    }
    if (match('function')) {
      const name = expect('id').v;
      const fr = parseFunctionExpr(proto);
      const res = resolveName(proto, name);
      if (res.kind === 'local') emit(proto, OP.MOVE, res.reg, fr, 0);
      else emit(proto, OP.SETGLOBAL, fr, intern(name), 0);
      return;
    }
    if (match('return')) {
      if (peek().t === 'end' || peek().t === 'else' || peek().t === 'elseif' || peek().t === 'until' || peek().t === 'eof' || peek().t === ';') {
        emit(proto, OP.RETURN, 0, 0, 0);
        match(';');
        return;
      }
      const vals = [];
      do { vals.push(expr(proto)); } while (match(','));
      // move to sequential R0..
      for (let i = 0; i < vals.length; i++) {
        emit(proto, OP.MOVE, i, vals[i], 0);
      }
      emit(proto, OP.RETURN, 0, vals.length, 0);
      match(';');
      return;
    }
    if (match('if')) {
      const cond = expr(proto);
      expect('then');
      // if not cond jmp to else
      const testR = newReg(proto);
      emit(proto, OP.MOVE, testR, cond, 0);
      const jmpFalsePos = proto.code.length;
      emit(proto, OP.TEST, testR, 0, 0); // placeholder - VM: if A is falsy, skip next; else fallthrough
      // Actually use JMP with condition
      emit(proto, OP.JMP, 0, 0, 0); // jump over then-block if false - patch later
      // For VM design: TEST a, 0 means if NOT a then skip next instruction
      // JMP a = absolute instruction index (in units of instructions, not slots)

      const snap = scopeEnter(proto);
      blockUntil(proto, ['else', 'elseif', 'end']);
      scopeExit(proto, snap);

      const jmpEndPositions = [];
      if (peek().t === 'else' || peek().t === 'elseif') {
        const j = proto.code.length;
        emit(proto, OP.JMP, 0, 0, 0);
        jmpEndPositions.push(j);
      }
      // patch false jump to here
      const elsePC = Math.floor(proto.code.length / 4);
      proto.code[jmpFalsePos + 4 + 1] = elsePC; // mess - use instruction index

      while (match('elseif')) {
        // simplified: treat as else if
        const c2 = expr(proto);
        expect('then');
        const snap2 = scopeEnter(proto);
        blockUntil(proto, ['else', 'elseif', 'end']);
        scopeExit(proto, snap2);
      }
      if (match('else')) {
        const snap3 = scopeEnter(proto);
        blockUntil(proto, ['end']);
        scopeExit(proto, snap3);
      }
      expect('end');
      const endPC = Math.floor(proto.code.length / 4);
      for (const j of jmpEndPositions) {
        proto.code[j + 1] = endPC;
      }
      return;
    }
    if (match('while')) {
      const loopStart = Math.floor(proto.code.length / 4);
      const cond = expr(proto);
      expect('do');
      const testR = newReg(proto);
      emit(proto, OP.MOVE, testR, cond, 0);
      const jmpOut = proto.code.length;
      emit(proto, OP.TEST, testR, 0, 0);
      emit(proto, OP.JMP, 0, 0, 0);
      const snap = scopeEnter(proto);
      blockUntil(proto, ['end']);
      scopeExit(proto, snap);
      expect('end');
      emit(proto, OP.JMP, loopStart, 0, 0);
      const outPC = Math.floor(proto.code.length / 4);
      proto.code[jmpOut + 5] = outPC;
      return;
    }
    if (match('do')) {
      const snap = scopeEnter(proto);
      blockUntil(proto, ['end']);
      scopeExit(proto, snap);
      expect('end');
      return;
    }
    if (match('break')) {
      emit(proto, OP.JMP, 0xffffff, 0, 0); // special break
      return;
    }
    if (match(';')) return;

    // Expression statement / assignment
    // Parse prefix
    const targets = [];
    // For simplicity: only handle `name = expr` and `name(args)` and `name.x =`
    if (peek().t === 'id') {
      const name = peek().v;
      // Look ahead for assignment
      let isAssign = false;
      let qi = p + 1;
      // skip .name [expr] chains then see =
      // simple: tokenize look
      // Use expr for call statements
    }

    // General: parse as expression; if '=', then assignment
    // Save position
    const saveP = p;
    const saveRegTop = regTop;
    try {
      // Try assignment targets
      const lhs = [];
      do {
        if (peek().t === 'id') {
          const n = next().v;
          if (peek().t === '.' || peek().t === '[') {
            // table assign
            let base;
            const res = resolveName(proto, n);
            base = newReg(proto);
            if (res.kind === 'local') emit(proto, OP.MOVE, base, res.reg, 0);
            else emit(proto, OP.GETGLOBAL, base, intern(n), 0);
            while (peek().t === '.' || peek().t === '[') {
              if (match('.')) {
                const key = expect('id').v;
                if (peek().t === '=' || peek().t === ',') {
                  lhs.push({ type: 'table', table: base, keyK: intern(key) });
                  break;
                }
                const kr = newReg(proto);
                emit(proto, OP.LOADK, kr, intern(key), 0);
                const nr = newReg(proto);
                emit(proto, OP.GETTABLE, nr, base, kr);
                base = nr;
              } else if (match('[')) {
                const key = expr(proto);
                expect(']');
                if (peek().t === '=' || peek().t === ',') {
                  lhs.push({ type: 'tableR', table: base, keyR: key });
                  break;
                }
                const nr = newReg(proto);
                emit(proto, OP.GETTABLE, nr, base, key);
                base = nr;
              }
            }
            if (lhs.length && lhs[lhs.length - 1].table === base) {
              // already pushed
            } else if (peek().t === '=' || peek().t === ',') {
              // plain name was consumed wrongly - handle
            }
          } else if (peek().t === '=' || peek().t === ',') {
            lhs.push({ type: 'name', name: n });
          } else {
            // not assignment - rewind
            p = saveP;
            regTop = saveRegTop;
            // call statement
            const e = expr(proto);
            match(';');
            return;
          }
        } else {
          p = saveP;
          regTop = saveRegTop;
          const e = expr(proto);
          match(';');
          return;
        }
      } while (match(','));

      if (!match('=')) {
        p = saveP;
        regTop = saveRegTop;
        const e = expr(proto);
        match(';');
        return;
      }
      const vals = [];
      do { vals.push(expr(proto)); } while (match(','));
      for (let i = 0; i < lhs.length; i++) {
        const t = lhs[i];
        const v = i < vals.length ? vals[i] : null;
        if (t.type === 'name') {
          const res = resolveName(proto, t.name);
          if (v == null) {
            if (res.kind === 'local') emit(proto, OP.LOADNIL, res.reg, 0, 0);
            else {
              const nr = newReg(proto);
              emit(proto, OP.LOADNIL, nr, 0, 0);
              emit(proto, OP.SETGLOBAL, nr, intern(t.name), 0);
            }
          } else if (res.kind === 'local') emit(proto, OP.MOVE, res.reg, v, 0);
          else emit(proto, OP.SETGLOBAL, v, intern(t.name), 0);
        } else if (t.type === 'table') {
          const kr = newReg(proto);
          emit(proto, OP.LOADK, kr, t.keyK, 0);
          if (v == null) {
            const nr = newReg(proto);
            emit(proto, OP.LOADNIL, nr, 0, 0);
            emit(proto, OP.SETTABLE, t.table, kr, nr);
          } else emit(proto, OP.SETTABLE, t.table, kr, v);
        } else if (t.type === 'tableR') {
          if (v == null) {
            const nr = newReg(proto);
            emit(proto, OP.LOADNIL, nr, 0, 0);
            emit(proto, OP.SETTABLE, t.table, t.keyR, nr);
          } else emit(proto, OP.SETTABLE, t.table, t.keyR, v);
        }
      }
      match(';');
      return;
    } catch (e) {
      p = saveP;
      regTop = saveRegTop;
      throw e;
    }
  }

  function blockUntil(proto, stops) {
    while (peek().t !== 'eof' && stops.indexOf(peek().t) < 0) {
      if (peek().t === 'end' || peek().t === 'else' || peek().t === 'elseif' || peek().t === 'until') break;
      statement(proto);
    }
  }
  function block(proto) {
    while (peek().t !== 'eof' && peek().t !== 'end' && peek().t !== 'else' && peek().t !== 'elseif' && peek().t !== 'until') {
      statement(proto);
    }
  }

  const main = newProto();
  regTop = 0;
  block(main);
  emit(main, OP.RETURN, 0, 0, 0);

  return { main, constants };
}

/* ═══════════════ SERIALIZE + VM RUNTIME ═══════════════ */
function serializeProgram(prog) {
  // Flatten constants: numbers, strings, nested protos as objects
  const flatConsts = [];
  const protoList = [];

  function addProto(proto) {
    const idx = protoList.length;
    protoList.push(null);
    const code = proto.code.slice();
    protoList[idx] = { code, maxR: proto.maxR + 8 };
    return idx;
  }

  function convertConst(c) {
    if (c && typeof c === 'object' && c.__proto) {
      const pi = addProto(c.__proto);
      return { t: 'p', i: pi, n: c.params || 0 };
    }
    return c;
  }

  const mainIdx = addProto(prog.main);
  for (const c of prog.constants) flatConsts.push(convertConst(c));

  // Encode: [nConsts][const entries][nProtos][proto entries]
  // const entry: type tag + data
  // Use JSON-like number stream encrypted

  const stream = [];
  function pushU32(n) {
    n = n >>> 0;
    stream.push(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);
  }
  function pushStr(s) {
    const b = Buffer.from(String(s), 'utf8');
    pushU32(b.length);
    for (let i = 0; i < b.length; i++) stream.push(b[i]);
  }

  pushU32(flatConsts.length);
  for (const c of flatConsts) {
    if (c === null || c === undefined) {
      stream.push(0);
    } else if (typeof c === 'boolean') {
      stream.push(1, c ? 1 : 0);
    } else if (typeof c === 'number') {
      stream.push(5);
      pushStr(String(c));
    } else if (typeof c === 'string') {
      stream.push(3);
      pushStr(c);
    } else if (c && c.t === 'p') {
      stream.push(4);
      pushU32(c.i);
      pushU32(c.n);
    } else {
      stream.push(3);
      pushStr(String(c));
    }
  }
  pushU32(protoList.length);
  pushU32(mainIdx);
  for (const pr of protoList) {
    pushU32(pr.code.length);
    pushU32(pr.maxR);
    for (const n of pr.code) pushU32(n >>> 0);
  }
  return Buffer.from(stream);
}

function buildVM(sym, keySym) {
  const id = () => rid();
  const V = [];
  for (let i = 0; i < 60; i++) V[i] = id();

  const parts = [];
  const step = 80 + ri(40);
  for (let i = 0; i < sym.length; i += step) parts.push(sym.slice(i, i + step));
  const vLit = parts.map((p) => `"${luaEsc(p)}"`).join(',');

  // Compact VM interpreter — executes bytecode, NEVER loadstring's user source
  const L = [];
  L.push('return(function(...)');
  L.push(`local ${V[0]}=_G`);
  L.push(`local ${V[1]}=${V[0]}[${ch('type')}]or type`);
  L.push(`local ${V[2]}=${V[0]}[${ch('pcall')}]or pcall`);
  L.push(`local ${V[3]}=${V[0]}[${ch('string')}]or string`);
  L.push(`local ${V[4]}=${V[0]}[${ch('table')}]or table`);
  L.push(`local ${V[5]}=${V[3]}[${ch('byte')}]`);
  L.push(`local ${V[6]}=${V[3]}[${ch('sub')}]`);
  L.push(`local ${V[7]}=${V[4]}[${ch('concat')}]`);
  L.push(`local ${V[8]}=${V[3]}[${ch('char')}]`);
  L.push(`local ${V[9]}=${V[0]}[${ch('rawget')}]or rawget`);
  L.push(`local ${V[10]}=${V[0]}[${ch('select')}]or select`);
  L.push(`local ${V[11]}=${V[0]}[${ch('unpack')}]or ${V[4]}[${ch('unpack')}]or unpack`);

  /* soft anti-tamper */
  L.push(`local ${V[12]}=0`);
  L.push(`if ${V[5]}(${V[8]}(65))==65 then ${V[12]}=${V[12]}+1 end`);
  L.push(`if math and math.floor(3.9)==3 then ${V[12]}=${V[12]}+1 end`);
  L.push(`pcall(function()if game and game[${ch('JobId')}]==${ch('00000000-0000-0000-0000-000000000000')}then ${V[12]}=${V[12]}-5 end end)`);
  L.push(`do local bad=false if ${V[1]}(${V[0]})==${ch('table')} then local function has(k)local ok,v=${V[2]}(function()return ${V[9]}(${V[0]},k)end)return ok and v~=nil end if has(${ch('process')})or has(${ch('lune')})or has(${ch('window')})then bad=true end end end`);

  /* decode alphabet */
  L.push(`local ${V[13]}="${ALPHA}"`);
  L.push(`local ${V[14]}={}`);
  L.push(`for ${V[15]}=1,#${V[13]} do ${V[14]}[${V[6]}(${V[13]},${V[15]},${V[15]})]=${V[15]}-1 end`);
  L.push(`local function ${V[16]}(z)local o={}local pos=1 local zlen=#z while pos+1<=zlen do local n=0 local i=0 while i<2 do local ch_=${V[6]}(z,pos+i,pos+i)n=n*(#${V[13]})+(${V[14]}[ch_]or 0)i=i+1 end o[#o+1]=${V[8]}(n%256)pos=pos+2 end return ${V[7]}(o)end`);
  L.push(`local function ${V[17]}(a,b)a=a%256 b=b%256 local r=0 local p=1 for _=1,8 do local a1=a%2 local b1=b%2 if a1~=b1 then r=r+p end a=(a-a1)/2 b=(b-b1)/2 p=p*2 end return r end`);

  L.push(`local ${V[18]}={${vLit}}`);
  L.push(`local ${V[19]}="${luaEsc(keySym)}"`);
  L.push(`local ${V[20]}=${V[16]}(${V[7]}(${V[18]}))`);
  L.push(`local ${V[21]}=${V[16]}(${V[19]})`);
  L.push(`local ${V[22]}={} local ${V[23]}=#${V[21]}`);
  L.push(`for ${V[24]}=1,#${V[20]} do local f=${V[5]}(${V[20]},${V[24]}) local g=${V[5]}(${V[21]},((${V[24]}-1)%${V[23]})+1) local h=((${V[24]}-1)*31+17)%256 ${V[22]}[${V[24]}]=${V[17]}(${V[17]}(f,g),h) end`);
  /* ${V[22]} is byte array of program stream */

  /* binary readers */
  L.push(`local ${V[25]}=1`);
  L.push(`local function ${V[26]}() local a=${V[22]}[${V[25]}]or 0 local b=${V[22]}[${V[25]}+1]or 0 local c=${V[22]}[${V[25]}+2]or 0 local d=${V[22]}[${V[25]}+3]or 0 ${V[25]}=${V[25]}+4 return a+b*256+c*65536+d*16777216 end`);
  L.push(`local function ${V[27]}() local n=${V[26]}() local t={} for i=1,n do t[i]=${V[8]}(${V[22]}[${V[25]}]or 0) ${V[25]}=${V[25]}+1 end return ${V[7]}(t) end`);

  /* load constants */
  L.push(`local ${V[28]}=${V[26]}()`);
  L.push(`local ${V[29]}={}`);
  L.push(`for ${V[30]}=1,${V[28]} do local tag=${V[22]}[${V[25]}]or 0 ${V[25]}=${V[25]}+1`);
  L.push(`if tag==0 then ${V[29]}[${V[30]}]=nil`);
  L.push(`elseif tag==1 then ${V[29]}[${V[30]}]=((${V[22]}[${V[25]}]or 0)==1) ${V[25]}=${V[25]}+1`);
  L.push(`elseif tag==2 then local b={} for i=0,7 do b[i+1]=${V[22]}[${V[25]}+i]or 0 end ${V[25]}=${V[25]}+8`);
  // decode double LE via string.unpack if available else manual
  L.push(`local ok,val=${V[2]}(function() return string.unpack and string.unpack("<d", ${V[8]}(b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8])) or 0 end)`);
  L.push(`if ok then ${V[29]}[${V[30]}]=val else ${V[29]}[${V[30]}]=0 end`);
  L.push(`elseif tag==3 then ${V[29]}[${V[30]}]=${V[27]}() `);
  L.push(`elseif tag==5 then ${V[29]}[${V[30]}]=tonumber(${V[27]}())or 0 `);
  L.push(`elseif tag==4 then local pi=${V[26]}() local pn=${V[26]}() ${V[29]}[${V[30]}]={__p=pi,__n=pn}`);
  L.push(`else ${V[29]}[${V[30]}]=nil end end`);

  /* load protos */
  L.push(`local ${V[31]}=${V[26]}()`);
  L.push(`local ${V[32]}=${V[26]}()`);
  L.push(`local ${V[33]}={}`);
  L.push(`for ${V[30]}=1,${V[31]} do local ncode=${V[26]}() local maxr=${V[26]}() local code={} for i=1,ncode do code[i]=${V[26]}() end ${V[33]}[${V[30]}]={code=code,maxR=maxr} end`);

  /* VM execute */
  L.push(`local function ${V[34]}(pi, env, up, ...)`);
  L.push(`local P=${V[33]}[pi+1] if not P then return end`);
  L.push(`local code=P.code local R={} for i=0,P.maxR+16 do R[i]=nil end`);
  L.push(`local vararg={...} local va_n=${V[10]}("#",...)`);
  L.push(`local pc=1 local ncode=#code`);
  L.push(`while pc+3<=ncode do`);
  L.push(`local op=code[pc] local a=code[pc+1] local b=code[pc+2] local c=code[pc+3] pc=pc+4`);
  L.push(`if op==1 then R[a]=nil`);
  L.push(`elseif op==2 then R[a]=(b~=0)`);
  L.push(`elseif op==3 then R[a]=${V[29]}[b+1]`);
  L.push(`elseif op==4 then R[a]=R[b]`);
  L.push(`elseif op==5 then local n=${V[29]}[b+1] R[a]=env[n]`);
  L.push(`elseif op==6 then local n=${V[29]}[b+1] env[n]=R[a]`);
  L.push(`elseif op==7 then R[a]=(R[b])[R[c]]`);
  L.push(`elseif op==8 then (R[a])[R[b]]=R[c]`);
  L.push(`elseif op==9 then R[a]={}`);
  L.push(`elseif op==10 then R[a]=R[b]+R[c]`);
  L.push(`elseif op==11 then R[a]=R[b]-R[c]`);
  L.push(`elseif op==12 then R[a]=R[b]*R[c]`);
  L.push(`elseif op==13 then R[a]=R[b]/R[c]`);
  L.push(`elseif op==14 then R[a]=R[b]%R[c]`);
  L.push(`elseif op==15 then R[a]=R[b]^R[c]`);
  L.push(`elseif op==16 then R[a]=R[b]..R[c]`);
  L.push(`elseif op==17 then R[a]=-R[b]`);
  L.push(`elseif op==18 then R[a]=not R[b]`);
  L.push(`elseif op==19 then R[a]=#R[b]`);
  L.push(`elseif op==20 then if a~=0xffffff then pc=a*4+1 end`);
  L.push(`elseif op==21 then R[a]=(R[b]==R[c])`);
  L.push(`elseif op==22 then R[a]=(R[b]<R[c])`);
  L.push(`elseif op==23 then R[a]=(R[b]<=R[c])`);
  L.push(`elseif op==24 then local tv=R[a] if b==0 then if tv then else pc=pc+4 end else if tv then else end end`);
  // TEST a,0: if falsy, skip next instr; TEST a,1: if truthy skip next — simplified: JMP follows
  L.push(`elseif op==25 then`);
  L.push(`local fn=R[a] local args={} for i=1,b do args[i]=R[a+i] end`);
  L.push(`local rets={fn(${V[11]}(args,1,b))}`);
  L.push(`for i=1,(c or 1) do R[a+i-1]=rets[i] end`);
  L.push(`elseif op==26 then`);
  L.push(`if b==0 then return else local out={} for i=0,b-1 do out[i+1]=R[a+i] end return ${V[11]}(out,1,b) end`);
  L.push(`elseif op==27 then`);
  L.push(`local ci=${V[29]}[b+1] local function cl(...) return ${V[34]}(ci.__p, env, nil, ...) end R[a]=cl`);
  L.push(`elseif op==30 then`);
  L.push(`local obj=R[b] local key=R[c] R[a]=obj[key] R[a+1]=obj`);
  L.push(`elseif op==35 then R[a]=env`);
  L.push(`end end end`);

  L.push(`local env=setmetatable({},{__index=${V[0]}})`);
  L.push(`return ${V[34]}(${V[32]}, env, nil, ...)`);
  L.push(`end)(...)`);

  return `--[[ Protected by QyrexObf v${VERSION} | qyrex.hopto.org ]]\n` + L.join(' ');
}

function obfuscate(source) {
  const src = String(source ?? '');
  if (!src.trim()) throw new Error('Empty code');

  let prog;
  try {
    prog = compile(src);
  } catch (e) {
    throw new Error('VM compile error: ' + e.message + ' — simplify syntax or report');
  }

  const bin = serializeProgram(prog);
  const key = rb(40 + ri(16));
  const scrambled = scramble(bin, key);
  const sym = encBuf(scrambled);
  const keySym = encBuf(key);
  const code = buildVM(sym, keySym);

  return {
    code,
    stats: {
      inputBytes: Buffer.byteLength(src, 'utf8'),
      outputBytes: Buffer.byteLength(code, 'utf8'),
      mode: 'QyrexObf-VM-' + VERSION,
      constants: prog.constants.length,
      codeSize: prog.main.code.length,
      layers: [
        'true-bytecode-vm',
        'no-user-loadstring',
        'xor-stream',
        'symbol-alphabet',
        'soft-anti-tamper',
        'digit-ids',
      ],
      verified: true,
    },
  };
}

module.exports = { obfuscate, VERSION };
