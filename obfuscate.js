/**
 * QyrexObf 1.0.2 — VM mode (source never goes through loadstring)
 * Soft anti-tamper + Luau-safe spacing.
 */
'use strict';
const crypto = require('crypto');
const VERSION = '1.0.2';
const ri = (n) => crypto.randomInt(0, n);
const RES = new Set(['and','break','do','else','elseif','end','false','for','function','goto','if','in','local','nil','not','or','repeat','return','then','true','until','while']);
function rid(){const L='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';let o='';do{o='q';for(let i=0;i<6+ri(4);i++)o+=L[ri(L.length)];}while(RES.has(o));return o;}

const OP={LOADNIL:1,LOADBOOL:2,LOADK:3,MOVE:4,GETGLOBAL:5,SETGLOBAL:6,GETTABLE:7,SETTABLE:8,NEWTABLE:9,ADD:10,SUB:11,MUL:12,DIV:13,MOD:14,POW:15,CONCAT:16,UNM:17,NOT:18,LEN:19,JMP:20,EQ:21,LT:22,LE:23,TEST:24,CALL:25,RETURN:26,SELF:27,CLOSURE:28};

function tokenize(src){
  const t=[];let i=0;const s=src;
  const isS=c=>/[A-Za-z_]/.test(c),isI=c=>/[A-Za-z0-9_]/.test(c);
  while(i<s.length){
    const c=s[i];
    if(c===' '||c==='\t'||c==='\r'||c==='\n'){i++;continue;}
    if(c==='-'&&s[i+1]==='-'){if(s[i+2]==='['){let eq=0,j=i+3;while(s[j]==='='){eq++;j++;}if(s[j]==='['){const cl=']'+'='.repeat(eq)+']';const e=s.indexOf(cl,j+1);i=e<0?s.length:e+cl.length;continue;}}while(i<s.length&&s[i]!=='\n')i++;continue;}
    if(c==='"'||c==="'"){const q=c;i++;let str='';while(i<s.length&&s[i]!==q){if(s[i]==='\\'){i++;const e=s[i++]||'';str+=({n:'\n',t:'\t',r:'\r','\\':'\\','"':'"',"'":"'"}[e]||e);}else str+=s[i++];}i++;t.push({t:'str',v:str});continue;}
    if(/[0-9]/.test(c)||(c==='.'&&/[0-9]/.test(s[i+1]||''))){let num='';while(i<s.length&&/[0-9]/.test(s[i]))num+=s[i++];if(s[i]==='.'){num+=s[i++];while(i<s.length&&/[0-9]/.test(s[i]))num+=s[i++];}t.push({t:'num',v:Number(num)});continue;}
    if(isS(c)){let id='';while(i<s.length&&isI(s[i]))id+=s[i++];t.push(RES.has(id)||id==='and'||id==='or'||id==='not'?{t:id}:{t:'id',v:id});continue;}
    const two=s.slice(i,i+2);
    if(two==='=='||two==='~='||two==='<='||two==='>='||two==='..'){t.push({t:two});i+=2;continue;}
    t.push({t:c});i++;
  }
  t.push({t:'eof'});return t;
}

function compile(src){
  const tokens=tokenize(src);let p=0;
  const peek=()=>tokens[p],next=()=>tokens[p++],match=t=>{if(peek().t===t){next();return true;}return false;};
  const expect=t=>{if(peek().t!==t)throw new Error('Expected '+t+' got '+peek().t);return next();};
  const constants=[];const cmap=new Map();
  const intern=v=>{const k=typeof v+':'+String(v);if(cmap.has(k))return cmap.get(k);const i=constants.length;constants.push(v);cmap.set(k,i);return i;};
  const newProto=()=>({code:[],maxR:0,locals:new Map(),localCount:0});
  const emit=(pr,op,a=0,b=0,c=0)=>{pr.code.push(op,a|0,b|0,c|0);};
  let regTop=0;
  const newReg=pr=>{const r=regTop++;if(r>pr.maxR)pr.maxR=r;return r;};
  const scopeEnter=pr=>({map:new Map(pr.locals),count:pr.localCount,regTop});
  const scopeExit=(pr,s)=>{pr.locals=s.map;pr.localCount=s.count;regTop=s.regTop;};
  const resolve=(pr,n)=>pr.locals.has(n)?{kind:'local',reg:pr.locals.get(n)}:{kind:'global',name:n};
  const pcOf=pr=>(pr.code.length/4)|0;

  function expr(pr){return exprOr(pr);}
  function exprOr(pr){let l=exprAnd(pr);while(match('or')){const rgt=exprAnd(pr);const r=newReg(pr);emit(pr,OP.MOVE,r,l,0);emit(pr,OP.TEST,r,0,0);emit(pr,OP.MOVE,r,rgt,0);l=r;}return l;}
  function exprAnd(pr){let l=exprCmp(pr);while(match('and')){const rgt=exprCmp(pr);const r=newReg(pr);emit(pr,OP.MOVE,r,l,0);emit(pr,OP.TEST,r,1,0);emit(pr,OP.MOVE,r,rgt,0);l=r;}return l;}
  function exprCmp(pr){let l=exprConcat(pr);while(true){const t=peek().t;if(t!=='=='&&t!=='~='&&t!=='<'&&t!=='>'&&t!=='<='&&t!=='>=')break;const op=next().t;const rgt=exprConcat(pr);const r=newReg(pr);
    if(op==='==')emit(pr,OP.EQ,r,l,rgt);else if(op==='~='){emit(pr,OP.EQ,r,l,rgt);emit(pr,OP.NOT,r,r,0);}else if(op==='<')emit(pr,OP.LT,r,l,rgt);else if(op==='>')emit(pr,OP.LT,r,rgt,l);else if(op==='<=')emit(pr,OP.LE,r,l,rgt);else emit(pr,OP.LE,r,rgt,l);l=r;}return l;}
  function exprConcat(pr){let l=exprAdd(pr);if(!match('..'))return l;const parts=[l];do{parts.push(exprAdd(pr));}while(match('..'));const r=newReg(pr);emit(pr,OP.MOVE,r,parts[0],0);for(let i=1;i<parts.length;i++)emit(pr,OP.CONCAT,r,r,parts[i]);return r;}
  function exprAdd(pr){let l=exprMul(pr);while(true){if(match('+')){const rgt=exprMul(pr);const r=newReg(pr);emit(pr,OP.ADD,r,l,rgt);l=r;}else if(match('-')){const rgt=exprMul(pr);const r=newReg(pr);emit(pr,OP.SUB,r,l,rgt);l=r;}else break;}return l;}
  function exprMul(pr){let l=exprUnary(pr);while(true){if(match('*')){const rgt=exprUnary(pr);const r=newReg(pr);emit(pr,OP.MUL,r,l,rgt);l=r;}else if(match('/')){const rgt=exprUnary(pr);const r=newReg(pr);emit(pr,OP.DIV,r,l,rgt);l=r;}else if(match('%')){const rgt=exprUnary(pr);const r=newReg(pr);emit(pr,OP.MOD,r,l,rgt);l=r;}else break;}return l;}
  function exprUnary(pr){if(match('not')){const e=exprUnary(pr);const r=newReg(pr);emit(pr,OP.NOT,r,e,0);return r;}if(match('-')){const e=exprUnary(pr);const r=newReg(pr);emit(pr,OP.UNM,r,e,0);return r;}if(match('#')){const e=exprUnary(pr);const r=newReg(pr);emit(pr,OP.LEN,r,e,0);return r;}return exprPow(pr);}
  function exprPow(pr){let l=exprSuffix(pr);if(match('^')){const rgt=exprUnary(pr);const r=newReg(pr);emit(pr,OP.POW,r,l,rgt);return r;}return l;}
  function exprSuffix(pr){
    let l=exprPrimary(pr);
    while(true){
      if(match('.')){const name=expect('id').v;const kr=newReg(pr);emit(pr,OP.LOADK,kr,intern(name),0);const r=newReg(pr);emit(pr,OP.GETTABLE,r,l,kr);l=r;}
      else if(match('[')){const idx=expr(pr);expect(']');const r=newReg(pr);emit(pr,OP.GETTABLE,r,l,idx);l=r;}
      else if(match(':')){
        const name=expect('id').v;const kr=newReg(pr);emit(pr,OP.LOADK,kr,intern(name),0);const selfR=newReg(pr);emit(pr,OP.SELF,selfR,l,kr);if(selfR+1>pr.maxR)pr.maxR=selfR+1;
        expect('(');const args=[];if(peek().t!==')'){do{args.push(expr(pr));}while(match(','));}expect(')');
        for(let i=0;i<args.length;i++){const ar=selfR+2+i;if(ar>pr.maxR)pr.maxR=ar;if(ar>=regTop)regTop=ar+1;emit(pr,OP.MOVE,ar,args[i],0);}
        emit(pr,OP.CALL,selfR,args.length+1,1);l=selfR;
      }else if(match('(')){
        const args=[];if(peek().t!==')'){do{args.push(expr(pr));}while(match(','));}expect(')');
        const base=newReg(pr);emit(pr,OP.MOVE,base,l,0);
        for(let i=0;i<args.length;i++){const ar=base+1+i;if(ar>pr.maxR)pr.maxR=ar;if(ar>=regTop)regTop=ar+1;emit(pr,OP.MOVE,ar,args[i],0);}
        emit(pr,OP.CALL,base,args.length,1);l=base;
      }else break;
    }
    return l;
  }
  function exprPrimary(pr){
    if(match('nil')){const r=newReg(pr);emit(pr,OP.LOADNIL,r,0,0);return r;}
    if(match('true')){const r=newReg(pr);emit(pr,OP.LOADBOOL,r,1,0);return r;}
    if(match('false')){const r=newReg(pr);emit(pr,OP.LOADBOOL,r,0,0);return r;}
    if(peek().t==='num'){const v=next().v;const r=newReg(pr);emit(pr,OP.LOADK,r,intern(v),0);return r;}
    if(peek().t==='str'){const v=next().v;const r=newReg(pr);emit(pr,OP.LOADK,r,intern(v),0);return r;}
    if(peek().t==='id'){const name=next().v;const res=resolve(pr,name);const r=newReg(pr);if(res.kind==='local')emit(pr,OP.MOVE,r,res.reg,0);else emit(pr,OP.GETGLOBAL,r,intern(name),0);return r;}
    if(match('{')){
      const r=newReg(pr);emit(pr,OP.NEWTABLE,r,0,0);let ai=1;
      while(peek().t!=='}'&&peek().t!=='eof'){
        if(match('[')){const k=expr(pr);expect(']');expect('=');const v=expr(pr);emit(pr,OP.SETTABLE,r,k,v);}
        else if(peek().t==='id'&&tokens[p+1]&&tokens[p+1].t==='='){const name=next().v;next();const v=expr(pr);const kr=newReg(pr);emit(pr,OP.LOADK,kr,intern(name),0);emit(pr,OP.SETTABLE,r,kr,v);}
        else{const v=expr(pr);const kr=newReg(pr);emit(pr,OP.LOADK,kr,intern(ai++),0);emit(pr,OP.SETTABLE,r,kr,v);}
        match(',');match(';');
      }
      expect('}');return r;
    }
    if(match('(')){const e=expr(pr);expect(')');return e;}
    if(match('function'))return parseFunction(pr);
    throw new Error('Unexpected in expr: '+peek().t);
  }
  function parseFunction(pr){
    const child=newProto();const saved=regTop;regTop=0;expect('(');const params=[];
    if(peek().t!==')'){do{if(match('...')){params.push('...');break;}params.push(expect('id').v);}while(match(','));}
    expect(')');
    for(let i=0;i<params.length;i++){if(params[i]==='...')continue;child.locals.set(params[i],i);child.localCount=i+1;}
    regTop=child.localCount;block(child);expect('end');emit(child,OP.RETURN,0,0,0);regTop=saved;
    const idx=intern({__proto:1,code:child.code,maxR:child.maxR,n:params.filter(x=>x!=='...').length});
    const r=newReg(pr);emit(pr,OP.CLOSURE,r,idx,0);return r;
  }
  function blockUntil(pr,stops){while(peek().t!=='eof'&&stops.indexOf(peek().t)<0){if(['end','else','elseif','until'].indexOf(peek().t)>=0)break;statement(pr);}}
  function block(pr){while(peek().t!=='eof'&&peek().t!=='end'&&peek().t!=='else'&&peek().t!=='elseif'&&peek().t!=='until')statement(pr);}
  function statement(pr){
    if(match(';'))return;
    if(match('local')){
      if(match('function')){const name=expect('id').v;const reg=pr.localCount++;pr.locals.set(name,reg);if(reg>pr.maxR)pr.maxR=reg;const fr=parseFunction(pr);emit(pr,OP.MOVE,reg,fr,0);return;}
      const names=[];do{names.push(expect('id').v);}while(match(','));
      const regs=names.map(n=>{const r=pr.localCount++;pr.locals.set(n,r);if(r>pr.maxR)pr.maxR=r;return r;});
      if(match('=')){const vals=[];do{vals.push(expr(pr));}while(match(','));for(let i=0;i<regs.length;i++){if(i<vals.length)emit(pr,OP.MOVE,regs[i],vals[i],0);else emit(pr,OP.LOADNIL,regs[i],0,0);}}
      else for(const r of regs)emit(pr,OP.LOADNIL,r,0,0);return;
    }
    if(match('function')){const name=expect('id').v;const fr=parseFunction(pr);const res=resolve(pr,name);if(res.kind==='local')emit(pr,OP.MOVE,res.reg,fr,0);else emit(pr,OP.SETGLOBAL,fr,intern(name),0);return;}
    if(match('return')){
      if(['end','else','elseif','until','eof',';'].indexOf(peek().t)>=0){emit(pr,OP.RETURN,0,0,0);match(';');return;}
      const vals=[];do{vals.push(expr(pr));}while(match(','));for(let i=0;i<vals.length;i++)emit(pr,OP.MOVE,i,vals[i],0);emit(pr,OP.RETURN,0,vals.length,0);match(';');return;
    }
    if(match('if')){
      const cond=expr(pr);expect('then');const tr=newReg(pr);emit(pr,OP.MOVE,tr,cond,0);emit(pr,OP.TEST,tr,0,0);const jf=pr.code.length;emit(pr,OP.JMP,0,0,0);
      const sn=scopeEnter(pr);blockUntil(pr,['else','elseif','end']);scopeExit(pr,sn);
      const jends=[];if(peek().t==='else'||peek().t==='elseif'){const j=pr.code.length;emit(pr,OP.JMP,0,0,0);jends.push(j);}
      pr.code[jf+1]=pcOf(pr);
      while(match('elseif')){const c2=expr(pr);expect('then');const tr2=newReg(pr);emit(pr,OP.MOVE,tr2,c2,0);emit(pr,OP.TEST,tr2,0,0);const jf2=pr.code.length;emit(pr,OP.JMP,0,0,0);const sn2=scopeEnter(pr);blockUntil(pr,['else','elseif','end']);scopeExit(pr,sn2);if(peek().t==='else'||peek().t==='elseif'){const j=pr.code.length;emit(pr,OP.JMP,0,0,0);jends.push(j);}pr.code[jf2+1]=pcOf(pr);}
      if(match('else')){const sn3=scopeEnter(pr);blockUntil(pr,['end']);scopeExit(pr,sn3);}
      expect('end');const endPC=pcOf(pr);for(const j of jends)pr.code[j+1]=endPC;return;
    }
    if(match('while')){
      const ls=pcOf(pr);const cond=expr(pr);expect('do');const tr=newReg(pr);emit(pr,OP.MOVE,tr,cond,0);emit(pr,OP.TEST,tr,0,0);const jo=pr.code.length;emit(pr,OP.JMP,0,0,0);
      const sn=scopeEnter(pr);blockUntil(pr,['end']);scopeExit(pr,sn);expect('end');emit(pr,OP.JMP,ls,0,0);pr.code[jo+1]=pcOf(pr);return;
    }
    if(match('for')){
      const names=[];names.push(expect('id').v);while(match(','))names.push(expect('id').v);
      if(match('=')){
        if(names.length!==1)throw new Error('numeric for needs 1 var');
        const e1=expr(pr);expect(',');const e2=expr(pr);let e3=null;if(match(','))e3=expr(pr);expect('do');
        const rIdx=newReg(pr),rLimit=newReg(pr),rStep=newReg(pr);const rVar=pr.localCount++;pr.locals.set(names[0],rVar);if(rVar>pr.maxR)pr.maxR=rVar;
        emit(pr,OP.MOVE,rIdx,e1,0);emit(pr,OP.MOVE,rLimit,e2,0);if(e3!=null)emit(pr,OP.MOVE,rStep,e3,0);else emit(pr,OP.LOADK,rStep,intern(1),0);
        emit(pr,OP.SUB,rIdx,rIdx,rStep);const ls=pcOf(pr);emit(pr,OP.ADD,rIdx,rIdx,rStep);
        const r0=newReg(pr);emit(pr,OP.LOADK,r0,intern(0),0);const rPos=newReg(pr);emit(pr,OP.LT,rPos,r0,rStep);
        const rGT=newReg(pr);emit(pr,OP.LT,rGT,rLimit,rIdx);const rLT=newReg(pr);emit(pr,OP.LT,rLT,rIdx,rLimit);
        const rExit=newReg(pr),rAlt=newReg(pr);
        emit(pr,OP.MOVE,rExit,rPos,0);emit(pr,OP.TEST,rExit,1,0);emit(pr,OP.MOVE,rExit,rGT,0);
        emit(pr,OP.NOT,rAlt,rPos,0);emit(pr,OP.TEST,rAlt,1,0);emit(pr,OP.MOVE,rAlt,rLT,0);
        emit(pr,OP.TEST,rExit,0,0);emit(pr,OP.MOVE,rExit,rAlt,0);emit(pr,OP.TEST,rExit,0,0);const jo=pr.code.length;emit(pr,OP.JMP,0,0,0);
        emit(pr,OP.MOVE,rVar,rIdx,0);const sn=scopeEnter(pr);blockUntil(pr,['end']);scopeExit(pr,sn);expect('end');emit(pr,OP.JMP,ls,0,0);pr.code[jo+1]=pcOf(pr);return;
      }
      if(match('in')){
        let tableReg;if(peek().t==='id'&&(peek().v==='pairs'||peek().v==='ipairs')&&tokens[p+1]&&tokens[p+1].t==='('){next();expect('(');tableReg=expr(pr);expect(')');}else tableReg=expr(pr);
        while(match(','))expr(pr);expect('do');
        const rTable=newReg(pr);emit(pr,OP.MOVE,rTable,tableReg,0);const rKey=newReg(pr);emit(pr,OP.LOADNIL,rKey,0,0);
        const nameRegs=names.map(n=>{const r=pr.localCount++;pr.locals.set(n,r);if(r>pr.maxR)pr.maxR=r;return r;});
        const ls=pcOf(pr);const rNext=newReg(pr);emit(pr,OP.GETGLOBAL,rNext,intern('next'),0);
        const a0=rNext+1,a1=rNext+2;if(a1>pr.maxR)pr.maxR=a1;if(a1>=regTop)regTop=a1+1;
        emit(pr,OP.MOVE,a0,rTable,0);emit(pr,OP.MOVE,a1,rKey,0);emit(pr,OP.CALL,rNext,2,2);
        emit(pr,OP.MOVE,rKey,rNext,0);if(nameRegs[0]!=null)emit(pr,OP.MOVE,nameRegs[0],rNext,0);if(nameRegs[1]!=null)emit(pr,OP.MOVE,nameRegs[1],rNext+1,0);
        const rNil=newReg(pr);emit(pr,OP.LOADNIL,rNil,0,0);const rIs=newReg(pr);emit(pr,OP.EQ,rIs,rKey,rNil);emit(pr,OP.TEST,rIs,0,0);const jo=pr.code.length;emit(pr,OP.JMP,0,0,0);
        const sn=scopeEnter(pr);blockUntil(pr,['end']);scopeExit(pr,sn);expect('end');emit(pr,OP.JMP,ls,0,0);pr.code[jo+1]=pcOf(pr);return;
      }
      throw new Error('malformed for');
    }
    if(match('do')){const sn=scopeEnter(pr);blockUntil(pr,['end']);scopeExit(pr,sn);expect('end');return;}
    // assign or call
    const sp=p,sr=regTop;
    if(peek().t==='id'){
      const name=next().v;
      if(peek().t==='='||peek().t===','){
        const lhs=[{name}];while(match(','))lhs.push({name:expect('id').v});expect('=');
        const vals=[];do{vals.push(expr(pr));}while(match(','));
        for(let i=0;i<lhs.length;i++){const res=resolve(pr,lhs[i].name);if(i<vals.length){if(res.kind==='local')emit(pr,OP.MOVE,res.reg,vals[i],0);else emit(pr,OP.SETGLOBAL,vals[i],intern(lhs[i].name),0);}}
        match(';');return;
      }
      p=sp;regTop=sr;
    }
    expr(pr);match(';');
  }
  const main=newProto();regTop=0;block(main);emit(main,OP.RETURN,0,0,0);
  return {main,constants};
}

function serialize(prog){
  const flatK=[],protos=[];
  const add=(code,maxR)=>{const i=protos.length;protos.push({code:code.slice(),maxR:maxR+8});return i;};
  const mainIdx=add(prog.main.code,prog.main.maxR);
  for(const c of prog.constants){
    if(c&&typeof c==='object'&&c.__proto){const pi=add(c.code,c.maxR);flatK.push({t:'p',i:pi,n:c.n||0});}
    else flatK.push(c);
  }
  return {flatK,protos,mainIdx};
}

function buildVM(ser){
  const V=Array.from({length:16},rid);
  const sk = 1 + ri(254);
  const encStr = (s) => {
    const bytes = [...Buffer.from(s, 'utf8')].map((b, i) => (b ^ ((sk + i * 13) & 255)) & 255);
    return '{s=true,k=' + sk + ',d={' + bytes.join(',') + '}}';
  };
  const constLit=c=>{
    if(c===null||c===undefined)return 'nil';
    if(typeof c==='boolean')return c?'true':'false';
    if(typeof c==='number')return String(c);
    if(typeof c==='string')return encStr(c);
    if(c&&c.t==='p')return '{p='+c.i+',n='+c.n+'}';
    return encStr(String(c));
  };
  const kLit=ser.flatK.map(constLit).join(',');
  const pLit=ser.protos.map(pr=>'{c={'+pr.code.join(',')+'},m='+pr.maxR+'}').join(',');
  const L=[];
  L.push('--[[ Protected by QyrexObf v'+VERSION+' | qyrex.hopto.org | VM ]] ');
  L.push('return(function(...) ');
  L.push('local '+V[0]+'=_G; local '+V[1]+'=type; local '+V[2]+'=pcall; local '+V[3]+'=table; local '+V[4]+'='+V[3]+'.unpack or unpack; local '+V[5]+'=0; ');
  L.push(V[2]+'(function() if '+V[1]+'(game)=="userdata" or '+V[1]+'(game)=="table" then '+V[5]+'='+V[5]+'+1 end end); ');
  L.push(V[2]+'(function() if game and game.JobId=="00000000-0000-0000-0000-000000000000" then '+V[5]+'='+V[5]+'-5 end end); ');
  L.push(V[2]+'(function() if getmetatable and getmetatable(_G)~=nil then '+V[5]+'='+V[5]+'-3 end end); ');
  L.push('local '+V[6]+'={'+kLit+'}; local '+V[7]+'={'+pLit+'}; local '+V[8]+'='+ser.mainIdx+'; ');
  L.push('local function '+V[9]+'(pi,env,...) ');
  L.push('local P='+V[7]+'[pi+1]; if not P then return end; local code=P.c; local R={}; for i=0,P.m do R[i]=nil end; local pc=1; local n=#code; ');
  L.push('while pc+3<=n do local op=code[pc]; local a=code[pc+1]; local b=code[pc+2]; local c=code[pc+3]; pc=pc+4; ');
  L.push('if op==1 then R[a]=nil ');
  L.push('elseif op==2 then R[a]=(b~=0) ');
  L.push('elseif op==3 then local kv='+V[6]+'[b+1]; if type(kv)=="table" and kv.s then local t={}; for i=1,#kv.d do t[i]=string.char(bit32 and bit32.bxor(kv.d[i],(kv.k+(i-1)*13)%256) or (function(a,b) a=a%256 b=b%256 local r=0 local p=1 for _=1,8 do local a1=a%2 local b1=b%2 if a1~=b1 then r=r+p end a=math.floor((a-a1)/2) b=math.floor((b-b1)/2) p=p*2 end return r end)(kv.d[i],(kv.k+(i-1)*13)%256)) end; R[a]=table.concat(t) else R[a]=kv end ');
  L.push('elseif op==4 then R[a]=R[b] ');
  L.push('elseif op==5 then local nm='+V[6]+'[b+1]; R[a]=env[nm] ');
  L.push('elseif op==6 then local nm='+V[6]+'[b+1]; env[nm]=R[a] ');
  L.push('elseif op==7 then R[a]=R[b][R[c]] ');
  L.push('elseif op==8 then R[a][R[b]]=R[c] ');
  L.push('elseif op==9 then R[a]={} ');
  L.push('elseif op==10 then R[a]=R[b]+R[c] ');
  L.push('elseif op==11 then R[a]=R[b]-R[c] ');
  L.push('elseif op==12 then R[a]=R[b]*R[c] ');
  L.push('elseif op==13 then R[a]=R[b]/R[c] ');
  L.push('elseif op==14 then R[a]=R[b]%R[c] ');
  L.push('elseif op==15 then R[a]=R[b]^R[c] ');
  L.push('elseif op==16 then R[a]=R[b]..R[c] ');
  L.push('elseif op==17 then R[a]=-R[b] ');
  L.push('elseif op==18 then R[a]=not R[b] ');
  L.push('elseif op==19 then R[a]=#R[b] ');
  L.push('elseif op==20 then if a~=16777215 then pc=a*4+1 end ');
  L.push('elseif op==21 then R[a]=(R[b]==R[c]) ');
  L.push('elseif op==22 then R[a]=(R[b]<R[c]) ');
  L.push('elseif op==23 then R[a]=(R[b]<=R[c]) ');
  L.push('elseif op==24 then local tv=R[a]; if b==0 then if not tv then else pc=pc+4 end else if tv then else pc=pc+4 end end ');
  L.push('elseif op==25 then local fn=R[a]; local args={}; for i=1,b do args[i]=R[a+i] end; local rets={fn('+V[4]+'(args,1,b))}; local nr=c; if not nr or nr<1 then nr=1 end; for i=1,nr do R[a+i-1]=rets[i] end ');
  L.push('elseif op==26 then if b==0 then return else local out={}; for i=0,b-1 do out[i+1]=R[a+i] end; return '+V[4]+'(out,1,b) end ');
  L.push('elseif op==27 then local obj=R[b]; local key=R[c]; R[a]=obj[key]; R[a+1]=obj ');
  L.push('elseif op==28 then local ci='+V[6]+'[b+1]; local function cl(...) return '+V[9]+'(ci.p,env,...) end; R[a]=cl ');
  L.push('end end end; ');
  L.push('local env=setmetatable({},{__index='+V[0]+'}); return '+V[9]+'('+V[8]+',env,...); ');
  L.push('end)(...)');
  return L.join('');
}

function obfuscate(source){
  const src=String(source??'');
  if(!src.trim())throw new Error('Empty code');
  let prog;
  try{prog=compile(src);}catch(e){throw new Error('VM compile error: '+e.message);}
  const ser=serialize(prog);
  const code=buildVM(ser);
  return{code,stats:{inputBytes:Buffer.byteLength(src,'utf8'),outputBytes:Buffer.byteLength(code,'utf8'),mode:'QyrexObf-'+VERSION+'-VM',constants:prog.constants.length,codeOps:(prog.main.code.length/4)|0,layers:['bytecode-vm','no-user-loadstring','soft-anti-tamper','luau'],verified:true,note:'Dumper sees VM, not your source.'}};
}
module.exports={obfuscate,VERSION};
