import {createHash} from 'node:crypto';
import {constants,openSync,closeSync,fstatSync,lstatSync,readFileSync,realpathSync} from 'node:fs';
import {dirname,join,isAbsolute,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {SafeError,type BackendPolicy} from './policy.js';
const fail=():never=>{throw new SafeError('supervisor_unavailable');};
const maximum=2*1024*1024;
function text(value:string,limit:number):Buffer{
  if(typeof value!=='string'||value.includes('\0'))return fail();
  if(value.length>limit)return fail();
  const bytes=Buffer.from(value,'utf8');
  if(bytes.length>maximum||bytes.toString('utf8')!==value)return fail();
  const length=Buffer.alloc(4);length.writeUInt32BE(bytes.length);return Buffer.concat([length,bytes]);
}
function count(value:number):Buffer{const bytes=Buffer.alloc(4);bytes.writeUInt32BE(value);return bytes;}
export function startFrame(policy:BackendPolicy,env:Record<string,string>):Buffer{
  if(!isAbsolute(policy.command)||!isAbsolute(policy.cwd)||policy.args.length>64||Object.keys(env).length>71)return fail();
  const fields=[text(policy.command,4096),text(policy.cwd,4096),count(policy.args.length)];
  for(const arg of policy.args)fields.push(text(arg,4096));
  fields.push(count(Object.keys(env).length));
  for(const [key,value]of Object.entries(env)){
    if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key))return fail();
    fields.push(text(key,maximum),text(value,16384));
  }
  const size=fields.reduce((n,b)=>n+b.length,0);if(size>maximum)return fail();
  const header=Buffer.alloc(12);header.write('PMMS');header[4]=1;header[5]=1;header.writeUInt32BE(size,8);
  return Buffer.concat([header,...fields]);
}
export function stopFrame():Buffer{const frame=Buffer.alloc(12);frame.write('PMMS');frame[4]=1;frame[5]=2;return frame;}
export class StatusReader{
  private bytes=Buffer.alloc(0);private ready=false;
  push(chunk:Buffer,stopped=false):boolean{
    if(stopped||this.ready||this.bytes.length+chunk.length>8)return fail();
    this.bytes=Buffer.concat([this.bytes,chunk]);if(this.bytes.length<8)return false;
    if(this.bytes.subarray(0,4).toString()!=='PMMR'||this.bytes[4]!==1||this.bytes[5]!==1||this.bytes[6]!==0||this.bytes[7]!==0)return fail();
    this.ready=true;return true;
  }
  end():void{if(!this.ready)return fail();}
}
function safeParents(path:string):void{
  for(let parent=dirname(path);;parent=dirname(parent)){
    const info=lstatSync(parent);
    if(!info.isDirectory()||info.isSymbolicLink()||(info.uid!==0&&info.uid!==process.getuid?.())||(info.mode&0o022)!==0)return fail();
    if(parent==='/')return;
  }
}
function checkedFile(path:string,limit:number):Buffer{
  if(realpathSync(path)!==path)return fail();
  safeParents(path);
  const info=lstatSync(path);if(info.isSymbolicLink())return fail();
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const stat=fstatSync(fd);if(!stat.isFile()||stat.uid!==process.getuid?.()||(stat.mode&0o022)!==0||stat.size>limit)return fail();return readFileSync(fd);}finally{closeSync(fd);}
}
/** No caller-selected executable and no environment-controlled fallback. */
export function nativeSupervisor():string{
  try{
    const dist=dirname(fileURLToPath(import.meta.url));
    if(realpathSync(dist)!==dist)return fail();
    const directory=lstatSync(dist);if(!directory.isDirectory()||directory.uid!==process.getuid?.()||(directory.mode&0o022)!==0)return fail();
    const manifest=JSON.parse(checkedFile(join(dist,'native-supervisor.json'),16384).toString('utf8'));
    const flags=['-std=c11','-O2','-Wall','-Wextra','-Werror','-fstack-protector-strong'];
    if(Object.keys(manifest).sort().join(',')!=='binary,binarySha256,compiler,flags,sourceSha256,version'||manifest.version!==1||manifest.binary!=='personal-mcp-supervisor'||! /^[a-f0-9]{64}$/.test(manifest.binarySha256)||! /^[a-f0-9]{64}$/.test(manifest.sourceSha256)||JSON.stringify(manifest.flags)!==JSON.stringify(flags)||Object.keys(manifest.compiler).sort().join(',')!=='path,target,version'||manifest.compiler.path!=='/usr/bin/clang'||typeof manifest.compiler.version!=='string'||!manifest.compiler.version||typeof manifest.compiler.target!=='string'||!manifest.compiler.target)return fail();
    const binary=join(dist,'personal-mcp-supervisor');
    if((lstatSync(binary).mode&0o111)===0)return fail();
    if(createHash('sha256').update(checkedFile(binary,16*1024*1024)).digest('hex')!==manifest.binarySha256)return fail();
    if(createHash('sha256').update(checkedFile(resolve(dist,'../native/supervisor.c'),1024*1024)).digest('hex')!==manifest.sourceSha256)return fail();
    return binary;
  }catch{return fail();}
}
