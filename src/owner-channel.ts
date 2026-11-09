import {decodeMysqlContext} from './mysql-context.js';
import type { Duplex } from 'node:stream';
import { isAbsolute, normalize } from 'node:path';
import { SafeError } from './policy.js';

export interface ClientCwd {readonly path:string;readonly device:string;readonly inode:string}
function decodeCwd(value:unknown):ClientCwd {
  if(!value||typeof value!=='object'||Array.isArray(value))throw new SafeError('owner_cwd_invalid');
  const v=value as Record<string,unknown>;
  if(Object.keys(v).sort().join(',')!=='device,inode,pathB64'||typeof v.pathB64!=='string'||v.pathB64.length>1364)throw new SafeError('owner_cwd_invalid');
  const bytes=Buffer.from(v.pathB64,'base64');
  if(bytes.length<1||bytes.length>1023||bytes.toString('base64')!==v.pathB64)throw new SafeError('owner_cwd_invalid');
  const path=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  if(!isAbsolute(path)||path.includes('\0')||normalize(path)!==path)throw new SafeError('owner_cwd_invalid');
  for(const key of ['device','inode'])if(typeof v[key]!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(v[key] as string)||BigInt(v[key] as string)>((1n<<64n)-1n))throw new SafeError('owner_cwd_invalid');
  if(v.inode==='0')throw new SafeError('owner_cwd_invalid');
  return Object.freeze({path,device:v.device as string,inode:v.inode as string});
}

/** Private inherited channel. Capabilities never enter error messages or diagnostics. */
export class OwnerChannel {
  private owners = new Map<string,Readonly<{backend:string;cwd?:ClientCwd;environment?:Readonly<Record<string,string>>}>>();
  private highWater = 0n;
  private buffer = Buffer.alloc(0);
  private frameTimer?:NodeJS.Timeout;
  private healthy = true;
  private closed = false;
  private pending = 0;
  private requestIds=new Set<string>();
  private timers = new Set<NodeJS.Timeout>();
  private exits = new Set<(owner:string)=>void>();
  private failures = new Set<()=>void>();
  constructor(private stream:Duplex, private backends:Set<string>, private maxCapabilities=1024, private clientCwdBackends=new Set<string>(), private mysqlContextBackends=new Set<string>()) {
    stream.on('data',chunk=>this.receive(Buffer.from(chunk)));
    stream.on('end',()=>this.fail()); stream.on('close',()=>this.fail()); stream.on('error',()=>this.fail());
    this.send({v:1,type:'ready'});
  }
  get isHealthy():boolean{return this.healthy;}
  assertHealthy():void {if(!this.healthy)throw new SafeError('owner_channel_failed');}
  assertOwner(owner:unknown,backend:string):void {
    this.assertHealthy();
    if(typeof owner!=='string'||!/^[0-9a-f]{64}$/.test(owner)||this.owners.get(owner)?.backend!==backend)throw new SafeError('owner_not_registered');
  }
  getCwd(owner:string,backend:string):ClientCwd|undefined {this.assertOwner(owner,backend);return this.owners.get(owner)!.cwd;}
  getMysqlContext(owner:string,backend:string):Readonly<Record<string,string>> {this.assertOwner(owner,backend);const value=this.owners.get(owner)!.environment;if(!value)throw new SafeError('mysql_context_required');return value;}
  onExit(callback:(owner:string)=>void):()=>void {this.exits.add(callback);return ()=>this.exits.delete(callback);}
  onFailure(callback:()=>void):()=>void {this.failures.add(callback);if(!this.healthy&&!this.closed)queueMicrotask(callback);return ()=>this.failures.delete(callback);}
  private emit(callback:()=>void):void {try{callback();}catch{this.fail();}}
  private send(value:Record<string,unknown>,complete?:()=>void):void {
    if(!this.healthy)return;
    if(this.pending>=16){this.fail();return;}this.pending++;
    const timer=setTimeout(()=>this.fail(),5000);timer.unref();this.timers.add(timer);
    try{if(!this.stream.write(JSON.stringify(value)+'\n',error=>{clearTimeout(timer);this.timers.delete(timer);this.pending--;complete?.();if(error)this.fail();}))this.fail();}
    catch{this.fail();}
  }
  private receive(chunk:Buffer):void {
    if(!this.healthy)return;
    // Bound both a partial frame and a coalesced batch; registration has no async work.
    if(chunk.length>4096*64){this.fail();return;}
    this.buffer=Buffer.concat([this.buffer,chunk]);let frames=0;
    try{
      while(this.buffer.includes(10)){
        const end=this.buffer.indexOf(10);if(end+1>131072||++frames>64)throw new Error();
        clearTimeout(this.frameTimer);this.frameTimer=undefined;
        const line=new TextDecoder('utf-8',{fatal:true}).decode(this.buffer.subarray(0,end));this.buffer=this.buffer.subarray(end+1);
        const keyTokens=line.match(/"(?:\\.|[^"\\])*"\s*:/g)??[];
        const names=keyTokens.map(key=>JSON.parse(key.slice(0,key.lastIndexOf(':')).trim()));
        if(new Set(names).size!==names.length)throw new Error();
        const value=JSON.parse(line) as Record<string,unknown>;
        if(!value||Array.isArray(value)||typeof value!=='object'||value.v!==1)throw new Error();
        if(value.type==='register'){
          if(typeof value.requestId!=='string'||!/^[0-9a-f]{32}$/.test(value.requestId)||this.requestIds.has(value.requestId)||typeof value.owner!=='string'||!/^[0-9a-f]{64}$/.test(value.owner)||typeof value.backend!=='string'||!this.backends.has(value.backend))throw new Error();
          if(end+1>4096&&!this.mysqlContextBackends.has(value.backend))throw new Error();
          const clientCwd=this.clientCwdBackends.has(value.backend),mysql=this.mysqlContextBackends.has(value.backend);
          const required=['backend','owner','requestId','type','v',...(clientCwd?['cwd']:[]),...(mysql?['mysqlContext']:[])].sort().join(',');
          if(Object.keys(value).sort().join(',')!==required)throw new Error();
          const cwd=clientCwd?decodeCwd(value.cwd):undefined;
          const environment=mysql?decodeMysqlContext(value.mysqlContext):undefined;
          const counter=BigInt('0x'+value.owner.slice(0,16));
          if(counter<=this.highWater||this.owners.size>=this.maxCapabilities)throw new Error();
          this.highWater=counter;this.owners.set(value.owner,Object.freeze({backend:value.backend,...(cwd?{cwd}:{}),...(environment?{environment}:{})}));const requestId=value.requestId;this.requestIds.add(requestId);this.send({v:1,type:'ack',requestId},()=>this.requestIds.delete(requestId));
        }else if(value.type==='exit'){
          if(Object.keys(value).sort().join(',')!=='owner,type,v'||typeof value.owner!=='string'||!/^[0-9a-f]{64}$/.test(value.owner))throw new Error();
          const counter=BigInt('0x'+value.owner.slice(0,16));
          if(counter===0n||counter>this.highWater)throw new Error();
          const existed=this.owners.delete(value.owner);if(existed)for(const callback of this.exits)this.emit(()=>callback(value.owner as string));
        }else throw new Error();
        if(!this.healthy)return;
      }
      if(this.buffer.length>=(this.mysqlContextBackends.size?131072:4096))throw new Error();
      if(this.buffer.length&&!this.frameTimer){this.frameTimer=setTimeout(()=>this.fail(),5000);this.frameTimer.unref();}
    }catch{this.fail();}
  }
  private fail():void {
    if(!this.healthy)return;this.healthy=false;this.owners.clear();this.requestIds.clear();this.buffer=Buffer.alloc(0);
    clearTimeout(this.frameTimer);this.frameTimer=undefined;
    for(const timer of this.timers)clearTimeout(timer);this.timers.clear();
    if(!this.closed)for(const callback of this.failures)try{callback();}catch{/* Failure stays terminal. */}
    this.stream.destroy();
  }
  close():void {this.closed=true;this.fail();this.exits.clear();this.failures.clear();}
}
