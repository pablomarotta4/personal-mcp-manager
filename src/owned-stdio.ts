import { AsyncLocalStorage } from "node:async_hooks";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants, closeSync, fstatSync, openSync, readFileSync, writeFileSync, ftruncateSync, unlinkSync, lstatSync, mkdirSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type {Writable,Readable} from "node:stream";
import {nativeSupervisor,startFrame,stopFrame,StatusReader} from "./supervisor-wire.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import type { JSONRPCMessage, RequestId } from "@modelcontextprotocol/sdk/types.js";
import { SafeError, type BackendPolicy } from "./policy.js";
const sleep=(ms:number)=>new Promise<void>(r=>setTimeout(r,ms));
export function groupAbsent(pid:number):boolean {
  try { process.kill(-pid,0); return false; }
  catch(e) { return (e as NodeJS.ErrnoException).code === "ESRCH"; }
}
/** An actual correlated backend error response, never a local transport failure. */
export class CompletedBackendError extends Error {
  constructor(readonly code:number,message:string,readonly data?:unknown){super(message);this.name="CompletedBackendError";}
}
interface ResponseScope {ids:Set<RequestId>;error?:CompletedBackendError}
interface RecordData { ownerPid:number; supervisorPid:number|null; generation:string }
export interface OwnedOptions { id:string; ownershipDir:string; closeTimeoutMs?:number; testOnlySupervisor?:"node-reference" }
export function privateDirectory(path:string):void {
  if(!path || resolve(path)!==path)throw new SafeError("invalid_ownership_directory");
  try{mkdirSync(path,{mode:0o700});}catch(e){if((e as NodeJS.ErrnoException).code!=="EEXIST")throw new SafeError("invalid_ownership_directory");}
  const s=lstatSync(path);
  if(!s.isDirectory() || s.isSymbolicLink() || s.uid!==process.getuid?.() || (s.mode&0o7777)!==0o700 || realpathSync(path)!==path)
    throw new SafeError("invalid_ownership_directory");
}
function readRecord(path:string):RecordData {
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
    const s=fstatSync(fd);
    if(!s.isFile() || s.uid!==process.getuid?.() || (s.mode&0o7777)!==0o600 || s.size>1024)throw new SafeError("ownership_quarantined");
    const r=JSON.parse(readFileSync(fd,"utf8")) as RecordData;
    if(!Number.isSafeInteger(r.ownerPid) || r.ownerPid<2 || (r.supervisorPid!==null&&(!Number.isSafeInteger(r.supervisorPid)||r.supervisorPid<2)) || typeof r.generation!=="string")throw new SafeError("ownership_quarantined");
    return r;
  }catch{throw new SafeError("ownership_quarantined");}finally{closeSync(fd);}
}
export class OwnedStdio implements Transport {
  onclose?:()=>void;
  onerror?:(error:Error)=>void;
  onmessage?:(message:JSONRPCMessage)=>void;
  private child?:ChildProcess;
  private control?:Writable;
  private status?:Readable;
  private closing?:Promise<void>;
  private exited?:Promise<void>;
  private started=false;
  private stopped=false;
  private closedNotified=false;
  private recordPath:string;
  private record:RecordData;
  private ownsRecord=false;
  private retainRecord=false;
  private responseScope=new AsyncLocalStorage<ResponseScope>();
  private responseOwners=new Map<RequestId,ResponseScope>();
  private buffer=new ReadBuffer({maxBufferSize:1024*1024});
  cleaned=false;
  get pid():number|undefined{return this.child?.pid;}
  constructor(private policy:BackendPolicy,private options:OwnedOptions){
    privateDirectory(options.ownershipDir);
    this.recordPath=join(options.ownershipDir,createHash("sha256").update(options.id).digest("hex")+".json");
    this.record={ownerPid:process.pid,supervisorPid:null,generation:randomUUID()};
  }
  private reserve():void {
    // Existing records are never auto-reclaimed: read-then-unlink would race
    // another manager after a crash. Recovery requires an explicit offline check.
    try{writeFileSync(this.recordPath,JSON.stringify(this.record),{flag:"wx",mode:0o600});this.ownsRecord=true;}
    catch{throw new SafeError("ownership_quarantined");}
  }
  private persistPid():void {
    const fd=openSync(this.recordPath,constants.O_WRONLY|constants.O_NOFOLLOW);
    try{const s=fstatSync(fd);if(!s.isFile()||s.uid!==process.getuid?.()||(s.mode&0o7777)!==0o600)throw new SafeError("ownership_quarantined");ftruncateSync(fd,0);writeFileSync(fd,JSON.stringify(this.record));}
    finally{closeSync(fd);}
  }
  async start():Promise<void>{
    if(this.started||this.stopped)throw new SafeError("backend_unavailable");
    this.started=true;this.reserve();
    const env:Record<string,string>={};
    for(const k of ["PATH","HOME","USER","LOGNAME","LANG","LC_ALL","TMPDIR"]){const v=process.env[k];if(v!==undefined)env[k]=v;}
    const backendEnv=(this.policy.catalogMode==='mysql-session')?{...this.policy.env}:{...env,...this.policy.env};
    let frame:Buffer|undefined;
    try{
      const reference=this.options.testOnlySupervisor==="node-reference";
      if(this.options.testOnlySupervisor!==undefined&&!reference)throw new SafeError("supervisor_unavailable");
      frame=reference?undefined:startFrame(this.policy,backendEnv);
      this.child=reference
        ?spawn(process.execPath,[fileURLToPath(new URL("./supervisor.js",import.meta.url))],{detached:true,stdio:["pipe","pipe","ignore","ipc"],env,shell:false})
        :spawn(nativeSupervisor(),[],{detached:true,stdio:["pipe","pipe","ignore","pipe","pipe"],env,shell:false});
      const child=this.child;
      if(!reference){this.control=child.stdio[3] as Writable;this.status=child.stdio[4] as Readable;this.control.on("error",()=>{});}
      this.exited=new Promise<void>(resolveExit=>{
        child.once("exit",()=>{resolveExit();this.notifyClosed();});
        child.once("error",()=>{resolveExit();this.notifyClosed();});
      });
      child.stdin!.on("error",()=>this.onerror?.(new SafeError("backend_unavailable")));
      child.stdout!.on("data",(chunk:Buffer)=>{
        try{this.buffer.append(chunk);let m;while((m=this.buffer.readMessage())!==null){
          if(!("method" in m)&&m.id!==undefined){
            const owner=this.responseOwners.get(m.id);
            if(owner){this.responseOwners.delete(m.id);owner.ids.delete(m.id);if("error" in m)owner.error=new CompletedBackendError(m.error.code,m.error.message,m.error.data);}
          }
          this.onmessage?.(m);
        }}
        catch{this.onerror?.(new SafeError("backend_protocol_error"));void this.close().catch(()=>{});}
      });
      child.stdout!.on("error",()=>this.onerror?.(new SafeError("backend_unavailable")));
      if(!child.pid)throw new SafeError("backend_unavailable");
      this.record.supervisorPid=child.pid;this.persistPid();
      await new Promise<void>((yes,no)=>{
        let settled=false;
        const timer=setTimeout(()=>done(new SafeError("backend_unavailable")),5000);
        const ready=(m:unknown)=>{if(m&&typeof m==="object"&&(m as {type?:string}).type==="ready")done();};
        const failed=()=>done(new SafeError("backend_unavailable"));
        const done=(error?:Error)=>{
          if(settled)return;settled=true;clearTimeout(timer);
          child.off("message",ready);child.off("exit",failed);child.off("error",failed);
          error?no(error):yes();
        };
        child.once("exit",failed);child.once("error",failed);
        if(reference){
          child.on("message",ready);
          child.send({type:"start",policy:{...this.policy,env:backendEnv}},error=>{if(error)failed();});
        }else{
          const reader=new StatusReader();
          const invalid=()=>{
            done(new SafeError("backend_unavailable"));
            this.onerror?.(new SafeError("backend_unavailable"));void this.close().catch(()=>{});
          };
          this.control!.on("error",invalid);this.status!.on("error",invalid);
          this.status!.on("data",(chunk:Buffer)=>{try{if(reader.push(chunk,this.stopped))done();}catch{invalid();}});
          this.status!.on("end",()=>{try{reader.end();}catch{if(!this.stopped)invalid();}});
          this.control!.write(frame!,error=>{frame!.fill(0);if(error)invalid();});
        }
      });
    }catch{try{await this.close();}finally{frame?.fill(0);}throw new SafeError("backend_unavailable");}
  }
  /** Correlation is captured at send, then matched before the SDK consumes a reply. */
  withCompletedResponses<T>(run:()=>Promise<T>):Promise<T>{
    const scope:ResponseScope={ids:new Set()};
    return this.responseScope.run(scope,async()=>{
      try{return await run();}
      catch(error){throw scope.error??error;}
      finally{for(const id of scope.ids){if(this.responseOwners.get(id)===scope)this.responseOwners.delete(id);}}
    });
  }
  private notifyClosed():void{if(!this.closedNotified){this.closedNotified=true;this.onclose?.();}}
  async send(message:JSONRPCMessage):Promise<void>{
    if(this.stopped||!this.child?.stdin?.writable)throw new SafeError("backend_unavailable");
    const value=serializeMessage(message);if(Buffer.byteLength(value)>1024*1024)throw new SafeError("request_too_large");
    const scope=this.responseScope.getStore();
    if(scope&&"method" in message&&"id" in message){scope.ids.add(message.id);this.responseOwners.set(message.id,scope);}
    await new Promise<void>((yes,no)=>this.child!.stdin!.write(value,error=>error?no(new SafeError("backend_unavailable")):yes()));
  }
  retainOwnershipRecord():void{this.retainRecord=true;}
  close():Promise<void>{
    if(this.closing)return this.closing;
    this.stopped=true;
    this.closing=(async()=>{
      const child=this.child;
      if(this.control){
        try{this.control.end(stopFrame());}catch{/* EOF remains the control fallback. */this.control.destroy();}
      }else if(child?.connected)try{child.send({type:"stop"},()=>{});}catch{/* exit/absence verification remains mandatory */}
      const deadline=Date.now()+(this.options.closeTimeoutMs??5000);
      if(this.exited){
        const result=await new Promise<boolean>(done=>{const timer=setTimeout(()=>done(false),Math.max(1,deadline-Date.now()));void this.exited!.then(()=>{clearTimeout(timer);done(true);});});
        if(!result)throw new SafeError("cleanup_unproven");
      }
      if(child?.pid){while(!groupAbsent(child.pid)){if(Date.now()>=deadline)throw new SafeError("cleanup_unproven");await sleep(20);}}
      this.buffer.clear();this.responseOwners.clear();child?.stdin?.destroy();child?.stdout?.destroy();this.control?.destroy();this.status?.destroy();
      if(this.ownsRecord&&!this.retainRecord){const record=readRecord(this.recordPath);if(record.generation!==this.record.generation)throw new SafeError("cleanup_unproven");unlinkSync(this.recordPath);this.ownsRecord=false;}
      this.cleaned=true;this.notifyClosed();
    })();
    return this.closing;
  }
}
