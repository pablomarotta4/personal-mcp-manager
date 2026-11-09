import {emitDiagnostic} from './backend-diagnostics.js';
import { randomBytes,createHash } from 'node:crypto';
import { constants,lstatSync,readdirSync,openSync,fstatSync,readFileSync,closeSync,rmdirSync,realpathSync } from 'node:fs';
import { join } from 'node:path';
import { BackendPool,ActiveBudget,type PoolOptions,type ManifestInvalidation,type CallContext } from './pool.js';
import { privateDirectory } from './owned-stdio.js';
import { SafeError,type Config } from './policy.js';
import type { ReviewedManifest,BackendDescription } from './manifest.js';
import type { FacadePool } from './facade.js';
import type { OwnerChannel,ClientCwd } from './owner-channel.js';

type Lease={id:string;backend:string;owner:string;cwd?:ClientCwd;environment?:Readonly<Record<string,string>>;pool?:BackendPool;directory?:string;closed:boolean;release?:Promise<void>};
export interface SessionLease { id:string;view:FacadePool;describe:()=>Promise<BackendDescription>;used:()=>boolean;close:()=>Promise<void> }

/** Cached facade views are cheap; the existing supervisor owns each used generation. */
export class SessionPool {
 private leases=new Map<string,Lease>();
 private invalid=new Set<string>();
 private listeners=new Map<string,Set<(kind:ManifestInvalidation)=>void>>();
 private starts=0;private stopping=false;
 private directory:string;private invalidationDir:string;
 constructor(private config:Config,private manifests:Map<string,ReviewedManifest>,private owners:OwnerChannel,private options:PoolOptions){
  this.directory=join(options.ownershipDir,'sessions');this.invalidationDir=join(options.ownershipDir,'session-invalidations');
  this.scan();owners.onExit(owner=>{for(const lease of this.leases.values())if(lease.owner===owner)void this.release(lease).catch(()=>{});});owners.onFailure(()=>{void this.shutdown().catch(()=>{});});
 }
 private scan():void {
  privateDirectory(this.options.ownershipDir);
  for(const directory of [this.directory,this.invalidationDir]){
   try{const stat=lstatSync(directory);if(!stat.isDirectory()||stat.isSymbolicLink())throw new SafeError('ownership_quarantined');privateDirectory(directory);}
   catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')continue;throw new SafeError('ownership_quarantined');}
   const entries=readdirSync(directory);if(entries.length>1024)throw new SafeError('ownership_quarantined');
   for(const name of entries){
    const path=join(directory,name);
    if(directory===this.directory){
     if(!/^[0-9a-f]{64}$/.test(name))throw new SafeError('ownership_quarantined');try{privateDirectory(path);}catch{throw new SafeError('ownership_quarantined');}
     if(readdirSync(path).length)throw new SafeError('ownership_quarantined');
    }else{
     if(!/^[0-9a-f]{64}\.invalid\.json$/.test(name))throw new SafeError('invalidation_state_untrusted');
     const manifest=[...this.manifests.values()].find(value=>createHash('sha256').update(value.backendId).digest('hex')+'.invalid.json'===name);
     if(!manifest)throw new SafeError('invalidation_state_untrusted');
     const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
     try{const stat=fstatSync(fd);if(!stat.isFile()||stat.uid!==process.getuid?.()||(stat.mode&0o7777)!==0o600||stat.size>1024)throw new SafeError('invalidation_state_untrusted');
      const value=JSON.parse(readFileSync(fd,'utf8'));if(Object.keys(value).sort().join(',')!=='fingerprint,reason,version'||value.version!==1||!['tools','resources','prompts','logging','drift'].includes(value.reason)||value.fingerprint!==manifest.fingerprint)throw new SafeError('invalidation_state_untrusted');this.invalid.add(manifest.backendId);
     }catch{throw new SafeError('invalidation_state_untrusted');}finally{closeSync(fd);}
    }
   }
  }
 }
 private assertProfile(backend:string):void {
  if(this.invalid.has(backend))throw new SafeError('manifest_invalid');
  try{lstatSync(this.invalidationDir);}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;this.invalid.add(backend);throw new SafeError('invalidation_state_untrusted');}
  let fd:number|undefined;
  try{privateDirectory(this.invalidationDir);fd=openSync(join(this.invalidationDir,createHash('sha256').update(backend).digest('hex')+'.invalid.json'),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
   const stat=fstatSync(fd);if(!stat.isFile()||stat.uid!==process.getuid?.()||(stat.mode&0o7777)!==0o600||stat.size>1024)throw new SafeError('invalidation_state_untrusted');
   const value=JSON.parse(readFileSync(fd,'utf8'));if(Object.keys(value).sort().join(',')!=='fingerprint,reason,version'||value.version!==1||!['tools','resources','prompts','logging','drift'].includes(value.reason)||value.fingerprint!==this.manifests.get(backend)?.fingerprint)throw new SafeError('invalidation_state_untrusted');
  }catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;this.invalid.add(backend);throw new SafeError('invalidation_state_untrusted');}
  finally{if(fd!==undefined)closeSync(fd);}
  this.invalid.add(backend);throw new SafeError('manifest_invalid');
 }
 private assert(lease:Lease,id:string):void {
  this.owners.assertOwner(lease.owner,lease.backend);
  if(this.stopping||lease.closed)throw new SafeError('shutting_down');
  if(id!==lease.backend||!this.manifests.has(id))throw new SafeError('not_allowed');
  this.assertProfile(id);
 }
 create(backend:string,owner:string):SessionLease {
  this.owners.assertOwner(owner,backend);if(this.stopping)throw new SafeError('shutting_down');
  if(!this.manifests.has(backend)||this.config.servers.get(backend)?.scope!=='session')throw new SafeError('not_allowed');
  this.assertProfile(backend);
  const cwd=this.config.servers.get(backend)!.cwdMode==='client'?this.owners.getCwd(owner,backend):undefined;
  if(this.config.servers.get(backend)!.cwdMode==='client'&&!cwd)throw new SafeError('owner_cwd_required');
  const environment=(this.config.servers.get(backend)!.catalogMode==='mysql-session')?this.owners.getMysqlContext(owner,backend):undefined;
  if(environment&&Object.entries(this.config.servers.get(backend)!.env).some(([key,value])=>environment[key]!==value))throw new SafeError('mysql_source_environment_mismatch');
  const lease:Lease={...(environment?{environment}:{}),id:randomBytes(32).toString('hex'),backend,owner,...(cwd?{cwd}:{}),closed:false};this.leases.set(lease.id,lease);
  const view:FacadePool={
   assertManifestValid:id=>this.assert(lease,id),
   onManifestInvalidated:(id,callback)=>{this.assert(lease,id);let callbacks=this.listeners.get(id);if(!callbacks){callbacks=new Set();this.listeners.set(id,callbacks);}callbacks.add(callback);return ()=>{callbacks!.delete(callback);if(!callbacks!.size)this.listeners.delete(id);};},
   call:(id,tool,args,context)=>{this.assert(lease,id);if(!this.config.servers.get(id)?.allowedTools.includes(tool))return Promise.reject(new SafeError('not_allowed'));if(context?.signal?.aborted)return Promise.reject(new SafeError('request_cancelled'));return this.pool(lease).call(id,tool,args,context);},
   listResources:(id,cursor,context)=>{this.assert(lease,id);if(context?.signal?.aborted)return Promise.reject(new SafeError('request_cancelled'));return this.pool(lease).listResources(id,cursor,context);},
   readResource:(id,uri,context)=>{this.assert(lease,id);if(this.config.servers.get(id)?.catalogMode!=="mysql-session"&&!this.manifests.get(id)?.description.resources?.some(value=>value.uri===uri))return Promise.reject(new SafeError('not_allowed'));if(context?.signal?.aborted)return Promise.reject(new SafeError('request_cancelled'));return this.pool(lease).readResource(id,uri,context);},
  };
  return {id:lease.id,view,describe:()=>{this.assert(lease,backend);return this.pool(lease).describe(backend);},used:()=>Boolean(lease.pool),close:()=>this.release(lease)};
 }
 private pool(lease:Lease):BackendPool {
  if(lease.pool)return lease.pool;
  if([...this.leases.values()].filter(value=>value.pool).length>=128||((this.options.activityBudget?.active??0)>=(this.options.activityBudget?.maximum??32)))throw new SafeError('busy');
  privateDirectory(this.directory);privateDirectory(this.invalidationDir);
  lease.directory=join(this.directory,lease.id);privateDirectory(lease.directory);
  const template=this.config.servers.get(lease.backend)!;
  const policy={...template,...(lease.cwd?{cwd:lease.cwd.path}:{}),...(lease.environment?{env:{...lease.environment,...template.env}}:{})};
  const beforeStart=lease.cwd?async(id:string)=>{
   await this.options.beforeStart?.(id);
   emitDiagnostic(this.options.diagnostic,"cwd","begin");
   try{
    const stat=lstatSync(lease.cwd!.path,{bigint:true});
    if(!stat.isDirectory()||stat.dev.toString()!==lease.cwd!.device||stat.ino.toString()!==lease.cwd!.inode||realpathSync(lease.cwd!.path)!==lease.cwd!.path)throw new Error();
    emitDiagnostic(this.options.diagnostic,"cwd","ok");
   }catch{emitDiagnostic(this.options.diagnostic,"cwd","owner_cwd_changed");throw new SafeError('owner_cwd_changed');}
  }:this.options.beforeStart;
  const pool=new BackendPool({servers:new Map([[lease.backend,policy]]),idleTimeoutMs:this.config.idleTimeoutMs},{...this.options,
   ...(policy.startupTimeoutMs===undefined?{}:{startupTimeoutMs:policy.startupTimeoutMs}),
   ...(policy.toolTimeoutMs===undefined?{}:{callTimeoutMs:policy.toolTimeoutMs}),
   beforeStart,ownershipDir:lease.directory,invalidationDir:this.invalidationDir,idleRetirement:false,oneGeneration:true,maxBackends:1});
  try{pool.bindManifest(lease.backend,this.manifests.get(lease.backend)!);}
  catch(error){if(!readdirSync(lease.directory).length)rmdirSync(lease.directory);lease.directory=undefined;throw error;}
  pool.onManifestInvalidated(lease.backend,kind=>{this.invalid.add(lease.backend);for(const callback of this.listeners.get(lease.backend)??[])try{callback(kind);}catch{/* Every other facade must still receive invalidation. */}});
  lease.pool=pool;this.starts++;return pool;
 }
 private release(lease:Lease):Promise<void> {
  lease.closed=true;
  lease.release??=(async()=>{
   await lease.pool?.shutdown();
   if(lease.directory){privateDirectory(lease.directory);if(readdirSync(lease.directory).length)throw new SafeError('ownership_quarantined');rmdirSync(lease.directory);}
   this.leases.delete(lease.id);
  })();return lease.release;
 }
 snapshot(){const pools=[...this.leases.values()].flatMap(lease=>lease.pool?[lease.pool.snapshot()]:[]);return {live:pools.reduce((n,p)=>n+p.live,0),starts:this.starts,active:pools.reduce((n,p)=>n+p.active,0),retained:pools.length,invalidationFailures:pools.reduce((n,p)=>n+p.invalidationFailures,0),quarantined:pools.reduce((n,p)=>n+p.quarantined,0)};}
 snapshotByProfile(){
  const profiles=new Map([...this.config.servers.keys()].map(id=>[id,{backendLive:0,retained:0}]));
  for(const lease of this.leases.values()){
   const row=profiles.get(lease.backend);if(!row)continue;
   if(lease.pool){row.retained++;row.backendLive+=lease.pool.snapshot().live;}
  }
  return Object.fromEntries(profiles);
 }
 async shutdown():Promise<void>{this.stopping=true;const results=await Promise.allSettled([...this.leases.values()].map(lease=>this.release(lease)));if(results.some(value=>value.status==='rejected'))throw new SafeError('cleanup_unproven');}
}
