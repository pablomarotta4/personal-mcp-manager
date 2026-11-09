import {emitDiagnostic,classifyDiagnosticFailure,type DiagnosticSink,type DiagnosticStage} from './backend-diagnostics.js';
import {createHash} from "node:crypto";
import {constants,openSync,closeSync,fstatSync,writeFileSync,fsyncSync,readFileSync} from "node:fs";
import {join} from "node:path";
import {Client} from "@modelcontextprotocol/sdk/client/index.js";
import {CallToolResultSchema,type CallToolResult,type Tool,type Progress,type Resource,type ListResourcesResult,type ResourceTemplate,type Prompt,type ReadResourceResult,ToolListChangedNotificationSchema,ResourceListChangedNotificationSchema,PromptListChangedNotificationSchema,LoggingMessageNotificationSchema} from "@modelcontextprotocol/sdk/types.js";
import {fingerprintDescription,mysqlInvariantDescription,parseManifest,type BackendDescription,type ReviewedManifest} from "./manifest.js";
export {CompletedBackendError} from "./owned-stdio.js";
import {OwnedStdio,CompletedBackendError,privateDirectory} from "./owned-stdio.js";
import {SafeError,type Config,type BackendPolicy} from "./policy.js";
const sleep=(ms:number)=>new Promise<void>(r=>setTimeout(r,ms));
interface Entry {client:Client;transport:OwnedStdio;ready:Promise<void>;active:number;tainted:boolean;closing?:Promise<void>;timer?:NodeJS.Timeout;tools?:Tool[];discovery?:Promise<Tool[]>;description?:Promise<BackendDescription>;invalidationPersistenceFailed?:boolean}
export type ManifestInvalidation="tools"|"resources"|"prompts"|"logging"|"drift";
export interface CallContext {signal?:AbortSignal;meta?:Record<string,unknown>;onProgress?:(progress:Progress)=>void|Promise<void>}
export class ActiveBudget { active=0; constructor(readonly maximum=32){} acquire():void{if(this.active>=this.maximum)throw new SafeError("busy");this.active++;} release():void{this.active--;} }
export interface PoolOptions {diagnostic?:DiagnosticSink;idleRetirement?:boolean;oneGeneration?:boolean;invalidationDir?:string;activityBudget?:ActiveBudget;ownershipDir:string;beforeStart?:(id:string)=>Promise<void>;callTimeoutMs?:number;startupTimeoutMs?:number;discoveryTimeoutMs?:number;cooldownMs?:number;maxActive?:number;maxBackends?:number;closeTimeoutMs?:number;shutdownDrainMs?:number}
export class BackendPool {
 private manifests=new Map<string,ReviewedManifest>();
 private invalidManifests=new Set<string>();
 private invalidationListeners=new Map<string,Set<(kind:ManifestInvalidation)=>void|Promise<void>>>();
 private entries=new Map<string,Entry>();private failedUntil=new Map<string,number>();private total=0;private starts=0;private stopping=false;
 constructor(private config:Config,private options:PoolOptions){if(!options?.ownershipDir)throw new SafeError("invalid_ownership_directory");}
 bindManifest(id:string,manifest:ReviewedManifest):void{
  const p=this.policy(id);this.assertNoPersistedState(id);
  if(this.entries.has(id)||this.manifests.has(id))throw new SafeError("manifest_bind_after_start");
  let checked:ReviewedManifest;try{checked=parseManifest(manifest);}catch{throw new SafeError("invalid_manifest");}
  if(checked.provenance.catalogMode!==p.catalogMode)throw new SafeError("manifest_policy_mismatch");
  if(checked.backendId!==id || checked.allowedTools.length!==p.allowedTools.length || checked.allowedTools.some(t=>!p.allowedTools.includes(t)))throw new SafeError("manifest_policy_mismatch");
  this.manifests.set(id,checked);
 }
 assertManifestValid(id:string):void{
  this.policy(id);if(!this.manifests.has(id))throw new SafeError("manifest_required");
 }
 onManifestInvalidated(id:string,callback:(kind:ManifestInvalidation)=>void|Promise<void>):()=>void{
  this.assertManifestValid(id);let listeners=this.invalidationListeners.get(id);
  if(!listeners){listeners=new Set();this.invalidationListeners.set(id,listeners);}listeners.add(callback);
  return ()=>{listeners!.delete(callback);if(listeners!.size===0)this.invalidationListeners.delete(id);};
 }
 private statePath(id:string,suffix:string):string{return join(suffix===".invalid.json"?(this.options.invalidationDir??this.options.ownershipDir):this.options.ownershipDir,createHash("sha256").update(id).digest("hex")+suffix);}
 private assertNoPersistedState(id:string,includeOwnership=true):void{
  privateDirectory(this.options.ownershipDir);privateDirectory(this.options.invalidationDir??this.options.ownershipDir);
  for(const suffix of includeOwnership?[".invalid.json",".json"]:[".invalid.json"]){
   let fd:number|undefined;
   try{
    fd=openSync(this.statePath(id,suffix),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const stat=fstatSync(fd);
    if(!stat.isFile()||stat.uid!==process.getuid?.()||(stat.mode&0o7777)!==0o600||stat.size>1024)throw new SafeError("invalidation_state_untrusted");
   }catch(error){if((error as NodeJS.ErrnoException).code==="ENOENT")continue;throw error instanceof SafeError?error:new SafeError("invalidation_state_untrusted");}
   finally{if(fd!==undefined)closeSync(fd);}
   // Presence blocks cold discovery as well as startup. No automatic recovery,
   // even for an absent PID, corrupt marker, or a different manifest fingerprint.
   throw new SafeError(suffix===".invalid.json"?"manifest_invalid":"ownership_quarantined");
  }
 }
 private persistInvalidation(id:string,kind:ManifestInvalidation):void{
  const directory=this.options.invalidationDir??this.options.ownershipDir;privateDirectory(directory);let file:number|undefined,dir:number|undefined;
  try{
   try{file=openSync(this.statePath(id,".invalid.json"),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);}
   catch(error){if((error as NodeJS.ErrnoException).code!=="EEXIST")throw error;
    const existing=openSync(this.statePath(id,".invalid.json"),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    try{const stat=fstatSync(existing);if(!stat.isFile()||stat.uid!==process.getuid?.()||(stat.mode&0o7777)!==0o600||stat.size>1024)throw new SafeError("invalidation_persistence_failed");
     const marker=JSON.parse(readFileSync(existing,"utf8"));if(Object.keys(marker).sort().join(",")!=="fingerprint,reason,version"||marker.version!==1||!["tools","resources","prompts","logging","drift"].includes(marker.reason)||marker.fingerprint!==this.manifests.get(id)?.fingerprint)throw new SafeError("invalidation_persistence_failed");return;
    }finally{closeSync(existing);}
   }
   const stat=fstatSync(file);if(!stat.isFile()||stat.uid!==process.getuid?.()||(stat.mode&0o7777)!==0o600)throw new SafeError("invalidation_persistence_failed");
   writeFileSync(file,JSON.stringify({version:1,reason:kind,...(this.manifests.has(id)?{fingerprint:this.manifests.get(id)!.fingerprint}:{})}));fsyncSync(file);
   dir=openSync(directory,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);fsyncSync(dir);
  }finally{if(file!==undefined)closeSync(file);if(dir!==undefined)closeSync(dir);}
 }
 private invalidate(id:string,e:Entry,kind:ManifestInvalidation):void{
  if(this.entries.get(id)!==e||this.invalidManifests.has(id))return;
  this.invalidManifests.add(id);
  try{this.persistInvalidation(id,kind);}catch{
   e.invalidationPersistenceFailed=true;e.transport.retainOwnershipRecord();
  }
  this.taint(id,e);
  for(const callback of this.invalidationListeners.get(id)??[])try{void Promise.resolve(callback(kind)).catch(()=>{});}catch{/* A closed frontend cannot affect other clients. */}
 }
 catalog(){return [...this.config.servers].map(([name,p])=>({name,instruction:p.instruction}));}
 snapshot(){return {live:this.entries.size,starts:this.starts,active:this.total,invalidationFailures:[...this.entries.values()].filter(e=>e.invalidationPersistenceFailed).length,quarantined:[...this.entries.values()].filter(e=>e.tainted).length};}
 snapshotByProfile(){return Object.fromEntries([...this.config.servers.keys()].map(id=>[id,{backendLive:this.entries.has(id)?1:0}]));}
 private policy(id:string,tool?:string):BackendPolicy{
  if(this.stopping)throw new SafeError("shutting_down");if(this.invalidManifests.has(id))throw new SafeError("manifest_invalid");const p=this.config.servers.get(id);
  if(!p||(tool!==undefined&&!p.allowedTools.includes(tool)))throw new SafeError("not_allowed");if(this.manifests.has(id))this.assertNoPersistedState(id,false);return p;
 }
 private start(id:string,p:BackendPolicy):Entry{
  this.assertNoPersistedState(id,false);
  if(this.options.oneGeneration&&this.starts>0)throw new SafeError("backend_unavailable");
  if(this.entries.size>=(this.options.maxBackends??8))throw new SafeError("busy");
  const client=new Client({name:"personal-mcp-manager",version:"0.1.0"});
  const transport=new OwnedStdio(p,{id,ownershipDir:this.options.ownershipDir,closeTimeoutMs:this.options.closeTimeoutMs});
  const e:Entry={client,transport,ready:Promise.resolve(),active:0,tainted:false};this.entries.set(id,e);this.starts++;
  client.setNotificationHandler(ToolListChangedNotificationSchema,()=>this.invalidate(id,e,"tools"));
  client.setNotificationHandler(ResourceListChangedNotificationSchema,()=>this.invalidate(id,e,"resources"));
  client.setNotificationHandler(PromptListChangedNotificationSchema,()=>this.invalidate(id,e,"prompts"));
  client.setNotificationHandler(LoggingMessageNotificationSchema,()=>this.invalidate(id,e,"logging"));
  client.onerror=error=>{emitDiagnostic(this.options.diagnostic,"transport",classifyDiagnosticFailure(error));this.taint(id,e);};
  client.onclose=()=>{if(!e.closing){emitDiagnostic(this.options.diagnostic,"transport","connection_closed");this.taint(id,e);}};
  e.ready=(async()=>{
   let stage:DiagnosticStage="before_start";
   try{
    emitDiagnostic(this.options.diagnostic,stage,"begin");
    await this.options.beforeStart?.(id);
    if(e.tainted||e.closing||this.stopping)throw new SafeError("backend_unavailable");
    emitDiagnostic(this.options.diagnostic,stage,"ok");stage="connect";emitDiagnostic(this.options.diagnostic,stage,"begin");
    await client.connect(transport,{timeout:this.options.startupTimeoutMs??30000});
    emitDiagnostic(this.options.diagnostic,stage,"ok");stage="capabilities";emitDiagnostic(this.options.diagnostic,stage,"begin");
    const caps=client.getServerCapabilities();if(!caps?.tools||caps.tasks)throw new SafeError("unsupported_backend");
    if(e.tainted||this.stopping)throw new SafeError("backend_unavailable");
    emitDiagnostic(this.options.diagnostic,stage,"ok");
    const manifest=this.manifests.get(id);
    if(manifest){
     stage="discovery";emitDiagnostic(this.options.diagnostic,stage,"begin");
     const description=await this.description(e,p.catalogMode);
     emitDiagnostic(this.options.diagnostic,stage,"ok");stage="manifest";emitDiagnostic(this.options.diagnostic,stage,"begin");
     let matches=fingerprintDescription(description)===manifest.fingerprint;
     if(p.catalogMode==="mysql-session"){
      const readOnly=!["ALLOW_DDL_OPERATION","ALLOW_DELETE_OPERATION","ALLOW_INSERT_OPERATION","ALLOW_UPDATE_OPERATION"].some(key=>p.env[key]==="true");
      const annotations=description.tools[0]?.annotations;
      matches=description.serverInfo.version===(p.env.npm_package_version||"1.0.0")
        &&annotations?.readOnlyHint===readOnly&&annotations?.idempotentHint===readOnly&&annotations?.destructiveHint===!readOnly
        &&fingerprintDescription(mysqlInvariantDescription(description))===fingerprintDescription(mysqlInvariantDescription(manifest.description));
     }
     if(!matches){emitDiagnostic(this.options.diagnostic,stage,"manifest_mismatch");this.invalidate(id,e,"drift");throw new SafeError("manifest_mismatch");}
     emitDiagnostic(this.options.diagnostic,stage,"ok");
    }
   }catch(error){emitDiagnostic(this.options.diagnostic,stage,classifyDiagnosticFailure(error));this.taint(id,e);throw new SafeError("backend_unavailable");}
  })();return e;
 }
 private taint(id:string,e:Entry):void{
  e.tainted=true;if(e.timer)clearTimeout(e.timer);e.timer=undefined;
  this.failedUntil.set(id,Date.now()+(this.options.cooldownMs??1000));
  if(e.active===0)void this.retire(id,e).catch(()=>{});
 }
 private async use<T>(id:string,run:(e:Entry)=>Promise<T>):Promise<T>{
  const p=this.policy(id);let e=this.entries.get(id);
  if(e?.tainted)throw new SafeError("backend_unavailable");
  if(e?.closing){await e.closing;this.policy(id);e=this.entries.get(id);}
  if((this.failedUntil.get(id)??0)>Date.now())throw new SafeError("backend_unavailable");
  if(this.total>=(this.options.maxActive??32))throw new SafeError("busy");
  this.options.activityBudget?.acquire();
  try{e??=this.start(id,p);if(e.tainted||e.closing)throw new SafeError("backend_unavailable");}
  catch(error){this.options.activityBudget?.release();throw error;}
  if(e.timer)clearTimeout(e.timer);e.timer=undefined;e.active++;this.total++;
  try{await e.ready;if(e.tainted)throw new SafeError("backend_unavailable");return await run(e);}
  catch(error){
   // A protocol error/timeout/cancel cannot prove downstream completion. Keep
   // this generation quarantined until other bounded requests drain and its
   // supervised process group is confirmed absent. Never replay the call.
   if(error instanceof CompletedBackendError)throw error;
   if(!(error instanceof SafeError))this.taint(id,e);
   throw error instanceof SafeError?error:new SafeError("backend_unavailable");
  }finally{
   e.active--;this.total--;this.options.activityBudget?.release();
   if(e.active===0){if(e.tainted||this.stopping)void this.retire(id,e).catch(()=>{});
    else if(!e.closing&&this.options.idleRetirement!==false){e.timer=setTimeout(()=>{void this.retire(id,e!).catch(()=>{});},this.config.idleTimeoutMs);e.timer.unref();}}
  }
 }
 private discover(e:Entry):Promise<Tool[]>{
  if(e.tools)return Promise.resolve(e.tools);if(e.discovery)return e.discovery;
  e.discovery=(async()=>{
   const tools:Tool[]=[];const cursors=new Set<string>();let cursor:string|undefined;
   for(let page=0;page<16;page++){
    const result=await e.transport.withCompletedResponses(()=>e.client.listTools(cursor?{cursor}:{},{timeout:this.options.discoveryTimeoutMs??30000}));tools.push(...result.tools);
    if(tools.length>2048)throw new SafeError("discovery_limit");cursor=result.nextCursor;if(!cursor)break;
    if(cursors.has(cursor)||page===15)throw new SafeError("discovery_limit");cursors.add(cursor);
   }
   e.tools=tools;return tools;
  })();return e.discovery;
 }
 async tools(id:string):Promise<Tool[]>{const p=this.policy(id);return this.use(id,async e=>(await this.discover(e)).filter(t=>p.allowedTools.includes(t.name)));}
 private async pages<T>(fetch:(cursor:string|undefined)=>Promise<{items:T[];nextCursor?:string}>):Promise<T[]>{
  const items:T[]=[];const cursors=new Set<string>();let cursor:string|undefined;
  for(let page=0;page<16;page++){
   const result=await fetch(cursor);items.push(...result.items);
   if(items.length>2048)throw new SafeError("discovery_limit");cursor=result.nextCursor;if(!cursor)return items;
   if(cursors.has(cursor)||page===15)throw new SafeError("discovery_limit");cursors.add(cursor);
  }
  throw new SafeError("discovery_limit");
 }
 private description(e:Entry,catalogMode?:"mysql-session"):Promise<BackendDescription>{
  if(e.description)return e.description;
  e.description=(async()=>{
   const serverInfo=e.client.getServerVersion(),capabilities=e.client.getServerCapabilities(),instructions=e.client.getInstructions();
   if(!serverInfo||!capabilities)throw new SafeError("backend_unavailable");
   const timeout=this.options.discoveryTimeoutMs??30000;
   const description:BackendDescription={serverInfo,capabilities,...(instructions===undefined?{}:{instructions}),tools:await this.discover(e)};
   if(capabilities.resources&&catalogMode==="mysql-session"){description.resources=[];description.resourceTemplates=[];}
   else if(capabilities.resources){
    description.resources=await this.pages<Resource>(async cursor=>{const result=await e.transport.withCompletedResponses(()=>e.client.listResources(cursor?{cursor}:{},{timeout}));return {items:result.resources,nextCursor:result.nextCursor};});
    description.resourceTemplates=await this.pages<ResourceTemplate>(async cursor=>{const result=await e.transport.withCompletedResponses(()=>e.client.listResourceTemplates(cursor?{cursor}:{},{timeout}));return {items:result.resourceTemplates,nextCursor:result.nextCursor};});
   }
   if(capabilities.prompts)description.prompts=await this.pages<Prompt>(async cursor=>{const result=await e.transport.withCompletedResponses(()=>e.client.listPrompts(cursor?{cursor}:{},{timeout}));return {items:result.prompts,nextCursor:result.nextCursor};});
   return description;
  })();return e.description;
 }
 async describe(id:string):Promise<BackendDescription>{this.policy(id);return this.use(id,e=>this.description(e,this.policy(id).catalogMode));}
 async listResources(id:string,cursor?:string,context:CallContext={}):Promise<ListResourcesResult>{
  this.assertManifestValid(id);
  if(this.policy(id).catalogMode!=="mysql-session")throw new SafeError("not_allowed");
  if(context.signal?.aborted)throw new SafeError("request_cancelled");
  return this.use(id,async e=>e.transport.withCompletedResponses(()=>e.client.listResources(cursor===undefined?{}:{cursor},this.requestOptions(context))));
 }
 async readResource(id:string,uri:string,context:CallContext={}):Promise<ReadResourceResult>{
  this.assertManifestValid(id);
  const resources=this.manifests.get(id)!.description.resources;
  if(this.policy(id).catalogMode!=="mysql-session"&&!resources?.some(resource=>resource.uri===uri))throw new SafeError("not_allowed");
  if(context.signal?.aborted)throw new SafeError("request_cancelled");
  return this.use(id,async e=>{
   if(context.signal?.aborted)throw new SafeError("request_cancelled");
   return this.tracedRequest("resource",context,()=>e.transport.withCompletedResponses(()=>e.client.readResource({uri,...(context.meta?{_meta:context.meta}:{})},this.requestOptions(context))));
  });
 }
 private async tracedRequest<T>(stage:"tool"|"resource",context:CallContext,run:()=>Promise<T>):Promise<T>{
  emitDiagnostic(this.options.diagnostic,stage,"begin");
  try{const result=await run();emitDiagnostic(this.options.diagnostic,stage,"ok");return result;}
  catch(error){
   emitDiagnostic(this.options.diagnostic,stage,classifyDiagnosticFailure(error));
   if(!(error instanceof CompletedBackendError)&&context.signal?.aborted)emitDiagnostic(this.options.diagnostic,stage,"request_cancelled");
   throw error;
  }
 }
 private requestOptions(context:CallContext){return {timeout:this.options.callTimeoutMs??600000,resetTimeoutOnProgress:false,signal:context.signal,onprogress:context.onProgress?(progress:Progress)=>{try{void Promise.resolve(context.onProgress!(progress)).catch(()=>{});}catch{/* Client disconnect must not fail unrelated requests. */}}:undefined};}
 async call(id:string,tool:string,args:Record<string,unknown>|undefined,context:CallContext={}):Promise<CallToolResult>{
  this.policy(id,tool);if(context.signal?.aborted)throw new SafeError("request_cancelled");
  return this.use(id,async e=>{
   if(context.signal?.aborted)throw new SafeError("request_cancelled");
   return this.tracedRequest("tool",context,()=>e.transport.withCompletedResponses(()=>e.client.callTool({name:tool,...(args===undefined?{}:{arguments:args}),...(context.meta?{_meta:context.meta}:{})},CallToolResultSchema,this.requestOptions(context)) as Promise<CallToolResult>));
  });
 }
 private retire(id:string,e:Entry):Promise<void>{
  if(e.closing)return e.closing;if(e.timer)clearTimeout(e.timer);e.timer=undefined;e.tools=undefined;
  // Cleanup failure deliberately retains the entry. Replacement would risk two
  // active generations; a restart consults the ownership record as well.
  emitDiagnostic(this.options.diagnostic,"retirement","begin");
  e.closing=(async()=>{try{await e.transport.close();if(e.invalidationPersistenceFailed)throw new SafeError("invalidation_persistence_failed");if(this.entries.get(id)===e)this.entries.delete(id);emitDiagnostic(this.options.diagnostic,"retirement","ok");}catch{emitDiagnostic(this.options.diagnostic,"retirement",e.invalidationPersistenceFailed?"invalidation_persistence_failed":"cleanup_unproven");e.tainted=true;throw new SafeError(e.invalidationPersistenceFailed?"invalidation_persistence_failed":"cleanup_unproven");}})();
  return e.closing;
 }
 async shutdown():Promise<void>{
  this.stopping=true;const deadline=Date.now()+(this.options.shutdownDrainMs??5000);
  while(this.total>0&&Date.now()<deadline)await sleep(20);
  const results=await Promise.allSettled([...this.entries].map(([id,e])=>this.retire(id,e)));
  if([...this.entries.values()].some(e=>e.invalidationPersistenceFailed))throw new SafeError("invalidation_persistence_failed");
  if(results.some(r=>r.status==="rejected"))throw new SafeError("cleanup_unproven");
 }
}
