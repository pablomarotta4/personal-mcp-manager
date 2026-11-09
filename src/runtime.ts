import {emitDiagnostic,classifyDiagnosticFailure,type DiagnosticSink} from './backend-diagnostics.js';
import { createHash, createHmac } from "node:crypto";
import { open } from "node:fs/promises";
import { join } from "node:path";
import type { Duplex } from "node:stream";
import { OwnerChannel } from "./owner-channel.js";
import { SessionPool } from "./session-pool.js";
import { ClosureVerifier } from "./closure-verifier.js";
import { BackendPool,ActiveBudget } from "./pool.js";
import { createFacade } from "./facade.js";
import { readManifest, fingerprintDescription, type ReviewedManifest } from "./manifest.js";
import { createProxy } from "./proxy.js";
import { TrafficCounters } from "./traffic-counters.js";
import { SafeError, parseConfig, type BackendPolicy, type Config } from "./policy.js";
import type { HttpServerOptions } from "./server.js";

function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b,"en")).map(([k,v])=>[k,sorted(v)]));
  return value;
}
/** The keyed digest binds credentials without storing them or a guessable plain hash. */
export function policyDigest(policy: BackendPolicy, token: string): string {
  if (!/^[0-9a-f]{64}$/.test(token)) throw new SafeError("invalid_token");
  return createHmac("sha256",Buffer.from(token,"hex")).update("personal-mcp-policy-v1\n").update(JSON.stringify(sorted(policy))).digest("hex");
}
/** For the first native-binary pilot this is the reviewed executable's digest.
 * Interpreter/package migrations additionally require a reviewed dependency closure.
 */
export async function executableDigest(path: string): Promise<string> {
  let file;
  try {
    file=await open(path,"r");const stat=await file.stat();
    if (!stat.isFile() || stat.size>256*1024*1024 || (stat.mode & 0o022)!==0) throw new SafeError("artifact_unavailable");
    const hash=createHash("sha256");let size=0;
    for await(const chunk of file.createReadStream({autoClose:false})) {
      size+=chunk.length;if(size>256*1024*1024)throw new SafeError("artifact_unavailable");hash.update(chunk);
    }
    return hash.digest("hex");
  } catch { throw new SafeError("artifact_unavailable"); }
  finally { await file?.close(); }
}
export async function createRuntime(config: Config, options: {token:string;ownershipDir:string;manifestDir?:string;ownerChannel?:Duplex;closureVerifierPython?:string;closureVerifierScript?:string;diagnostic?:DiagnosticSink}) {
  // The validated template is runtime-owned. Caller edits must not change a
  // later generation's launch or remove a previously authenticated closure.
  config=parseConfig({mcpServers:Object.fromEntries(config.servers),idleTimeoutMs:config.idleTimeoutMs});
  const stateful=new Set([...config.servers].filter(([,policy])=>policy.scope==="session").map(([id])=>id));
  if(stateful.size&&(!options.manifestDir||!options.ownerChannel))throw new SafeError("owner_channel_required");
  const budget=new ActiveBudget();
  const manifests=new Map<string,ReviewedManifest>();
  if(options.manifestDir) {
    for(const [id,policy] of config.servers) {
      const manifest=readManifest(join(options.manifestDir,`${id}.json`));
      if(manifest.provenance.catalogMode!==policy.catalogMode)throw new SafeError("manifest_policy_mismatch");
      if(manifest.backendId!==id || manifest.provenance.policyDigest!==policyDigest(policy,options.token)) throw new SafeError("manifest_policy_mismatch");
      if(policy.closure
          ?manifest.provenance.closureDigest!==policy.closure.digest||!manifest.provenance.dependencyReportSha256
          :manifest.provenance.closureDigest!==undefined||manifest.provenance.dependencyReportSha256!==undefined)
        throw new SafeError("manifest_policy_mismatch");
      manifests.set(id,manifest);
    }
  }
  const traffic=new TrafficCounters(manifests.keys());
  const closures=[...config.servers.values()].some(policy=>policy.closure);
  if(closures&&!options.closureVerifierPython)throw new SafeError("closure_verifier_required");
  const verifier=closures?new ClosureVerifier({python:options.closureVerifierPython!,...(options.closureVerifierScript!==undefined?{script:options.closureVerifierScript}:{}),diagnostic:options.diagnostic}):undefined;
  const beforeStart=options.manifestDir?async(id:string)=>{
      const manifest=manifests.get(id),policy=config.servers.get(id);
      emitDiagnostic(options.diagnostic,"artifact","begin");
      try{if(!manifest||!policy||await executableDigest(policy.command)!==manifest.provenance.artifactSha256)throw new SafeError("artifact_changed");emitDiagnostic(options.diagnostic,"artifact","ok");}
      catch(error){emitDiagnostic(options.diagnostic,"artifact",classifyDiagnosticFailure(error));throw error;}
      if(policy!.closure){emitDiagnostic(options.diagnostic,"closure","begin");await verifier!.verify(policy!.closure);emitDiagnostic(options.diagnostic,"closure","ok");}
    }:undefined;
  const pool=new BackendPool(config,{ownershipDir:options.ownershipDir,activityBudget:budget,beforeStart,diagnostic:options.diagnostic});
  let owners:OwnerChannel|undefined;let sessionPool:SessionPool|undefined;
  try {
  for(const [id,manifest] of manifests)pool.bindManifest(id,manifest);
  const clientCwd=new Set([...config.servers].filter(([,policy])=>policy.cwdMode==='client').map(([id])=>id));
  owners=options.ownerChannel?new OwnerChannel(options.ownerChannel,stateful,1024,clientCwd,new Set([...config.servers].filter(([,policy])=>policy.catalogMode==='mysql-session').map(([id])=>id))):undefined;
  owners?.assertHealthy();
  sessionPool=stateful.size?new SessionPool(config,manifests,owners!,{ownershipDir:options.ownershipDir,beforeStart,activityBudget:budget,diagnostic:options.diagnostic}):undefined;
  const sessions=sessionPool;
  const httpOptions:Partial<HttpServerOptions>&Pick<HttpServerOptions,"routes"|"buildServer">=options.manifestDir?{
    ...(sessionPool?{statefulRoutes:new Set([...stateful].map(id=>`/mcp/${id}`)),owners,getRetained:()=>sessions!.snapshot().retained+(verifier?.snapshot().outstanding??0),maxSessions:512}:{}),
    routes:new Set([...manifests.keys()].map(id=>`/mcp/${id}`)),
    getTrafficCounts:()=>traffic.snapshot(),
    getProfileMonitoringCounts:()=>{
      const shared=pool.snapshotByProfile();
      const session=sessionPool?.snapshotByProfile();
      return Object.fromEntries([...manifests.keys()].map(id=>[id,{
        backendLive:(shared[id]?.backendLive??0)+(session?.[id]?.backendLive??0),
        retained:stateful.has(id)?(session?.[id]?.retained??0):null,
      }]));
    },
    buildServer:async(path,owner)=>{
      const manifest=manifests.get((path??"").slice("/mcp/".length));
      if(!manifest)throw new SafeError("not_allowed");
      if(stateful.has(manifest.backendId)){
        const lease=sessionPool!.create(manifest.backendId,owner!);
        try{
          const actual=config.servers.get(manifest.backendId)!.catalogMode==='mysql-session'?await lease.describe():undefined;
          const facade=createFacade(actual?{...manifest,description:actual,fingerprint:fingerprintDescription(actual)}:manifest,lease.view,traffic);
          facade.retained=lease.used;facade.disposeLease=lease.close;return facade;
        }catch(error){await lease.close();throw error;}
      }
      return createFacade(manifest,pool,traffic);
    },
  }:{routes:new Set(["/mcp"]),buildServer:()=>createProxy(pool)};
  const aggregate=sessionPool?{snapshot:()=>{const shared=pool.snapshot(),session=sessions!.snapshot(),checks=verifier?.snapshot();return {...shared,live:shared.live+session.live,starts:shared.starts+session.starts,active:budget.active,retained:session.retained+(checks?.outstanding??0),invalidationFailures:shared.invalidationFailures+session.invalidationFailures,quarantined:shared.quarantined+session.quarantined+(checks?.unproven??0)};},shutdown:async()=>{const results=await Promise.allSettled([pool.shutdown(),sessions!.shutdown(),...(verifier?[verifier.shutdown()]:[])]);if(results.some(value=>value.status==="rejected"))throw new SafeError("cleanup_unproven");}}:pool;
  owners?.onFailure(()=>{void aggregate.shutdown().catch(()=>{});});
  return {pool:aggregate,httpOptions,owners};
  }catch(error){
    owners?.close();
    await Promise.allSettled([pool.shutdown(),...(sessionPool?[sessionPool.shutdown()]:[]),...(verifier?[verifier.shutdown()]:[])]);
    throw error;
  }
}
