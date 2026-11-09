import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadDist } from './helpers/private-dist.mjs';
import { fixture, httpClient } from './helpers.mjs';
const { BackendPool } = await loadDist('pool.js');
const { parseConfig } = await loadDist('policy.js');
const { fingerprintDescription } = await loadDist('manifest.js');
const { startHttpServer } = await loadDist('server.js');
const api=await loadDist('runtime.js').catch(()=>({}));

test('reviewed endpoint stays cold for five clients then shares one native backend',async()=>{
  assert.equal(typeof api.createRuntime,'function','reviewed runtime is implemented');
  const f=fixture(1000),token='a'.repeat(64);f.config.mcpServers.demo.allowedTools=['read','write'];
  const config=parseConfig(f.config),provision=new BackendPool(config,{ownershipDir:f.ownershipDir});
  let runtime,http;const clients=[],rows=[];
  try{
    const description=await provision.describe('demo');await provision.shutdown();
    const manifestDir=join(f.dir,'manifests');mkdirSync(manifestDir,{mode:0o700});
    const manifest={version:1,backendId:'demo',allowedTools:['read','write'],description,fingerprint:fingerprintDescription(description),
      provenance:{sourceIdentity:'fixture:synthetic',artifactSha256:await api.executableDigest(process.execPath),policyDigest:api.policyDigest(config.servers.get('demo'),token),reviewedAt:new Date().toISOString()}};
    writeFileSync(join(manifestDir,'demo.json'),JSON.stringify(manifest),{mode:0o600});
    runtime=await api.createRuntime(config,{token,ownershipDir:f.ownershipDir,manifestDir,diagnostic:(stage,reason)=>rows.push([stage,reason])});
    http=await startHttpServer({host:'127.0.0.1',port:0,expectedToken:token,...runtime.httpOptions,onShutdown:()=>runtime.pool.shutdown()});
    for(let n=0;n<5;n++){
      const c=await httpClient(`http://127.0.0.1:${http.getPort()}/mcp/demo`,token);clients.push(c);
      assert.deepEqual((await c.listTools()).tools,description.tools);
      assert.deepEqual(c.getServerVersion(),description.serverInfo);
    }
    assert.equal(runtime.pool.snapshot().starts,0);
    const calls=await Promise.all(clients.map(c=>c.callTool({name:'read',arguments:{delayMs:50}})));
    assert.equal(new Set(calls.map(r=>r.structuredContent.pid)).size,1);
    assert.equal(runtime.pool.snapshot().starts,1);assert(rows.some(row=>row[0]==='artifact'&&row[1]==='ok'));
    const monitoring=await fetch(`http://127.0.0.1:${http.getPort()}/_control/status`,{headers:{Authorization:`Bearer ${token}`}}).then(response=>response.json());
    assert.equal(monitoring.monitoring.profiles.demo.sessions,5);assert.equal(monitoring.monitoring.profiles.demo.idleSessions,5);
    assert.equal(monitoring.monitoring.profiles.demo.busySessions,0);assert.equal(monitoring.monitoring.profiles.demo.backendLive,1);
    assert.equal(monitoring.monitoring.profiles.demo.retained,null);
    const response=await fetch(`http://127.0.0.1:${http.getPort()}/mcp`,{headers:{Authorization:`Bearer ${token}`}});
    assert.equal(response.status,404);
    const changed=parseConfig(f.config);changed.servers.get('demo').env.NEW_SECRET='SYNTHETIC';
    await assert.rejects(api.createRuntime(changed,{token,ownershipDir:f.ownershipDir,manifestDir}),/manifest_policy_mismatch/);
  }finally{await Promise.allSettled(clients.map(c=>c.close()));await http?.close();await runtime?.pool.shutdown();await provision.shutdown();f.cleanup();}
});
test('authenticated traffic status follows one synthetic profile from cold catalog to completed tool call',async()=>{
 assert.equal(typeof api.createRuntime,'function');
 const f=fixture(1000),token='a'.repeat(64);f.config.mcpServers.demo.allowedTools=['read','write'];
 const config=parseConfig(f.config),provision=new BackendPool(config,{ownershipDir:f.ownershipDir});
 let runtime,http,client,baselineStarts=0;
 try{
  const description=await provision.describe('demo');await provision.shutdown();baselineStarts=f.events().filter(event=>event.event==='start').length;
  const manifestDir=join(f.dir,'manifests');mkdirSync(manifestDir,{mode:0o700});
  writeFileSync(join(manifestDir,'demo.json'),JSON.stringify({version:1,backendId:'demo',allowedTools:['read','write'],description,
   fingerprint:fingerprintDescription(description),provenance:{sourceIdentity:'fixture:synthetic-traffic',artifactSha256:await api.executableDigest(process.execPath),
    policyDigest:api.policyDigest(config.servers.get('demo'),token),reviewedAt:new Date().toISOString()}}),{mode:0o600});
  runtime=await api.createRuntime(config,{token,ownershipDir:f.ownershipDir,manifestDir});
  http=await startHttpServer({host:'127.0.0.1',port:0,expectedToken:token,...runtime.httpOptions,onShutdown:()=>runtime.pool.shutdown()});
  client=await httpClient(`http://127.0.0.1:${http.getPort()}/mcp/demo`,token);
  assert.deepEqual((await client.listTools()).tools,description.tools);
  const statusUrl=`http://127.0.0.1:${http.getPort()}/_control/status`,headers={Authorization:`Bearer ${token}`};
  const coldResponse=await fetch(statusUrl,{headers});assert.equal(coldResponse.status,200);const cold=await coldResponse.json();
  assert.deepEqual(cold.trafficCounters.profiles.demo,{catalogRequests:1,toolAttempts:0,toolSuccesses:0,toolFailures:0});
  assert.deepEqual(cold.monitoring.profiles.demo,{sessions:1,idleSessions:1,busySessions:0,subscriptions:1,requests:0,active:0,backendLive:0,retained:null});
  assert.equal(runtime.pool.snapshot().starts,0);
  const result=await client.callTool({name:'read',arguments:{delayMs:40}});assert(Number.isInteger(result.structuredContent.pid));
  const usedResponse=await fetch(statusUrl,{headers});assert.equal(usedResponse.status,200);const used=await usedResponse.json();
  assert.deepEqual(Object.keys(used.trafficCounters.profiles),['demo']);
  assert.deepEqual(used.trafficCounters.profiles.demo,{catalogRequests:1,toolAttempts:1,toolSuccesses:1,toolFailures:0});
  assert.equal(used.monitoring.profiles.demo.backendLive,1);assert.equal(used.monitoring.profiles.demo.retained,null);
  assert.equal(used.monitoring.profiles.demo.active,0);assert.equal(used.monitoring.profiles.demo.busySessions,0);
  assert.equal(runtime.pool.snapshot().starts,1);assert.equal(f.events().filter(event=>event.event==='start').length,baselineStarts+1);
 }finally{await client?.close();await http?.close();await runtime?.pool.shutdown();await provision.shutdown();f.cleanup();}
});
test('policy digest is canonical and changes when credentials or launch policy changes',()=>{
  assert.equal(typeof api.policyDigest,'function');
  const f=fixture();try{
    const p=parseConfig(f.config).servers.get('demo');
    assert.equal(api.policyDigest(p,'a'.repeat(64)),api.policyDigest(Object.fromEntries(Object.entries(p).reverse()),'a'.repeat(64)));
    assert.notEqual(api.policyDigest(p,'a'.repeat(64)),api.policyDigest({...p,env:{SYNTHETIC:'changed'}},'a'.repeat(64)));
    assert.notEqual(api.policyDigest(p,'a'.repeat(64)),api.policyDigest(p,'b'.repeat(64)));
  }finally{f.cleanup();}
});
test('runtime snapshots caller-owned policies and map before a cold generation starts',async()=>{
 const f=fixture(),token='a'.repeat(64);f.backend.allowedTools=['read','write'];
 const config=parseConfig(f.config),provision=new BackendPool(config,{ownershipDir:f.ownershipDir});let runtime,http,client;
 try{
  const description=await provision.describe('demo');await provision.shutdown();
  const manifestDir=join(f.dir,'manifests');mkdirSync(manifestDir,{mode:0o700});
  writeFileSync(join(manifestDir,'demo.json'),JSON.stringify({version:1,backendId:'demo',allowedTools:['read','write'],description,fingerprint:fingerprintDescription(description),provenance:{sourceIdentity:'fixture:synthetic',artifactSha256:await api.executableDigest(process.execPath),policyDigest:api.policyDigest(config.servers.get('demo'),token),reviewedAt:new Date().toISOString()}}),{mode:0o600});
  runtime=await api.createRuntime(config,{token,ownershipDir:f.ownershipDir,manifestDir});
  const policy=config.servers.get('demo');policy.args.splice(0);policy.env.FIXTURE_LEDGER='/unreviewed';policy.allowedTools.splice(0);policy.command='/unreviewed';config.servers.clear();
  http=await startHttpServer({host:'127.0.0.1',port:0,expectedToken:token,...runtime.httpOptions,onShutdown:()=>runtime.pool.shutdown()});
  client=await httpClient(`http://127.0.0.1:${http.getPort()}/mcp/demo`,token);
  assert.deepEqual((await client.listTools()).tools,description.tools);
  const result=await client.callTool({name:'read'});assert(Number.isInteger(result.structuredContent.pid));
  assert.equal(f.events().filter(e=>e.event==='start').length,2);
 }finally{await client?.close();await http?.close();await runtime?.pool.shutdown();await provision.shutdown();f.cleanup()}
});
test('runtime creation closes its acquired owner channel when nested startup quarantine fails',async()=>{
 const {Duplex}=await import('node:stream'),{readFileSync}=await import('node:fs');const f=fixture(),token='a'.repeat(64);f.config.mcpServers.demo.scope='session';const config=parseConfig(f.config),manifestDir=join(f.dir,'manifests');mkdirSync(manifestDir,{mode:0o700});
 const description={serverInfo:{name:'synthetic',version:'1'},capabilities:{tools:{}},tools:[{name:'read',inputSchema:{type:'object'}}]};
 const manifest={version:1,backendId:'demo',allowedTools:['read'],description,fingerprint:fingerprintDescription(description),provenance:{sourceIdentity:'fixture:synthetic',artifactSha256:await api.executableDigest(process.execPath),policyDigest:api.policyDigest(config.servers.get('demo'),token),reviewedAt:new Date().toISOString()}};writeFileSync(join(manifestDir,'demo.json'),JSON.stringify(manifest),{mode:0o600});
 const sessions=join(f.ownershipDir,'sessions'),leaf=join(sessions,'a'.repeat(64)),record=join(leaf,'orphan.json');mkdirSync(sessions,{mode:0o700});mkdirSync(leaf,{mode:0o700});writeFileSync(record,'{}',{mode:0o600});
 const stream=new Duplex({read(){},write(_chunk,_encoding,callback){callback()}});
 try{await assert.rejects(api.createRuntime(config,{token,ownershipDir:f.ownershipDir,manifestDir,ownerChannel:stream}),/ownership_quarantined/);assert.equal(stream.destroyed,true);assert.equal(readFileSync(record,'utf8'),'{}');assert.equal(f.events().length,0)}finally{stream.destroy();f.cleanup()}
});
test('artifact failure observations preserve startup rejection without backend spawn',async()=>{
 const outputs=[];for(const enabled of [false,true]){const f=fixture(),token='a'.repeat(64),rows=[],config=parseConfig(f.config),manifestDir=join(f.dir,'manifests');mkdirSync(manifestDir,{mode:0o700});const description={serverInfo:{name:'synthetic',version:'1'},capabilities:{tools:{}},tools:[{name:'read',inputSchema:{type:'object'}}]};writeFileSync(join(manifestDir,'demo.json'),JSON.stringify({version:1,backendId:'demo',allowedTools:['read'],description,fingerprint:fingerprintDescription(description),provenance:{sourceIdentity:'synthetic',artifactSha256:'b'.repeat(64),policyDigest:api.policyDigest(config.servers.get('demo'),token),reviewedAt:'2026-10-13T00:00:00.000Z'}}),{mode:0o600});let runtime;try{runtime=await api.createRuntime(config,{token,ownershipDir:f.ownershipDir,manifestDir,...(enabled?{diagnostic:(stage,reason)=>rows.push([stage,reason])}:{})});let error;try{await runtime.pool.call('demo','read',{})}catch(e){error=e}outputs.push({type:error.constructor.name,code:error.code,message:error.message,starts:runtime.pool.snapshot().starts,calls:f.events().length});assert.equal(f.events().length,0);if(enabled){assert(rows.some(row=>row[0]==='artifact'&&row[1]==='artifact_changed'));assert(!rows.some(row=>row[0]==='tool'))}}finally{await runtime?.pool.shutdown();f.cleanup()}}assert.deepEqual(outputs[1],outputs[0]);
});
