import test from 'node:test';
import assert from 'node:assert/strict';
import {BackendPool} from '../dist/pool.js';
import {fixture,delay,until,alive} from './helpers.mjs';
const cfg=f=>({servers:new Map(Object.entries(f.config.mcpServers)),idleTimeoutMs:f.config.idleTimeoutMs});
test('lazy singleflight startup preserves results, full schema and active leases',async()=>{
 const f=fixture(50),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});
 try{assert.equal(pool.snapshot().live,0);await assert.rejects(pool.call('demo','write',{}),/not_allowed/);assert.equal(f.events().length,0);
 const results=await Promise.all(Array.from({length:20},()=>pool.call('demo','read',{delayMs:60})));
 assert.equal(new Set(results.map(x=>x.structuredContent.pid)).size,1);assert.equal(f.events().filter(x=>x.event==='start').length,1);
 const tools=await pool.tools('demo');assert.deepEqual(tools.map(t=>t.name),['read']);assert.equal(tools[0].annotations.readOnlyHint,true);assert.equal(tools[0]._meta.synthetic,true);assert(tools[0].outputSchema);
 const err=await pool.call('demo','read',{error:true});assert.equal(err.isError,true);assert.equal(err._meta.synthetic,true);assert.equal(err.structuredContent.ok,false);
 const long=pool.call('demo','read',{delayMs:200});await delay(130);assert.equal(pool.snapshot().live,1);await long;
 await until(()=>pool.snapshot().live===0);await pool.call('demo','read',{});assert.equal(pool.snapshot().starts,2);
 }finally{await pool.shutdown();f.cleanup()}
});
test('timeout taints generation and holds it until bounded other work drains and cleanup is proven',async()=>{
 const f=fixture(30),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir,callTimeoutMs:150,cooldownMs:0});
 try{await pool.tools('demo');const slow=pool.call('demo','read',{delayMs:900});const rejected=assert.rejects(slow,/backend_unavailable/);
 await delay(100);const other=pool.call('demo','read',{delayMs:120});await rejected;
 await assert.rejects(pool.call('demo','read',{}),/backend_unavailable/);const r=await other;assert.equal(r.structuredContent.ok,true);
 const oldpid=r.structuredContent.pid;await until(()=>pool.snapshot().live===0);assert.equal(alive(oldpid),false);await pool.call('demo','read',{});assert.equal(pool.snapshot().starts,2);
 }finally{await pool.shutdown();f.cleanup()}
});
test('failed startup cleans before retry; shutdown prevents new work',async()=>{
 const f=fixture();f.backend.command='/nonexistent/synthetic';const pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});
 try{await assert.rejects(pool.call('demo','read',{}),/backend_unavailable/);await pool.shutdown();assert.equal(pool.snapshot().live,0);await assert.rejects(pool.call('demo','read',{}),/shutting_down/)}finally{await pool.shutdown();f.cleanup()}
});

test('failed cleanup quarantines a generation and never starts its replacement',async()=>{
 const f=fixture(20);f.backend.env.FIXTURE_DESCENDANT='1';f.backend.env.FIXTURE_DESCENDANT_LIFETIME='1800';
 const pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir,closeTimeoutMs:5,cooldownMs:0});
 try{await pool.call('demo','read',{});await until(()=>pool.snapshot().quarantined===1);
 await assert.rejects(pool.call('demo','read',{}),/backend_unavailable/);assert.equal(pool.snapshot().starts,1);
 await assert.rejects(pool.shutdown(),/cleanup_unproven/);
 await until(()=>f.events().every(x=>!alive(x.pid)));
 await assert.rejects(pool.call('demo','read',{}),/shutting_down/);
 }finally{await pool.shutdown().catch(()=>{});await until(()=>f.events().every(x=>!alive(x.pid)));f.cleanup()}
});

test('caller cancellation does not abort another caller and taints until teardown',async()=>{
 const f=fixture(50),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir,cooldownMs:0});
 try{await pool.tools('demo');const abort=new AbortController();
 const cancel=pool.call('demo','read',{delayMs:700},{signal:abort.signal});
 const rejected=assert.rejects(cancel,/backend_unavailable/);
 const other=pool.call('demo','read',{delayMs:120});await delay(30);abort.abort();
 await rejected;await assert.rejects(pool.call('demo','read',{}),/backend_unavailable/);assert.equal((await other).structuredContent.ok,true);
 await until(()=>pool.snapshot().live===0);
 }finally{await pool.shutdown();f.cleanup()}
});

test('manifest validates the complete native catalog before any call each generation',async()=>{
 const {fingerprintDescription,parseManifest}=await import('../dist/manifest.js');
 const f=fixture(25);f.backend.allowedTools=['read','write'];
 const inspect=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});let description;
 try{description=await inspect.describe('demo')}finally{await inspect.shutdown()}
 assert.deepEqual(description.tools.map(t=>t.name),['read','write']);
 const raw={version:1,backendId:'demo',allowedTools:['read','write'],provenance:{sourceIdentity:'synthetic',artifactSha256:'a'.repeat(64),policyDigest:'b'.repeat(64),reviewedAt:'2026-10-13T00:00:00.000Z'},description,fingerprint:fingerprintDescription(description)};
 const pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir,cooldownMs:0});
 try{pool.bindManifest('demo',parseManifest(raw));await pool.call('demo','read',{});await until(()=>pool.snapshot().live===0);await pool.call('demo','read',{});assert.equal(pool.snapshot().starts,2)}finally{await pool.shutdown()}
 const changed=structuredClone(raw);changed.description.instructions='unreviewed change';changed.fingerprint=fingerprintDescription(changed.description);
 const denied=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});const before=f.events().filter(x=>x.event==='call').length;
 try{denied.bindManifest('demo',parseManifest(changed));await assert.rejects(denied.call('demo','read',{}),/backend_unavailable/);assert.equal(f.events().filter(x=>x.event==='call').length,before)}finally{await denied.shutdown();f.cleanup()}
});

test('artifact verification rejection prevents every backend spawn',async()=>{
 const f=fixture();let checks=0;const pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir,beforeStart:async id=>{assert.equal(id,'demo');checks++;throw Error('synthetic_artifact_rejected')}});
 try{await assert.rejects(pool.call('demo','read',{}),/backend_unavailable/);assert.equal(checks,1);assert.equal(f.events().length,0)}finally{await pool.shutdown();f.cleanup()}
});
test('artifact verification is singleflight and repeats only for a new generation',async()=>{
 const f=fixture(25);let checks=0;const pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir,beforeStart:async()=>{checks++;await delay(20)}});
 try{await Promise.all(Array.from({length:12},()=>pool.call('demo','read',{})));assert.equal(checks,1);assert.equal(f.events().filter(x=>x.event==='start').length,1);await until(()=>pool.snapshot().live===0);await pool.call('demo','read',{});assert.equal(checks,2)}finally{await pool.shutdown();f.cleanup()}
});
test('shutdown during artifact verification cannot launch a backend after close',async()=>{
 const f=fixture();let finish;const verification=new Promise(r=>{finish=r});
 const pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir,shutdownDrainMs:10,beforeStart:()=>verification});
 try{const result=assert.rejects(pool.call('demo','read',{}),/backend_unavailable/);await pool.shutdown();finish();await result;assert.equal(f.events().length,0)}finally{finish();await pool.shutdown();f.cleanup()}
});

test('rejected and throwing progress callbacks cannot fail tool results or unrelated callers',async()=>{
 const f=fixture(),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});let callbacks=0;
 try{
 const asyncRejected=pool.call('demo','read',{progress:true,delayMs:40},{onProgress:async p=>{assert.equal(p.progress,1);callbacks++;throw Error('synthetic_callback_rejection')}});
 const syncRejected=pool.call('demo','read',{progress:true,delayMs:40},{onProgress:p=>{assert.equal(p.total,2);callbacks++;throw Error('synthetic_callback_throw')}});
 const unrelated=pool.call('demo','read',{delayMs:60});
 const result=await Promise.all([asyncRejected,syncRejected,unrelated]);assert(result.every(r=>r.structuredContent.ok===true));assert.equal(callbacks,2);assert.equal(pool.snapshot().quarantined,0);assert.equal(pool.snapshot().starts,1);
 }finally{await pool.shutdown();f.cleanup()}
});

test('received JSON-RPC errors preserve origin and leave the shared generation ready',async()=>{
 const f=fixture(),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});
 try{
 const other=pool.call('demo','read',{delayMs:90});
 for(const code of [-32602,-32123,-32001]){
  await assert.rejects(pool.call('demo','read',{protocolError:code}),error=>error.name==='CompletedBackendError'&&error.code===code&&error.message==='synthetic_invalid_params'&&error.data.field==='synthetic');
  assert.equal(pool.snapshot().quarantined,0);
 }
 assert.equal((await other).structuredContent.ok,true);assert.equal((await pool.call('demo','read',{})).structuredContent.ok,true);assert.equal(pool.snapshot().starts,1);
 }finally{await pool.shutdown();f.cleanup()}
});

async function resourceFixture(logging=false){
 const {fingerprintDescription,parseManifest}=await import('../dist/manifest.js');
 const f=fixture(30);f.backend.env.FIXTURE_CAPABILITIES='resources';if(logging)f.backend.env.FIXTURE_LOGGING='1';f.backend.allowedTools=['read','write'];
 const inspect=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});let description;
 try{description=await inspect.describe('demo')}finally{await inspect.shutdown()}
 const manifest=parseManifest({version:1,backendId:'demo',allowedTools:['read','write'],provenance:{sourceIdentity:'synthetic',artifactSha256:'a'.repeat(64),policyDigest:'b'.repeat(64),reviewedAt:'2026-10-13T00:00:00.000Z',...(logging?{logging:'no-backend-notifications'}:{})},description,fingerprint:fingerprintDescription(description)});
 return {f,manifest};
}
test('full resource snapshots and exact URI reads preserve text, blob and error envelopes',async()=>{
 const {f,manifest}=await resourceFixture(),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});pool.bindManifest('demo',manifest);
 try{assert.equal(manifest.description.resources.length,5);assert.deepEqual(manifest.description.resourceTemplates,[]);assert.deepEqual(manifest.description.prompts,[]);
 await assert.rejects(pool.readResource('demo','synthetic://unknown'),/not_allowed/);assert.equal(pool.snapshot().starts,0);
 const text=await pool.readResource('demo','synthetic://text');assert.deepEqual(text,{contents:[{uri:'synthetic://text',mimeType:'text/plain',text:'synthetic text'}],_meta:{synthetic:true}});
 const blob=await pool.readResource('demo','synthetic://blob');assert.equal(blob.contents[0].blob,'AAEC');assert.equal(blob._meta.synthetic,true);
 await assert.rejects(pool.readResource('demo','synthetic://error'),e=>e.name==='CompletedBackendError'&&e.code===-32602&&e.data.field==='uri');assert.equal(pool.snapshot().quarantined,0);
 await until(()=>pool.snapshot().live===0);assert.equal(pool.snapshot().starts,1);
 }finally{await pool.shutdown();f.cleanup()}
});
test('resource cancellation drains other work and restarts only after proven teardown',async()=>{
 const {f,manifest}=await resourceFixture(),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir,cooldownMs:0});pool.bindManifest('demo',manifest);
 try{await pool.readResource('demo','synthetic://text');const abort=new AbortController();
 const cancelled=assert.rejects(pool.readResource('demo','synthetic://slow',{signal:abort.signal}),/backend_unavailable/);
 const other=pool.readResource('demo','synthetic://parallel');await delay(30);abort.abort();await cancelled;assert.equal((await other).contents[0].text,'synthetic text');
 await until(()=>pool.snapshot().live===0);await pool.readResource('demo','synthetic://text');assert.equal(pool.snapshot().starts,2);
 }finally{await pool.shutdown();f.cleanup()}
});
test('catalog notifications permanently invalidate only their backend and preserve active leases',async()=>{
 const {f,manifest}=await resourceFixture();const configuration=cfg(f);configuration.servers.set('other',{...f.backend,env:{...f.backend.env}});
 const pool=new BackendPool(configuration,{ownershipDir:f.ownershipDir});pool.bindManifest('demo',manifest);pool.bindManifest('other',{...manifest,backendId:'other'});
 let invalid=0,unrelated=0;const unsubscribe=pool.onManifestInvalidated('demo',()=>{invalid++});pool.onManifestInvalidated('other',()=>{unrelated++});
 try{const pending=pool.readResource('demo','synthetic://slow');await until(()=>f.events().some(x=>x.event==='resource'));
 const trigger=pool.call('demo','read',{notify:'resources',delayMs:90});await until(()=>invalid===1);
 assert.throws(()=>pool.assertManifestValid('demo'),/manifest_invalid/);pool.assertManifestValid('other');
 await assert.rejects(pool.call('demo','read',{}),/manifest_invalid/);await assert.rejects(pool.readResource('demo','synthetic://text'),/manifest_invalid/);
 assert.equal((await trigger).structuredContent.ok,true);assert.equal((await pending).contents[0].text,'synthetic text');await until(()=>pool.snapshot().live===0);
 await assert.rejects(pool.readResource('demo','synthetic://text'),/manifest_invalid/);assert.equal(pool.snapshot().starts,1);assert.equal(unrelated,0);
 assert.equal((await pool.readResource('other','synthetic://text')).contents[0].text,'synthetic text');assert.equal(invalid,1);
 }finally{unsubscribe();await pool.shutdown();f.cleanup()}
});

test('resource catalog drift invalidates reviewed state before backend read',async()=>{
 const {fingerprintDescription}=await import('../dist/manifest.js');const {f,manifest}=await resourceFixture();
 const changed=structuredClone(manifest);changed.description.resources[0].name='unreviewed resource name';changed.fingerprint=fingerprintDescription(changed.description);
 const pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});pool.bindManifest('demo',changed);const kinds=[];pool.onManifestInvalidated('demo',kind=>kinds.push(kind));
 try{const before=f.events().filter(x=>x.event==='resource').length;await assert.rejects(pool.readResource('demo','synthetic://text'),/backend_unavailable/);assert.equal(f.events().filter(x=>x.event==='resource').length,before);assert.deepEqual(kinds,['drift']);assert.throws(()=>pool.assertManifestValid('demo'),/manifest_invalid/)}finally{await pool.shutdown();f.cleanup()}
});
for(const kind of ['tools','prompts','logging'])test(`${kind} notifications invalidate permanently without forwarding payload`,async()=>{
 const {f,manifest}=await resourceFixture(kind==='logging'),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});pool.bindManifest('demo',manifest);const kinds=[];
 const unsub=pool.onManifestInvalidated('demo',received=>{kinds.push(received);return Promise.reject(Error('synthetic_listener_disconnect'))});
 try{await pool.call('demo','read',{notify:kind});await until(()=>kinds.length===1);assert.deepEqual(kinds,[kind]);assert.throws(()=>pool.assertManifestValid('demo'),/manifest_invalid/);await until(()=>pool.snapshot().live===0);await assert.rejects(pool.call('demo','read',{}),/manifest_invalid/);assert.equal(pool.snapshot().starts,1)}finally{unsub();await pool.shutdown();f.cleanup()}
});

test('catalog invalidation survives shutdown and refuses cold rebinding across manager restart',async()=>{
 const {f,manifest}=await resourceFixture(),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});pool.bindManifest('demo',manifest);
 try{await pool.call('demo','read',{notify:'resources'});await pool.shutdown();
 const next=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});
 assert.throws(()=>next.bindManifest('demo',manifest),/manifest_invalid/);assert.equal(next.snapshot().starts,0);
 const otherConfig=cfg(f);otherConfig.servers.set('other',{...f.backend});const other=new BackendPool(otherConfig,{ownershipDir:f.ownershipDir});other.bindManifest('other',{...manifest,backendId:'other'});other.assertManifestValid('other');await other.shutdown();await next.shutdown();
 }finally{await pool.shutdown();f.cleanup()}
});
test('failed durable invalidation retains ownership record and reports failure after teardown',async()=>{
 const {chmodSync,readdirSync}=await import('node:fs');const {f,manifest}=await resourceFixture(),pool=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});pool.bindManifest('demo',manifest);
 try{await pool.call('demo','read',{});const before=f.events().filter(x=>x.event==='call').length;
 const trigger=pool.call('demo','read',{notify:'resources',notifyDelayMs:60});await until(()=>f.events().filter(x=>x.event==='call').length>before);chmodSync(f.ownershipDir,0o500);
 await trigger;await until(()=>pool.snapshot().invalidationFailures===1);
 chmodSync(f.ownershipDir,0o700);await assert.rejects(pool.shutdown(),/invalidation_persistence_failed/);
 assert(readdirSync(f.ownershipDir).some(name=>name.endsWith('.json')&&!name.endsWith('.invalid.json')));
 assert(f.events().every(x=>!alive(x.pid)));
 const next=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});assert.throws(()=>next.bindManifest('demo',manifest),/ownership_quarantined/);await next.shutdown();
 }finally{chmodSync(f.ownershipDir,0o700);await pool.shutdown().catch(()=>{});f.cleanup()}
});

test('an already-cold manager observes durable invalidation written by another manager',async()=>{
 const {f,manifest}=await resourceFixture(),first=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir}),cold=new BackendPool(cfg(f),{ownershipDir:f.ownershipDir});first.bindManifest('demo',manifest);cold.bindManifest('demo',manifest);
 try{await first.call('demo','read',{notify:'resources'});await first.shutdown();assert.throws(()=>cold.assertManifestValid('demo'),/manifest_invalid/);await assert.rejects(cold.call('demo','read',{}),/manifest_invalid/);assert.equal(cold.snapshot().starts,0)}finally{await first.shutdown();await cold.shutdown();f.cleanup()}
});

test('invalid-state marker permissions, symlinks and oversized files fail closed before cold bind',async()=>{
 const {writeFileSync,symlinkSync,chmodSync,unlinkSync}=await import('node:fs');const {join}=await import('node:path');const {createHash}=await import('node:crypto');const {f,manifest}=await resourceFixture();
 const path=join(f.ownershipDir,createHash('sha256').update('demo').digest('hex')+'.invalid.json');
 try{
  writeFileSync(path,'{}',{mode:0o644});assert.throws(()=>new BackendPool(cfg(f),{ownershipDir:f.ownershipDir}).bindManifest('demo',manifest),/invalidation_state_untrusted/);unlinkSync(path);
  symlinkSync(join(f.dir,'absent'),path);assert.throws(()=>new BackendPool(cfg(f),{ownershipDir:f.ownershipDir}).bindManifest('demo',manifest),/invalidation_state_untrusted/);unlinkSync(path);
  writeFileSync(path,'x'.repeat(1025),{mode:0o600});assert.throws(()=>new BackendPool(cfg(f),{ownershipDir:f.ownershipDir}).bindManifest('demo',manifest),/invalidation_state_untrusted/);unlinkSync(path);
  writeFileSync(path,'{}',{mode:0o600});assert.throws(()=>new BackendPool(cfg(f),{ownershipDir:f.ownershipDir}).bindManifest('demo',manifest),/manifest_invalid/);chmodSync(path,0o600);
 }finally{f.cleanup()}
});
