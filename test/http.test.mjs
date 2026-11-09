import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { CallToolRequestSchema, CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { loadDist } from './helpers/private-dist.mjs';

const { startHttpServer } = await loadDist('server.js');

const token = 'a'.repeat(64);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const initialize = {jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'fixture',version:'1'}}};
function factory() { return new Server({name:'synthetic',version:'1'}, {capabilities:{tools:{}}}); }
async function start(extra={}) { return startHttpServer({host:'127.0.0.1',port:0,expectedToken:token,buildServer:factory,...extra}); }
async function request(gateway, body=initialize, extra={}) {
  if (extra.headers?.Host) {
    return new Promise((resolve,reject)=>{
      const req=http.request({host:'127.0.0.1',port:gateway.getPort(),path:'/mcp',method:'POST',headers:{Authorization:`Bearer ${token}`,Accept:'application/json, text/event-stream','Content-Type':'application/json',...extra.headers}},res=>{
        resolve({status:res.statusCode,text:async()=>{let text='';for await(const chunk of res)text+=chunk;return text;}});
      });
      req.on('error',reject);req.end(JSON.stringify(body));
    });
  }
  return fetch(`http://127.0.0.1:${gateway.getPort()}${extra.path??'/mcp'}`, {
    method:extra.method??'POST',headers:{Authorization:`Bearer ${token}`,Accept:'application/json, text/event-stream','Content-Type':'application/json',...extra.headers},body:extra.method==='GET'||extra.method==='DELETE'?undefined:JSON.stringify(body),signal:extra.signal,
  });
}

test('authentication, host, origin and content type gates allocate no sessions',async()=>{
  let built=0; const gateway=await start({buildServer:()=>{built++; return factory();}});
  try {
    for(const headers of [{Authorization:'Bearer '+'é'.repeat(64)},{Authorization:'Bearer short'},{Host:'evil.invalid'},{Origin:'null'},{'Content-Type':'text/plain'}]) {
      const response=await request(gateway,initialize,{headers});
      assert.ok([401,403,415].includes(response.status), `${Object.keys(headers)}: ${response.status}`); await response.text();
    }
    assert.equal(built,0); assert.equal(gateway.snapshot().sessions,0);
  } finally {await gateway.close();}
});

test('malformed initialize including missing id is rejected before construction',async()=>{
  let built=0; const gateway=await start({buildServer:()=>{built++;return factory();}});
  try {
    for(const body of [{jsonrpc:'2.0',id:1,method:'initialize'}, {...initialize,id:undefined},{...initialize,params:{...initialize.params,clientInfo:{name:5}}}]) {
      const response=await request(gateway,body); assert.equal(response.status,400);await response.text();
    }
    assert.equal(built,0);assert.deepEqual(gateway.snapshot(),{sessions:0,pending:0,requests:0});
  } finally {await gateway.close();}
});

test('throwing factory cannot leak pending capacity',async()=>{
  let attempts=0;const gateway=await start({maxSessions:1,buildServer:()=>{if(++attempts===1)throw Error('SYNTHETIC_SECRET');return factory();}});
  try {
    const failure=await request(gateway);assert.equal(failure.status,500);assert.equal((await failure.json()).error,'request_failed');
    const success=await request(gateway);assert.equal(success.status,200);await success.text();assert.equal(gateway.snapshot().pending,0);
  } finally {await gateway.close();}
});

test('session limits and exact route binding fail closed',async()=>{
  const gateway=await start({routes:new Set(['/mcp/a','/mcp/b']),maxSessions:1});
  try {
    const first=await request(gateway,initialize,{path:'/mcp/a'});assert.equal(first.status,200);const sid=first.headers.get('mcp-session-id');await first.text();assert.ok(sid);
    const wrong=await request(gateway,{jsonrpc:'2.0',id:2,method:'ping'},{path:'/mcp/b',headers:{'mcp-session-id':sid}});assert.equal(wrong.status,404);await wrong.text();
    const full=await request(gateway,initialize,{path:'/mcp/b'});assert.equal(full.status,429);await full.text();
    const unknown=await request(gateway,initialize,{path:'/mcp/a',headers:{'mcp-session-id':'unknown'}});assert.equal(unknown.status,404);await unknown.text();
    assert.equal(gateway.snapshot().sessions,1);
  } finally {await gateway.close();}
});

test('chunked oversize and slow bodies close without allocation',async()=>{
  const gateway=await start({bodyTimeoutMs:50});
  async function raw(chunks,end) {
    return new Promise((resolve,reject)=>{
      const req=http.request({host:'127.0.0.1',port:gateway.getPort(),path:'/mcp',method:'POST',headers:{Authorization:`Bearer ${token}`,Accept:'application/json, text/event-stream','Content-Type':'application/json','Transfer-Encoding':'chunked'}},res=>{
        const parts=[];res.on('data',chunk=>parts.push(chunk));res.on('end',()=>resolve({status:res.statusCode,connection:res.headers.connection}));
      });
      req.on('error',reject);req.setTimeout(2000,()=>req.destroy(Error('TEST_TIMEOUT')));
      for(const chunk of chunks)req.write(chunk);if(end)req.end();
    });
  }
  try {
    const large=await raw(['x'.repeat(262145)],true);assert.equal(large.status,413);assert.equal(large.connection,'close');
    const slow=await raw(['{'],false);assert.equal(slow.status,408);assert.equal(slow.connection,'close');
    assert.equal(gateway.snapshot().sessions,0);assert.equal(gateway.snapshot().requests,0);
  } finally {await gateway.close();}
});

test('idle eviction respects actual handler work after caller cancellation',async()=>{
  let server;let settled=false;const gateway=await start({sessionIdleTimeoutMs:30,buildServer:()=>{
    server=factory();let active=0;Object.defineProperty(server,'activeCalls',{get:()=>active});
    server.setRequestHandler(CallToolRequestSchema,async()=>{active++;try{await delay(180);settled=true;return {content:[{type:'text',text:'safe'}]};}finally{active--;}});return server;
  }});
  try {
    const first=await request(gateway);const sid=first.headers.get('mcp-session-id');await first.text();
    const abort=new AbortController();
    const response=request(gateway,{jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'read',arguments:{}}},{headers:{'mcp-session-id':sid},signal:abort.signal}).catch(()=>undefined);
    await delay(15);abort.abort();await response;await delay(65);
    assert.equal(server.activeCalls,1);assert.equal(gateway.snapshot().sessions,1);
    await delay(150);assert.equal(settled,true);await delay(70);assert.equal(gateway.snapshot().sessions,0);
  }finally{await gateway.close();}
});

test('connect rejection releases pending and simultaneous initialization is bounded',async()=>{
  let attempts=0;const gateway=await start({maxSessions:1,buildServer:()=>{
    const server=factory();const connect=server.connect.bind(server);
    server.connect=async transport=>{await delay(60);if(++attempts===1)throw Error('SYNTHETIC_FAILURE');return connect(transport);};return server;
  }});
  try {
    const first=request(gateway);await delay(15);
    assert.equal(gateway.snapshot().pending,1);
    const busy=await request(gateway);assert.equal(busy.status,429);await busy.text();
    const failed=await first;assert.equal(failed.status,500);await failed.text();assert.equal(gateway.snapshot().pending,0);
    const retry=await request(gateway);assert.equal(retry.status,200);await retry.text();assert.equal(gateway.snapshot().sessions,1);
  } finally {await gateway.close();}
});

test('global HTTP concurrency counts body readers and recovers after timeout',async()=>{
  const gateway=await start({maxRequests:1,bodyTimeoutMs:80});let req;
  try {
    const waiting=new Promise((resolve,reject)=>{
      req=http.request({host:'127.0.0.1',port:gateway.getPort(),path:'/mcp',method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.write('{');
    });
    await delay(15);assert.equal(gateway.snapshot().requests,1);
    const busy=await request(gateway);assert.equal(busy.status,429);await busy.text();
    assert.equal(await waiting,408);assert.equal(gateway.snapshot().requests,0);
    const good=await request(gateway);assert.equal(good.status,200);await good.text();
  } finally {req?.destroy();await gateway.close();}
});

test('shutdown waits for admitted handler work before closing its session',async()=>{
  let active=0,settled=false;const gateway=await start({buildServer:()=>{
    const server=factory();Object.defineProperty(server,'activeCalls',{get:()=>active});server.setRequestHandler(CallToolRequestSchema,async()=>{active++;try{await delay(80);settled=true;return {content:[]};}finally{active--;}});return server;
  }});
  const first=await request(gateway);const sid=first.headers.get('mcp-session-id');await first.text();
  const call=request(gateway,{jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'read',arguments:{}}},{headers:{'mcp-session-id':sid}});
  await delay(15);assert.equal(active,1);
  await gateway.close();assert.equal(settled,true);await (await call).text();assert.equal(gateway.snapshot().sessions,0);
});

test('real HTTP SDK clients receive isolated progress and one cancellation leaves the other running',async()=>{
  const seenTokens=[];
  const completed=[];
  const activeServers=[];
  const gateway=await start({routes:new Set(['/mcp/fixture']),sessionIdleTimeoutMs:30,buildServer:()=>{
    const server=factory();let active=0;Object.defineProperty(server,'activeCalls',{get:()=>active});activeServers.push(server);
    server.setRequestHandler(CallToolRequestSchema,async(request,extra)=>{
      active++;
      const label=request.params.arguments.label;
      const progressToken=request.params._meta.progressToken;
      seenTokens.push(progressToken);
      try {
        await extra.sendNotification({method:'notifications/progress',params:{progressToken,progress:1,total:2,message:label}});
        await delay(180);
        await extra.sendNotification({method:'notifications/progress',params:{progressToken,progress:2,total:2,message:label}}).catch(()=>{});
        completed.push(label);
        return {content:[{type:'text',text:label}]};
      }finally{active--;}
    });return server;
  }});
  const clients=[new Client({name:'one',version:'1'}),new Client({name:'two',version:'1'})];
  const progress=[[],[]];
  const abort=new AbortController();
  try {
    for(const client of clients)await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${gateway.getPort()}/mcp/fixture`),{requestInit:{headers:{Authorization:`Bearer ${token}`}}}));
    const calls=clients.map((client,index)=>client.callTool({name:'read',arguments:{label:index===0?'one':'two'}},CallToolResultSchema,{onprogress:value=>progress[index].push(value),...(index===0?{signal:abort.signal}:{}),timeout:2000}).then(value=>({value}),error=>({error})));
    const deadline=Date.now()+1000;
    while(progress.some(items=>items.length===0)&&Date.now()<deadline)await delay(5);
    assert.equal(progress[0].length,1,'first HTTP client must receive request-bound progress');
    assert.equal(progress[1].length,1,'second HTTP client must receive request-bound progress');
    assert.equal(seenTokens.length,2);assert.equal(seenTokens[0],seenTokens[1],'clients intentionally use identical progress tokens');
    abort.abort();
    await delay(65);
    assert.equal(activeServers.reduce((total,server)=>total+server.activeCalls,0),2);
    assert.equal(gateway.snapshot().sessions,2,'idle sweep cannot evict active work after HTTP cancellation');
    const [cancelled,success]=await Promise.all(calls);
    assert.ok(cancelled.error);assert.equal(success.error,undefined);assert.equal(success.value.content[0].text,'two');
    assert.ok(progress[0].every(item=>item.message==='one'));
    assert.deepEqual(progress[1].map(item=>item.message),['two','two']);
    assert.deepEqual(completed.sort(),['one','two']);
  }finally{await Promise.allSettled(clients.map(client=>client.close()));await gateway.close();}
});

test('ninety cold SDK sessions leave request capacity available and first session works',async()=>{
  let calls=0;
  const gateway=await start({maxRequests:4,buildServer:()=>{
    const server=factory();server.setRequestHandler(CallToolRequestSchema,async()=>{calls++;return {content:[]};});return server;
  }});
  const clients=[];
  try {
    for(let index=0;index<90;index++) {
      const client=new Client({name:`cold-${index}`,version:'1'});clients.push(client);
      await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${gateway.getPort()}/mcp`),{requestInit:{headers:{Authorization:`Bearer ${token}`}}}));
    }
    await delay(20);assert.equal(gateway.snapshot().sessions,90);assert.equal(gateway.snapshot().requests,0);assert.equal(calls,0);
    await clients[0].callTool({name:'read',arguments:{}});assert.equal(calls,1);
  } finally {await Promise.allSettled(clients.map(client=>client.close()));await gateway.close();}
});

test('one standing GET subscription per session is bounded and releases on disconnect',async()=>{
  const gateway=await start({maxSessions:1,sessionIdleTimeoutMs:30});
  const controller=new AbortController();let response;
  try {
    const initialized=await request(gateway);const sid=initialized.headers.get('mcp-session-id');await initialized.text();
    const headers={Authorization:`Bearer ${token}`,Accept:'text/event-stream','mcp-session-id':sid};
    response=await fetch(`http://127.0.0.1:${gateway.getPort()}/mcp`,{headers,signal:controller.signal});assert.equal(response.status,200);
    await delay(80);assert.equal(gateway.snapshot().sessions,1,'standing authenticated subscription retains its session');assert.equal(gateway.snapshot().requests,0);
    const duplicate=await fetch(`http://127.0.0.1:${gateway.getPort()}/mcp`,{headers});assert.equal(duplicate.status,429);assert.equal((await duplicate.json()).error,'subscription_limit');
    controller.abort();await response.body.cancel().catch(()=>{});await delay(80);assert.equal(gateway.snapshot().sessions,0);
  } finally {controller.abort();await response?.body?.cancel().catch(()=>{});await gateway.close();}
});

test('standing subscriptions do not bypass the active POST response limit',async()=>{
  const gateway=await start({maxRequests:1,buildServer:()=>{
    const server=factory();server.setRequestHandler(CallToolRequestSchema,async()=>{await delay(80);return {content:[]};});return server;
  }});
  const clients=[new Client({name:'post-one',version:'1'}),new Client({name:'post-two',version:'1'})];
  try {
    for(const client of clients)await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${gateway.getPort()}/mcp`),{requestInit:{headers:{Authorization:`Bearer ${token}`}}}));
    const first=clients[0].callTool({name:'read',arguments:{}});await delay(15);assert.equal(gateway.snapshot().requests,1);
    await assert.rejects(clients[1].callTool({name:'read',arguments:{}}),error=>error.code===429);
    await first;assert.equal(gateway.snapshot().requests,0);
  } finally {await Promise.allSettled(clients.map(client=>client.close()));await gateway.close();}
});

test('configurable session capacity remains finite and socket budget includes reusable POST connections',async()=>{
  const gateway=await start({maxSessions:512,maxRequests:128});
  try {assert.equal(gateway.server.maxConnections,1168);}finally{await gateway.close();}
  for(const options of [{maxSessions:513},{maxRequests:129},{maxSessions:0}]) {
    await assert.rejects(start(options),error=>error.code==='invalid_listener_config');
  }
});

const control=async(gateway,operation,extra={})=>fetch(`http://127.0.0.1:${gateway.getPort()}/_control/${operation}`,{method:operation==='status'?'GET':'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json',...extra.headers},...(operation==='status'?{}:{body:JSON.stringify(extra.body??{})})});
test('traffic status is an authenticated read and preserves the existing lifecycle snapshot',async()=>{
 let reads=0;
 const snapshot={generation:'00000000-0000-4000-8000-000000000001',profiles:{demo:{catalogRequests:2,toolAttempts:1,toolSuccesses:1,toolFailures:0}}};
 const gateway=await start({routes:new Set(['/mcp/demo']),getTrafficCounts:()=>{reads++;return snapshot;}});
 try{
  const denied=await control(gateway,'status',{headers:{Authorization:'Bearer invalid'}});assert.equal(denied.status,401);await denied.text();assert.equal(reads,0);
  const forbidden=await control(gateway,'status',{headers:{Origin:'https://invalid.example'}});assert.equal(forbidden.status,403);await forbidden.text();assert.equal(reads,0);
  const wrongHost=await new Promise((resolve,reject)=>{
   const req=http.request({host:'127.0.0.1',port:gateway.getPort(),path:'/_control/status',headers:{Authorization:`Bearer ${token}`,Host:'evil.invalid'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.end();
  });assert.equal(wrongHost,403);assert.equal(reads,0);
  const unknownRoute=await request(gateway,initialize,{path:'/mcp/unknown'});assert.equal(unknownRoute.status,404);await unknownRoute.text();assert.equal(reads,0);
  const unknownControl=await control(gateway,'unknown');assert.equal(unknownControl.status,404);await unknownControl.text();assert.equal(reads,0);
  for(const operation of ['drain','resume']){const response=await control(gateway,operation);assert.equal(response.status,200);assert.equal(Object.hasOwn(await response.json(),'trafficCounters'),false);}
  assert.equal(reads,0);
  const status=await control(gateway,'status');assert.equal(status.status,200);
  const result=await status.json();
  assert.deepEqual(Object.keys(result.monitoring),['version','uptimeSeconds','sessions','idleSessions','busySessions','subscriptions','profiles']);
  assert.equal(result.monitoring.version,1);assert.equal(typeof result.monitoring.uptimeSeconds,'number');assert(result.monitoring.uptimeSeconds>=0);
  assert.deepEqual(result.monitoring,{version:1,uptimeSeconds:result.monitoring.uptimeSeconds,sessions:0,idleSessions:0,busySessions:0,subscriptions:0,
   profiles:{demo:{sessions:0,idleSessions:0,busySessions:0,subscriptions:0,requests:0,active:0,backendLive:null,retained:null}}});
  assert.deepEqual({...result,monitoring:undefined},{draining:false,quiescent:true,pending:0,requests:0,active:0,monitoring:undefined,trafficCounters:snapshot});
  assert.equal(reads,1);
 }finally{await gateway.close();}
});

test('monitoring reports bounded per-route session, request, activity and SSE counts',async()=>{
 let active=0,release;const gate=new Promise(resolve=>release=resolve);let built=0;
 const gateway=await start({routes:new Set(['/mcp/a','/mcp/b']),getProfileMonitoringCounts:()=>({
  a:{backendLive:0,retained:0},b:{backendLive:null,retained:null},
 }),buildServer:()=>{
  built++;let sessionActive=0;const server=factory();Object.defineProperty(server,'activeCalls',{get:()=>sessionActive});
  server.setRequestHandler(CallToolRequestSchema,async()=>{active++;sessionActive++;try{await gate;return {content:[]};}finally{active--;sessionActive--;}});return server;
 }});
 const controller=new AbortController();let subscription;
 try{
  const empty=await(await control(gateway,'status')).json();assert.deepEqual(Object.keys(empty.monitoring.profiles),['a','b']);
  assert.deepEqual(empty.monitoring.profiles.a,{sessions:0,idleSessions:0,busySessions:0,subscriptions:0,requests:0,active:0,backendLive:0,retained:0});assert.equal(built,0);
  const a=await request(gateway,initialize,{path:'/mcp/a'});const sidA=a.headers.get('mcp-session-id');await a.text();
  const b=await request(gateway,initialize,{path:'/mcp/b'});const sidB=b.headers.get('mcp-session-id');await b.text();
  const idle=await(await control(gateway,'status')).json();assert.equal(idle.monitoring.sessions,2);assert.equal(idle.monitoring.idleSessions,2);assert.equal(idle.monitoring.busySessions,0);
  assert.deepEqual(idle.monitoring.profiles.a,{sessions:1,idleSessions:1,busySessions:0,subscriptions:0,requests:0,active:0,backendLive:0,retained:0});
  assert.deepEqual(idle.monitoring.profiles.b,{sessions:1,idleSessions:1,busySessions:0,subscriptions:0,requests:0,active:0,backendLive:null,retained:null});
  const call=request(gateway,{jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'read',arguments:{}}},{path:'/mcp/a',headers:{'mcp-session-id':sidA}});
  for(let i=0;i<100&&active===0;i++)await delay(2);assert.equal(active,1);
  const busy=await(await control(gateway,'status')).json();assert.equal(busy.monitoring.busySessions,1);assert.equal(busy.monitoring.idleSessions,1);
  assert.equal(busy.monitoring.profiles.a.requests,1);assert.equal(busy.monitoring.profiles.a.active,1);assert.equal(busy.monitoring.profiles.a.busySessions,1);
  release();const completed=await call;assert.equal(completed.status,200);await completed.text();
  subscription=await fetch(`http://127.0.0.1:${gateway.getPort()}/mcp/b`,{headers:{Authorization:`Bearer ${token}`,Accept:'text/event-stream','mcp-session-id':sidB},signal:controller.signal});assert.equal(subscription.status,200);
  await delay(15);const subscribed=await(await control(gateway,'status')).json();assert.equal(subscribed.monitoring.subscriptions,1);
  assert.equal(subscribed.monitoring.profiles.b.subscriptions,1);assert.equal(subscribed.monitoring.profiles.b.requests,0);
  assert.equal(subscribed.monitoring.profiles.b.idleSessions,1);assert.equal(subscribed.monitoring.profiles.b.busySessions,0);
  assert.deepEqual(Object.keys(subscribed.monitoring.profiles),['a','b']);assert.equal(built,2);
 }finally{release();controller.abort();await subscription?.body?.cancel().catch(()=>{});await gateway.close();}
});

test('malformed backend monitoring snapshots fail closed without exposing injected values',async()=>{
 const good=()=>({demo:{backendLive:1,retained:0}});
 const extra=good();extra.demo.args='MONITORING_SECRET';
 const missing=good();delete missing.demo.retained;
 const extraProfile=good();extraProfile.other={backendLive:1,retained:0};
 const inherited=Object.assign(Object.create({other:{backendLive:0,retained:0}}),good());
 const getter=good();Object.defineProperty(getter.demo,'backendLive',{enumerable:true,get(){throw Error('MONITORING_SECRET');}});
 const invalid=[extra,missing,extraProfile,inherited,getter,
  ...[-1,0.5,NaN,Infinity,Number.MAX_SAFE_INTEGER+1,'1'].map(value=>({demo:{backendLive:value,retained:0}})),
  {demo:{backendLive:0,retained:-1}},null,[],new Proxy(good(),{})];
 let snapshot=good();
 const gateway=await start({routes:new Set(['/mcp/demo']),getProfileMonitoringCounts:()=>snapshot});
 try{
  for(const value of invalid){snapshot=value;const response=await control(gateway,'status');assert.equal(response.status,400);
   const body=await response.text();assert.equal(body,'{"error":"monitoring_counts_invalid"}');assert.equal(body.includes('MONITORING_SECRET'),false);}
 }finally{await gateway.close();}
});

test('monitoring route table cannot exceed configured profile bounds',async()=>{
 const routes=new Set(Array.from({length:65},(_,index)=>`/mcp/profile-${index}`));
 await assert.rejects(start({routes}),error=>error.code==='invalid_listener_config');
});

test('invalid traffic snapshots fail with one fixed error and never expose injected fields',async()=>{
 const good=()=>({generation:'00000000-0000-4000-8000-000000000001',profiles:{demo:{catalogRequests:0,toolAttempts:0,toolSuccesses:0,toolFailures:0}}});
 const topExtra=good();topExtra.args={sentinel:'top-level-secret'};
 const rowExtra=good();rowExtra.profiles.demo.result={sentinel:'row-secret'};
 const missingTop=good();delete missingTop.generation;
 const extraProfile=good();extraProfile.profiles.other={catalogRequests:0,toolAttempts:0,toolSuccesses:0,toolFailures:0};
 const missingField=good();delete missingField.profiles.demo.toolFailures;
 const customPrototype=Object.assign(Object.create({inherited:true}),good());
 const nullPrototype=Object.assign(Object.create(null),good());
 const customProfiles=good();customProfiles.profiles=Object.assign(Object.create({inherited:true}),good().profiles);
 const nullProfiles=good();nullProfiles.profiles=Object.assign(Object.create(null),good().profiles);
 const symbolTop=good();symbolTop[Symbol('extra')]=true;
 const hiddenTop=good();Object.defineProperty(hiddenTop,'hidden',{value:true});
 const getterTop=good();Object.defineProperty(getterTop,'generation',{enumerable:true,get(){throw Error('getter-secret');}});
 const getterProfiles=good();Object.defineProperty(getterProfiles,'profiles',{enumerable:true,get(){throw Error('profiles-getter-secret');}});
 const getterRow=good();Object.defineProperty(getterRow.profiles.demo,'toolSuccesses',{enumerable:true,get(){throw Error('row-getter-secret');}});
 const symbolProfiles=good();symbolProfiles.profiles[Symbol('extra')]=true;
 const hiddenProfiles=good();Object.defineProperty(hiddenProfiles.profiles,'hidden',{value:true});
 const getterProfile=good();Object.defineProperty(getterProfile.profiles,'demo',{enumerable:true,get(){throw Error('profile-getter-secret');}});
 const symbolRow=good();symbolRow.profiles.demo[Symbol('extra')]=true;
 const hiddenRow=good();Object.defineProperty(hiddenRow.profiles.demo,'hidden',{value:true});
 const badValues=[
  null,[],{...good(),generation:'not-a-uuid'},missingTop,{...good(),extra:'top-secret'},extraProfile,missingField,
  topExtra,rowExtra,customPrototype,nullPrototype,customProfiles,nullProfiles,new Proxy(good(),{}),
  {...good(),profiles:new Proxy(good().profiles,{})},
  {...good(),profiles:{demo:new Proxy(good().profiles.demo,{})}},symbolTop,hiddenTop,getterTop,getterProfiles,getterRow,
  symbolProfiles,hiddenProfiles,getterProfile,symbolRow,hiddenRow,
  ...[-1,0.5,NaN,Infinity,Number.MAX_SAFE_INTEGER+1,'1'].map(value=>({...good(),profiles:{demo:{catalogRequests:value,toolAttempts:0,toolSuccesses:0,toolFailures:0}}})),
 ];
 let value=good();
 const gateway=await start({routes:new Set(['/mcp/demo']),getTrafficCounts:()=>value});
 try{
  for(const invalid of badValues){
   value=invalid;
   const response=await control(gateway,'status');assert.equal(response.status,400);
   const body=await response.text();assert.equal(body,'{"error":"traffic_counts_invalid"}');
   assert.equal(body.includes('sentinel'),false);assert.equal(body.includes('secret'),false);assert.equal(body.includes('top-secret'),false);
  }
 }finally{await gateway.close();}
});
test('authenticated status exposes monotonic launch admissions without changing drain or resume',async()=>{
 let counts={starts:0,live:0},reads=0;
 const gateway=await start({getBackendCounts:()=>{reads++;return counts;}});
 try{
  const denied=await control(gateway,'status',{headers:{Authorization:'invalid'}});assert.equal(denied.status,401);await denied.text();assert.equal(reads,0);
  const forbidden=await control(gateway,'status',{headers:{Origin:'https://invalid.example'}});assert.equal(forbidden.status,403);await forbidden.text();assert.equal(reads,0);
  const cold=await(await control(gateway,'status')).json();assert.equal(cold.backendStarts,0);assert.equal(cold.backendLive,0);
  counts={starts:2,live:2};const used=await(await control(gateway,'status')).json();assert.equal(used.backendStarts,2);assert.equal(used.backendLive,2);
  counts={starts:2,live:0};const retired=await(await control(gateway,'status')).json();assert.equal(retired.backendStarts,2);assert.equal(retired.backendLive,0);
  const before=reads;for(const operation of ['drain','resume']){const value=await(await control(gateway,operation)).json();assert(!Object.hasOwn(value,'backendStarts'));assert(!Object.hasOwn(value,'backendLive'));}assert.equal(reads,before);
 }finally{await gateway.close();}
});
test('invalid or decreasing launch counters fail with a safe error before success headers',async()=>{
 let counts={starts:3,live:0};const gateway=await start({getBackendCounts:()=>{if(counts==='throw')throw Error('private-marker');return counts;}});
 try{
  await(await control(gateway,'status')).json();
  for(const value of [{starts:-1,live:0},{starts:3.5,live:0},{starts:NaN,live:0},{starts:Infinity,live:0},{starts:Number.MAX_SAFE_INTEGER+1,live:0},{starts:3,live:4},{starts:2,live:0},{starts:3,live:-1},'throw']){
   counts=value;const response=await control(gateway,'status');assert.equal(response.status,400);assert.deepEqual(await response.json(),{error:'backend_counts_invalid'});
  }
 }finally{await gateway.close();}
});
test('private drain closes admission, excludes idle SSE and expires without shutdown',async()=>{
  const gateway=await start({maintenanceTimeoutMs:80});
  try{
    const initialized=await request(gateway);await initialized.text();
    const status=await control(gateway,'status');assert.equal(status.status,200);
    const statusBody=await status.json();assert.deepEqual({...statusBody,monitoring:undefined},{draining:false,quiescent:true,pending:0,requests:0,active:0,monitoring:undefined});
    const drain=await control(gateway,'drain');assert.equal(drain.status,200);assert.equal((await drain.json()).draining,true);
    const late=await request(gateway);assert.equal(late.status,503);assert.equal((await late.json()).error,'draining');
    await delay(40);await control(gateway,'drain');
    await delay(60);assert.equal((await(await control(gateway,'status')).json()).draining,false);
    const good=await request(gateway);assert.equal(good.status,200);await good.text();
    await control(gateway,'drain');const resume=await control(gateway,'resume');assert.equal((await resume.json()).draining,false);
  }finally{await gateway.close();}
});

test('admitted unfinished body prevents quiescence and completes after drain',async()=>{
  const gateway=await start({bodyTimeoutMs:1000});let req;
  try{
    const response=new Promise((resolve,reject)=>{
      req=http.request({host:'127.0.0.1',port:gateway.getPort(),path:'/mcp',method:'POST',headers:{Authorization:`Bearer ${token}`,Accept:'application/json, text/event-stream','Content-Type':'application/json'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.write('{');
    });
    await delay(20);
    const status=await(await control(gateway,'drain')).json();assert.equal(status.quiescent,false);assert.equal(status.pending,1);assert.equal(status.requests,1);
    req.end(JSON.stringify(initialize).slice(1));assert.equal(await response,200);
    assert.equal((await(await control(gateway,'status')).json()).quiescent,true);
  }finally{req?.destroy();await gateway.close();}
});

test('control enforces authentication origin schema and method without building MCP servers',async()=>{
  let built=0;const gateway=await start({buildServer:()=>{built++;return factory();}});
  try{
    for(const headers of [{Authorization:'Bearer invalid'},{Origin:'null'}]){
      const response=await control(gateway,'drain',{headers});assert.ok([401,403].includes(response.status));await response.text();
    }
    const wrongHost=await new Promise((resolve,reject)=>{
      const req=http.request({host:'127.0.0.1',port:gateway.getPort(),path:'/_control/status',headers:{Authorization:`Bearer ${token}`,Host:'evil.invalid'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});req.on('error',reject);req.end();
    });assert.equal(wrongHost,403);
    const malformed=await control(gateway,'drain',{body:{budget:1}});assert.equal(malformed.status,400);await malformed.text();
    const wrong=await fetch(`http://127.0.0.1:${gateway.getPort()}/_control/drain`,{headers:{Authorization:`Bearer ${token}`}});assert.equal(wrong.status,404);await wrong.text();
    assert.equal(built,0);const status=await(await control(gateway,'status')).json();assert.equal(status.draining,false);assert.equal(status.monitoring.sessions,0);assert.equal(built,0);
  }finally{await gateway.close();}
});

test('drain preserves a call longer than the previous shutdown window exactly once',async()=>{
  let active=0,calls=0,completions=0;
  const gateway=await start({buildServer:()=>{
    const server=factory();Object.defineProperty(server,'activeCalls',{get:()=>active});
    server.setRequestHandler(CallToolRequestSchema,async()=>{calls++;active++;try{await delay(15500);completions++;return {content:[]};}finally{active--;}});return server;
  }});
  const client=new Client({name:'long-drain',version:'1'});
  try{
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${gateway.getPort()}/mcp`),{requestInit:{headers:{Authorization:`Bearer ${token}`}}}));
    const call=client.callTool({name:'read',arguments:{}},CallToolResultSchema,{timeout:20000});
    for(let i=0;i<100&&!active;i++)await delay(5);assert.equal(active,1);
    const draining=await(await control(gateway,'drain')).json();assert.equal(draining.quiescent,false);assert.equal(draining.active,1);
    const late=await request(gateway);assert.equal(late.status,503);await late.text();
    await call;assert.equal(calls,1);assert.equal(completions,1);
    const status=await(await control(gateway,'status')).json();assert.equal(status.quiescent,true);
    await control(gateway,'resume');assert.equal((await(await control(gateway,'status')).json()).draining,false);
  }finally{await client.close();await gateway.close();}
});

test('drain status covers pending initialization and backend work after frontend disconnect',async()=>{
  let connecting=false,backendActive=0;
  const gateway=await start({getActive:()=>backendActive,buildServer:()=>{
    const server=factory(),connect=server.connect.bind(server);
    server.connect=async transport=>{connecting=true;await delay(120);return connect(transport);};return server;
  }});
  try{
    const initial=request(gateway);
    for(let i=0;i<100&&!connecting;i++)await delay(5);
    const waiting=await(await control(gateway,'drain')).json();assert.equal(waiting.pending,1);assert.equal(waiting.quiescent,false);
    const response=await initial;assert.equal(response.status,200);await response.text();
    backendActive=1;
    const active=await(await control(gateway,'status')).json();assert.equal(active.active,1);assert.equal(active.quiescent,false);
    backendActive=0;assert.equal((await(await control(gateway,'status')).json()).quiescent,true);
  }finally{await gateway.close();}
});

test('standing idle SSE does not prevent drain quiescence',async()=>{
  const gateway=await start();const controller=new AbortController();let subscription;
  try{
    const first=await request(gateway);const sid=first.headers.get('mcp-session-id');await first.text();
    subscription=await fetch(`http://127.0.0.1:${gateway.getPort()}/mcp`,{headers:{Authorization:`Bearer ${token}`,Accept:'text/event-stream','mcp-session-id':sid},signal:controller.signal});
    assert.equal(subscription.status,200);
    const status=await(await control(gateway,'drain')).json();assert.equal(status.quiescent,true);assert.equal(status.requests,0);
  }finally{controller.abort();await subscription?.body?.cancel().catch(()=>{});await gateway.close();}
});

test('control readers are bounded and excluded from maintenance counts',async()=>{
  const gateway=await start({bodyTimeoutMs:100});const readers=[];
  const results=[];
  try{
    for(let i=0;i<4;i++)results.push(new Promise((resolve,reject)=>{
      const req=http.request({host:'127.0.0.1',port:gateway.getPort(),path:'/_control/drain',method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));});readers.push(req);req.on('error',reject);req.write('{');
    }));
    await delay(20);
    const busy=await control(gateway,'status');assert.equal(busy.status,429);await busy.text();
    assert.deepEqual(gateway.snapshot(),{sessions:0,pending:0,requests:0});
    assert.deepEqual(await Promise.all(results),[408,408,408,408]);
    const status=await(await control(gateway,'status')).json();assert.equal(status.quiescent,true);assert.equal(status.draining,false);
  }finally{readers.forEach(req=>req.destroy());await gateway.close();}
});
