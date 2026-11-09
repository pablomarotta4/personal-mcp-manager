import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdirSync,writeFileSync,openSync,closeSync,readFileSync,fstatSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {BackendPool} from '../dist/pool.js';
import {parseConfig} from '../dist/policy.js';
import {policyDigest,executableDigest} from '../dist/runtime.js';
import {fingerprintDescription} from '../dist/manifest.js';
import {fixture,alive,until} from './helpers.mjs';

for(const termination of ['owner EOF','requested shutdown','host verifier option','diagnostic option'])test(`entrypoint private owner fd gates session use and ${termination} cleans its backend`,async()=>{
  const f=fixture();f.backend.scope='session';f.backend.allowedTools=['read','write'];
  let config=parseConfig(f.config);const token='a'.repeat(64),owner='0000000000000001'+'b'.repeat(48);
  let provision;
  let child,client,endedStatus,port,traceFd;const trace=join(f.dir,'trace');const frames=[];let output='',wire='';
  try{
    if(termination==='diagnostic option'){
      traceFd=openSync(trace,'wx',0o600);const info=fstatSync(traceFd);
      const preload=join(f.dir,'check-fd.mjs');
      writeFileSync(preload,`import {fstatSync} from 'node:fs';for(let fd=3;fd<=1024;fd++){try{const s=fstatSync(fd);if(s.dev===${info.dev}&&s.ino===${info.ino})throw Error('DIAGNOSTIC_FD_INHERITED')}catch(e){if(e.message==='DIAGNOSTIC_FD_INHERITED')throw e}}`);
      f.backend.args.unshift('--import',preload);
    }
    config=parseConfig(f.config);provision=new BackendPool(config,{ownershipDir:f.ownershipDir});
    const description=await provision.describe('demo');await provision.shutdown();
    const manifests=join(f.dir,'manifests');mkdirSync(manifests,{mode:0o700});
    writeFileSync(join(f.dir,'token'),token,{mode:0o600});
    writeFileSync(join(manifests,'demo.json'),JSON.stringify({version:1,backendId:'demo',allowedTools:['read','write'],description,
      fingerprint:fingerprintDescription(description),provenance:{sourceIdentity:'fixture:synthetic',artifactSha256:await executableDigest(process.execPath),
      policyDigest:policyDigest(config.servers.get('demo'),token),reviewedAt:new Date().toISOString()}}),{mode:0o600});
    child=spawn(process.execPath,[resolve('dist/index.js'),'--config-stdin','--token-file',join(f.dir,'token'),'--port','0','--manifest-dir',manifests,'--owner-channel-fd','3',...(termination==='host verifier option'?['--closure-verifier-python','/reviewed/host-python']:[]),...(traceFd!==undefined?['--backend-diagnostic-fd','4']:[])],{
      stdio:['pipe','pipe','ignore','pipe',...(traceFd!==undefined?[traceFd]:[])],env:{PATH:process.env.PATH,HOME:f.dir},
    });
    if(traceFd!==undefined){closeSync(traceFd);traceFd=undefined;}
    child.once('exit',(code,signal)=>{endedStatus={code,signal};});
    child.stdin.on('error',()=>{});child.stdio[3].on('error',()=>{});
    child.stdout.on('data',chunk=>{output+=chunk;for(const line of output.trim().split('\n'))try{const value=JSON.parse(line);if(value.event==='listening')port=value.port;}catch{}});
    child.stdio[3].on('data',chunk=>{wire+=chunk;while(wire.includes('\n')){const end=wire.indexOf('\n');frames.push(JSON.parse(wire.slice(0,end)));wire=wire.slice(end+1);}});
    child.stdin.end(JSON.stringify(f.config));
    await until(()=>Number.isInteger(port)||endedStatus!==undefined);
    assert(Number.isInteger(port),'entrypoint accepts the inherited owner channel');
    await until(()=>frames.some(frame=>frame.type==='ready'));
    child.stdio[3].write(JSON.stringify({v:1,type:'register',requestId:'c'.repeat(32),owner,backend:'demo'})+'\n');
    await until(()=>frames.some(frame=>frame.type==='ack'));
    client=new Client({name:'owner-entry',version:'1'});
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp/demo`),{requestInit:{headers:{Authorization:`Bearer ${token}`,'X-Personal-MCP-Owner':owner}}}));
    await client.listTools();assert.equal(f.events().filter(event=>event.event==='start').length,1,'discovery leaves only the already-closed provisioner in history');
    const result=await client.callTool({name:'read',arguments:{}});assert(alive(result.structuredContent.pid));
    if(termination==='diagnostic option'){const rows=readFileSync(trace,'utf8').trim().split('\n').map(JSON.parse);assert(rows.some(row=>row.stage==='tool'&&row.reason==='ok'),'writer remains live after listening');}
    if(termination==='owner EOF')child.stdio[3].destroy();
    else child.kill('SIGTERM');
    await until(()=>endedStatus!==undefined,8000);
    assert.deepEqual(endedStatus,{code:termination==='owner EOF'?1:0,signal:null});
    await until(()=>f.events().every(event=>!alive(event.pid)));
    if(termination==='diagnostic option')assert.equal(JSON.parse(readFileSync(trace,'utf8').trim().split('\n').at(-1)).reason,'closed');
  }finally{
    if(traceFd!==undefined)closeSync(traceFd);
    await client?.close();
    if(child&&child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
    if(child)await until(()=>endedStatus!==undefined,8000);
    await provision?.shutdown();await until(()=>f.events().every(event=>!alive(event.pid)));
    f.cleanup();
  }
});
test('diagnostic descriptor must differ from owner socket and installed port is refused',async()=>{
 for(const mode of ['same','installed','malformed','repeated']){const f=fixture(),token='a'.repeat(64);writeFileSync(join(f.dir,'token'),token,{mode:0o600});const path=join(f.dir,'trace'),fd=openSync(path,'wx',0o600);let child,status,stderr='';try{
 const pair=mode==='same'?['--backend-diagnostic-fd','3']:mode==='malformed'?['--backend-diagnostic-fd','x']:mode==='repeated'?['--backend-diagnostic-fd','4','--backend-diagnostic-fd','4']:['--backend-diagnostic-fd','4'];
 child=spawn(process.execPath,[resolve('dist/index.js'),'--config-stdin','--token-file',join(f.dir,'token'),'--port',mode==='installed'?'18765':'0','--manifest-dir',f.dir,'--owner-channel-fd','3',...pair],{stdio:['pipe','pipe','pipe','pipe',fd],env:{PATH:process.env.PATH,HOME:f.dir}});closeSync(fd);child.stdin.on('error',()=>{});child.stdio[3].on('error',()=>{});child.stderr.on('data',b=>stderr+=b);const ended=new Promise(r=>child.once('exit',(code,signal)=>{status={code,signal};r()}));child.stdin.end(JSON.stringify(f.config));await ended;assert.deepEqual(status,{code:1,signal:null});assert.equal(stderr,'{"event":"startup_failed"}\n');assert.equal(readFileSync(path,'utf8'),'');
 }finally{if(!child)closeSync(fd);if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGTERM');await until(()=>status!==undefined)}f.cleanup()}}
});
