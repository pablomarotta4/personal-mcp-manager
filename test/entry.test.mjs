import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, chmodSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

async function launch(payload,{token='a'.repeat(64),argv=[]}={}) {
  const dir=mkdtempSync(join(tmpdir(),'mcp-entry-'));chmodSync(dir,0o700);
  const path=join(dir,'token');writeFileSync(path,token,{mode:0o600});
  const child=spawn(process.execPath,[resolve('dist/index.js'),'--config-stdin','--token-file',path,'--port','0',...argv],
    {stdio:['pipe','pipe','pipe'],env:{PATH:process.env.PATH,HOME:dir}});
  let output='',errors='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>errors+=b);
  child.stdin.on('error',()=>{});child.stdin.end(typeof payload==='string'?payload:JSON.stringify(payload));
  const ended=new Promise(r=>child.once('exit',(code,signal)=>r({code,signal})));
  const stop=async()=>{
    if(child.exitCode===null&&child.signalCode===null){
      child.kill('SIGTERM');
      let timeout;try{await Promise.race([ended,new Promise((_,reject)=>{timeout=setTimeout(()=>reject(Error('STOP_TIMEOUT')),8000)})]);}
      finally{clearTimeout(timeout);}
    }
    rmSync(dir,{recursive:true,force:true});
  };
  return {child,ended,token,dir,stop,logs:()=>output+errors,port:()=>{
    try{return JSON.parse(output.trim()).port}catch{return undefined}
  }};
}
const config=()=>({mcpServers:{demo:{command:process.execPath,args:[resolve('test/fixtures/backend.mjs')],env:{},cwd:process.cwd(),shared:true,allowedTools:['read'],instruction:'Synthetic'}}});
test('standalone runtime starts cold and keeps tool payloads out of diagnostics',async()=>{
  const g=await launch(config());let client;
  try{
    for(let i=0;i<100&&!g.port()&&g.child.exitCode===null;i++)await new Promise(r=>setTimeout(r,30));
    assert(Number.isInteger(g.port()),'entrypoint should accept private stdin config');
    client=new Client({name:'entry-test',version:'1'});
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${g.port()}/mcp`),{requestInit:{headers:{Authorization:`Bearer ${g.token}`}}}));
    await client.listTools();
    const valid=await client.callTool({name:'call_mcp_tool',arguments:{mcp:'demo',toolName:'read',arguments:{marker:'SYNTHETIC_SECRET'}}});
    assert.equal(valid.isError,undefined);assert(Number.isInteger(valid.structuredContent?.pid));
    const invalid=await client.callTool({name:'call_mcp_tool',arguments:{mcp:'SYNTHETIC_SECRET',toolName:'read',arguments:{marker:'SYNTHETIC_SECRET'}}});
    assert.equal(invalid.isError,true);assert(!JSON.stringify(invalid).includes('SYNTHETIC_SECRET'));
  }finally{await client?.close();await g.stop();}
  assert(!g.logs().includes('SYNTHETIC_SECRET'));assert(!g.logs().includes(g.token));
});
test('invalid credentials/config/flags fail closed with bounded diagnostics',async()=>{
  for(const [payload,options] of [[config(),{token:'invalid'}],['{"bad":"SYNTHETIC_SECRET"}',{}],[config(),{argv:['--host','0.0.0.0']}],[config(),{argv:['--backend-diagnostic-fd','4']}],[config(),{argv:['--backend-diagnostic-fd','x']}],[config(),{argv:['--backend-diagnostic-fd','4','--backend-diagnostic-fd','4']}],['x'.repeat(1024*1024+1),{}]]){
    const g=await launch(payload,options);
    try{const result=await g.ended;assert.equal(result.code,1);assert(!g.port());assert.equal(g.logs(),'{"event":"startup_failed"}\n');}
    finally{await g.stop();}
  }
});

test('repeated shutdown signals drain an active call and remove owned processes',async()=>{
  const {readFileSync,readdirSync}=await import('node:fs');
  const evidence=mkdtempSync(join(tmpdir(),'mcp-shutdown-ledger-'));
  const ledger=join(evidence,'events');
  const payload=config();payload.mcpServers.demo.env.FIXTURE_LEDGER=ledger;
  const g=await launch(payload);let client;
  const delay=ms=>new Promise(r=>setTimeout(r,ms));
  const absent=pid=>{try{process.kill(pid,0);return false;}catch(error){return error.code==='ESRCH';}};
  try{
    for(let i=0;i<100&&!g.port()&&g.child.exitCode===null;i++)await delay(30);
    assert(Number.isInteger(g.port()));
    client=new Client({name:'shutdown-entry-test',version:'1'});
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${g.port()}/mcp`),{requestInit:{headers:{Authorization:`Bearer ${g.token}`}}}));
    const initial=await client.callTool({name:'call_mcp_tool',arguments:{mcp:'demo',toolName:'read',arguments:{}}});
    const backendPid=initial.structuredContent.pid;
    const ownership=join(g.dir,'ownership');
    const record=JSON.parse(readFileSync(join(ownership,readdirSync(ownership)[0]),'utf8'));
    const pending=client.callTool({name:'call_mcp_tool',arguments:{mcp:'demo',toolName:'read',arguments:{delayMs:800}}});
    const settled=pending.then(()=>{},()=>{});
    for(let i=0;i<100;i++){
      const events=readFileSync(ledger,'utf8').trim().split('\n').map(line=>JSON.parse(line));
      if(events.filter(event=>event.event==='call').length===2)break;
      await delay(10);
    }
    const activeEvents=readFileSync(ledger,'utf8').trim().split('\n').map(line=>JSON.parse(line));
    assert.equal(activeEvents.filter(event=>event.event==='call').length,2);
    assert.equal(activeEvents.filter(event=>event.event==='complete').length,1,'slow call must still be active');
    const status=await fetch(`http://127.0.0.1:${g.port()}/_control/status`,{headers:{Authorization:`Bearer ${g.token}`}});
    assert.equal(status.status,200);
    const activity=await status.json();assert.equal(activity.active,1);assert.equal(activity.quiescent,false);
    g.child.kill('SIGINT');await delay(60);g.child.kill('SIGINT');
    await delay(60);g.child.kill('SIGTERM');g.child.kill('SIGTERM');
    let timeout;
    try{
      const result=await Promise.race([g.ended,new Promise((_,reject)=>{timeout=setTimeout(()=>reject(Error('SHUTDOWN_TIMEOUT')),8000);})]);
      assert.deepEqual(result,{code:0,signal:null});
    }finally{clearTimeout(timeout);}
    await settled;
    assert.deepEqual(readdirSync(ownership),[]);
    assert(absent(record.supervisorPid),'owned supervisor must be gone');
    assert(absent(backendPid),'owned backend must be gone');
  }finally{await client?.close();await g.stop();rmSync(evidence,{recursive:true,force:true});}
});
