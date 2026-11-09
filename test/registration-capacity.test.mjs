import test from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
const base = pathToFileURL(resolve(process.env.PERSONAL_MCP_TEST_DIST ?? new URL('../dist/', import.meta.url).pathname) + '/');
const {parseConfig,MAX_BACKEND_PROFILES} = await import(new URL('policy.js',base));
const {startHttpServer} = await import(new URL('server.js',base));
const policy = () => ({command:process.execPath,args:[],env:{},cwd:process.cwd(),shared:true,allowedTools:['read']});
const config = count => ({mcpServers:Object.fromEntries(Array.from({length:count},(_,i)=>[`fixture-${i}`,policy()]))});
test('full local inventory and bounded registration headroom are accepted',()=>{
  assert.equal(parseConfig(config(26)).servers.size,26);
  assert.equal(parseConfig(config(32)).servers.size,32);
  assert.equal(parseConfig(config(MAX_BACKEND_PROFILES)).servers.size,MAX_BACKEND_PROFILES);
});
test('registration limit remains finite and rejects empty configuration',()=>{
  assert.throws(()=>parseConfig(config(MAX_BACKEND_PROFILES+1)),/invalid_config/);
  assert.throws(()=>parseConfig(config(0)),/invalid_config/);
});
test('named routes plus dispatcher retain authentication before facade allocation',async()=>{
  const routes=new Set(['/mcp',...Array.from({length:32},(_,i)=>`/mcp/fixture-${i}`)]);
  let builds=0;
  const gateway=await startHttpServer({host:'127.0.0.1',port:0,expectedToken:'a'.repeat(64),routes,buildServer:()=>{
    builds++;return new Server({name:'fixture',version:'1'},{capabilities:{tools:{}}});
  }});
  const initialize={jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'fixture',version:'1'}}};
  const request=(path,authorized)=>fetch(`http://127.0.0.1:${gateway.getPort()}${path}`,{method:'POST',headers:{Accept:'application/json, text/event-stream','Content-Type':'application/json',...(authorized?{Authorization:'Bearer '+'a'.repeat(64)}:{})},body:JSON.stringify(initialize)});
  try{
    const rejected=await request('/mcp/fixture-31',false);await rejected.text();assert.equal(rejected.status,401);assert.equal(builds,0);
    const accepted=await request('/mcp/fixture-31',true);await accepted.text();assert.equal(accepted.status,200);assert.equal(builds,1);
    const unknown=await request('/mcp/fixture-32',true);await unknown.text();assert.equal(unknown.status,404);assert.equal(builds,1);
  }finally{await gateway.close();}
});
test('HTTP route table rejects registrations beyond bounded capacity',async()=>{
  await assert.rejects(startHttpServer({host:'127.0.0.1',port:0,expectedToken:'a'.repeat(64),routes:new Set(),buildServer:()=>{throw Error('must not allocate')}}),/invalid_listener_config/);
  await assert.rejects(startHttpServer({host:'127.0.0.1',port:0,expectedToken:'a'.repeat(64),routes:new Set(Array.from({length:MAX_BACKEND_PROFILES+2},(_,i)=>`/mcp/fixture-${i}`)),buildServer:()=>{throw Error('must not allocate')}}),/invalid_listener_config/);
});
