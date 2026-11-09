import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createProxy } from '../dist/proxy.js';

test('discovery stays lazy; dispatch preserves result envelope and denies malformed arguments', async () => {
  let calls=0;
  const result={content:[{type:'text',text:'synthetic'}],structuredContent:{ok:false},isError:true,_meta:{synthetic:1}};
  const tool={name:'read',inputSchema:{type:'object'},outputSchema:{type:'object'},annotations:{readOnlyHint:true},_meta:{custom:'retained'}};
  const pool={catalog:()=>[{name:'demo',instruction:'Synthetic'}], tools:async()=>{calls++;return [tool]},
    call:async()=>{calls++;return result}};
  const server=createProxy(pool),client=new Client({name:'synthetic',version:'1'});
  const [a,b]=InMemoryTransport.createLinkedPair();
  try {
    await server.connect(a);await client.connect(b);
    const listing=await client.listTools();assert.equal(listing.tools.length,2);assert.equal(calls,0);
    const discovered=await client.callTool({name:'get_mcp_tools',arguments:{mcp:'demo'}});
    assert.deepEqual(JSON.parse(discovered.content[0].text).tools,[tool]);
    assert.deepEqual(await client.callTool({name:'call_mcp_tool',arguments:{mcp:'demo',toolName:'read',arguments:{}}}),result);
    const bad=await client.callTool({name:'call_mcp_tool',arguments:{mcp:'demo',toolName:'read',arguments:[]}});
    assert.equal(bad.isError,true);assert.equal(calls,2);assert.equal(server.activeCalls,0);
  } finally {await client.close();await server.close();}
});
test('internal exceptions cannot leak backend secrets into client errors',async()=>{
  const pool={catalog:()=>[],call:async()=>{throw Error('SYNTHETIC_CREDENTIAL')},tools:async()=>[]};
  const server=createProxy(pool),client=new Client({name:'synthetic',version:'1'});
  const [a,b]=InMemoryTransport.createLinkedPair();
  try{await server.connect(a);await client.connect(b);
    const result=await client.callTool({name:'call_mcp_tool',arguments:{mcp:'demo',toolName:'read',arguments:{}}});
    assert.equal(result.isError,true);assert(!JSON.stringify(result).includes('SYNTHETIC_CREDENTIAL'));
  }finally{await client.close();await server.close();}
});
