// Synthetic values only. No configuration files or network access.
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {CallToolRequestSchema,ListToolsRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {relevantEnvironmentKeys} from '../../scripts/verify-service.mjs';
import {appendFileSync} from 'node:fs';
appendFileSync(process.env.SOURCE_ENV_LEDGER,JSON.stringify({pid:process.pid})+'\n',{mode:0o600});
const tool={name:'inspect_source_env',description:'Read synthetic fixture launch inputs',inputSchema:{type:'object',properties:{keys:{type:'array',items:{type:'string',enum:relevantEnvironmentKeys},uniqueItems:true,maxItems:relevantEnvironmentKeys.length}},additionalProperties:false},annotations:{readOnlyHint:true,destructiveHint:false}};
const server=new Server({name:'source-env-fixture',version:'1'},{capabilities:{tools:{}}});
server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:[tool]}));
server.setRequestHandler(CallToolRequestSchema,async request=>{
 if(request.params.name!==tool.name)throw Error('unknown_fixture_tool');
 const args=request.params.arguments??{};
 if(Object.keys(args).some(key=>key!=='keys')||!Array.isArray(args.keys??[])||(args.keys??[]).some(key=>!relevantEnvironmentKeys.includes(key))||new Set(args.keys??[]).size!==(args.keys??[]).length)throw Error('fixture_keys_invalid');
 const value={pid:process.pid,cwd:process.cwd(),env:Object.fromEntries(['HOME','PATH','SOURCE_ENV_SENTINEL',...(args.keys??[])].map(key=>[key,process.env[key]??null]))};
 return {content:[{type:'text',text:JSON.stringify(value)}],structuredContent:value};
});
await server.connect(new StdioServerTransport());
