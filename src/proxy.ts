// src/proxy.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema,ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { Tool, CallToolResult } from "@modelcontextprotocol/sdk/types.js";
export interface ProxyPool {
  catalog(): {name:string;instruction?:string}[];
  tools(id:string):Promise<Tool[]>;
  call(id:string,tool:string,args:Record<string,unknown>):Promise<CallToolResult>;
}
import { SafeError } from "./policy.js";
import { packageJson } from "./version.js";
export type SessionServer=Server & {activeCalls:number};
const plain=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==="object"&&!Array.isArray(v);
export function createProxy(pool:ProxyPool):SessionServer{
  const server=Object.assign(new Server(packageJson,{capabilities:{tools:{}},
    instructions:"Discover reviewed backends with get_mcp_tools; call them using call_mcp_tool.\n"+
      pool.catalog().map(x=>`${x.name}: ${x.instruction}`).join("\n")}),{activeCalls:0});
  server.onerror=()=>{};
  server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:[
    {name:"get_mcp_tools",description:"Discover allowed tools for a configured backend.",
      inputSchema:{type:"object",properties:{mcp:{type:"string"},query:{type:"string"},limit:{type:"integer",minimum:1,maximum:128}},required:["mcp"],additionalProperties:false}},
    {name:"call_mcp_tool",description:"Invoke one explicitly allowed backend tool.",
      annotations:{readOnlyHint:false,destructiveHint:true},
      inputSchema:{type:"object",properties:{mcp:{type:"string"},toolName:{type:"string"},arguments:{type:"object"}},required:["mcp","toolName","arguments"],additionalProperties:false}}
  ]}));
  server.setRequestHandler(CallToolRequestSchema,async request=>{
    server.activeCalls++;
    try{
      const a=request.params.arguments;
      if(!plain(a)||typeof a.mcp!=="string")throw new SafeError("invalid_request");
      if(request.params.name==="get_mcp_tools"){
        if(Object.keys(a).some(k=>!["mcp","query","limit"].includes(k))
          ||(a.query!==undefined&&typeof a.query!=="string")
          ||(a.limit!==undefined&&(!Number.isInteger(a.limit)||Number(a.limit)<1||Number(a.limit)>128)))
          throw new SafeError("invalid_request");
        let tools=await pool.tools(a.mcp);
        if(a.query){const q=String(a.query).toLowerCase();tools=tools.filter(t=>(t.name+" "+(t.description??"")).toLowerCase().includes(q));}
        return {content:[{type:"text",text:JSON.stringify({mcp:a.mcp,tools:tools.slice(0,Number(a.limit??50))})}]};
      }
      if(request.params.name!=="call_mcp_tool"||typeof a.toolName!=="string"||!plain(a.arguments)
        ||Object.keys(a).some(k=>!["mcp","toolName","arguments"].includes(k)))throw new SafeError("invalid_request");
      return await pool.call(a.mcp,a.toolName,a.arguments);
    }catch(e){return {isError:true,content:[{type:"text",text:e instanceof SafeError?e.code:"backend_unavailable"}]};}
    finally{server.activeCalls--;}
  });
  return server;
}
