import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {CallToolRequestSchema,ListToolsRequestSchema,ListResourcesRequestSchema,ListResourceTemplatesRequestSchema,ListPromptsRequestSchema,ReadResourceRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {appendFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
const ledger=e=>{if(process.env.FIXTURE_LEDGER)appendFileSync(process.env.FIXTURE_LEDGER,JSON.stringify(e)+'\n')};
ledger({event:'start',pid:process.pid});
if(process.env.FIXTURE_DESCENDANT==='1'){
 const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});setInterval(()=>{},1000);if(process.env.LIFETIME)setTimeout(()=>process.exit(),Number(process.env.LIFETIME))"],{stdio:'ignore',env:{LIFETIME:process.env.FIXTURE_DESCENDANT_LIFETIME??''}});
 ledger({event:'descendant',pid:child.pid});
}
if(process.env.FIXTURE_START_DELAY)await new Promise(r=>setTimeout(r,Number(process.env.FIXTURE_START_DELAY)));
if(process.env.FIXTURE_NOISY==='1'){process.stdout.write('X'.repeat(2*1024*1024));setInterval(()=>{},1000);}
else{
const extended=process.env.FIXTURE_CAPABILITIES==='resources';
const capabilities=extended?{tools:{listChanged:true},resources:{listChanged:true},prompts:{listChanged:true},...(process.env.FIXTURE_LOGGING==='1'?{logging:{}}:{})}:{tools:{}};
const server=new Server({name:'synthetic',version:'1'},{capabilities,instructions:'Synthetic backend instructions'});
const read={name:'read',description:'Synthetic read',inputSchema:{type:'object',properties:{delayMs:{type:'number'},error:{type:'boolean'}}},annotations:{readOnlyHint:true,destructiveHint:false},outputSchema:{type:'object',properties:{pid:{type:'integer'},ok:{type:'boolean'}},required:['pid','ok']},_meta:{synthetic:true}};
server.setRequestHandler(ListToolsRequestSchema,async req=>req.params?.cursor==='page2'?{tools:[{...read,name:'write'}]}:{tools:[read],nextCursor:'page2'});
server.setRequestHandler(CallToolRequestSchema,async (req,extra)=>{
 ledger({event:'call',pid:process.pid});
 if(req.params.arguments?.notifyDelayMs)await new Promise(r=>setTimeout(r,Math.min(Number(req.params.arguments.notifyDelayMs),1000)));
 if(extended&&['tools','resources','prompts'].includes(req.params.arguments?.notify))await extra.sendNotification({method:`notifications/${req.params.arguments.notify}/list_changed`});
 if(extended&&req.params.arguments?.notify==='logging')await extra.sendNotification({method:'notifications/message',params:{level:'info',data:'synthetic_private_log_body'}});
 if(req.params.arguments?.exit===true){process.exit(3)}
 if(typeof req.params.arguments?.protocolError==='number')throw Object.assign(new Error('synthetic_invalid_params'),{code:req.params.arguments.protocolError,data:{field:'synthetic'}});
 if(req.params.arguments?.progress===true&&req.params._meta?.progressToken!==undefined)await extra.sendNotification({method:'notifications/progress',params:{progressToken:req.params._meta.progressToken,progress:1,total:2}});
 await new Promise(r=>setTimeout(r,Math.min(Number(req.params.arguments?.delayMs??0),10000)));
 const value={pid:process.pid,ok:req.params.arguments?.error!==true};
 ledger({event:'complete',pid:process.pid});
 return {content:[{type:'text',text:JSON.stringify(value)}],structuredContent:value,...(value.ok?{}:{isError:true}),_meta:{synthetic:true}};
});
if(extended){
 const resources=['text','blob','slow','parallel','error'].map(name=>({uri:`synthetic://${name}`,name,mimeType:name==='blob'?'application/octet-stream':'text/plain',_meta:{synthetic:true}}));
 server.setRequestHandler(ListResourcesRequestSchema,async req=>req.params?.cursor==='page2'?{resources:resources.slice(2)}:{resources:resources.slice(0,2),nextCursor:'page2'});
 server.setRequestHandler(ListResourceTemplatesRequestSchema,async()=>({resourceTemplates:[]}));
 server.setRequestHandler(ListPromptsRequestSchema,async()=>({prompts:[]}));
 server.setRequestHandler(ReadResourceRequestSchema,async req=>{
  ledger({event:'resource',pid:process.pid});
  const uri=req.params.uri;
  if(uri==='synthetic://error')throw Object.assign(new Error('synthetic_resource_error'),{code:-32602,data:{field:'uri'}});
  if(uri==='synthetic://slow'||uri==='synthetic://parallel')await new Promise(r=>setTimeout(r,uri.endsWith('slow')?400:120));
  return {contents:[uri==='synthetic://blob'?{uri,mimeType:'application/octet-stream',blob:'AAEC'}:{uri,mimeType:'text/plain',text:'synthetic text'}],_meta:{synthetic:true}};
 });
}
await server.connect(new StdioServerTransport());
}
