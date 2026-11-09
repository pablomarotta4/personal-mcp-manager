import {mkdtempSync,readFileSync,rmSync,mkdirSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
export const delay=ms=>new Promise(r=>setTimeout(r,ms));
export const alive=pid=>{try{process.kill(pid,0);return true}catch{return false}};
export async function until(fn,ms=5000){const end=Date.now()+ms;while(!fn()){if(Date.now()>end)throw Error('condition_timeout');await delay(20)}}
export function fixture(idleTimeoutMs=100){
  const dir=realpathSync(mkdtempSync(join(tmpdir(),'personal-mcp-test-'))),ledger=join(dir,'events'),ownershipDir=join(dir,'ownership');
  mkdirSync(ownershipDir,{mode:0o700});
  const backend={command:process.execPath,args:[resolve('test/fixtures/backend.mjs')],env:{FIXTURE_LEDGER:ledger},cwd:process.cwd(),shared:true,allowedTools:['read'],instruction:'Synthetic read'};
  return {dir,ledger,ownershipDir,backend,config:{mcpServers:{demo:backend},idleTimeoutMs},events(){try{return readFileSync(ledger,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse)}catch(e){if(e.code==='ENOENT')return [];throw e}},cleanup(){rmSync(dir,{recursive:true,force:true})}};
}
export async function httpClient(url,token){const c=new Client({name:'test',version:'1'});await c.connect(new StreamableHTTPClientTransport(new URL(url),{requestInit:{headers:{Authorization:`Bearer ${token}`}}}));return c}
