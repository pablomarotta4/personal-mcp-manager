import {createDiagnosticWriter} from './backend-diagnostics.js';
// src/index.ts
import { dirname, join } from "node:path";
import { fstatSync, realpathSync } from "node:fs";
import { Socket } from "node:net";
import { parseConfig,readToken,SafeError } from "./policy.js";
import { createRuntime } from "./runtime.js";
import { startHttpServer } from "./server.js";

async function main(){
  const args=process.argv.slice(2);
  let diagnosticArgument:string|undefined;
  if(args.at(-2)==="--backend-diagnostic-fd"){diagnosticArgument=args.pop();args.pop();}
  if(![5,7,9,11].includes(args.length)||args[0]!=="--config-stdin"||args[1]!=="--token-file"||args[3]!=="--port"
      ||(args.length>=7&&args[5]!=="--manifest-dir")
      ||(args.length>=9&&args[7]!=="--owner-channel-fd")
      ||(args.length===11&&args[9]!=="--closure-verifier-python"))
    throw new SafeError("invalid_arguments");
  const port=Number(args[4]);
  if(!Number.isInteger(port)||port<0||port>65535)throw new SafeError("invalid_arguments");
  const token=readToken(args[2]);let size=0;const chunks:Buffer[]=[];
  for await(const chunk of process.stdin){
    const b=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);size+=b.length;
    if(size>1024*1024)throw new SafeError("invalid_config");chunks.push(b);
  }
  let raw:unknown;try{raw=JSON.parse(Buffer.concat(chunks).toString("utf8"));}
  catch{throw new SafeError("invalid_config");}
  let diagnosticWriter:ReturnType<typeof createDiagnosticWriter>|undefined;
  let channel:Socket|undefined;
  let runtime:Awaited<ReturnType<typeof createRuntime>>|undefined;
  let http:Awaited<ReturnType<typeof startHttpServer>>|undefined;
  let starting=true,stopping=false,closing:Promise<void>|undefined;
  const cleanup=()=>closing??=(async()=>{
    try{if(http)await http.close();else await runtime?.pool.shutdown();}
    catch{process.exitCode=1;}
    finally{try{runtime?.owners?.close();channel?.destroy();}finally{diagnosticWriter?.close();}}
  })();
  const stop=()=>{stopping=true;if(!starting)void cleanup();};
  // Keep listeners installed while owned backend cleanup drains; a second
  // terminal/parent signal must not restore Node's immediate-exit behavior.
  process.on("SIGINT",stop);process.on("SIGTERM",stop);
  try{
    if(args.length>=9){
      const fd=Number(args[8]);
      if(!/^[1-9][0-9]*$/.test(args[8])||!Number.isInteger(fd)||fd<3||fd>1024||!fstatSync(fd).isSocket())
        throw new SafeError("invalid_arguments");
      channel=new Socket({fd,readable:true,writable:true});
      channel.on("error",()=>{});
    }
    if(diagnosticArgument!==undefined){
      const fd=Number(diagnosticArgument);
      if(!channel||port===18765||fd===Number(args[8])||! /^[1-9][0-9]*$/.test(diagnosticArgument))throw new SafeError("invalid_arguments");
      diagnosticWriter=createDiagnosticWriter(fd);
    }
    runtime=await createRuntime(parseConfig(raw), {token,
      ...(diagnosticWriter?{diagnostic:diagnosticWriter.sink}:{}),
      ownershipDir:join(realpathSync(dirname(args[2])),"ownership"),
      ...(args.length>=7?{manifestDir:args[6]}:{}),...(channel?{ownerChannel:channel}:{}),
      ...(args.length===11?{closureVerifierPython:args[10]}:{})});
    const activeRuntime=runtime;
    runtime.owners?.onFailure(()=>{process.exitCode=1;stop();});
    http=await startHttpServer({host:"127.0.0.1",port,expectedToken:token,
      ...runtime.httpOptions,getActive:()=>activeRuntime.pool.snapshot().active,
      getBackendCounts:()=>{const value=activeRuntime.pool.snapshot();return {starts:value.starts,live:value.live};},
      onShutdown:()=>activeRuntime.pool.shutdown()});
    starting=false;
    if(stopping||runtime.owners?.isHealthy===false){await cleanup();return;}
    process.stdout.write(JSON.stringify({event:"listening",port:http.getPort()})+"\n");
  }catch(error){starting=false;await cleanup();throw error;}
}
void main().catch(()=>{
  process.stderr.write(JSON.stringify({event:"startup_failed"})+"\n");process.exitCode=1;
});
