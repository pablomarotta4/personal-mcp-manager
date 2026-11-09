// Credential-bearing policies arrive on stdin and never enter diagnostics.
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseConfig,readToken} from '../dist/policy.js';
import {readManifest} from '../dist/manifest.js';
import {policyDigest} from '../dist/runtime.js';

export async function validatePortablePolicies(policies,token,manifestReader) {
  if(!policies||Array.isArray(policies)||typeof policies!=='object'||Object.keys(policies).length<1||Object.keys(policies).length>64)throw Error('PORTABLE_POLICY_INVALID');
  const config=parseConfig({mcpServers:policies});
  for(const [id,policy] of config.servers){
    const manifest=await manifestReader(id);
    if(manifest.backendId!==id||manifest.provenance?.policyDigest!==policyDigest(policy,token))throw Error('PORTABLE_POLICY_MISMATCH');
  }
  return {status:'PASS',profiles:config.servers.size};
}

async function main(){
  if(process.argv.length!==4||process.argv[2]!=='--runtime')throw Error('PORTABLE_POLICY_INVALID');
  const runtime=process.argv[3];
  let size=0;const chunks=[];
  for await(const chunk of process.stdin){size+=chunk.length;if(size>4194304)throw Error('PORTABLE_POLICY_INVALID');chunks.push(chunk);}
  const policies=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const result=await validatePortablePolicies(policies,readToken(join(runtime,'token')),async id=>readManifest(join(runtime,'manifests',id+'.json')));
  process.stdout.write(JSON.stringify(result));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  main().catch(()=>{process.stderr.write('PORTABLE_POLICY_VERIFICATION_FAILED\n');process.exitCode=1;});
}
