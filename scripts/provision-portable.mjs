// Explicit installer probe. Backend credentials are stdin-only and never logged.
import {mkdirSync,lstatSync,readFileSync,readdirSync,writeFileSync,realpathSync} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {pathToFileURL} from 'node:url';
import {BackendPool} from '../dist/pool.js';
import {ClosureVerifier} from '../dist/closure-verifier.js';
import {parseConfig,readToken} from '../dist/policy.js';
import {executableDigest,policyDigest} from '../dist/runtime.js';
import {fingerprintDescription,mysqlInvariantDescription,parseManifest} from '../dist/manifest.js';

function privateDirectory(path){
  const stat=lstatSync(path);
  if(!isAbsolute(path)||!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o7777)!==0o700||realpathSync(path)!==path)throw Error('PORTABLE_PROVISION_PATH_INVALID');
}

export function portableExpectedCatalog(artifact,policy){
  if(artifact.family!=='langfuse'||!policy.args.includes('--read-only'))return artifact.catalog;
  const catalog=structuredClone(artifact.catalog);
  catalog.tools=catalog.tools.filter(tool=>!['create_','update_','delete_'].some(prefix=>tool.name.startsWith(prefix)));
  return catalog;
}

export async function provisionPortable(raw,stage){
  privateDirectory(stage);privateDirectory(join(stage,'manifests'));
  const input=structuredClone(raw),{routeId:id,artifact}=input;
  if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(id)||!artifact||!artifact.catalog)throw Error('PORTABLE_PROVISION_INPUT_INVALID');
  const template=parseConfig({mcpServers:{[id]:input.policy}}).servers.get(id);
  const config=parseConfig({mcpServers:{[id]:input.probePolicy}}),launch=config.servers.get(id);
  if(template.command!==launch.command||JSON.stringify(template.args)!==JSON.stringify(launch.args))throw Error('PORTABLE_PROVISION_INPUT_INVALID');
  const ownership=join(stage,'ownership');
  try{mkdirSync(ownership,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw error;}
  privateDirectory(ownership);
  if(readdirSync(ownership).length)throw Error('PORTABLE_OWNERSHIP_NOT_EMPTY');
  const verifier=template.closure?new ClosureVerifier({python:input.hostPython}):undefined;
  const check=async()=>{
    if(template.closure)await verifier.verify(template.closure);
    if(await executableDigest(template.command)!==artifact.artifactSha256)throw Error('PORTABLE_ARTIFACT_CHANGED');
  };
  let pool,manifest;
  try{
    await check();
    pool=new BackendPool(config,{ownershipDir:ownership,oneGeneration:true,startupTimeoutMs:launch.startupTimeoutMs??30000,
      callTimeoutMs:launch.toolTimeoutMs??60000,discoveryTimeoutMs:30000,beforeStart:check});
    const description=await pool.describe(id);
    const mysql=template.catalogMode==='mysql-session';
    const actual=mysql?mysqlInvariantDescription(description):description;
    const expected=mysql?mysqlInvariantDescription(artifact.catalog):portableExpectedCatalog(artifact,template);
    if(fingerprintDescription(artifact.catalog)!==artifact.catalogFingerprint||fingerprintDescription(actual)!==fingerprintDescription(expected))throw Error('PORTABLE_CATALOG_MISMATCH');
    if(mysql){
      const readOnly=!['ALLOW_DDL_OPERATION','ALLOW_DELETE_OPERATION','ALLOW_INSERT_OPERATION','ALLOW_UPDATE_OPERATION'].some(key=>launch.env[key]==='true');
      const annotations=description.tools[0]?.annotations;
      if(description.serverInfo.version!==(launch.env.npm_package_version||'1.0.0')||annotations?.readOnlyHint!==readOnly||annotations?.idempotentHint!==readOnly||annotations?.destructiveHint!==!readOnly)throw Error('PORTABLE_MYSQL_CONTEXT_MISMATCH');
    }
    await check();
    manifest=parseManifest({version:1,backendId:id,allowedTools:template.allowedTools,description,
      fingerprint:fingerprintDescription(description),provenance:{sourceIdentity:artifact.sourceIdentity,
        artifactSha256:artifact.artifactSha256,policyDigest:policyDigest(template,readToken(join(stage,'token'))),reviewedAt:new Date().toISOString(),
        ...(template.closure?{closureDigest:artifact.closureDigest,dependencyReportSha256:artifact.dependencyReportSha256}:{}),
        ...(mysql?{catalogMode:'mysql-session'}:{}),
        ...(description.capabilities.logging?{logging:'no-backend-notifications'}:{})}});
  }finally{
    try{await pool?.shutdown();}finally{await verifier?.shutdown();}
  }
  if(!pool||pool.snapshot().live!==0||readdirSync(ownership).length!==0)throw Error('PORTABLE_CLEANUP_UNPROVEN');
  writeFileSync(join(stage,'manifests',id+'.json'),JSON.stringify(manifest),{flag:'wx',mode:0o600});
  return {allowedTools:manifest.allowedTools,artifactSha256:artifact.artifactSha256,fingerprint:manifest.fingerprint,
    closureDigest:artifact.closureDigest,dependencyReportSha256:artifact.dependencyReportSha256};
}

async function main(){
  if(process.argv.length!==4||process.argv[2]!=='--stage')throw Error('PORTABLE_PROVISION_INPUT_INVALID');
  let size=0;const chunks=[];
  for await(const chunk of process.stdin){size+=chunk.length;if(size>4194304)throw Error('PORTABLE_PROVISION_INPUT_INVALID');chunks.push(chunk);}
  process.stdout.write(JSON.stringify(await provisionPortable(JSON.parse(Buffer.concat(chunks).toString('utf8')),process.argv[3])));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  main().catch(()=>{process.stderr.write('PORTABLE_PROVISION_FAILED\n');process.exitCode=1;});
}
