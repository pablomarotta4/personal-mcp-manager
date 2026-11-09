import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {BackendPool} from '../dist/pool.js';
import {parseConfig} from '../dist/policy.js';
import {fingerprintDescription} from '../dist/manifest.js';
import {executableDigest,policyDigest} from '../dist/runtime.js';
import {fixture} from './helpers.mjs';
import {provisionPortable,portableExpectedCatalog} from '../scripts/provision-portable.mjs';

test('Langfuse read-only expectation excludes native write tools without mutating the admitted full catalog',()=>{
 const artifact={family:'langfuse',catalog:{tools:['fetch_traces','create_dataset','update_prompt_labels','delete_dataset_run'].map(name=>({name})),resources:[]}};
 assert.deepEqual(portableExpectedCatalog(artifact,{args:['--','--read-only']}).tools.map(tool=>tool.name),['fetch_traces']);
 assert.equal(artifact.catalog.tools.length,4);
 assert.equal(portableExpectedCatalog(artifact,{args:['--','--no-log-to-console']}),artifact.catalog);
});

test('portable provisioning binds full native metadata and proves owned cleanup before publication',async()=>{
  const f=fixture(),id='demo';f.backend.allowedTools=['read','write'];let initial;
  try{
    const config=parseConfig(f.config);initial=new BackendPool(config,{ownershipDir:f.ownershipDir});
    const catalog=await initial.describe(id);await initial.shutdown();
    mkdirSync(join(f.dir,'manifests'),{mode:0o700});writeFileSync(join(f.dir,'token'),'a'.repeat(64),{mode:0o600});
    const artifact={family:'grafana',sourceIdentity:'synthetic:1',artifactSha256:await executableDigest(process.execPath),
      catalog,catalogFingerprint:fingerprintDescription(catalog),closureDigest:'b'.repeat(64),dependencyReportSha256:'c'.repeat(64)};
    const out=await provisionPortable({routeId:id,policy:f.backend,probePolicy:f.backend,artifact,hostPython:'/unused'},f.dir);
    const saved=JSON.parse(readFileSync(join(f.dir,'manifests',id+'.json'),'utf8'));
    assert.deepEqual(saved.description,catalog);
    assert.equal(saved.provenance.policyDigest,policyDigest(config.servers.get(id),'a'.repeat(64)));
    assert.equal(out.fingerprint,fingerprintDescription(catalog));
    assert.equal(f.events().filter(e=>e.event==='tool').length,0);
  }finally{await initial?.shutdown();f.cleanup();}
});
