import test from 'node:test';
import assert from 'node:assert/strict';
import {validatePortablePolicies} from '../scripts/portable-verify-config.mjs';
import {parseConfig} from '../dist/policy.js';
import {decodeMysqlContext} from '../dist/mysql-context.js';

test('public policies refuse an unshipped custom client environment',()=>{
  const kind='custom-db',digest='a'.repeat(64),root='/synthetic/'+digest;
  const policy={command:root+'/python/bin/python3.14',
    args:['-I','-S','-B',root+'/manager/'+kind+'-entry.py'],
    env:{},cwd:'/',shared:true,scope:'session',closure:{root,digest},
    clientEnvironment:kind,allowedTools:['mysql_query','list_schemas','list_tables','list_columns']};
  assert.throws(()=>parseConfig({mcpServers:{['mysql-'+kind+'-prd']:policy}}),/invalid_config/);
});

test('public MySQL context cannot enable an unshipped credential family',()=>{
  assert.throws(()=>decodeMysqlContext({environment:{AWS_PROFILE:'synthetic'}},'custom-db'),/mysql_context_invalid/);
});

test('a persisted manifest policy mismatch is refused before runtime launch', async () => {
  const policies={fixture:{command:'/synthetic/executable',args:[],env:{SECRET:'synthetic-secret'},cwd:'/',shared:true,allowedTools:['read'],instruction:'Synthetic'}};
  const manifest={backendId:'fixture',provenance:{policyDigest:'0'.repeat(64)}};
  await assert.rejects(()=>validatePortablePolicies(policies,'a'.repeat(64),async()=>manifest),/PORTABLE_POLICY_MISMATCH/);
});

test('aliased Loki keeps its explicitly reviewed family restrictions',()=>{
  const digest='a'.repeat(64),root='/synthetic/'+digest,id='loki-prd-0123456789ab';
  const policy={reviewedProfile:'loki-prd',command:root+'/runtime/bin/node',args:['--no-addons','--no-global-search-paths',root+'/app/node_modules/simple-loki-mcp/dist/src/index.js'],
    env:{HOME:'/synthetic',LOKI_ADDR:'https://synthetic.invalid',LOKI_DATASOURCE_ID:'synthetic',LOKI_BEARER_TOKEN:'synthetic-token'},cwd:'/',shared:true,scope:'session',cwdMode:'client',closure:{root,digest},
    allowedTools:['query_loki','get_label_values','get_labels'],instruction:'Reviewed Loki'};
  const parsed=parseConfig({mcpServers:{[id]:policy}}).servers.get(id);
  assert.equal(parsed.reviewedProfile,'loki-prd');
  assert.throws(()=>parseConfig({mcpServers:{[id]:{...policy,allowedTools:['arbitrary_write']}}}),/invalid_config/);
  assert.throws(()=>parseConfig({mcpServers:{[id]:{...policy,reviewedProfile:'langfuse-traces'}}}),/invalid_config/);
  assert.throws(()=>parseConfig({mcpServers:{unrelated:policy}}),/invalid_config/);
});

test('Langfuse aliases bind the reviewed wrapper profile and distinct route data root',()=>{
  const digest='a'.repeat(64),root='/synthetic/'+digest,profile='langfuse-traces',id=profile+'-0123456789ab';
  const policy={reviewedProfile:profile,command:root+'/python/bin/python3.13',
    args:['-I','-S','-B',root+'/manager/langfuse-entry.py','--manager-data-root','/synthetic/data/'+id,'--manager-profile',profile,'--'],
    env:{LANGFUSE_HOST:'https://synthetic.invalid'},cwd:'/',shared:true,scope:'session',cwdMode:'client',closure:{root,digest},allowedTools:['fetch_traces'],instruction:'Reviewed Langfuse'};
  const parsed=parseConfig({mcpServers:{[id]:policy}}).servers.get(id);
  assert.equal(parsed.args[5],'/synthetic/data/'+id);
  assert.equal(parsed.args[7],profile);
  const wrong={...policy,args:[...policy.args]};wrong.args[7]='langfuse-api-dev';
  assert.throws(()=>parseConfig({mcpServers:{[id]:wrong}}),/invalid_config/);
});

test('empty portable policy set is not an installed runtime', async () => {
  await assert.rejects(()=>validatePortablePolicies({},'a'.repeat(64),async()=>{}),/PORTABLE_POLICY_INVALID/);
});
