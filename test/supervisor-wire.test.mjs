import test from 'node:test';
import assert from 'node:assert/strict';
import {startFrame,stopFrame,StatusReader,nativeSupervisor} from '../dist/supervisor-wire.js';
const policy={command:'/synthetic/native',cwd:'/synthetic',args:['one'],env:{},shared:true,allowedTools:['read'],instruction:''};
test('native supervisor frame contains fixed headers and bounded binary fields',()=>{
 const frame=startFrame(policy,{TOKEN:'synthetic-secret'});assert.equal(frame.subarray(0,4).toString(),'PMMS');assert.equal(frame[4],1);assert.equal(frame[5],1);assert.equal(frame.readUInt32BE(8),frame.length-12);assert(frame.includes(Buffer.from('synthetic-secret')));assert.equal(stopFrame().toString('hex'),'504d4d530102000000000000');
 for(const invalid of [{...policy,command:'relative'},{...policy,args:['x\0y']},{...policy,args:['\ud800']}])assert.throws(()=>startFrame(invalid,{}),/supervisor_unavailable/);
 const unicode=startFrame({...policy,args:['é'.repeat(4096)]},{TOKEN:'é'.repeat(16384),['A'.repeat(5000)]:'ok'});assert(unicode.length>40000);
 assert.throws(()=>startFrame(policy,{'bad-key':'x'}),/supervisor_unavailable/);assert.throws(()=>startFrame(policy,{TOKEN:'x'.repeat(16385)}),/supervisor_unavailable/);
});
test('status parsing accepts every split and rejects duplicates malformed EOF and ready after stop',()=>{
 const ready=Buffer.from('504d4d5201010000','hex');
 for(let i=1;i<8;i++){const parser=new StatusReader();assert.equal(parser.push(ready.subarray(0,i)),false);assert.equal(parser.push(ready.subarray(i)),true);parser.end();assert.throws(()=>parser.push(ready),/supervisor_unavailable/);}
 for(const value of ['504d4d5201020000','504d4d5202010000','504d4d5201010100','0000000001010000','504d4d520101000000'])assert.throws(()=>new StatusReader().push(Buffer.from(value,'hex')),/supervisor_unavailable/);
 assert.throws(()=>new StatusReader().end(),/supervisor_unavailable/);assert.throws(()=>new StatusReader().push(ready,true),/supervisor_unavailable/);
});

test('fixed artifact verification refuses missing drifted symlink and unsafe binary before execution',async()=>{
 const {mkdtempSync,mkdirSync,writeFileSync,copyFileSync,chmodSync,symlinkSync,unlinkSync,rmSync,realpathSync}=await import('node:fs');
 const {tmpdir}=await import('node:os');const {join,resolve}=await import('node:path');const {pathToFileURL}=await import('node:url');const {createHash}=await import('node:crypto');
 const dir=realpathSync(mkdtempSync(join(tmpdir(),'supervisor-artifact-')));mkdirSync(join(dir,'dist'),{mode:0o700});mkdirSync(join(dir,'native'),{mode:0o700});writeFileSync(join(dir,'package.json'),'{"type":"module"}');
 for(const name of ['supervisor-wire.js','policy.js','mysql-context.js'])copyFileSync(resolve('dist',name),join(dir,'dist',name));
 const api=await import(pathToFileURL(join(dir,'dist/supervisor-wire.js')).href);
 const source=Buffer.from('synthetic source'),binary=Buffer.from('synthetic binary');const hash=b=>createHash('sha256').update(b).digest('hex');
 const manifest={version:1,binary:'personal-mcp-supervisor',binarySha256:hash(binary),sourceSha256:hash(source),compiler:{path:'/usr/bin/clang',version:'synthetic',target:'synthetic'},flags:['-std=c11','-O2','-Wall','-Wextra','-Werror','-fstack-protector-strong']};
 try{
  assert.throws(()=>api.nativeSupervisor(),/supervisor_unavailable/);
  writeFileSync(join(dir,'dist/native-supervisor.json'),JSON.stringify(manifest),{mode:0o600});writeFileSync(join(dir,'native/supervisor.c'),source,{mode:0o600});
  const path=join(dir,'dist/personal-mcp-supervisor');writeFileSync(path,binary,{mode:0o700});assert.equal(api.nativeSupervisor(),path);
  writeFileSync(path,'changed');assert.throws(()=>api.nativeSupervisor(),/supervisor_unavailable/);writeFileSync(path,binary);chmodSync(path,0o777);assert.throws(()=>api.nativeSupervisor(),/supervisor_unavailable/);
  unlinkSync(path);symlinkSync(join(dir,'native/supervisor.c'),path);assert.throws(()=>api.nativeSupervisor(),/supervisor_unavailable/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
