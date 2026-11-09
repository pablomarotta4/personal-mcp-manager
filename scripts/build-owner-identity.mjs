// Explicit build only; owner helper/watcher never invokes a compiler.
import {spawnSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {chmodSync,lstatSync,mkdirSync,readFileSync,realpathSync,renameSync,rmSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const dir=join(root,'dist'),source=join(root,'native/owner-identity.c'),compiler='/usr/bin/clang';
const flags=['-std=c11','-O2','-Wall','-Wextra','-Werror','-fstack-protector-strong','-dynamiclib','-lproc'];
if(process.argv.length!==2)throw Error('invalid_arguments');
function safeDirectory(path){const s=lstatSync(path);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o022)||realpathSync(path)!==path)throw Error('unsafe_owner_build_directory');}
safeDirectory(root.slice(0,-1));safeDirectory(join(root,'native'));
const sourceStat=lstatSync(source);if(!sourceStat.isFile()||sourceStat.isSymbolicLink()||sourceStat.uid!==process.getuid()||(sourceStat.mode&0o022)||realpathSync(source)!==source)throw Error('unsafe_owner_source');
mkdirSync(dir,{recursive:true,mode:0o700});safeDirectory(dir);
const version=spawnSync(compiler,['--version'],{encoding:'utf8',timeout:10000});
if(version.status!==0)throw Error('owner_compiler_unavailable');
const metadata={path:compiler,version:version.stdout.split('\n')[0],target:version.stdout.split('\n').find(s=>s.startsWith('Target: '))?.slice(8)??''};
if(!metadata.target)throw Error('owner_compiler_target_missing');
const name='personal-mcp-owner-identity.dylib',temporary=join(dir,`.owner-build-${randomUUID()}`);mkdirSync(temporary,{mode:0o700});
try{
 const output=join(temporary,name),snapshot=join(temporary,'owner-identity.c'),sourceBytes=readFileSync(source);
 writeFileSync(snapshot,sourceBytes,{flag:'wx',mode:0o600});
 const result=spawnSync(compiler,[...flags,snapshot,'-o',output],{encoding:'utf8',timeout:30000});
 if(result.status!==0)throw Error('owner_identity_build_failed');
 chmodSync(output,0o700);const hash=b=>createHash('sha256').update(b).digest('hex');
 if(hash(readFileSync(source))!==hash(sourceBytes))throw Error('owner_source_changed_during_build');
 const manifest={version:1,binary:name,binarySha256:hash(readFileSync(output)),sourceSha256:hash(sourceBytes),compiler:metadata,flags};
 const manifestFile=join(temporary,'owner-identity.json');writeFileSync(manifestFile,JSON.stringify(manifest,null,2)+'\n',{flag:'wx',mode:0o600});
 renameSync(output,join(dir,name));renameSync(manifestFile,join(dir,'owner-identity.json'));
 console.log('Built personal-mcp-owner-identity.dylib');
}finally{rmSync(temporary,{recursive:true,force:true});}
