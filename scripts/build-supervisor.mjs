// Explicit build only; tool use never invokes a compiler.
import {spawnSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {chmodSync,lstatSync,mkdirSync,readFileSync,realpathSync,renameSync,rmSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const dir=join(root,'dist'),source=join(root,'native/supervisor.c');
const compiler='/usr/bin/clang';
const sanitizer=process.argv.includes('--sanitize');
const flags=['-std=c11','-O2','-Wall','-Wextra','-Werror','-fstack-protector-strong',...(sanitizer?['-fsanitize=address,undefined','-fno-omit-frame-pointer']:[])];
function safeDirectory(path){const s=lstatSync(path);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o022)||realpathSync(path)!==path)throw Error('unsafe native build directory');}
safeDirectory(root.slice(0,-1));safeDirectory(join(root,'native'));
const sourceStat=lstatSync(source);if(!sourceStat.isFile()||sourceStat.isSymbolicLink()||sourceStat.uid!==process.getuid()||(sourceStat.mode&0o022)||realpathSync(source)!==source)throw Error('unsafe native source');
mkdirSync(dir,{recursive:true,mode:0o700});safeDirectory(dir);
const version=spawnSync(compiler,['--version'],{encoding:'utf8'});if(version.status!==0)throw Error('native compiler unavailable');
const metadata={path:compiler,version:version.stdout.split('\n')[0],target:version.stdout.split('\n').find(s=>s.startsWith('Target: '))?.slice(8)??''};
const name=sanitizer?'personal-mcp-supervisor-sanitized':'personal-mcp-supervisor';
const tmpDir=join(dir,`.native-build-${randomUUID()}`);mkdirSync(tmpDir,{mode:0o700});
try{
  const output=join(tmpDir,name),snapshot=join(tmpDir,'supervisor.c');
  const sourceBytes=readFileSync(source);writeFileSync(snapshot,sourceBytes,{flag:'wx',mode:0o600});
  const result=spawnSync(compiler,[...flags,snapshot,'-o',output],{encoding:'utf8'});
  if(result.status!==0)throw Error(`native build failed\n${result.stderr}`);
  chmodSync(output,0o700);
  const sha=b=>createHash('sha256').update(b).digest('hex');
  if(sha(readFileSync(source))!==sha(sourceBytes))throw Error('native source changed during build');
  const manifest={version:1,binary:name,binarySha256:sha(readFileSync(output)),sourceSha256:sha(sourceBytes),compiler:metadata,flags};
  const manifestFile=join(tmpDir,'native-supervisor.json');writeFileSync(manifestFile,JSON.stringify(manifest,null,2)+'\n',{flag:'wx',mode:0o600});
  renameSync(output,join(dir,name));renameSync(manifestFile,join(dir,sanitizer?'native-supervisor-sanitized.json':'native-supervisor.json'));
  console.log(`Built ${name} (${metadata.target}; ${manifest.binarySha256})`);
}finally{rmSync(tmpDir,{recursive:true,force:true});}
