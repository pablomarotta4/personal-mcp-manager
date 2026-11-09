import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
const mode=process.argv[2];
if(mode==='echo'){process.stdin.pipe(process.stdout);process.stdin.on('end',()=>setInterval(()=>{},1000));}
else if(mode==='tree'||mode==='exit-first'){for(const signal of ['SIGTERM','SIGINT','SIGHUP'])process.on(signal,()=>{});const child=spawn(process.execPath,[import.meta.filename,'resistant',process.argv[3]],{stdio:'ignore'});if(mode==='exit-first')setTimeout(()=>process.exit(0),150);else setInterval(()=>{},1000);void child;}
else if(mode==='resistant'){for(const signal of ['SIGTERM','SIGINT','SIGHUP'])process.on(signal,()=>{});writeFileSync(process.argv[3],String(process.pid));setInterval(()=>{},1000);}
else if(mode==='flood'){for(const signal of ['SIGTERM','SIGINT','SIGHUP'])process.on(signal,()=>{});const b=Buffer.alloc(65536);function pump(){while(process.stdout.write(b)){}process.stdout.once('drain',pump)}pump();}
else if(mode==='block-input'){for(const signal of ['SIGTERM','SIGINT','SIGHUP'])process.on(signal,()=>{});setInterval(()=>{},1000);}
