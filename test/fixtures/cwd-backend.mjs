import {appendFileSync,readFileSync} from 'node:fs';
appendFileSync(process.env.FIXTURE_CWD_LEDGER,JSON.stringify({pid:process.pid,cwd:process.cwd(),marker:readFileSync('marker','utf8')})+'\n');
await import('./backend.mjs');
