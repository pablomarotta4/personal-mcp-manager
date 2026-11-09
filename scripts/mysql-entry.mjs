// Effective dotenv inputs were resolved and HMAC-bound by signed-owner admission.
// Disable the second filesystem read, which would otherwise race that admission.
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const require=createRequire(import.meta.url);
const dotenv=require('../app/node_modules/dotenv/lib/main.js');
dotenv.config=()=>({parsed:{}});
const entry=new URL('../app/node_modules/@benborla29/mcp-server-mysql/dist/index.js',import.meta.url);
process.argv[1]=fileURLToPath(entry);
await import(entry.href);
