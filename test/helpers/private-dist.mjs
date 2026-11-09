import {lstatSync,realpathSync} from 'node:fs';
import {isAbsolute,relative,resolve,sep} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const configuredRoot=process.env.PERSONAL_MCP_TEST_DIST;
const fallbackRoot=resolve(fileURLToPath(new URL('../../dist/',import.meta.url)));

function privateOutputRoot(){
 const candidate=configuredRoot??fallbackRoot;
 if(!isAbsolute(candidate)||resolve(candidate)!==candidate)throw Error('private_dist_root_invalid');
 const info=lstatSync(candidate);
 if(!info.isDirectory()||info.isSymbolicLink())throw Error('private_dist_root_invalid');
 const canonical=realpathSync(candidate);
 if(canonical!==candidate)throw Error('private_dist_root_invalid');
 if(configuredRoot!==undefined&&(info.uid!==process.getuid?.()||(info.mode&0o077)!==0))throw Error('private_dist_permissions_invalid');
 return canonical;
}

export async function loadDist(relativePath){
 if(typeof relativePath!=='string'||!relativePath||isAbsolute(relativePath))throw Error('private_dist_path_invalid');
 const root=privateOutputRoot();
 const candidate=resolve(root,relativePath);
 const within=relative(root,candidate);
 if(!within||within==='..'||within.startsWith('..'+sep)||isAbsolute(within))throw Error('private_dist_path_invalid');
 const info=lstatSync(candidate);
 if(!info.isFile()||info.isSymbolicLink())throw Error('private_dist_module_invalid');
 const canonical=realpathSync(candidate);
 if(canonical!==candidate)throw Error('private_dist_module_invalid');
 return import(pathToFileURL(canonical).href);
}
