// src/policy.ts
import { constants, closeSync, fstatSync, openSync, readFileSync, lstatSync } from "node:fs";
import { isAbsolute, dirname, basename, normalize, join } from "node:path";
import { MYSQL_CONTEXT_KEYS } from "./mysql-context.js";

export class SafeError extends Error {
  constructor(readonly code: string) { super(code); }
}
export interface ClosureIdentity { root: string; digest: string }
export interface BackendPolicy {
  command: string; args: string[]; env: Record<string,string>; cwd: string;
  shared: true; scope?: "session"; cwdMode?: "client"; allowedTools: string[]; instruction: string;
  closure?: ClosureIdentity; catalogMode?: "mysql-session";
  startupTimeoutMs?: number; toolTimeoutMs?: number;
  reviewedProfile?: string;
}
export interface Config { servers: Map<string,BackendPolicy>; idleTimeoutMs: number }
export const MAX_BACKEND_PROFILES = 64;
const invalid = (): never => { throw new SafeError("invalid_config"); };
const object = (x: unknown): Record<string,unknown> => {
  if (!x || typeof x !== "object" || Array.isArray(x)) return invalid();
  return x as Record<string,unknown>;
};
const keys = (x: Record<string,unknown>, allowed: string[]) => {
  if (Object.keys(x).some(k => !allowed.includes(k))) invalid();
};
const name = (x: string) => /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(x)
  && !["__proto__","prototype","constructor"].includes(x);
const text = (x: unknown, max=4096): x is string => typeof x === "string"
  && x.length <= max && !x.includes("\0");
const lokiIds = new Set(["loki-stg","loki-prd","loki-tools"]);
const lokiTools = ["query_loki","get_label_values","get_labels"];
const portableProfiles = new Set([
  ...lokiIds,"grafana-dev","grafana-prd","grafana-tools",
  "langfuse-traces","langfuse-api-dev","agent-dev",
  "api-traces","worker-prod","worker-dev",
  "mysql-primary-dev","mysql-secondary-dev","mysql-imported-dev",
  "mysql-plugin-dev",
]);
// Keep aligned with the reviewed source configuration keys in loki_profile.INHERITED.
const lokiEnv = new Set(["LOKI_ADDR","LOKI_DATASOURCE_ID","LOKI_BEARER_TOKEN","HOME",
  "LOKI_CONFIG_PATH","LOKI_USERNAME","LOKI_PASSWORD","LOKI_TENANT_ID","LOKI_BEARER_TOKEN_FILE",
  "LOKI_CA_FILE","LOKI_CERT_FILE","LOKI_KEY_FILE","LOKI_ORG_ID","LOKI_TLS_SKIP_VERIFY",
  "HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY","http_proxy","https_proxy","all_proxy","no_proxy",
  "NODE_EXTRA_CA_CERTS","NODE_TLS_REJECT_UNAUTHORIZED","SSL_CERT_FILE","SSL_CERT_DIR"]);

export function parseConfig(input: unknown): Config {
  const root=object(input); keys(root,["mcpServers","idleTimeoutMs"]);
  const entries=Object.entries(object(root.mcpServers));
  if (!entries.length || entries.length>MAX_BACKEND_PROFILES) invalid();
  const idle=root.idleTimeoutMs ?? 300_000;
  if (!Number.isInteger(idle) || Number(idle)<20 || Number(idle)>300_000) invalid();
  const servers=new Map<string,BackendPolicy>();
  for (const [id,value] of entries) {
    if (!name(id)) invalid(); const v=object(value);
    keys(v,["command","args","env","cwd","shared","scope","cwdMode","closure","startupTimeoutMs","toolTimeoutMs","allowedTools","instruction","catalogMode","reviewedProfile"]);
    const profile = v.reviewedProfile ?? id;
    if(v.reviewedProfile!==undefined && (typeof profile!=="string"||!portableProfiles.has(profile)
        ||(id!==profile && (id.slice(0,-13)!==profile||!/^-[0-9a-f]{12}$/.test(id.slice(-13))))))invalid();
    if (!text(v.command) || !isAbsolute(v.command) || !text(v.cwd) || !isAbsolute(v.cwd)
        || v.shared!==true || (v.scope!==undefined&&v.scope!=="session")) invalid();
    if(v.cwdMode!==undefined&&(v.cwdMode!=="client"||v.scope!=="session"||v.cwd!=="/"))invalid();
    for(const field of ["startupTimeoutMs","toolTimeoutMs"])if(v[field]!==undefined
        &&(v.scope!=="session"||!Number.isSafeInteger(v[field])||Number(v[field])<20||Number(v[field])>600_000))invalid();
    const args=v.args ?? [];
    if (!Array.isArray(args) || args.length>64 || !args.every(a=>text(a))) invalid();
    const launchArgs=args as string[];
    const loki=lokiIds.has(profile as string);
    const mysql=v.catalogMode==="mysql-session";
    if(v.catalogMode!==undefined&&(!mysql||!/^mysql-[a-z0-9-]+$/.test(id)||v.scope!=="session"||v.closure===undefined))invalid();
    if(loki&&v.closure===undefined)invalid();
    let closure: ClosureIdentity | undefined;
    if (v.closure!==undefined) {
      const value=object(v.closure);keys(value,["root","digest"]);
      const canonicalPath=(path: unknown): path is string=>text(path)&&isAbsolute(path)&&normalize(path)===path
        &&(path==="/"||!path.endsWith("/"));
      if(v.scope!=="session"||!canonicalPath(value.root)||typeof value.digest!=="string"
          ||!/^[a-f0-9]{64}$/.test(value.digest)||basename(value.root)!==value.digest)invalid();
      const root=value.root as string,digest=value.digest as string;
      const prefix=["-I","-S","-B",join(root,"manager/langfuse-entry.py"),"--manager-data-root",
        launchArgs[5],"--manager-profile",profile,"--"];
      if(mysql){
        const mysqlArgs=["--no-addons","--no-global-search-paths",join(root,"manager/mysql-entry.mjs")];
        if(v.command!==join(root,"runtime/bin/node")||launchArgs.length!==mysqlArgs.length||mysqlArgs.some((part,index)=>launchArgs[index]!==part))invalid();
      }else if(loki){
        const nodeArgs=["--no-addons","--no-global-search-paths",join(root,"app/node_modules/simple-loki-mcp/dist/src/index.js")];
        if(v.command!==join(root,"runtime/bin/node")||launchArgs.length!==nodeArgs.length
            ||nodeArgs.some((part,index)=>launchArgs[index]!==part))invalid();
      }else if(v.command!==join(root,"python/bin/python3.13")||launchArgs.length<prefix.length
          ||prefix.some((part,index)=>launchArgs[index]!==part)||!canonicalPath(launchArgs[5]))invalid();
      closure={root,digest};
    }
    const env=object(v.env ?? {});
    if(mysql&&Object.keys(env).some(key=>!MYSQL_CONTEXT_KEYS.has(key)))invalid();
    if (Object.keys(env).length>64 || Object.entries(env).some(([k,val]) =>
      !/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) || !text(val,16384))) invalid();
    if(loki&&(Object.keys(env).some(key=>!lokiEnv.has(key))
        ||["LOKI_ADDR","LOKI_DATASOURCE_ID","LOKI_BEARER_TOKEN","HOME"].some(key=>!text(env[key],16384)||!env[key])
        ||!isAbsolute(env.HOME as string)))invalid();
    const allowed=v.allowedTools;
    if (!Array.isArray(allowed) || !allowed.length || allowed.length>128
        || !allowed.every(t=>typeof t==="string" && name(t))) invalid();
    const toolNames=allowed as string[];
    if(mysql&&(toolNames.length!==1||toolNames[0]!=="mysql_query"))invalid();
    if(loki&&(toolNames.length!==lokiTools.length||new Set(toolNames).size!==lokiTools.length
        ||lokiTools.some(tool=>!toolNames.includes(tool))))invalid();
    if (v.instruction!==undefined && !text(v.instruction,512)) invalid();
    servers.set(id,{command:v.command as string,args:[...launchArgs],
      env:{...env} as Record<string,string>,cwd:v.cwd as string,shared:true,...(v.scope==="session"?{scope:"session" as const}:{}),
      ...(v.cwdMode==="client"?{cwdMode:"client" as const}:{}),
      ...(closure?{closure}:{}),
      ...(mysql?{catalogMode:"mysql-session" as const}:{}),
      ...(v.startupTimeoutMs!==undefined?{startupTimeoutMs:v.startupTimeoutMs as number}:{}),
      ...(v.toolTimeoutMs!==undefined?{toolTimeoutMs:v.toolTimeoutMs as number}:{}),
      ...(v.reviewedProfile!==undefined?{reviewedProfile:profile as string}:{}),
      allowedTools:[...new Set(allowed as string[])],instruction:(v.instruction as string) ?? ""});
  }
  return {servers,idleTimeoutMs:Number(idle)};
}

export function readToken(path: string): string {
  let fd: number | undefined;
  try {
    if (!isAbsolute(path)) throw new SafeError("invalid_token_file");
    const parent = lstatSync(dirname(path));
    if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid?.()
        || (parent.mode & 0o7777) !== 0o700) throw new SafeError("invalid_token_file");
    fd=openSync(path,constants.O_RDONLY | constants.O_NOFOLLOW);
    const s=fstatSync(fd);
    if (!s.isFile() || s.uid!==process.getuid?.() || (s.mode & 0o7777)!==0o600 || s.size>128)
      throw new SafeError("invalid_token_file");
    const token=readFileSync(fd,"utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(token)) throw new SafeError("invalid_token_file");
    return token;
  } catch { throw new SafeError("invalid_token_file"); }
  finally { if (fd!==undefined) closeSync(fd); }
}
