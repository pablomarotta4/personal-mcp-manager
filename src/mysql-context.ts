import {SafeError} from './policy.js';
export const MYSQL_CONTEXT_KEYS=new Set(`ALLOW_DDL_OPERATION ALLOW_DELETE_OPERATION ALLOW_INSERT_OPERATION ALLOW_UPDATE_OPERATION ENABLE_LOGGING ENABLE_PII_REDACTION IS_REMOTE_MCP MULTI_DB_WRITE_MODE MYSQL_BIG_NUMBER_STRINGS MYSQL_CONNECTION_STRING MYSQL_CONNECT_TIMEOUT MYSQL_DATE_STRINGS MYSQL_DB MYSQL_DISABLE_READ_ONLY_TRANSACTIONS MYSQL_HOST MYSQL_PASS MYSQL_PORT MYSQL_QUEUE_LIMIT MYSQL_SOCKET_PATH MYSQL_SSL MYSQL_SSL_CA MYSQL_SSL_CERT MYSQL_SSL_KEY MYSQL_SSL_REJECT_UNAUTHORIZED MYSQL_TIMEZONE MYSQL_USER NODE_ENV PII_ALLOW_INTROSPECTION PII_ALLOW_REFERENCES PII_ALLOW_SELECT_STAR PII_BLOCK_INTROSPECTION PII_EXTRA_COLUMNS PII_EXTRA_COLUMN_PATTERNS PII_REDACT_JSON_STRINGS PORT REMOTE_SECRET_KEY SCHEMA_DDL_PERMISSIONS SCHEMA_DELETE_PERMISSIONS SCHEMA_INSERT_PERMISSIONS SCHEMA_UPDATE_PERMISSIONS VITEST npm_package_version HOME NODE_EXTRA_CA_CERTS NODE_TLS_REJECT_UNAUTHORIZED SSL_CERT_FILE SSL_CERT_DIR PATH USER LOGNAME LANG LC_ALL TMPDIR`.split(' '));
/** This context arrives only over the inherited, signed-owner private channel. */
export function decodeMysqlContext(value:unknown):Readonly<Record<string,string>>{
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).join(',')!=='environment')throw new SafeError('mysql_context_invalid');
 const environment=(value as {environment:unknown}).environment;
 if(!environment||typeof environment!=='object'||Array.isArray(environment)||Object.keys(environment).length>64)throw new SafeError('mysql_context_invalid');
 const entries=Object.entries(environment);
 if(entries.some(([key,value])=>!MYSQL_CONTEXT_KEYS.has(key)||typeof value!=='string'||value.includes('\0')||Buffer.byteLength(value)>16384)||Buffer.byteLength(JSON.stringify(environment))>120000)throw new SafeError('mysql_context_invalid');
 if((environment as Record<string,string>).IS_REMOTE_MCP==='true')throw new SafeError('mysql_context_invalid');
 return Object.freeze(Object.fromEntries(entries) as Record<string,string>);
}
