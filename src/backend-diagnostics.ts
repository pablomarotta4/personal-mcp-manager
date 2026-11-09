import {fstatSync,writeSync,closeSync} from 'node:fs';
import {McpError,ErrorCode} from '@modelcontextprotocol/sdk/types.js';
import {SafeError} from './policy.js';
import {CompletedBackendError} from './owned-stdio.js';
export const DIAGNOSTIC_STAGES=['trace','before_start','artifact','closure','cwd','connect','capabilities','discovery','manifest','tool','resource','transport','retirement'] as const;
export const DIAGNOSTIC_REASONS=['begin','ok','closed','limit','unknown','artifact_changed','artifact_unavailable','owner_cwd_changed','unsupported_backend','manifest_mismatch','discovery_limit','request_timeout','request_cancelled','connection_closed','completed_backend_error','backend_protocol_error','backend_unavailable','ownership_quarantined','supervisor_unavailable','cleanup_unproven','invalidation_persistence_failed','closure_closed','closure_trust_rejected','closure_spawn_failed','closure_child_error','closure_stdout_error','closure_output_limit','closure_output_invalid','closure_deadline','closure_shutdown','closure_exit_rejected','closure_cleanup_unproven'] as const;
export type DiagnosticStage=typeof DIAGNOSTIC_STAGES[number];
export type DiagnosticReason=typeof DIAGNOSTIC_REASONS[number];
export type DiagnosticSink=(stage:DiagnosticStage,reason:DiagnosticReason)=>void;
export function emitDiagnostic(sink:DiagnosticSink|undefined,stage:DiagnosticStage,reason:DiagnosticReason):void{
 if(!sink||!DIAGNOSTIC_STAGES.includes(stage)||!DIAGNOSTIC_REASONS.includes(reason))return;
 try{sink(stage,reason);}catch{/* Diagnostics cannot affect ownership or public results. */}
}
const safeReasons=new Set<DiagnosticReason>(['artifact_changed','artifact_unavailable','owner_cwd_changed','unsupported_backend','manifest_mismatch','discovery_limit','request_cancelled','backend_protocol_error','backend_unavailable','ownership_quarantined','supervisor_unavailable','cleanup_unproven','invalidation_persistence_failed']);
export function classifyDiagnosticFailure(error:unknown):DiagnosticReason{
 if(error instanceof CompletedBackendError)return 'completed_backend_error';
 if(error instanceof SafeError&&safeReasons.has(error.code as DiagnosticReason))return error.code as DiagnosticReason;
 if(error instanceof McpError){if(error.code===ErrorCode.RequestTimeout)return 'request_timeout';if(error.code===ErrorCode.ConnectionClosed)return 'connection_closed';}
 return 'unknown';
}
/** Owns only a staging-inherited descriptor; never reopens paths or emits raw data. */
export function createDiagnosticWriter(fd:number):{sink:DiagnosticSink;close:()=>void}{
 if(!Number.isInteger(fd)||fd<3||fd>1024)throw new SafeError('invalid_arguments');
 try{const stat=fstatSync(fd);if(!stat.isFile()||stat.uid!==process.getuid?.()||(stat.mode&0o7777)!==0o600||stat.nlink!==1||stat.size!==0)throw new SafeError('invalid_arguments');}
 catch{try{closeSync(fd);}catch{}throw new SafeError('invalid_arguments');}
 let sequence=0,bytes=0,disabled=false,closed=false;
 const write=(stage:DiagnosticStage,reason:DiagnosticReason)=>{
  const line=Buffer.from(JSON.stringify({version:1,sequence:sequence+1,stage,reason})+'\n');
  if(bytes+line.length>128*1024){disabled=true;return;}
  try{if(writeSync(fd,line)!==line.length){disabled=true;return;}sequence++;bytes+=line.length;}catch{disabled=true;}
 };
 const sink:DiagnosticSink=(stage,reason)=>{
  if(disabled||closed||!DIAGNOSTIC_STAGES.includes(stage)||!DIAGNOSTIC_REASONS.includes(reason))return;
  if(sequence>=511||bytes+256>128*1024){write('trace','limit');disabled=true;return;}write(stage,reason);
 };
 return {sink,close:()=>{if(closed)return;sink('trace','closed');closed=true;try{closeSync(fd);}catch{}}};
}
