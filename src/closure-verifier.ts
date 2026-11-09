import {emitDiagnostic,type DiagnosticSink,type DiagnosticReason} from './backend-diagnostics.js';
import { spawn, type ChildProcess } from 'node:child_process';
import { lstatSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface ClosureReference { root: string; digest: string }
export interface ClosureVerifierOptions { python: string; script?: string; timeoutMs?: number;diagnostic?:DiagnosticSink }
const failure = () => new Error('Closure verification failed');
const cleanupFailure = () => new Error('Closure verifier cleanup unproven');
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function trustedPath(path: string, directory = false): void {
  if (!isAbsolute(path) || resolve(path) !== path || realpathSync(path) !== path) throw failure();
  let current = path;
  for (;;) {
    const info = lstatSync(current);
    const stickyTmp = current === '/private/tmp' && info.uid === 0 && (info.mode & 0o1000) !== 0;
    if (info.isSymbolicLink() || ![0, process.getuid?.()].includes(info.uid) || ((info.mode & 0o22) !== 0 && !stickyTmp)) throw failure();
    if (current === path ? (directory ? !info.isDirectory() : !info.isFile()) : !info.isDirectory()) throw failure();
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

interface OwnedCheck { stop(): void; done: Promise<void>; unproven: boolean }
/** Pending-only coalescing: every later generation rechecks the entire tree. */
export class ClosureVerifier {
  private readonly python: string;
  private readonly script: string;
  private readonly timeoutMs: number;
  private readonly pending = new Map<string, Promise<void>>();
  private readonly children = new Set<OwnedCheck>();
  private closed = false;
  private readonly diagnostic:DiagnosticSink|undefined;

  constructor(options: ClosureVerifierOptions) {
    this.diagnostic=options.diagnostic;
    try {
      this.python = options.python;
      this.script = options.script ?? resolve(repo, 'scripts/verify-langfuse-closure.py');
      this.timeoutMs = options.timeoutMs ?? 30_000;
      if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 30_000) throw failure();
      trustedPath(this.python); trustedPath(this.script); trustedPath(repo, true);
      if (!(lstatSync(this.python).mode & 0o111)) throw failure();
    } catch { emitDiagnostic(this.diagnostic,"closure","closure_trust_rejected");throw failure(); }
  }

  verify(reference: ClosureReference): Promise<void> {
    if (this.closed){emitDiagnostic(this.diagnostic,"closure","closure_closed");return Promise.reject(failure());}
    try {
      if (!/^[0-9a-f]{64}$/.test(reference.digest) || basename(reference.root) !== reference.digest) throw failure();
      trustedPath(reference.root, true);
      // Unchecked artifact code must never run before its own integrity check.
      if ([this.python, this.script, repo].some(path => path === reference.root || path.startsWith(reference.root + sep))) throw failure();
      // Recheck trusted launch paths for each child, including constructor-to-use drift.
      trustedPath(this.python); trustedPath(this.script); trustedPath(repo, true);
    } catch { emitDiagnostic(this.diagnostic,"closure","closure_trust_rejected");return Promise.reject(failure()); }
    const key = JSON.stringify([reference.root, reference.digest]);
    const existing = this.pending.get(key);
    if (existing) return existing;
    const check = this.run(reference).finally(() => { this.pending.delete(key); });
    this.pending.set(key, check);
    return check;
  }

  private run(reference: ClosureReference): Promise<void> {
    return new Promise<void>((resolveCheck, rejectCheck) => {
      let child: ChildProcess;
      try {
        child = spawn(this.python, ['-I', '-S', '-B', this.script, '--root', reference.root, '--digest', reference.digest], {
          cwd: repo, env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'ignore'], shell: false,
        });
      } catch { emitDiagnostic(this.diagnostic,"closure","closure_spawn_failed");rejectCheck(failure()); return; }
      let output = Buffer.alloc(0), failed = false, finished = false;
      let killTimer: NodeJS.Timeout | undefined, proofTimer: NodeJS.Timeout | undefined;
      let resolveDone!: () => void;
      const done = new Promise<void>(resolve => { resolveDone = resolve; });
      const live = () => child.pid !== undefined && child.exitCode === null && child.signalCode === null;
      const signalOwned = (signal: NodeJS.Signals) => {
        if (live()) { try { child.kill(signal); } catch { /* Deadline proves exit or rejects cleanup. */ } }
      };
      const stop = (reason:DiagnosticReason) => {
        if (finished || failed) return;
        failed = true;emitDiagnostic(this.diagnostic,"closure",reason);
        signalOwned('SIGTERM');
        killTimer = setTimeout(() => {
          signalOwned('SIGKILL');
          proofTimer = setTimeout(() => {
            if (!finished) { finished = true; this.closed = true; owned.unproven = true; emitDiagnostic(this.diagnostic,"closure","closure_cleanup_unproven");clearTimeout(deadline); rejectCheck(cleanupFailure()); }
            // Retain ownership/done until close; shutdown must also reject unproved cleanup.
          }, 1_000);
        }, 500);
      };
      const owned: OwnedCheck = { stop:()=>stop("closure_shutdown"), done, unproven: false };
      this.children.add(owned);
      const deadline = setTimeout(()=>stop("closure_deadline"), this.timeoutMs);
      child.on('error',()=>stop('closure_child_error'));
      child.stdout!.on('error',()=>stop('closure_stdout_error'));
      child.stdout!.on('data', (chunk: Buffer) => {
        if (failed || finished) return;
        if (output.length + chunk.length > 4096) { stop("closure_output_limit"); return; }
        output = Buffer.concat([output, chunk]);
        if (output.includes(10) && !this.valid(output, reference.digest)) stop("closure_output_invalid");
      });
      child.once('close', (code, signal) => {
        clearTimeout(deadline); clearTimeout(killTimer); clearTimeout(proofTimer);
        this.children.delete(owned); resolveDone();
        if (finished) return;
        finished = true;
        if (!failed && code === 0 && signal === null && this.valid(output, reference.digest)) resolveCheck();
        else {if(!failed)emitDiagnostic(this.diagnostic,"closure","closure_exit_rejected");rejectCheck(failure());}
      });
    });
  }

  private valid(output: Buffer, digest: string): boolean {
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(output);
      const tokens = text.match(/"(?:\\.|[^"\\])*"\s*:/g) ?? [];
      const names = tokens.map(token => JSON.parse(token.slice(0, token.lastIndexOf(':')).trim()));
      if (names.length !== 3 || new Set(names).size !== names.length) return false;
      const value = JSON.parse(text);
      return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).sort().join(',') === 'digest,valid,version'
        && value.version === 1 && value.valid === true && value.digest === digest;
    } catch { return false; }
  }

  snapshot(): { outstanding: number; unproven: number } {
    return { outstanding: this.children.size, unproven: [...this.children].filter(check => check.unproven).length };
  }

  async shutdown(): Promise<void> {
    this.closed = true;
    const owned = [...this.children];
    for (const check of owned) check.stop();
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        Promise.all(owned.map(check => check.done)),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(cleanupFailure()), 2_000); }),
      ]);
      if (this.children.size) throw cleanupFailure();
    } finally { clearTimeout(timer); }
  }
}
