// This process remains its group's live leader until teardown. Only this process
// may signal the group; the manager never signals a saved numeric group ID.
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import type { BackendPolicy } from "./policy.js";
let child: ChildProcessWithoutNullStreams | undefined;
let started = false;
let stopping = false;
function stop(): void {
  if (stopping) return;
  stopping = true;
  process.stdin.unpipe();
  child?.stdin.end();
  // Give a cooperative stdio backend a chance to drain first. We must stay alive
  // even after it exits: grandchildren may still share this process group.
  setTimeout(() => {
    try { process.kill(-process.pid, "SIGTERM"); } catch { /* final self-owned kill follows */ }
    setTimeout(() => {
      try { process.kill(-process.pid, "SIGKILL"); } catch { process.exit(1); }
    }, 150);
  }, 100);
}
for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) process.on(signal, stop);
process.on("disconnect", stop);
process.on("uncaughtException", stop);
process.on("unhandledRejection", stop);
process.stdin.on("error", stop);
process.stdout.on("error", stop);
process.on("message", (message: unknown) => {
  if (!message || typeof message !== "object") return stop();
  const data = message as { type?: string; policy?: BackendPolicy };
  if (data.type === "stop") return stop();
  if (data.type !== "start" || started || stopping || !data.policy) return stop();
  started = true;
  const p = data.policy;
  try {
    child = spawn(p.command, p.args, { cwd: p.cwd, env: p.env, stdio: ["pipe", "pipe", "pipe"], shell: false });
    child.stderr.resume(); // Backend diagnostics may contain credentials; do not forward.
    child.stdin.on("error", () => {});
    child.stdout.on("error", stop);
    child.stdout.pipe(process.stdout, { end: false });
    process.stdin.pipe(child.stdin);
    child.on("error", stop);
    child.on("exit", stop);
    child.on("spawn", () => {
      if (stopping) return;
      process.send?.({ type: "ready" });
    });
  } catch { stop(); }
});
// A parent dying between spawn and initial IPC must not leave an idle orphan.
if (!process.connected) stop();
