#!/usr/bin/env python3
"""Run the portable manager service and its authenticated owner channel."""
import argparse
import ctypes
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
from pathlib import Path

from pilot import ENV_KEYS, SafeError, private


def publish(stage, runtime):
    """Publish a staged artifact without replacing an existing runtime."""
    if sys.platform != "darwin":
        raise SafeError("EXCLUSIVE_RENAME_UNAVAILABLE")
    try:
        renamex_np = ctypes.CDLL(None, use_errno=True).renamex_np
    except (AttributeError, OSError):
        raise SafeError("EXCLUSIVE_RENAME_UNAVAILABLE") from None
    renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    renamex_np.restype = ctypes.c_int
    if renamex_np(os.fsencode(stage), os.fsencode(runtime), 0x00000004) != 0:
        raise SafeError("PUBLISH_COLLISION_OR_FAILURE")


def ownership_empty(directory):
    """Validate empty owned state without mistaking known session folders for children."""
    directory = private(directory, directory=True)
    for child in directory.iterdir():
        if child.name not in {"sessions", "session-invalidations"}:
            raise SafeError("OWNERSHIP_RESIDUE")
        private(child, directory=True)
        entries = list(child.iterdir())
        if child.name == "session-invalidations" and entries or len(entries) > 512:
            raise SafeError("OWNERSHIP_RESIDUE")
        for lease in entries:
            if not re.fullmatch(r"[a-f0-9]{64}", lease.name):
                raise SafeError("OWNERSHIP_RESIDUE")
            private(lease, directory=True)
            if next(lease.iterdir(), None) is not None:
                raise SafeError("OWNERSHIP_RESIDUE")
    return True


def launch_backends(backends, runtime, repo, node, manifest_dir, *, port=18765,
                    on_started=None, loki_environment_guard=None,
                    mysql_environment_guard=None, diagnostic_fd=None,
                    owner_paths=None, portable_environment_guard=None,
                    claude_paths=None):
    """Launch validated policies; credentials use stdin, owner events a private fd."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise SafeError("PORT_INVALID")
    session_backends = frozenset(
        route_id for route_id, backend in backends.items()
        if backend.get("scope") == "session"
    )
    if (diagnostic_fd is not None and
            (port == 18765 or not session_backends or type(diagnostic_fd) is not int
             or not 3 <= diagnostic_fd <= 1024)):
        raise SafeError("DIAGNOSTIC_FD_INVALID")
    closure_backends = frozenset(
        route_id for route_id, backend in backends.items() if "closure" in backend
    )
    if not closure_backends.issubset(session_backends):
        raise SafeError("CLOSURE_SCOPE_INVALID")
    payload = json.dumps({"mcpServers": backends, "idleTimeoutMs": 300000}).encode()
    if session_backends:
        cwd_backends = frozenset(
            route_id for route_id, backend in backends.items()
            if backend.get("cwdMode") == "client"
        )
        host_python = str(Path(sys.executable).resolve(strict=True)) if closure_backends else None
        return launch_with_owners(
            payload, session_backends, runtime, repo, node, manifest_dir, port,
            cwd_backends=cwd_backends, closure_verifier_python=host_python,
            on_started=on_started,
            loki_environment_guard=loki_environment_guard,
            mysql_environment_guard=mysql_environment_guard,
            diagnostic_fd=diagnostic_fd, owner_paths=owner_paths,
            portable_environment_guard=portable_environment_guard,
            claude_paths=claude_paths,
        )

    child = subprocess.Popen(
        [node, str(Path(repo) / "dist/index.js"), "--config-stdin",
         "--token-file", str(Path(runtime) / "token"), "--port", str(port),
         "--manifest-dir", str(manifest_dir)],
        stdin=subprocess.PIPE, cwd=repo,
        env={key: value for key, value in os.environ.items() if key in ENV_KEYS},
    )

    def forward(signum, _frame):
        if child.poll() is None:
            child.send_signal(signum)

    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGTERM, signal.SIGINT)}
    reaped = False
    try:
        if on_started is not None:
            on_started(child)
        child.communicate(payload)
        result = child.wait()
        reaped = True
        return result
    finally:
        try:
            if not reaped and child.poll() is None:
                if child.stdin and not child.stdin.closed:
                    child.stdin.close()
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    raise SafeError("CLEANUP_UNPROVEN") from None
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def launch_with_owners(payload, backends, runtime, repo, node, manifest_dir, port,
                       *, cwd_backends=frozenset(), closure_verifier_python=None,
                       on_started=None, loki_environment_guard=None,
                       mysql_environment_guard=None, diagnostic_fd=None,
                       owner_paths=None, portable_environment_guard=None,
                       claude_paths=None):
    if (diagnostic_fd is not None and
            (port == 18765 or not backends or type(diagnostic_fd) is not int
             or not 3 <= diagnostic_fd <= 1024)):
        raise SafeError("DIAGNOSTIC_FD_INVALID")
    from owner_watch import OwnerWatch

    parent_channel, child_channel = socket.socketpair()
    child = None
    watcher = None
    previous = {}
    reaped = False
    failed = threading.Event()
    shutdown_requested = threading.Event()

    def forward(signum, _frame=None):
        if child is not None and child.poll() is None:
            child.send_signal(signum)

    def owner_failed():
        failed.set()
        # An intentional Node shutdown closes this channel after cleanup.
        if not shutdown_requested.is_set():
            forward(signal.SIGTERM)

    def request_shutdown(signum, frame):
        shutdown_requested.set()
        forward(signum, frame)

    try:
        claude_options = {}
        if claude_paths is not None:
            from owner_watch import signed_claude

            admitted_claude = frozenset(claude_paths)
            claude_options = {
                "claude_match": lambda path: path in admitted_claude,
                "claude_signature": lambda path: signed_claude(
                    path, root=str(Path(path).parent)
                ),
                "claude_root": None,
            }
        watcher = OwnerWatch(
            runtime, parent_channel, backends=backends,
            cwd_backends=cwd_backends, on_failure=owner_failed,
            loki_environment_guard=loki_environment_guard,
            mysql_environment_guard=mysql_environment_guard,
            **({"owner_paths": owner_paths} if owner_paths is not None else {}),
            **({"portable_environment_guard": portable_environment_guard}
               if portable_environment_guard is not None else {}),
            **claude_options,
        )
        descriptor = child_channel.fileno()
        if diagnostic_fd == descriptor:
            raise SafeError("DIAGNOSTIC_FD_INVALID")
        child = subprocess.Popen(
            [node, str(Path(repo) / "dist/index.js"), "--config-stdin",
             "--token-file", str(Path(runtime) / "token"), "--port", str(port),
             "--manifest-dir", str(manifest_dir), "--owner-channel-fd",
             str(descriptor),
             *(["--closure-verifier-python", closure_verifier_python]
               if closure_verifier_python else []),
             *(["--backend-diagnostic-fd", str(diagnostic_fd)]
               if diagnostic_fd is not None else [])],
            stdin=subprocess.PIPE,
            pass_fds=(descriptor,) if diagnostic_fd is None else (descriptor, diagnostic_fd),
            cwd=repo,
            env={key: value for key, value in os.environ.items() if key in ENV_KEYS},
        )
        child_channel.close()
        previous = {
            sig: signal.signal(sig, request_shutdown)
            for sig in (signal.SIGTERM, signal.SIGINT)
        }
        if on_started is not None:
            on_started(child)
        # Node must receive EOF and build its registry before the watcher waits for READY.
        child.stdin.write(payload)
        child.stdin.close()
        watcher.start()
        result = child.wait()
        reaped = True
        return 1 if failed.is_set() and not shutdown_requested.is_set() and result == 0 else result
    finally:
        try:
            if watcher is not None:
                watcher.close()
        finally:
            parent_channel.close()
            child_channel.close()
            try:
                if child is not None and not reaped:
                    if child.stdin is not None and not child.stdin.closed:
                        child.stdin.close()
                    forward(signal.SIGTERM)
                    try:
                        child.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        # Preserve ownership state when cleanup cannot be proven.
                        raise SafeError("CLEANUP_UNPROVEN") from None
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--installation" not in arguments:
        print("LEGACY_INSTALLATION_UNSUPPORTED", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["run"])
    parser.add_argument("--installation", type=Path, required=True)
    args = parser.parse_args(arguments)
    from installation_context import load_context
    from portable_engine import run_service

    return run_service(load_context(args.installation))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("SERVICE_OPERATION_FAILED", file=sys.stderr)
        raise SystemExit(1)
