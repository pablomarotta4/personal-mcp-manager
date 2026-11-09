#!/usr/bin/env python3
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import tomllib

MAX_CONFIG = 262144
ENV_KEYS = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT"}


class SafeError(Exception):
    pass


def private(path, directory=False):
    path = Path(path)
    info = path.lstat()
    expected = 0o700 if directory else 0o600
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != expected:
        raise SafeError("PRIVATE_FILE_INVALID")
    return path


def read_private(path):
    path = private(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode):
            raise SafeError("PRIVATE_FILE_INVALID")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(MAX_CONFIG + 1)
        if len(value) > MAX_CONFIG:
            raise SafeError("FILE_TOO_LARGE")
        return value
    finally:
        os.close(descriptor)


def write_private(path, data, exclusive=False):
    path = Path(path)
    private(path.parent, directory=True)
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return
    fd, temporary = tempfile.mkstemp(prefix=".pilot-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def setup_token(runtime):
    runtime = Path(runtime)
    if not runtime.exists():
        runtime.mkdir(mode=0o700)
    private(runtime, directory=True)
    token = runtime / "token"
    if token.exists() or token.is_symlink():
        read_token(token)
    else:
        write_private(token, secrets.token_hex(32).encode("ascii"), exclusive=True)
    return token


def read_token(path):
    private(Path(path).parent, directory=True)
    value = read_private(path).decode("ascii")
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SafeError("TOKEN_INVALID")
    return value


def headers(token, backend=None):
    # Only Codex invokes this command with the real token; do not manually print it.
    values = {"Authorization": "Bearer " + read_token(token)}
    if backend is not None:
        from owner_watch import request_owner
        values['X-Personal-MCP-Owner'] = request_owner(Path(token).parent, backend)
    print(json.dumps(values))


def runtime_config(config, policy):
    raw = read_private(config)
    if len(raw) > MAX_CONFIG:
        raise SafeError("CONFIG_TOO_LARGE")
    source = tomllib.loads(raw.decode("utf-8"))
    selected = source.get("mcp_servers", {}).get("grafana-dev")
    rules = json.loads(read_private(policy))
    if set(rules) != {"backend", "allowedTools", "command", "args", "cwd"}:
        raise SafeError("POLICY_INVALID")
    if rules["backend"] != "grafana-dev" or rules["allowedTools"] != ["list_datasources"]:
        raise SafeError("POLICY_INVALID")
    if not isinstance(selected, dict) or set(selected) - {"command", "args", "env", "enabled", "cwd", "startup_timeout_sec", "tool_timeout_sec"}:
        raise SafeError("SOURCE_UNSUPPORTED")
    command = selected.get("command")
    args = selected.get("args", [])
    env = selected.get("env", {})
    if not isinstance(command, str) or not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise SafeError("SOURCE_INVALID")
    resolved = command if os.path.isabs(command) else shutil.which(command)
    if not resolved or not os.path.isabs(resolved) or resolved != rules["command"] or args != rules["args"]:
        raise SafeError("SOURCE_CHANGED")
    if not isinstance(env, dict) or set(env) != {"GRAFANA_URL", "GRAFANA_SERVICE_ACCOUNT_TOKEN"} or not all(isinstance(value, str) and value for value in env.values()):
        raise SafeError("ENV_INVALID")
    cwd = rules["cwd"]
    if not isinstance(cwd, str) or not os.path.isabs(cwd) or selected.get("cwd", cwd) != cwd:
        raise SafeError("CWD_INVALID")
    result = {"mcpServers": {"grafana-dev": {
        "command": resolved, "args": args, "env": env, "cwd": cwd,
        "shared": True, "allowedTools": ["list_datasources"],
        "instruction": "Read-only DEV Grafana datasource inventory.",
    }}, "idleTimeoutMs": 300000}
    if len(json.dumps(result).encode("utf-8")) > MAX_CONFIG:
        raise SafeError("RUNTIME_CONFIG_TOO_LARGE")
    return result


def launch(config, policy, token, node, repo):
    read_token(token)
    if not os.path.isabs(node):
        raise SafeError("NODE_PATH_INVALID")
    payload = json.dumps(runtime_config(config, policy)).encode("utf-8")
    command = [node, str(Path(repo) / "dist/index.js"), "--config-stdin", "--token-file", str(token), "--port", "18765"]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, cwd=repo,
                             env={key: value for key, value in os.environ.items() if key in ENV_KEYS})
    def forward(signum, frame):
        if child.poll() is None:
            child.send_signal(signum)
    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        child.communicate(payload)
        return child.wait()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
TABLE = re.compile(r"(?m)^\[(mcp_servers\.(?:grafana-dev|personal-mcp-manager)(?:\.[A-Za-z0-9_-]+)?)\][ \t]*(?:#[^\n]*)?\n")
ANY_TABLE = re.compile(r"(?m)^\[[^\n]+\][ \t]*(?:#[^\n]*)?(?:\n|$)")
ENABLED = re.compile(r"(?m)^enabled[ \t]*=[ \t]*(?:true|false)[ \t]*(?:#[^\n]*)?\n")


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_editable(text):
    # Conservative rejection is intentional: a small pilot is not a TOML lexer.
    if '"""' in text or "'" * 3 in text:
        raise SafeError("MULTILINE_LAYOUT_UNSUPPORTED")
    return tomllib.loads(text)


def assert_semantics(actual, expected):
    if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise SafeError("UNEXPECTED_SEMANTIC_CHANGE")


def enabled_value(line, value):
    return re.sub(r"^(enabled[ \t]*=[ \t]*)(true|false)",
                  lambda match: match.group(1) + value, line)


def block(text, name):
    parse_editable(text)
    root = "mcp_servers." + name
    matches = list(TABLE.finditer(text))
    selected = [match for match in matches if match.group(1) == root or match.group(1).startswith(root + ".")]
    if not selected or selected[0].group(1) != root:
        raise SafeError("TABLE_LAYOUT_UNSUPPORTED")
    begin = selected[0].start()
    ends = []
    for match in selected:
        next_header = ANY_TABLE.search(text, match.end())
        ends.append(next_header.start() if next_header else len(text))
    end = max(ends)
    # Reject interleaving tables: one contiguous root plus its child tables only.
    for match in ANY_TABLE.finditer(text, begin, end):
        if not any(match.start() == item.start() for item in selected):
            raise SafeError("TABLE_LAYOUT_UNSUPPORTED")
    root_end = ANY_TABLE.search(text, selected[0].end())
    return begin, end, selected[0].end(), root_end.start() if root_end else len(text)


def registration(python, script, runtime):
    helper = " ".join(shlex_quote(item) for item in [python, script, "headers", "--runtime", str(runtime)])
    return ('[mcp_servers.personal-mcp-manager]\n'
            'url = "http://127.0.0.1:18765/mcp"\n'
            'http_headers_helper = ' + json.dumps(helper) + '\n'
            'enabled = true\n')


def shlex_quote(value):
    import shlex
    return shlex.quote(str(value))


def propose(text, manager):
    parsed = parse_editable(text)
    servers = parsed.get("mcp_servers", {})
    if "personal-mcp-manager" in servers:
        raise SafeError("MANAGER_ALREADY_PRESENT")
    entry = servers.get("grafana-dev")
    if not isinstance(entry, dict) or entry.get("enabled", True) is not True:
        raise SafeError("PILOT_NOT_ENABLED")
    start, end, body_start, body_end = block(text, "grafana-dev")
    root_body = text[body_start:body_end]
    existing = list(ENABLED.finditer(root_body))
    if len(existing) > 1 or ("enabled" in entry and not existing):
        raise SafeError("ENABLED_LAYOUT_UNSUPPORTED")
    old_line = "true" if existing else ""
    new_body = ENABLED.sub(lambda match: enabled_value(match.group(), "false"), root_body) if existing else "enabled = false\n" + root_body
    replaced = text[:body_start] + new_body + text[body_end:]
    # Insert directly before grafana; avoids an appended separator whose rollback
    # would require changing unrelated bytes.
    proposed = replaced[:start] + manager + replaced[start:]
    manager_parsed = parse_editable(manager)
    if set(manager_parsed) != {"mcp_servers"} or set(manager_parsed["mcp_servers"]) != {"personal-mcp-manager"}:
        raise SafeError("REGISTRATION_INVALID")
    expected = copy.deepcopy(parsed)
    expected["mcp_servers"]["grafana-dev"]["enabled"] = False
    expected["mcp_servers"]["personal-mcp-manager"] = manager_parsed["mcp_servers"]["personal-mcp-manager"]
    assert_semantics(parse_editable(proposed), expected)
    gs, ge, _, _ = block(proposed, "grafana-dev")
    ms, me, _, _ = block(proposed, "personal-mcp-manager")
    return {"beforeHash": digest(text), "after": proposed, "oldEnabledLine": old_line,
            "grafanaHash": digest(proposed[gs:ge]), "managerHash": digest(proposed[ms:me]),
            "manager": manager}


def locked(config):
    path = Path(config).with_name(Path(config).name + ".personal-mcp-manager.lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(fd)
        raise SafeError("LOCK_INVALID")
    fcntl.flock(fd, fcntl.LOCK_EX)
    return os.fdopen(fd, "rb")


def replace_config(config, before, after):
    config = Path(config)
    info = config.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise SafeError("CONFIG_FILE_INVALID")
    fd, temporary = tempfile.mkstemp(prefix=".codex-pilot-", dir=config.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(after.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        if read_private(config).decode("utf-8") != before:
            raise SafeError("CONFIG_CONCURRENT_CHANGE")
        os.replace(temporary, config)
        directory = os.open(config.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply(config, journal, proposal):
    with locked(config):
        before = read_private(config).decode("utf-8")
        if digest(before) != proposal["beforeHash"]:
            raise SafeError("PROPOSAL_STALE")
        if Path(journal).exists() or Path(journal).is_symlink():
            raise SafeError("TRANSACTION_EXISTS")
        record = {key: value for key, value in proposal.items() if key != "after"}
        record["state"] = "prepared"
        write_private(journal, json.dumps(record).encode(), exclusive=True)
        replace_config(config, before, proposal["after"])
        # The prepared journal is sufficient for recovery even if this update fails.
        record["state"] = "applied"
        write_private(journal, json.dumps(record).encode())


def rollback(config, journal):
    record = json.loads(read_private(journal))
    with locked(config):
        current = read_private(config).decode("utf-8")
        parsed = parse_editable(current)
        if digest(current) == record["beforeHash"]:
            Path(journal).unlink()  # prepared transaction never replaced config
            return
        gs, ge, body_start, body_end = block(current, "grafana-dev")
        ms, me, _, _ = block(current, "personal-mcp-manager")
        if digest(current[gs:ge]) != record["grafanaHash"] or digest(current[ms:me]) != record["managerHash"]:
            raise SafeError("ROLLBACK_MANAGED_ENTRY_CONFLICT")
        root_body = current[body_start:body_end]
        if len(list(ENABLED.finditer(root_body))) != 1:
            raise SafeError("ROLLBACK_ENABLED_CONFLICT")
        restored_body = ENABLED.sub(lambda match: enabled_value(match.group(), "true") if record["oldEnabledLine"] == "true" else "", root_body)
        restored = current[:body_start] + restored_body + current[body_end:]
        # manager is before grafana, so its positions survive the enabled edit.
        restored = restored[:ms] + restored[me:]
        expected = copy.deepcopy(parsed)
        expected["mcp_servers"].pop("personal-mcp-manager")
        if record["oldEnabledLine"] == "true":
            expected["mcp_servers"]["grafana-dev"]["enabled"] = True
        else:
            expected["mcp_servers"]["grafana-dev"].pop("enabled")
        assert_semantics(parse_editable(restored), expected)
        replace_config(config, current, restored)
        Path(journal).unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["setup-token", "headers", "launch", "preview", "apply", "rollback"])
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--config", type=Path, default=Path.home() / ".codex/config.toml")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--node", default="")
    parser.add_argument("--expected-hash", default="")
    parser.add_argument("--backend")
    args = parser.parse_args()
    if args.installation is not None:
        if args.action != 'headers' or args.backend is None:
            raise SafeError('INSTALLATION_HEADERS_ONLY')
        from installation_context import load_context
        from portable_engine import requires_owner
        context = load_context(args.installation)
        if args.runtime is not None and args.runtime != context.runtime:
            raise SafeError('INSTALLATION_RUNTIME_MISMATCH')
        headers(context.runtime / 'token', backend=args.backend if requires_owner(context, args.backend) else None)
        return 0
    if args.runtime is None:
        args.runtime = Path.home() / '.codex/personal-mcp-manager-runtime'
    if args.backend is not None and args.action != 'headers':
        raise SafeError('BACKEND_ONLY_FOR_HEADERS')
    if args.action == "setup-token":
        setup_token(args.runtime)
        print("TOKEN_READY")
    elif args.action == "headers":
        headers(args.runtime / "token", backend=args.backend)
    elif args.action == "launch":
        return launch(args.config, args.runtime / "policy.json", args.runtime / "token", args.node, args.repo)
    elif args.action == "rollback":
        rollback(args.config, args.runtime / "transaction.json")
        print("ROLLBACK_COMPLETE")
    else:
        text = read_private(args.config).decode("utf-8")
        manager = registration(sys.executable, Path(__file__).resolve(), args.runtime)
        proposal = propose(text, manager)
        if args.action == "preview":
            # This is a change-only diff, never a contextual diff containing env.
            print("beforeHash=" + proposal["beforeHash"])
            print("+ " + manager.replace("\n", "\n+ ").rstrip("+ "))
            print("grafana-dev.enabled: true (explicit or default) -> false")
        else:
            if args.expected_hash != proposal["beforeHash"]:
                raise SafeError("REVIEWED_HASH_REQUIRED")
            apply(args.config, args.runtime / "transaction.json", proposal)
            print("APPLY_COMPLETE")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Never print parser data, transport exceptions or secret-bearing source.
        print("PILOT_OPERATION_FAILED", file=sys.stderr)
        raise SystemExit(1)
