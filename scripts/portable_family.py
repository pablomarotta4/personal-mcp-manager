"""Policy templates for verified artifacts, with source values kept in memory."""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess

import migrate
from pilot import SafeError, private


def _fail():
    raise SafeError("PORTABLE_FAMILY_POLICY_INVALID")


def _source(candidate):
    source = deepcopy(candidate.source)
    if source.get("type", "stdio") != "stdio":
        _fail()
    source.pop("type", None)
    migrate.validate(source)
    if set(source) - migrate.POLICY - {"command", "args", "env", "cwd"} or source.get("enabled", True) is not True:
        _fail()
    source.pop("enabled", None)
    return source


def _private_tree(root: Path, parts: tuple[str, ...]) -> Path:
    private(root, directory=True)
    current = root
    for part in parts:
        current = current / part
        current.mkdir(mode=0o700, exist_ok=True)
        private(current, directory=True)
        if current.resolve(strict=True) != current:
            _fail()
    return current


def _timeouts(source):
    if "startup_timeout_ms" in source and "startup_timeout_sec" in source:
        _fail()
    startup = source.get("startup_timeout_ms", source.get("startup_timeout_sec", 30) * 1000)
    tool = source.get("tool_timeout_sec", 60) * 1000
    if any(type(value) not in (int, float) or not 20 <= value <= 600000 or int(value) != value for value in (startup, tool)):
        _fail()
    return {"startupTimeoutMs": int(startup), "toolTimeoutMs": int(tool)}


def build_portable_policy(context, candidate, artifact, route_id, runtime, token,
                          *, admission_verifier=None, owner_environment=None):
    if admission_verifier is None:
        from artifact_install import verify_artifact_admission
        admission_verifier = verify_artifact_admission
    admission_verifier(context, artifact)
    profile = candidate.profile_id
    if (artifact.get("family") != candidate.family or profile not in artifact.get("profileIds", [])
            or not isinstance(route_id, str) or not (route_id == profile or re.fullmatch(re.escape(profile) + r"-[0-9a-f]{12}", route_id))):
        _fail()
    source = _source(candidate)
    root = Path(artifact["artifactRoot"])
    if not root.is_absolute() or root.name != artifact["closureDigest"]:
        _fail()
    tools = [tool["name"] for tool in artifact["catalog"]["tools"]]
    if candidate.family == "langfuse" and "--read-only" in source.get("args", []):
        # In the pinned native package these prefixes are exactly WRITE_TOOLS.
        # Provisioning still compares the complete observed read-only catalog;
        # changed upstream behavior fails admission instead of adding access.
        tools = [name for name in tools if not name.startswith(("create_", "update_", "delete_"))]
    if not tools or len(set(tools)) != len(tools):
        _fail()
    shared = {"shared": True, "allowedTools": tools,
              "instruction": "Reviewed " + candidate.family + " " + profile}
    if route_id != profile:
        shared["reviewedProfile"] = profile
    family = candidate.family
    env = source.get("env", {})
    if family == "grafana":
        command = artifact["nativeCommand"]
        command = [command] if isinstance(command, str) else command
        if (source.get("command") != "uvx" or source.get("args") != ["mcp-grafana"]
                or len(command) != 1 or not Path(command[0]).is_relative_to(root)):
            _fail()
        expected = {"GRAFANA_URL", "GRAFANA_API_KEY" if profile == "grafana-tools" else "GRAFANA_SERVICE_ACCOUNT_TOKEN"}
        if set(env) != expected:
            _fail()
        # A relative cwd affects native behavior; never replace an unknown client
        # cwd with the manager's working directory for a shared backend.
        cwd = source.get("cwd")
        if cwd is None:
            cwd = str(candidate.ref.config.parent)
        return dict(command=command[0], args=[], cwd=cwd, env=deepcopy(env), **shared)
    common = dict(scope="session", closure={"root": str(root), "digest": artifact["closureDigest"]},
                  cwd=source.get("cwd", "/"), **({} if "cwd" in source else {"cwdMode": "client"}),
                  **_timeouts(source), **shared)
    if family == "loki":
        import loki_profile
        loki_profile.validate_source(source, profile)
        inherited = loki_profile.native_owner_environment(dict(os.environ) if owner_environment is None else owner_environment,
                                                         source.get("cwd", os.getcwd()))
        effective = loki_profile.source_policy(source, inherited)["env"]
        return dict(command=str(root / "runtime/bin/node"),
                    args=["--no-addons", "--no-global-search-paths", str(root / "app/node_modules/simple-loki-mcp/dist/src/index.js")],
                    env=effective, **common)
    if family == "mysql":
        import mysql_profile
        mysql_profile.validate_source(source, profile)
        if source.get("command") != "npx":
            raise SafeError("PORTABLE_CUSTOM_WRAPPER_UNAVAILABLE")
        return dict(command=str(root / "runtime/bin/node"),
                    args=["--no-addons", "--no-global-search-paths", str(root / "manager/mysql-entry.mjs")],
                    env=deepcopy(env), catalogMode="mysql-session", **common)
    if family == "langfuse":
        args = source.get("args", [])
        if (Path(source.get("command", "")).name != "uvx" or args[:3] != ["--with", "mcp[cli]<2", "langfuse-mcp"]
                or any(arg not in {"--read-only", "--no-log-to-console"} for arg in args[3:])
                or set(env) != {"LANGFUSE_HOST", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"}):
            _fail()
        data = _private_tree(Path(runtime), ("data", "langfuse", route_id))
        return dict(command=str(root / "python/bin/python3.13"),
            args=["-I", "-S", "-B", str(root / "manager/langfuse-entry.py"), "--manager-data-root", str(data),
                  "--manager-profile", profile, "--", *args[3:]], env=deepcopy(env), **common)
    raise SafeError("PORTABLE_FAMILY_UNAVAILABLE")


def provision_portable(context, candidate, artifact, route_id, stage, token):
    policy = build_portable_policy(context, candidate, artifact, route_id, context.runtime, token)
    probe_policy = deepcopy(policy)
    if policy.get("cwdMode") == "client":
        probe = _private_tree(Path(stage), ("probe",))
        probe_policy["cwd"] = str(probe)
        probe_policy.pop("cwdMode")
    if candidate.family == "mysql":
        from mysql_environment import INHERITED, effective_environment
        inherited = {key: value for key, value in os.environ.items() if key in INHERITED}
        probe_policy["env"], _ = effective_environment(candidate.source, inherited, probe_policy["cwd"])
    payload = {"policy": policy, "probePolicy": probe_policy, "artifact": artifact,
               "routeId": route_id, "hostPython": str(context.python)}
    try:
        result = subprocess.run([str(context.node), str(context.release / "scripts/provision-portable.mjs"),
            "--stage", str(stage)], input=json.dumps(payload).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=context.release, timeout=150,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        if result.returncode or len(result.stdout) > 32768:
            raise SafeError("PORTABLE_PROVISION_FAILED")
        metadata = json.loads(result.stdout)
        expected = {"allowedTools", "artifactSha256", "fingerprint", "closureDigest", "dependencyReportSha256"}
        if type(metadata) is not dict or set(metadata) != expected:
            raise SafeError("PORTABLE_PROVISION_FAILED")
        return metadata
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SafeError("PORTABLE_PROVISION_FAILED") from None
