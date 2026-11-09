"""Portable orchestration of reviewed artifacts and the existing owned runtime.

Only source references and authenticated admission metadata are persisted here.
Backend credentials and effective environments remain in memory or stdin pipes.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import socket
import signal
import time
import urllib.error
import urllib.request
from dataclasses import asdict, replace
from types import SimpleNamespace

import migrate
from pilot import SafeError, private, read_private, read_token, setup_token, write_private

ROUTES_DOMAIN = "personal-mcp-manager/routes/v1"
REGISTRY_DOMAIN = "personal-mcp-manager/registry/v3"
FAMILIES = frozenset({"grafana", "langfuse", "loki", "mysql"})
MAX_RUNTIME_METADATA = 8 * 1024 * 1024


def _authenticated(path: Path, domain: str, token: str) -> dict:
    try:
        from owner_watch import strict_json
        from source_inputs import protected_read
        value = strict_json(protected_read(path, MAX_RUNTIME_METADATA, private=True))
        if type(value) is not dict or set(value) != {"payload", "mac"} or type(value["payload"]) is not dict:
            raise ValueError()
        expected = migrate.mac({"domain": domain, "payload": value["payload"]}, token)
        if not isinstance(value["mac"], str) or not hmac.compare_digest(expected, value["mac"]):
            raise ValueError()
        return value["payload"]
    except Exception:
        code = "ROUTES_AUTHENTICATION_FAILED" if domain == ROUTES_DOMAIN else "REGISTRY_AUTHENTICATION_FAILED"
        raise SafeError(code) from None


def _publish_authenticated(path: Path, payload: dict, domain: str, token: str) -> None:
    record = {"payload": payload, "mac": migrate.mac({"domain": domain, "payload": payload}, token)}
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_RUNTIME_METADATA:
        raise SafeError("RUNTIME_METADATA_LIMIT")
    write_private(path, raw, exclusive=True)
    if _authenticated(path, domain, token) != payload:
        raise SafeError("RUNTIME_READBACK_FAILED")


def read_routes(context, token: str) -> list[dict]:
    payload = _authenticated(context.runtime / "routes.json", ROUTES_DOMAIN, token)
    if set(payload) != {"version", "routes"} or payload["version"] != 1 or type(payload["routes"]) is not list or not 1 <= len(payload["routes"]) <= 64:
        raise SafeError("ROUTES_INVALID")
    routes = payload["routes"]
    if any(type(row) is not dict or row.get("family") not in FAMILIES for row in routes):
        raise SafeError("ROUTES_INVALID")
    identifiers = [row.get("route_id") for row in routes]
    from owner_watch import BACKEND
    if any(not isinstance(name, str) or not BACKEND.fullmatch(name) for name in identifiers) or len(set(identifiers)) != len(identifiers):
        raise SafeError("ROUTES_INVALID")
    return routes


def requires_owner(context, backend: str) -> bool:
    token = read_token(context.runtime / "token")
    matches = [row for row in read_routes(context, token) if row["route_id"] == backend]
    if len(matches) != 1:
        raise SafeError("ROUTE_NOT_ADMITTED")
    return matches[0]["family"] != "grafana"


def write_registry(context, records: dict, token: str) -> None:
    if type(records) is not dict or not 1 <= len(records) <= 64:
        raise SafeError("REGISTRY_INVALID")
    _publish_authenticated(context.runtime / "registry.json", {"version": 3, "profiles": records}, REGISTRY_DOMAIN, token)


def read_registry(context, token: str) -> dict:
    payload = _authenticated(context.runtime / "registry.json", REGISTRY_DOMAIN, token)
    if set(payload) != {"version", "profiles"} or payload["version"] != 3 or type(payload["profiles"]) is not dict or not 1 <= len(payload["profiles"]) <= 64:
        raise SafeError("REGISTRY_INVALID")
    return payload["profiles"]


def manifest_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _candidate_with_profile(candidate, profile_id):
    return SimpleNamespace(ref=candidate.ref, family=candidate.family,
        enabled=candidate.enabled, source=candidate.source, policy=candidate.policy,
        blockers=candidate.blockers, profile_id=profile_id)


def _credential_free_metadata(value: dict, source: dict) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    for key, secret in source.get("env", {}).items():
        if any(marker in key.upper() for marker in ("PASSWORD", "_PASS", "TOKEN", "SECRET", "_KEY")):
            if isinstance(secret, str) and secret and (
                    secret.encode() in data or json.dumps(secret, ensure_ascii=False)[1:-1].encode() in data):
                raise SafeError("CREDENTIAL_IN_METADATA")
    return data


def prepare_runtime(context, selected, artifacts, *, provisioner=None) -> dict:
    """Provision every selected source before publishing authenticated routing."""
    from client_sources import build_route_map, source_key
    from manage import ownership_empty
    if provisioner is None:
        from portable_family import provision_portable
        provisioner = provision_portable
    runtime = Path(context.runtime)
    runtime.mkdir(mode=0o700, exist_ok=True)
    private(runtime, directory=True)
    setup_token(runtime)
    token = read_token(runtime / "token")
    if any((runtime / name).exists() or (runtime / name).is_symlink() for name in ("registry.json", "routes.json", "owner.sock")):
        raise SafeError("PREPARED_RUNTIME_EXISTS")
    selected = list(selected)
    envelope = build_route_map(selected, token)
    rows = envelope["payload"]["routes"]
    candidates = {source_key(candidate, token): candidate for candidate in selected}
    manifests = runtime / "manifests"
    manifests.mkdir(mode=0o700, exist_ok=True)
    private(manifests, directory=True)
    ownership = runtime / "ownership"
    ownership.mkdir(mode=0o700, exist_ok=True)
    ownership_empty(ownership)
    records = {}
    for route in rows:
        candidate = candidates[route["source_hmac"]]
        if route["family"] not in artifacts:
            raise SafeError("FAMILY_ARTIFACT_NOT_ADMITTED")
        artifact = artifacts[route["family"]]
        stage = Path(tempfile.mkdtemp(prefix=".provision-", dir=runtime)).resolve()
        stage.chmod(0o700)
        write_private(stage / "token", token.encode(), exclusive=True)
        (stage / "manifests").mkdir(mode=0o700)
        route_id = route["route_id"]
        portable = _candidate_with_profile(candidate, route["profile_id"])
        metadata = provisioner(context, portable, artifact, route_id, stage, token)
        ownership_empty(stage / "ownership")
        raw = read_private(stage / "manifests" / (route_id + ".json"))
        manifest = json.loads(raw)
        if manifest.get("backendId") != route_id or manifest.get("fingerprint") != metadata.get("fingerprint"):
            raise SafeError("PROVISION_MANIFEST_MISMATCH")
        record = {"route": route, "artifact": artifact, "metadata": metadata,
                  "manifestSha256": manifest_digest(raw)}
        _credential_free_metadata(record, candidate.source)
        _credential_free_metadata(manifest, candidate.source)
        write_private(manifests / (route_id + ".json"), raw, exclusive=True)
        records[route_id] = record
    write_registry(context, records, token)
    _publish_authenticated(runtime / "routes.json", envelope["payload"], ROUTES_DOMAIN, token)
    return {"profile_count": len(records), "status": "PREPARED"}


def _resolve_candidate(context, route, token, source_resolver):
    from client_sources import SourceCandidate, source_key, source_ref_from_dict
    from installation_context import read_install_key
    ref = source_ref_from_dict(route["source_ref"])
    source = source_resolver(context, ref, install_key=read_install_key(context))
    policy = {key: value for key, value in source.items() if key in migrate.POLICY}
    candidate = SourceCandidate(ref, route["family"], True, source, policy)
    if not hmac.compare_digest(source_key(candidate, token), route["source_hmac"]):
        raise SafeError("RUNTIME_SOURCE_CHANGED")
    return _candidate_with_profile(candidate, route["profile_id"])


def validate_policies(context, policies: dict) -> None:
    result = subprocess.run([str(context.node), str(context.release / "scripts/portable-verify-config.mjs"),
        "--runtime", str(context.runtime)], input=json.dumps(policies).encode(),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, cwd=context.release,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    if result.returncode or len(result.stdout) > 1024:
        raise SafeError("RUNTIME_POLICY_VERIFICATION_FAILED")
    try:
        value = json.loads(result.stdout)
    except ValueError:
        raise SafeError("RUNTIME_POLICY_VERIFICATION_FAILED") from None
    if value != {"status": "PASS", "profiles": len(policies)}:
        raise SafeError("RUNTIME_POLICY_VERIFICATION_FAILED")


def load_runtime(context, *, source_resolver=None, policy_builder=None, policy_validator=None):
    """Authenticate all persistent metadata before resolving original sources."""
    token = read_token(context.runtime / "token")
    routes = read_routes(context, token)
    records = read_registry(context, token)
    if set(records) != {row["route_id"] for row in routes}:
        raise SafeError("RUNTIME_ROUTE_MISMATCH")
    for route in routes:
        record = records[route["route_id"]]
        if record.get("route") != route:
            raise SafeError("RUNTIME_ROUTE_MISMATCH")
        raw = read_private(context.runtime / "manifests" / (route["route_id"] + ".json"))
        if manifest_digest(raw) != record.get("manifestSha256"):
            raise SafeError("RUNTIME_MANIFEST_CHANGED")
    if source_resolver is None:
        from client_projection import resolve_native_source
        source_resolver = resolve_native_source
    if policy_builder is None:
        from portable_family import build_portable_policy
        policy_builder = build_portable_policy
    candidates, policies = {}, {}
    for route in routes:
        route_id = route["route_id"]
        candidate = _resolve_candidate(context, route, token, source_resolver)
        candidates[route_id] = candidate
        policies[route_id] = policy_builder(context, candidate, records[route_id]["artifact"],
                                           route_id, context.runtime, token)
    (policy_validator or validate_policies)(context, policies)
    return policies, candidates, records


def _process_record(child, identity) -> dict:
    node = identity.process(child.pid)
    launcher = identity.process(os.getpid())
    return {"version": 1, "pid": node.pid, "uid": node.uid,
            "start_seconds": node.seconds, "start_microseconds": node.microseconds,
            "executable": node.path, "launcher_pid": launcher.pid,
            "launcher_start_seconds": launcher.seconds,
            "launcher_start_microseconds": launcher.microseconds,
            "launcher_executable": launcher.path}


def run_service(context) -> int:
    """Launch the existing supervised daemon with portable, source-bound policies."""
    import manage
    from owner_watch import NativeIdentity
    from portable_owner_environment import PortableEnvironmentGuard
    from source_environment import KernelEnvironmentReader
    from client_projection import resolve_native_source
    policies, candidates, records = load_runtime(context)
    _check_owner_socket_path(context, session=any(policy.get("scope") == "session" for policy in policies.values()))
    identity = NativeIdentity()
    clients = {kind: frozenset(str(path) for client in context.clients if client.kind == kind
                               for path in client.owner_executables) for kind in ("claude", "codex")}
    def client_kind(path):
        return next((kind for kind, paths in clients.items() if path in paths), None)
    token = read_token(context.runtime / "token")
    def verify_source(backend):
        _resolve_candidate(context, records[backend]["route"], token, resolve_native_source)
    session_routes = {backend: {"family": candidates[backend].family,
        "source": candidates[backend].source, "expected_env": policy["env"],
        "clients": (candidates[backend].ref.client,)}
        for backend, policy in policies.items() if policy.get("scope") == "session"}
    guard = PortableEnvironmentGuard(session_routes, identity=identity,
        reader=KernelEnvironmentReader(identity=identity), client_kind=client_kind,
        source_verifier=verify_source) if session_routes else None
    process_path = context.runtime / "manager-process.json"
    if process_path.exists() or process_path.is_symlink():
        raise SafeError("MANAGER_PROCESS_RECORD_EXISTS")
    process_bytes = None
    def started(child):
        nonlocal process_bytes
        process_bytes = json.dumps(_process_record(child, identity), sort_keys=True).encode()
        write_private(process_path, process_bytes, exclusive=True)
    result = manage.launch_backends(policies, context.runtime, context.release, str(context.node),
        context.runtime / "manifests", port=context.port, on_started=started,
        owner_paths=tuple(sorted(clients["codex"])), claude_paths=tuple(sorted(clients["claude"])),
        portable_environment_guard=guard)
    manage.ownership_empty(context.runtime / "ownership")
    if process_bytes is not None:
        if read_private(process_path) != process_bytes:
            raise SafeError("MANAGER_PROCESS_RECORD_CHANGED")
        process_path.unlink()
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _candidate_environment():
    # Loki's template binds reviewed native inheritance. The candidate must see
    # the same inputs as provisioning, through memory only, rather than silently
    # dropping HOME/proxy/TLS inputs before authenticating its policy manifest.
    from loki_profile import INHERITED
    from pilot import ENV_KEYS
    allowed = INHERITED | ENV_KEYS
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.setdefault("PATH", "/usr/bin:/bin")
    environment.setdefault("LANG", "C")
    return environment


def _check_owner_socket_path(context, *, session):
    # Darwin sockaddr_un.sun_path is 104 bytes, including the terminating NUL.
    if session and len(os.fsencode(context.runtime / "owner.sock")) >= 104:
        raise SafeError("OWNER_SOCKET_PATH_TOO_LONG")


def _candidate_status(context) -> dict:
    token = read_token(context.runtime / "token")
    request = urllib.request.Request(f"http://127.0.0.1:{context.port}/_control/status",
        headers={"Authorization": "Bearer " + token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=1) as response:
        if response.status != 200:
            raise SafeError("CANDIDATE_NOT_HEALTHY")
        raw = response.read(131073)
        if len(raw) > 131072:
            raise SafeError("CANDIDATE_NOT_HEALTHY")
        return json.loads(raw)


def verify_candidate(context, selected) -> dict:
    """Boot an unused candidate on a distinct port and prove owned shutdown."""
    import manage
    _check_owner_socket_path(context, session=any(candidate.family != "grafana" for candidate in selected))
    manage.ownership_empty(context.runtime / "ownership")
    if (context.runtime / "owner.sock").exists() or (context.runtime / "manager-process.json").exists():
        raise SafeError("CANDIDATE_OWNERSHIP_NOT_EMPTY")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    if port == context.port:
        raise SafeError("CANDIDATE_PORT_CONFLICT")
    candidate = replace(context, port=port)
    payload = json.dumps(asdict(candidate), default=str).encode()
    child = subprocess.Popen([str(context.python), str(context.release / "scripts/portable_engine.py"), "--candidate"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=context.release, env=_candidate_environment())
    ready = False
    try:
        child.stdin.write(payload)
        child.stdin.close()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise SafeError("CANDIDATE_START_FAILED")
            try:
                status = _candidate_status(candidate)
                if (status.get("draining") is not False or status.get("quiescent") is not True
                        or status.get("retained", 0) != 0
                        or len(status.get("trafficCounters", {}).get("profiles", {})) != len(selected)):
                    raise SafeError("CANDIDATE_NOT_QUIESCENT")
                ready = True
                break
            except urllib.error.URLError as error:
                if not isinstance(error.reason, ConnectionRefusedError):
                    raise SafeError("CANDIDATE_HEALTH_FAILED") from None
            time.sleep(0.1)
        if not ready:
            raise SafeError("CANDIDATE_START_TIMEOUT")
    finally:
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
        try:
            code = child.wait(timeout=25)
        except subprocess.TimeoutExpired:
            raise SafeError("CANDIDATE_CLEANUP_UNPROVEN") from None
        manage.ownership_empty(context.runtime / "ownership")
        if (context.runtime / "owner.sock").exists() or (context.runtime / "manager-process.json").exists():
            raise SafeError("CANDIDATE_CLEANUP_UNPROVEN")
        if ready and code != 0:
            raise SafeError("CANDIDATE_CLEANUP_UNPROVEN")
    return {"status": "PASS", "profiles": len(selected), "service": "PASS", "cleanup": "PASS"}


def _decode_candidate(value: dict):
    from installation_context import ClientPaths, InstallContext
    expected = {"version", "root", "release", "runtime", "artifacts", "python", "node", "port", "clients"}
    if type(value) is not dict or set(value) != expected:
        raise SafeError("CANDIDATE_INPUT_INVALID")
    clients = tuple(ClientPaths(row["kind"], Path(row["config"]),
        None if row["settings"] is None else Path(row["settings"]),
        tuple(Path(path) for path in row["plugin_roots"]),
        tuple(Path(path) for path in row["owner_executables"])) for row in value["clients"])
    return InstallContext(value["version"], *(Path(value[key]) for key in
        ("root", "release", "runtime", "artifacts", "python", "node")), value["port"], clients)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments != ["--candidate"]:
        raise SafeError("PORTABLE_ENGINE_ARGUMENTS_INVALID")
    raw = sys.stdin.buffer.read(262145)
    if len(raw) > 262144:
        raise SafeError("CANDIDATE_INPUT_INVALID")
    from owner_watch import strict_json
    return run_service(_decode_candidate(strict_json(raw)))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("PORTABLE_ENGINE_FAILED", file=sys.stderr)
        raise SystemExit(1)
