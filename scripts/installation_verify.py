"""Redacted installation health checks and fixed, read-only provider probes."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import urllib.error
import urllib.parse
import urllib.request

import migrate
from pilot import SafeError, read_token


MAX_MCP_RESPONSE = 262144
MCP_PROTOCOL_VERSION = "2025-03-26"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _check(status, reason=None, **fields):
    result = {"status": status}
    if reason is not None:
        result["reason"] = reason
    result.update(fields)
    return result


def _error_code(error):
    value = str(error)
    return value if value.isupper() and len(value) <= 96 else "CHECK_FAILED"


def _load_descriptor(context):
    from installation_context import load_context
    actual = load_context(Path(context.root) / "installation.json")
    names = ("version", "root", "release", "runtime", "artifacts", "python", "node", "port", "clients")
    if any(getattr(actual, name) != getattr(context, name) for name in names):
        raise SafeError("INSTALLATION_CONTEXT_MISMATCH")
    return actual


def _load_runtime(context):
    from portable_engine import read_registry, read_routes
    token = read_token(Path(context.runtime) / "token")
    routes = read_routes(context, token)
    registry = read_registry(context, token)
    route_ids = {route["route_id"] for route in routes}
    if route_ids != set(registry):
        raise SafeError("RUNTIME_ROUTE_MISMATCH")
    for route in routes:
        record = registry[route["route_id"]]
        if type(record) is not dict or record.get("route") != route:
            raise SafeError("RUNTIME_ROUTE_MISMATCH")
    return token, routes, registry


def _check_installed(context):
    _load_descriptor(context)
    token, routes, registry = _load_runtime(context)
    if not routes:
        raise SafeError("RUNTIME_ROUTES_EMPTY")
    return token, routes, registry


def _check_catalog(context, routes, registry):
    from source_inputs import protected_read, strict_json
    stateful = []
    for route in routes:
        route_id = route["route_id"]
        record = registry[route_id]
        raw = protected_read(Path(context.runtime) / "manifests" / (route_id + ".json"),
                             4 * 1048576, private=True, error_code="MANIFEST_INVALID")
        if hashlib.sha256(raw).hexdigest() != record.get("manifestSha256"):
            raise SafeError("MANIFEST_CHANGED")
        try:
            manifest = strict_json(raw.decode("utf-8", errors="strict"))
        except Exception:
            raise SafeError("MANIFEST_INVALID") from None
        if (type(manifest) is not dict or manifest.get("backendId") != route_id
                or not isinstance(manifest.get("allowedTools"), list)
                or not isinstance(manifest.get("description"), dict)):
            raise SafeError("MANIFEST_INVALID")
        tools = manifest["description"].get("tools")
        if (type(tools) is not list or not tools
                or [row.get("name") for row in tools if type(row) is dict] != manifest["allowedTools"]):
            raise SafeError("MANIFEST_CATALOG_INVALID")
        if route.get("family") != "grafana":
            stateful.append(route["route_id"])
    if stateful:
        try:
            from owner_watch import request_owner
            for route_id in stateful:
                request_owner(Path(context.runtime), route_id)
        except Exception:
            return _check("NOT_TESTED", "SIGNED_CLIENT_REQUIRED", routes=len(routes))
    return {route["route_id"]: registry[route["route_id"]] for route in routes}


def _check_sources(context, routes, token):
    from client_projection import resolve_native_source
    from client_sources import SourceCandidate, source_key, source_ref_from_dict
    from installation_context import read_install_key
    install_key = read_install_key(context)
    for route in routes:
        ref = source_ref_from_dict(route["source_ref"])
        source = resolve_native_source(context, ref, install_key=install_key)
        candidate = SourceCandidate(ref, route["family"], True, source,
            {key: value for key, value in source.items() if key in migrate.POLICY})
        if not hmac.compare_digest(source_key(candidate, token), route["source_hmac"]):
            raise SafeError("RUNTIME_SOURCE_CHANGED")
    return True


def _check_ownership(context):
    from manage import ownership_empty
    directory = Path(context.runtime) / "ownership"
    if not directory.exists() or directory.is_symlink():
        raise SafeError("OWNERSHIP_DIRECTORY_INVALID")
    # A healthy running manager can retain session leases. Doctor performs
    # read-only structural checks and never reaps ownership records.
    try:
        for child in directory.iterdir():
            if child.name not in {"sessions", "session-invalidations"}:
                raise ValueError()
            info = child.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.getuid() or info.st_mode & 0o022):
                raise ValueError()
            entries = list(child.iterdir())
            if child.name == "session-invalidations" and entries:
                return _check("NOT_TESTED", "OWNERSHIP_STATE_PRESENT")
            for lease in entries:
                if not re.fullmatch(r"[a-f0-9]{64}", lease.name):
                    raise ValueError()
                lease_info = lease.lstat()
                if (not stat.S_ISDIR(lease_info.st_mode) or stat.S_ISLNK(lease_info.st_mode)
                        or lease_info.st_uid != os.getuid() or lease_info.st_mode & 0o022
                        or next(lease.iterdir(), None) is not None):
                    raise ValueError()
            if entries:
                return _check("NOT_TESTED", "OWNERSHIP_ACTIVE")
    except Exception:
        raise SafeError("OWNERSHIP_RESIDUE") from None
    ownership_empty(directory)
    return True


def _probe_for_route(route):
    family = route.get("family")
    profile = route.get("profile_id")
    if family == "grafana" and profile in {"grafana-dev", "grafana-prd", "grafana-tools"}:
        return "list_datasources", {}
    if family == "loki" and profile in {"loki-stg", "loki-prd", "loki-tools"}:
        return "get_labels", {}
    if family == "mysql" and profile in {
        "mysql-primary-dev", "mysql-secondary-dev", "mysql-imported-dev",
        "mysql-plugin-dev",
    }:
        return "mysql_query", {"sql": "SELECT 1"}
    if family == "langfuse" and profile in {
        "langfuse-traces", "langfuse-api-dev", "agent-dev",
        "worker-dev", "api-traces", "worker-prod",
    }:
        return "fetch_traces", {"age": 10}
    return None


def _http_mcp(context, route_id, token, owner, session_id, body, *, method="POST"):
    path = "/mcp/" + urllib.parse.quote(route_id, safe="")
    headers = {
        "Authorization": "Bearer " + token,
        "Host": "127.0.0.1:" + str(context.port),
        "Accept": "application/json, text/event-stream",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    if owner is not None:
        headers["X-Personal-MCP-Owner"] = owner
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    data = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{context.port}{path}",
                                     data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            raw = response.read(MAX_MCP_RESPONSE + 1)
            if len(raw) > MAX_MCP_RESPONSE:
                raise SafeError("MCP_RESPONSE_TOO_LARGE")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if not raw:
                payload = None
            elif content_type == "application/json":
                payload = _strict_json(raw)
            elif content_type == "text/event-stream":
                payload = _sse_payload(raw)
            else:
                raise SafeError("MCP_RESPONSE_INVALID")
            return payload, response.headers, response.status
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise SafeError("MCP_REDIRECT_REFUSED") from None
        if error.code in (401, 403):
            raise SafeError("MCP_AUTHENTICATION_FAILED") from None
        raise SafeError("MCP_HTTP_FAILED") from None
    except SafeError:
        raise
    except (urllib.error.URLError, OSError, TimeoutError):
        raise SafeError("MCP_UNAVAILABLE") from None
    except Exception:
        raise SafeError("MCP_RESPONSE_INVALID") from None


def _strict_json(raw):
    from owner_watch import strict_json
    try:
        return strict_json(raw.decode("utf-8", errors="strict"))
    except Exception:
        raise SafeError("MCP_RESPONSE_INVALID") from None


def _sse_payload(raw):
    data = []
    try:
        for line in raw.decode("utf-8", errors="strict").splitlines():
            if line.startswith("data:"):
                data.append(_strict_json(line[5:].lstrip()))
    except UnicodeError:
        raise SafeError("MCP_RESPONSE_INVALID") from None
    if len(data) != 1 or type(data[0]) is not dict:
        raise SafeError("MCP_RESPONSE_INVALID")
    return data[0]


def _mcp_rpc(context, route, token, owner, session_id, message, *, method="POST"):
    return _http_mcp(context, route["route_id"], token, owner, session_id, message, method=method)


def _result(payload, request_id):
    if (type(payload) is not dict or payload.get("jsonrpc") != "2.0"
            or payload.get("id") != request_id):
        raise SafeError("MCP_RESPONSE_INVALID")
    if "error" in payload:
        raise SafeError("MCP_RPC_FAILED")
    result = payload.get("result")
    if type(result) is not dict:
        raise SafeError("MCP_RESPONSE_INVALID")
    return result


def _reviewed_read_tool(manifest, tool_name):
    description = manifest.get("description", {})
    tools = description.get("tools", []) if type(description) is dict else []
    matches = [tool for tool in tools if type(tool) is dict and tool.get("name") == tool_name]
    if len(matches) != 1:
        return False
    return matches[0].get("annotations", {}).get("readOnlyHint") is True


def _safe_read_route(context, route, token, manifest):
    probe = _probe_for_route(route)
    if probe is None:
        return _check("UNSUPPORTED", "SAFE_READ_UNSUPPORTED", route_id=route.get("route_id"))
    family = route["family"]
    owner = None
    if family != "grafana":
        try:
            from owner_watch import request_owner
            owner = request_owner(Path(context.runtime), route["route_id"])
        except Exception:
            return _check("NOT_TESTED", "SIGNED_CLIENT_REQUIRED", route_id=route["route_id"])
    tool, arguments = probe
    if not _reviewed_read_tool(manifest, tool):
        return _check("UNSUPPORTED", "REVIEWED_READ_TOOL_UNAVAILABLE", route_id=route["route_id"])
    session_id = None
    cleanup_ok = True
    failure = None
    try:
        initialized, headers, status = _mcp_rpc(context, route, token, owner, None, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "personal-mcp-manager-doctor", "version": "1"},
            }})
        session_id = headers.get("Mcp-Session-Id")
        if not isinstance(session_id, str) or not session_id or status != 200:
            raise SafeError("MCP_SESSION_INVALID")
        _result(initialized, 1)
        _, _, status = _mcp_rpc(context, route, token, owner, session_id, {
            "jsonrpc": "2.0", "method": "notifications/initialized",
            "params": {},
        })
        if status not in (200, 202):
            raise SafeError("MCP_INITIALIZATION_FAILED")
        listed, _, _ = _mcp_rpc(context, route, token, owner, session_id, {
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        })
        actual_tools = _result(listed, 2).get("tools")
        expected_tools = manifest.get("description", {}).get("tools")
        if actual_tools != expected_tools:
            raise SafeError("MCP_CATALOG_CHANGED")
        called, _, _ = _mcp_rpc(context, route, token, owner, session_id, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        })
        result = _result(called, 3)
        if result.get("isError") is True:
            raise SafeError("PROVIDER_READ_FAILED")
    except SafeError as error:
        code = str(error)
        status = "NEEDS_AUTH" if code == "PROVIDER_AUTH_REQUIRED" else "FAIL"
        failure = _check(status, code, route_id=route.get("route_id"))
    except Exception as error:
        failure = _check("FAIL", _error_code(error), route_id=route.get("route_id"))
    finally:
        if session_id is not None:
            try:
                _, _, cleanup_status = _mcp_rpc(context, route, token, owner, session_id, None,
                                                method="DELETE")
                cleanup_ok = cleanup_status in (200, 202, 204)
            except SafeError:
                cleanup_ok = False
    if not cleanup_ok:
        return _check("FAIL", "MCP_SESSION_CLEANUP_UNPROVEN", route_id=route.get("route_id"))
    if failure is not None:
        return failure
    return _check("PASS", route_id=route.get("route_id"), tool=tool)


def _perform_safe_reads(context, routes, token, registry):
    from source_inputs import protected_read, strict_json
    results = []
    for route in routes:
        route_id = route["route_id"]
        raw = protected_read(Path(context.runtime) / "manifests" / (route_id + ".json"),
                             4 * 1048576, private=True, error_code="MANIFEST_INVALID")
        try:
            manifest = strict_json(raw.decode("utf-8", errors="strict"))
        except Exception:
            results.append(_check("FAIL", "MANIFEST_INVALID", route_id=route_id))
            continue
        results.append(_safe_read_route(context, route, token, manifest))
    statuses = {row["status"] for row in results}
    if "FAIL" in statuses:
        overall = "FAIL"
    elif "NEEDS_AUTH" in statuses:
        overall = "NEEDS_AUTH"
    elif statuses == {"PASS"}:
        overall = "PASS"
    elif statuses == {"UNSUPPORTED"}:
        overall = "UNSUPPORTED"
    else:
        overall = "NOT_TESTED"
    return _check(overall, routes=results)


def verify_installation_details(context, *, safe_reads=False):
    """Return structured, credential-free checks; upstream reads are opt-in."""
    checks = {}
    try:
        token, routes, registry = _check_installed(context)
        checks["installed"] = _check("PASS")
    except Exception as error:
        token, routes, registry = None, [], {}
        checks["installed"] = _check("FAIL", _error_code(error))

    if checks["installed"]["status"] == "PASS":
        try:
            catalog = _check_catalog(context, routes, registry)
            checks["catalog"] = (catalog if type(catalog) is dict and "status" in catalog
                                 else _check("PASS", routes=len(routes)))
        except Exception as error:
            manifests = {}
            checks["catalog"] = _check("FAIL", _error_code(error))
        try:
            _check_sources(context, routes, token)
            checks["source"] = _check("PASS", routes=len(routes))
        except Exception as error:
            checks["source"] = _check("FAIL", _error_code(error))
        try:
            ownership = _check_ownership(context)
            checks["ownership"] = ownership if isinstance(ownership, dict) else _check("PASS")
        except Exception as error:
            checks["ownership"] = _check("FAIL", _error_code(error))
        try:
            import service_install
            service = service_install.verify_service(context)
            checks["service"] = _check(service.get("status", "FAIL"), service.get("reason"))
        except Exception as error:
            checks["service"] = _check("FAIL", _error_code(error))
        if not safe_reads:
            checks["safeRead"] = _check("NOT_TESTED", "DOCTOR_SAFE_READS_NOT_REQUESTED")
        elif checks["service"]["status"] != "PASS":
            checks["safeRead"] = _check("NOT_TESTED", "SERVICE_NOT_READY")
        else:
            try:
                checks["safeRead"] = _perform_safe_reads(context, routes, token, registry)
            except Exception as error:
                checks["safeRead"] = _check("FAIL", _error_code(error))
    else:
        for name in ("service", "catalog", "source", "ownership"):
            checks[name] = _check("NOT_TESTED", "INSTALLATION_NOT_VERIFIED")
        checks["safeRead"] = _check("NOT_TESTED", "INSTALLATION_NOT_VERIFIED")

    core = ("installed", "service", "catalog", "source", "ownership")
    if any(checks[name]["status"] == "FAIL" for name in core) or checks["safeRead"]["status"] == "FAIL":
        overall = "FAIL"
    elif checks["safeRead"]["status"] == "NEEDS_AUTH":
        overall = "NEEDS_AUTH"
    elif all(checks[name]["status"] == "PASS" for name in core):
        overall = "PASS"
    else:
        overall = "NOT_TESTED"
    return {"status": overall, "checks": checks}


def verify_installation(context, *, safe_reads=False):
    """Return the stable six-check enum map consumed by the installer coordinator."""
    details = verify_installation_details(context, safe_reads=safe_reads)
    result = {}
    for name in ("installed", "service", "catalog", "safeRead", "source", "ownership"):
        check = details["checks"][name]
        item = {"status": check["status"]}
        if "reason" in check:
            item["reason"] = check["reason"]
        routes = check.get("routes")
        if type(routes) is list:
            item["routes"] = len(routes)
        elif type(routes) is int:
            item["routes"] = routes
        result[name] = item
    return result

