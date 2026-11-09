"""Conditional client registration projection and offline native restoration."""
from contextlib import ExitStack
from copy import deepcopy
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import tempfile
import tomllib

import client_sources
import migrate
import source_inputs
from pilot import SafeError, locked


JOURNAL_NAME = "client-projections.jsonl"
JOURNAL_DOMAIN = b"personal-mcp-manager/client-projection/v1\n"
ROUTES_DOMAIN = "personal-mcp-manager/routes/v1"
MAX_JOURNAL_BYTES = 16 * 1048576
MAX_ROUTE_COUNT = 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
BARE_TOML_KEY = re.compile(r"[A-Za-z0-9_-]+\Z")


def _fail(code="PROJECTION_CONFLICT"):
    raise SafeError(code)


def _key_bytes(install_key):
    if isinstance(install_key, bytes) and len(install_key) >= 32:
        return install_key
    if isinstance(install_key, str) and HEX64.fullmatch(install_key):
        return bytes.fromhex(install_key)
    _fail("PROJECTION_KEY_INVALID")


def _json_bytes(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError):
        _fail("PROJECTION_RECORD_INVALID")


def _mac(value, install_key):
    return hmac.new(_key_bytes(install_key), JOURNAL_DOMAIN + _json_bytes(value), hashlib.sha256).hexdigest()


def _content_hmac(value, install_key, domain):
    return hmac.new(_key_bytes(install_key), domain + _json_bytes(value), hashlib.sha256).hexdigest()


def projection_journal_path(context):
    return Path(context.runtime) / JOURNAL_NAME


def _read_path(path, maximum, *, allow_missing=False):
    path = Path(path)
    try:
        path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return None
        _fail("PROJECTION_SOURCE_MISSING")
    return source_inputs.protected_read(path, maximum, error_code="PROJECTION_SOURCE_INVALID")


def _read_json(path, maximum, *, allow_missing=False):
    raw = _read_path(path, maximum, allow_missing=allow_missing)
    if raw is None:
        return None, {}
    try:
        value = source_inputs.strict_json(raw.decode("utf-8", errors="strict"))
    except Exception:
        _fail("PROJECTION_CONFIG_INVALID")
    if type(value) is not dict:
        _fail("PROJECTION_CONFIG_INVALID")
    return raw, value


def _serialize_json(value):
    try:
        return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError):
        _fail("PROJECTION_CONFIG_INVALID")


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_replace(path, before, after, *, create=False):
    """Replace one client file after an exact fresh-byte comparison."""
    path = Path(path)
    parent = path.parent
    try:
        parent_info = parent.lstat()
        if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid not in (0, os.getuid()) or parent_info.st_mode & 0o022:
            _fail("PROJECTION_PARENT_UNSAFE")
        try:
            current_info = path.lstat()
        except FileNotFoundError:
            if not create or before is not None:
                _fail("PROJECTION_CONCURRENT_CHANGE")
            mode = 0o600
        else:
            if (not stat.S_ISREG(current_info.st_mode) or current_info.st_uid != os.getuid()
                    or current_info.st_mode & 0o022):
                _fail("PROJECTION_CONFIG_UNSAFE")
            mode = stat.S_IMODE(current_info.st_mode)
            current = source_inputs.protected_read(path, MAX_JOURNAL_BYTES,
                                                   error_code="PROJECTION_CONFIG_UNSAFE")
            if current != before:
                _fail("PROJECTION_CONCURRENT_CHANGE")
        fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".manager-", dir=parent)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as stream:
                stream.write(after)
                stream.flush()
                os.fsync(stream.fileno())
            if before is None:
                if path.exists() or path.is_symlink():
                    _fail("PROJECTION_CONCURRENT_CHANGE")
            else:
                latest = source_inputs.protected_read(path, MAX_JOURNAL_BYTES,
                                                      error_code="PROJECTION_CONFIG_UNSAFE")
                if latest != before:
                    _fail("PROJECTION_CONCURRENT_CHANGE")
            os.replace(temporary, path)
            _sync_directory(parent)
            observed = source_inputs.protected_read(path, MAX_JOURNAL_BYTES,
                                                    error_code="PROJECTION_CONFIG_UNSAFE")
            if observed != after:
                _fail("PROJECTION_READBACK_FAILED")
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except SafeError:
        raise
    except Exception:
        raise SafeError("PROJECTION_WRITE_FAILED") from None


def _append_event(path, install_key, *, txid, phase, payload):
    path = Path(path)
    if not path.parent.is_dir() or path.parent.is_symlink():
        _fail("PROJECTION_JOURNAL_PATH_INVALID")
    parent = path.parent.lstat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        _fail("PROJECTION_JOURNAL_PATH_INVALID")
    record = {"version": 1, "txid": txid, "phase": phase, "payload": payload}
    envelope = {"record": record, "mac": _mac(record, install_key)}
    line = _json_bytes(envelope) + b"\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size + len(line) > MAX_JOURNAL_BYTES):
                _fail("PROJECTION_JOURNAL_INVALID")
            fcntl.flock(fd, fcntl.LOCK_EX)
            offset = 0
            while offset < len(line):
                offset += os.write(fd, line[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        _sync_directory(path.parent)
    except SafeError:
        raise
    except Exception:
        raise SafeError("PROJECTION_JOURNAL_WRITE_FAILED") from None


def _journal_events(path, install_key):
    raw = _read_path(path, MAX_JOURNAL_BYTES, allow_missing=True)
    if raw is None:
        return []
    try:
        from owner_watch import strict_json
        events = []
        for line in raw.splitlines():
            envelope = strict_json(line)
            if type(envelope) is not dict or set(envelope) != {"record", "mac"}:
                raise ValueError()
            record = envelope["record"]
            if (type(record) is not dict or set(record) != {"version", "txid", "phase", "payload"}
                    or record["version"] != 1 or not isinstance(record["txid"], str)
                    or not re.fullmatch(r"[0-9a-f]{32}", record["txid"])
                    or not isinstance(record["phase"], str) or type(record["payload"]) is not dict
                    or not isinstance(envelope["mac"], str)
                    or not hmac.compare_digest(envelope["mac"], _mac(record, install_key))):
                raise ValueError()
            events.append(record)
        return events
    except Exception:
        _fail("PROJECTION_JOURNAL_INVALID")


def _active_transaction(events):
    if not events:
        return None
    latest = events[-1]
    if latest["phase"] == "rolled-back":
        return None
    txid = latest["txid"]
    starts = [event for event in events if event["txid"] == txid and event["phase"] == "prepared"]
    if len(starts) != 1:
        _fail("PROJECTION_JOURNAL_INVALID")
    return starts[0]["payload"]


def _client(context, kind):
    matches = [client for client in context.clients if client.kind == kind]
    if len(matches) != 1:
        _fail("PROJECTION_CLIENT_INVALID")
    return matches[0]


def _settings_path(client):
    if client.kind != "claude":
        return None
    if client.settings is not None:
        return Path(client.settings)
    return Path(client.config).parent / ".claude" / "settings.json"


def _settings_value(path, name):
    _, settings = _read_json(path, 1048576, allow_missing=True)
    rows = settings.get("deniedMcpServers", [])
    if type(rows) is not list:
        _fail("CLAUDE_DENIALS_INVALID")
    return settings, ({"serverName": name} in rows or name in rows)


def _denial_present(settings, name):
    rows = settings.get("deniedMcpServers", [])
    if type(rows) is not list:
        _fail("CLAUDE_DENIALS_INVALID")
    return {"serverName": name} in rows or name in rows


def _ensure_settings_parent(path, client):
    path = Path(path)
    parent = path.parent
    allowed_parent = Path(client.config).parent / ".claude"
    if parent != allowed_parent:
        _fail("CLAUDE_SETTINGS_PATH_INVALID")
    if not parent.exists():
        if parent.is_symlink():
            _fail("CLAUDE_SETTINGS_PATH_INVALID")
        parent.mkdir(mode=0o700)
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or parent.resolve() != parent):
        _fail("CLAUDE_SETTINGS_PATH_INVALID")


def _toml_header_path(header):
    try:
        value = tomllib.loads("[" + header + "]\n")
    except Exception:
        return None
    path = []
    current = value
    while type(current) is dict and len(current) == 1:
        key, child = next(iter(current.items()))
        path.append(key)
        if child == {}:
            break
        current = child
    return tuple(path)


def _toml_headers(text):
    matches = list(migrate.HEADER.finditer(text))
    rows = []
    for index, match in enumerate(matches):
        path = _toml_header_path(match.group(1))
        if path is None:
            _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        rows.append((match, path, end))
    return rows


def _toml_key(key):
    return key if BARE_TOML_KEY.fullmatch(key) else json.dumps(key, ensure_ascii=True)


def _toml_header(path):
    return ".".join(_toml_key(part) for part in path)


def _toml_entry(text, path):
    parsed = tomllib.loads(text)
    value = parsed
    for key in path:
        if type(value) is not dict or key not in value:
            _fail("PROJECTION_SOURCE_MISSING")
        value = value[key]
    if type(value) is not dict:
        _fail("PROJECTION_SOURCE_INVALID")
    return value


def _toml_find_exact_table(text, path):
    rows = [row for row in _toml_headers(text) if row[1] == tuple(path)]
    if len(rows) > 1:
        _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    return rows[0] if rows else None


def _toml_set_enabled(text, path, value):
    table = _toml_find_exact_table(text, path)
    if table is None:
        _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    match, _, end = table
    body_start = match.end()
    body = text[body_start:end]
    enabled_lines = list(re.finditer(r"(?m)^([ \t]*)enabled([ \t]*=[ \t]*)(true|false)([ \t]*(?:#[^\n]*)?)(\n|$)", body))
    entry = _toml_entry(text, path)
    if "enabled" in entry and len(enabled_lines) != 1:
        _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    if "enabled" not in entry and enabled_lines:
        _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    if value is None:
        if not enabled_lines:
            return text
        selected = enabled_lines[0]
        inline_comment = selected.group(4)
        replacement = (inline_comment.strip() + selected.group(5)) if inline_comment.strip().startswith("#") else ""
        body = body[:selected.start()] + replacement + body[selected.end():]
    elif enabled_lines:
        selected = enabled_lines[0]
        literal = "true" if value else "false"
        body = body[:selected.start(3)] + literal + body[selected.end(3):]
    else:
        body = "\nenabled = " + ("true" if value else "false") + "\n" + body
    return text[:body_start] + body + text[end:]


def _toml_append_table(text, path, values):
    if _toml_find_exact_table(text, path) is not None:
        _fail("PROJECTION_ROUTE_COLLISION")
    table = "[" + _toml_header(path) + "]\n"
    table += "".join(key + " = " + migrate.literal(value) + "\n" for key, value in values.items())
    updated = text + ("" if text.endswith("\n") else "\n") + table
    try:
        tomllib.loads(updated)
    except Exception:
        _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    return updated


def _toml_rename(text, old_prefix, new_prefix):
    changed = False
    edits = []
    for match, path, _ in _toml_headers(text):
        if path[:len(old_prefix)] == tuple(old_prefix):
            replacement = "[" + _toml_header(tuple(new_prefix) + path[len(old_prefix):]) + "]"
            if match.group().endswith("\n"):
                replacement += "\n"
            edits.append((match.start(), match.end(), replacement))
            changed = True
    if not changed:
        _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    try:
        tomllib.loads(text)
    except Exception:
        _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    return text


def _toml_remove_table(text, prefix):
    edits = []
    for match, path, end in _toml_headers(text):
        if path[:len(prefix)] != tuple(prefix):
            continue
        body = text[match.end():end]
        comments = "".join(line for line in body.splitlines(keepends=True)
                            if not line.strip() or line.lstrip().startswith("#"))
        edits.append((match.start(), end, comments))
    if not edits:
        return text
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    try:
        tomllib.loads(text)
    except Exception:
        _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    return text


def _route_value(context, candidate, route_id):
    from installation_context import helper_argv
    url = f"http://127.0.0.1:{context.port}/mcp/{route_id}"
    helper = shlex.join(helper_argv(context, route_id))
    if candidate.ref.client == "codex":
        value = deepcopy(candidate.policy)
        value.update(url=url, http_headers_helper=helper)
        return value
    if set(candidate.policy) - {"enabled"}:
        _fail("CLAUDE_POLICY_UNSUPPORTED")
    return {"type": "http", "url": url, "headersHelper": helper}


def _scope_selector(ref):
    if ref.scope == "global":
        return ("mcpServers", ref.name) if ref.client == "claude" else ("mcp_servers", ref.name)
    if ref.scope == "project":
        return ref.selector
    return None


def _lookup(mapping, selector):
    current = mapping
    for item in selector:
        if type(current) is not dict or item not in current:
            _fail("PROJECTION_SOURCE_MISSING")
        current = current[item]
    if type(current) is not dict:
        _fail("PROJECTION_SOURCE_INVALID")
    return current


def _route_map(context, selected, token):
    path = Path(context.runtime) / "routes.json"
    expected = client_sources.build_route_map(selected, token)
    if path.exists() or path.is_symlink():
        raw = source_inputs.protected_read(path, MAX_JOURNAL_BYTES,
                                           private=True, error_code="ROUTES_AUTHENTICATION_FAILED")
        try:
            observed = source_inputs.strict_json(raw.decode("utf-8"))
        except Exception:
            _fail("ROUTES_AUTHENTICATION_FAILED")
        client_sources.verify_route_map(observed, token)
        if observed != expected:
            _fail("ROUTE_MAP_CONFLICT")
    else:
        from pilot import write_private
        write_private(path, _json_bytes(expected), exclusive=True)
    return expected


def _route_by_key(route_map, token):
    return {row["source_hmac"]: row for row in client_sources.verify_route_map(route_map, token)["routes"]}


def _source_key_for(candidate, token):
    return client_sources.source_key(candidate, token)


def _override_state(client, ref, config):
    if ref.scope != "plugin" or client.kind != "codex":
        return {"present": False, "enabled_present": False, "enabled": None}
    row = config.get("plugins", {}).get(ref.plugin_id, {})
    if type(row) is not dict:
        _fail("CODEX_PLUGIN_SETTINGS_INVALID")
    overrides = row.get("mcp_servers", {})
    if type(overrides) is not dict:
        _fail("CODEX_PLUGIN_SETTINGS_INVALID")
    present = ref.name in overrides
    override = overrides.get(ref.name, {})
    if type(override) is not dict or set(override) - {"enabled"}:
        _fail("CODEX_PLUGIN_OVERRIDE_UNSUPPORTED")
    return {"present": present, "enabled_present": "enabled" in override,
            "enabled": override.get("enabled")}


def _journal_entry(context, candidate, route, install_key):
    client = _client(context, candidate.ref.client)
    route_id = route["route_id"]
    if candidate.ref.client == "claude":
        config_path = Path(client.config)
        _, config = _read_json(config_path, source_inputs.MAX_CLAUDE_CONFIG_BYTES)
    else:
        config_path = Path(client.config)
        raw = _read_path(config_path, source_inputs.MAX_CONFIG_BYTES)
        try:
            config = tomllib.loads(raw.decode("utf-8"))
        except Exception:
            _fail("PROJECTION_CONFIG_INVALID")
    native = candidate.ref.scope != "plugin"
    backup_name = "personal-manager-source-" + route_id if native else None
    target_selector = _scope_selector(candidate.ref) if native else ("mcpServers", route_id) if candidate.ref.client == "claude" else ("mcp_servers", route_id)
    if native:
        slot = _lookup(config, target_selector[:-1])
        if candidate.ref.name not in slot or slot[candidate.ref.name] != candidate.source:
            _fail("SOURCE_CHANGED")
        if backup_name in slot:
            _fail("SOURCE_COLLISION")
        if route_id != candidate.ref.name and route_id in slot:
            _fail("PROJECTION_ROUTE_COLLISION")
        original = deepcopy(candidate.source)
        backup = deepcopy(original)
        original_enabled_present = "enabled" in original
        original_enabled = original.get("enabled")
        if candidate.ref.client == "codex":
            backup["enabled"] = False
    else:
        original = deepcopy(candidate.source)
        backup = None
        original_enabled_present = None
        original_enabled = None
        if candidate.ref.client == "claude":
            globals_map = config.get("mcpServers", {})
        else:
            globals_map = config.get("mcp_servers", {})
        if type(globals_map) is not dict or route_id in globals_map:
            _fail("PROJECTION_ROUTE_COLLISION")
    managed = _route_value(context, candidate, route_id)
    denial_name = None
    denial_added = False
    settings_file_existed = None
    settings_denials_present = None
    if candidate.ref.client == "claude":
        settings_path = _settings_path(client)
        if settings_path.parent != Path(client.config).parent / ".claude":
            _fail("CLAUDE_SETTINGS_PATH_INVALID")
        if native:
            denial_name = backup_name
        else:
            short = candidate.ref.plugin_id.split("@", 1)[0]
            denial_name = f"plugin:{short}:{candidate.ref.name}"
        settings_data, settings = _read_json(settings_path, 1048576, allow_missing=True)
        settings_file_existed = settings_data is not None
        current_denials = settings.get("deniedMcpServers", [])
        if type(current_denials) is not list:
            _fail("CLAUDE_DENIALS_INVALID")
        settings_denials_present = "deniedMcpServers" in settings
        denial_added = {"serverName": denial_name} not in current_denials and denial_name not in current_denials
    override_state = _override_state(client, candidate.ref, config)
    if candidate.ref.client == "codex" and not native and override_state["enabled"] is False:
        _fail("SOURCE_CHANGED")
    backup_hmac = None if backup is None else _content_hmac(backup, install_key, b"projection-backup-v1\n")
    plugin_mcp_servers_present = False
    if candidate.ref.client == "codex" and not native:
        plugin_settings = config.get("plugins", {}).get(candidate.ref.plugin_id, {})
        if type(plugin_settings) is not dict:
            _fail("CODEX_PLUGIN_SETTINGS_INVALID")
        plugin_mcp_servers_present = "mcp_servers" in plugin_settings
    return {
        "route_id": route_id,
        "profile_id": route["profile_id"],
        "family": candidate.family,
        "source_ref": client_sources.source_ref_dict(candidate.ref),
        "source_route_hmac": route["source_hmac"],
        "source_install_hmac": client_sources.source_key(candidate, install_key),
        "route_hmac": _content_hmac(managed, install_key, b"projection-route-v1\n"),
        "backup_hmac": backup_hmac,
        "backup_name": backup_name,
        "native": native,
        "target_selector": list(target_selector),
        "original_enabled_present": original_enabled_present,
        "original_enabled": original_enabled,
        "settings_path": str(_settings_path(client)) if candidate.ref.client == "claude" else None,
        "denial_name": denial_name,
        "denial_added": denial_added,
        "settings_file_existed": settings_file_existed,
        "settings_denials_present": settings_denials_present,
        "plugin_override_before": override_state,
        "plugin_override_added": bool(candidate.ref.client == "codex" and not native
                                        and not override_state["present"]),
        "plugin_mcp_servers_present": plugin_mcp_servers_present,
        "config_path": str(config_path),
        "client": candidate.ref.client,
    }


def _prepare(context, selected, token, install_key):
    if not 1 <= len(selected) <= MAX_ROUTE_COUNT:
        _fail("SOURCE_SELECTION_INVALID")
    routes_envelope = _route_map(context, selected, token)
    routes = _route_by_key(routes_envelope, token)
    projects = tuple(Path(candidate.ref.selector[1]) for candidate in selected if candidate.ref.scope == "project")
    current = client_sources.inventory_sources(context, projects=projects)
    by_ref = {}
    for candidate in current:
        by_ref.setdefault(_json_bytes(client_sources.source_ref_dict(candidate.ref)), []).append(candidate)
    entries = []
    seen = set()
    for selected_candidate in selected:
        if (not isinstance(selected_candidate, client_sources.SourceCandidate)
                or not selected_candidate.enabled or selected_candidate.blockers):
            _fail("SOURCE_SELECTION_UNSUPPORTED")
        ref_key = _json_bytes(client_sources.source_ref_dict(selected_candidate.ref))
        if ref_key in seen:
            _fail("SOURCE_SELECTION_DUPLICATE")
        seen.add(ref_key)
        matches = by_ref.get(ref_key, [])
        if len(matches) != 1:
            _fail("SOURCE_REFERENCE_AMBIGUOUS")
        fresh = matches[0]
        if (fresh.family != selected_candidate.family or fresh.blockers or not fresh.enabled
                or not hmac.compare_digest(client_sources.source_key(fresh, token),
                                           client_sources.source_key(selected_candidate, token))):
            _fail("SOURCE_CHANGED")
        source_hmac = client_sources.source_key(fresh, token)
        route = routes.get(source_hmac)
        if route is None or route["source_ref"] != client_sources.source_ref_dict(fresh.ref):
            _fail("ROUTE_MAP_CONFLICT")
        entries.append(_journal_entry(context, fresh, route, install_key))
    return routes_envelope, entries


def _append_route_map_if_missing(context, envelope):
    path = Path(context.runtime) / "routes.json"
    if path.exists() or path.is_symlink():
        raw = source_inputs.protected_read(path, MAX_JOURNAL_BYTES, private=True,
                                           error_code="ROUTES_AUTHENTICATION_FAILED")
        try:
            value = source_inputs.strict_json(raw.decode("utf-8"))
        except Exception:
            _fail("ROUTES_AUTHENTICATION_FAILED")
        if value != envelope:
            _fail("ROUTE_MAP_CONFLICT")
        return
    from pilot import write_private
    write_private(path, _json_bytes(envelope), exclusive=True)


def _add_denial(settings, name):
    denials = settings.setdefault("deniedMcpServers", [])
    if type(denials) is not list:
        _fail("CLAUDE_DENIALS_INVALID")
    row = {"serverName": name}
    if row not in denials and name not in denials:
        denials.append(row)


def _apply_settings(context, entries):
    grouped = {}
    for entry in entries:
        if entry["client"] != "claude" or not entry["denial_added"]:
            continue
        path = Path(entry["settings_path"])
        client = _client(context, "claude")
        _ensure_settings_parent(path, client)
        grouped.setdefault(path, []).append(entry)
    for path, rows in grouped.items():
        before, settings = _read_json(path, 1048576, allow_missing=True)
        for entry in rows:
            _add_denial(settings, entry["denial_name"])
        after = _serialize_json(settings)
        _atomic_replace(path, before, after, create=before is None)
        _, readback = _read_json(path, 1048576)
        if any({"serverName": entry["denial_name"]} not in readback.get("deniedMcpServers", [])
               for entry in rows):
            _fail("CLAUDE_DENIAL_READBACK_FAILED")


def _toml_add_route(text, route_id, managed):
    path = ("mcp_servers", route_id)
    text = _toml_append_table(text, path, managed)
    if _toml_entry(text, path) != managed:
        _fail("PROJECTION_READBACK_FAILED")
    return text


def _apply_codex(text, entries):
    _fail("PROJECTION_IMPLEMENTATION_INVALID")


def _apply_codex_config(context, text, entries, candidates, token, install_key):
    try:
        parsed = tomllib.loads(text)
    except Exception:
        _fail("PROJECTION_CONFIG_INVALID")
    for entry in entries:
        ref = client_sources.source_ref_from_dict(entry["source_ref"])
        candidate = candidates.get(entry["source_route_hmac"])
        if candidate is None:
            _fail("PROJECTION_SELECTION_MISMATCH")
        managed = _route_value(context, candidate, entry["route_id"])
        if not hmac.compare_digest(_content_hmac(managed, install_key,
                                                 b"projection-route-v1\n"), entry["route_hmac"]):
            _fail("PROJECTION_ROUTE_CONFLICT")
        route_path = ("mcp_servers", entry["route_id"])
        if entry["native"]:
            source_path = ("mcp_servers", ref.name)
            original = _toml_entry(text, source_path)
            fresh = client_sources.SourceCandidate(ref, entry["family"], True, original,
                {key: value for key, value in original.items() if key in migrate.POLICY})
            if (not hmac.compare_digest(client_sources.source_key(fresh, token), entry["source_route_hmac"])
                    or not hmac.compare_digest(client_sources.source_key(fresh, install_key), entry["source_install_hmac"])):
                _fail("SOURCE_CHANGED")
            backup_path = ("mcp_servers", entry["backup_name"])
            if _toml_find_exact_table(text, backup_path) is not None:
                _fail("SOURCE_COLLISION")
            if entry["route_id"] != ref.name and _toml_find_exact_table(text, route_path) is not None:
                _fail("PROJECTION_ROUTE_COLLISION")
            text = _toml_rename(text, source_path, backup_path)
            text = _toml_set_enabled(text, backup_path, False)
        else:
            fresh_source = client_sources.read_source(context, ref)
            fresh = client_sources.SourceCandidate(ref, entry["family"], True, fresh_source,
                {key: value for key, value in fresh_source.items() if key in migrate.POLICY})
            if (not hmac.compare_digest(client_sources.source_key(fresh, token), entry["source_route_hmac"])
                    or not hmac.compare_digest(client_sources.source_key(fresh, install_key), entry["source_install_hmac"])):
                _fail("SOURCE_CHANGED")
            plugin_path = ("plugins", ref.plugin_id, "mcp_servers", ref.name)
            plugin_settings = _toml_entry(text, ("plugins", ref.plugin_id))
            plugin_overrides = plugin_settings.get("mcp_servers", {})
            if type(plugin_overrides) is not dict:
                _fail("CODEX_PLUGIN_OVERRIDE_UNSUPPORTED")
            current_override = plugin_overrides.get(ref.name, {})
            if _override_state(_client(context, "codex"), ref, parsed) != entry["plugin_override_before"]:
                _fail("SOURCE_CHANGED")
            text = _toml_set_enabled(text, plugin_path, False) if entry["plugin_override_before"]["present"] else _toml_append_table(text, plugin_path, {"enabled": False})
        text = _toml_add_route(text, entry["route_id"], managed)
    try:
        tomllib.loads(text)
    except Exception:
        _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    return text


def _apply_client_configs(context, entries, token, install_key, journal_path, candidates):
    grouped = {}
    for entry in entries:
        grouped.setdefault((entry["client"], Path(entry["config_path"])), []).append(entry)
    for (kind, path), rows in grouped.items():
        client = _client(context, kind)
        if path != Path(client.config):
            _fail("PROJECTION_CONFIG_PATH_INVALID")
        if kind == "claude":
            before, config = _read_json(path, source_inputs.MAX_CLAUDE_CONFIG_BYTES)
            updated = _apply_claude(context, config, rows, token, install_key, candidates)
            after = _serialize_json(updated)
        else:
            before = _read_path(path, source_inputs.MAX_CONFIG_BYTES)
            try:
                text = before.decode("utf-8")
            except UnicodeError:
                _fail("PROJECTION_CONFIG_INVALID")
            after_text = _apply_codex_config(context, text, rows, candidates, token, install_key)
            after = after_text.encode("utf-8")
        _atomic_replace(path, before, after)
        if kind == "claude":
            _, observed = _read_json(path, source_inputs.MAX_CLAUDE_CONFIG_BYTES)
            for entry in rows:
                route_path = _scope_selector(client_sources.source_ref_from_dict(entry["source_ref"]))
                slot = _lookup(observed, route_path[:-1])
                route = slot.get(entry["route_id"])
                if type(route) is not dict or not hmac.compare_digest(
                        _content_hmac(route, install_key, b"projection-route-v1\n"), entry["route_hmac"]):
                    _fail("PROJECTION_READBACK_FAILED")
        else:
            try:
                observed = tomllib.loads(_read_path(path, source_inputs.MAX_CONFIG_BYTES).decode("utf-8"))
            except Exception:
                _fail("PROJECTION_READBACK_FAILED")
            servers = observed.get("mcp_servers", {})
            for entry in rows:
                route = servers.get(entry["route_id"])
                if type(route) is not dict or not hmac.compare_digest(
                        _content_hmac(route, install_key, b"projection-route-v1\n"), entry["route_hmac"]):
                    _fail("PROJECTION_READBACK_FAILED")


def _apply_claude(context, config, entries, token, install_key, candidates):
    updated = deepcopy(config)
    global_servers = updated.get("mcpServers", {})
    if type(global_servers) is not dict:
        _fail("SOURCE_CONFIG_INVALID")
    for entry in entries:
        ref = client_sources.source_ref_from_dict(entry["source_ref"])
        # The caller passes only entries whose source HMAC was resolved from the
        # fresh selected candidates. A route is synthesized from that in-memory
        # candidate, never from a secret-bearing journal field.
        candidate = candidates.get(entry["source_route_hmac"])
        if candidate is None:
            _fail("PROJECTION_SELECTION_MISMATCH")
        route = _route_value(context, candidate, entry["route_id"])
        if not hmac.compare_digest(_content_hmac(route, install_key, b"projection-route-v1\n"),
                                   entry["route_hmac"]):
            _fail("PROJECTION_ROUTE_CONFLICT")
        if entry["native"]:
            selector = _scope_selector(ref)
            slot = _lookup(updated, selector[:-1])
            source = slot.get(ref.name)
            if type(source) is not dict:
                _fail("SOURCE_CHANGED")
            current_candidate = client_sources.SourceCandidate(ref, entry["family"], True,
                source, {key: value for key, value in source.items() if key in migrate.POLICY})
            if not hmac.compare_digest(client_sources.source_key(current_candidate, token), entry["source_route_hmac"]):
                _fail("SOURCE_CHANGED")
            if entry["backup_name"] in slot:
                _fail("SOURCE_COLLISION")
            if entry["route_id"] != ref.name and entry["route_id"] in slot:
                _fail("PROJECTION_ROUTE_COLLISION")
            slot[entry["backup_name"]] = deepcopy(source)
            del slot[ref.name]
            slot[entry["route_id"]] = route
        else:
            source = client_sources.read_source(context, ref)
            fresh = client_sources.SourceCandidate(ref, entry["family"], True, source,
                {key: value for key, value in source.items() if key in migrate.POLICY})
            if (not hmac.compare_digest(client_sources.source_key(fresh, token), entry["source_route_hmac"])
                    or not hmac.compare_digest(client_sources.source_key(fresh, install_key),
                                               entry["source_install_hmac"])):
                _fail("SOURCE_CHANGED")
            if "mcpServers" not in updated:
                updated["mcpServers"] = global_servers
            if entry["route_id"] in global_servers:
                _fail("PROJECTION_ROUTE_COLLISION")
            global_servers[entry["route_id"]] = route
    return updated


def _read_projection(context, install_key, journal_path=None):
    path = Path(journal_path) if journal_path is not None else projection_journal_path(context)
    events = _journal_events(path, install_key)
    active = _active_transaction(events)
    return path, events, active


def _native_backup(context, entry, install_key):
    ref = client_sources.source_ref_from_dict(entry["source_ref"])
    client = _client(context, ref.client)
    if ref.client == "codex":
        text = _read_path(client.config, source_inputs.MAX_CONFIG_BYTES).decode("utf-8")
        parsed = tomllib.loads(text)
        backup = parsed.get("mcp_servers", {}).get(entry["backup_name"])
    else:
        _, parsed = _read_json(client.config, source_inputs.MAX_CLAUDE_CONFIG_BYTES)
        selector = _scope_selector(ref)
        backup_slot = _lookup(parsed, selector[:-1])
        backup = backup_slot.get(entry["backup_name"])
    if type(backup) is not dict or not hmac.compare_digest(
            _content_hmac(backup, install_key, b"projection-backup-v1\n"), entry["backup_hmac"]):
        _fail("PROJECTION_SOURCE_CONFLICT")
    source = deepcopy(backup)
    if ref.client == "codex":
        if source.get("enabled") is not False:
            _fail("PROJECTION_SOURCE_CONFLICT")
        if entry["original_enabled_present"]:
            source["enabled"] = entry["original_enabled"]
        else:
            source.pop("enabled", None)
    return source


def _plugin_native(context, entry, install_key, *, projected=True):
    ref = client_sources.source_ref_from_dict(entry["source_ref"])
    client = _client(context, ref.client)
    plugins = source_inputs.read_plugins(client=ref.client, roots=client.plugin_roots)
    matches = [plugin for plugin in plugins if plugin["id"] == ref.plugin_id]
    if len(matches) != 1:
        _fail("PROJECTION_SOURCE_MISSING")
    plugin = matches[0]
    source = deepcopy(plugin["servers"].get(ref.name))
    if type(source) is not dict:
        _fail("PROJECTION_SOURCE_MISSING")
    if ref.client == "codex":
        _, config = source_inputs.read_config(client.config)
        override_state = entry["plugin_override_before"]
        current_state = _override_state(client, ref, config)
        if projected and (not current_state["present"] or current_state["enabled"] is not False):
            _fail("PROJECTION_SOURCE_CONFLICT")
        if not projected and current_state != override_state:
            _fail("PROJECTION_SOURCE_CONFLICT")
        if override_state["present"]:
            if override_state["enabled_present"]:
                source["enabled"] = override_state["enabled"]
        else:
            source.pop("enabled", None)
    candidate = client_sources.SourceCandidate(ref, entry["family"], True, source,
        {key: value for key, value in source.items() if key in migrate.POLICY})
    if not hmac.compare_digest(client_sources.source_key(candidate, install_key),
                               entry["source_install_hmac"]):
        _fail("PROJECTION_SOURCE_CONFLICT")
    return source


def _validate_source_candidate(ref, family, enabled, source, expected_hmac, install_key):
    candidate = client_sources.SourceCandidate(ref, family, enabled, source,
        {key: value for key, value in source.items() if key in migrate.POLICY})
    if not hmac.compare_digest(client_sources.source_key(candidate, install_key), expected_hmac):
        _fail("PROJECTION_SOURCE_CONFLICT")
    return candidate


def _restore_json_group(context, path, entries, install_key):
    before, config = _read_json(path, source_inputs.MAX_CLAUDE_CONFIG_BYTES)
    updated = deepcopy(config)
    for entry in entries:
        ref = client_sources.source_ref_from_dict(entry["source_ref"])
        route_slot = (_lookup(updated, _scope_selector(ref)[:-1]) if entry["native"]
                      else updated.get("mcpServers", {}))
        if type(route_slot) is not dict:
            _fail("PROJECTION_CONFIG_INVALID")
        route = route_slot.get(entry["route_id"])
        if entry["native"]:
            if route is not None and entry["backup_name"] not in route_slot:
                _validate_source_candidate(ref, entry["family"], True, route,
                                           entry["source_install_hmac"], install_key)
                continue
            if route is None:
                source = route_slot.get(ref.name)
                if entry["backup_name"] not in route_slot and type(source) is dict:
                    _validate_source_candidate(ref, entry["family"], True, source,
                                               entry["source_install_hmac"], install_key)
                    continue
                _fail("PROJECTION_CONFLICT")
            if type(route) is not dict or not hmac.compare_digest(
                    _content_hmac(route, install_key, b"projection-route-v1\n"), entry["route_hmac"]):
                _fail("PROJECTION_CONFLICT")
            if entry["route_id"] != ref.name and ref.name in route_slot:
                _fail("PROJECTION_CONFLICT")
            backup = route_slot.get(entry["backup_name"])
            if type(backup) is not dict or not hmac.compare_digest(
                    _content_hmac(backup, install_key, b"projection-backup-v1\n"), entry["backup_hmac"]):
                _fail("PROJECTION_CONFLICT")
            source = deepcopy(backup)
            _validate_source_candidate(ref, entry["family"], True, source,
                                       entry["source_install_hmac"], install_key)
            route_slot.pop(entry["route_id"], None)
            route_slot.pop(entry["backup_name"], None)
            route_slot[ref.name] = source
        else:
            if route is None:
                continue
            if type(route) is not dict or not hmac.compare_digest(
                    _content_hmac(route, install_key, b"projection-route-v1\n"), entry["route_hmac"]):
                _fail("PROJECTION_CONFLICT")
            _plugin_native(context, entry, install_key, projected=True)
            route_slot.pop(entry["route_id"], None)
    if updated != config:
        _atomic_replace(path, before, _serialize_json(updated))


def _restore_codex_group(context, path, entries, install_key):
    before = _read_path(path, source_inputs.MAX_CONFIG_BYTES)
    try:
        text = before.decode("utf-8")
        current = tomllib.loads(text)
    except Exception:
        _fail("PROJECTION_CONFIG_INVALID")
    for entry in entries:
        ref = client_sources.source_ref_from_dict(entry["source_ref"])
        servers = current.get("mcp_servers", {})
        route = servers.get(entry["route_id"])
        if type(servers) is not dict:
            _fail("PROJECTION_CONFIG_INVALID")
        if entry["native"]:
            if route is not None and entry["backup_name"] not in servers:
                _validate_source_candidate(ref, entry["family"], True, route,
                                           entry["source_install_hmac"], install_key)
                continue
            if route is None:
                source = servers.get(ref.name)
                if entry["backup_name"] not in servers and type(source) is dict:
                    _validate_source_candidate(ref, entry["family"], True, source,
                                               entry["source_install_hmac"], install_key)
                    continue
                _fail("PROJECTION_CONFLICT")
            if type(route) is not dict or not hmac.compare_digest(
                    _content_hmac(route, install_key, b"projection-route-v1\n"), entry["route_hmac"]):
                _fail("PROJECTION_CONFLICT")
            if entry["route_id"] != ref.name and ref.name in servers:
                _fail("PROJECTION_CONFLICT")
            backup = servers.get(entry["backup_name"])
            if type(backup) is not dict or not hmac.compare_digest(
                    _content_hmac(backup, install_key, b"projection-backup-v1\n"), entry["backup_hmac"]):
                _fail("PROJECTION_CONFLICT")
            original = deepcopy(backup)
            if original.get("enabled") is not False:
                _fail("PROJECTION_CONFLICT")
            if entry["original_enabled_present"]:
                original["enabled"] = entry["original_enabled"]
            else:
                original.pop("enabled", None)
            _validate_source_candidate(ref, entry["family"], True, original,
                                       entry["source_install_hmac"], install_key)
            text = _toml_remove_table(text, ("mcp_servers", entry["route_id"]))
            text = _toml_rename(text, ("mcp_servers", entry["backup_name"]),
                                ("mcp_servers", ref.name))
            text = _toml_set_enabled(text, ("mcp_servers", ref.name),
                                     entry["original_enabled"] if entry["original_enabled_present"] else None)
        else:
            if route is None:
                continue
            if type(route) is not dict or not hmac.compare_digest(
                    _content_hmac(route, install_key, b"projection-route-v1\n"), entry["route_hmac"]):
                _fail("PROJECTION_CONFLICT")
            _plugin_native(context, entry, install_key, projected=True)
            text = _toml_remove_table(text, ("mcp_servers", entry["route_id"]))
            override = entry["plugin_override_before"]
            path_parts = ("plugins", ref.plugin_id, "mcp_servers", ref.name)
            if entry["plugin_override_added"]:
                text = _toml_remove_table(text, path_parts)
                if not entry["plugin_mcp_servers_present"]:
                    text = _toml_remove_table(text, ("plugins", ref.plugin_id, "mcp_servers"))
            else:
                text = _toml_set_enabled(text, path_parts,
                    override["enabled"] if override["enabled_present"] else None)
        try:
            current = tomllib.loads(text)
        except Exception:
            _fail("PROJECTION_TOML_LAYOUT_UNSUPPORTED")
    if text.encode("utf-8") != before:
        _atomic_replace(path, before, text.encode("utf-8"))


def _restore_settings(context, entries):
    grouped = {}
    for entry in entries:
        if entry["client"] == "claude" and entry["denial_added"]:
            grouped.setdefault(Path(entry["settings_path"]), []).append(entry)
    for path, rows in grouped.items():
        before, settings = _read_json(path, 1048576, allow_missing=True)
        if before is None:
            continue
        denials = settings.get("deniedMcpServers", [])
        if type(denials) is not list:
            _fail("CLAUDE_DENIALS_INVALID")
        for entry in rows:
            exact = {"serverName": entry["denial_name"]}
            index = next((index for index, row in enumerate(denials) if row == exact), None)
            if index is not None:
                del denials[index]
        if not entry["settings_denials_present"] and not denials:
            settings.pop("deniedMcpServers", None)
        if settings == {} and not any(entry["settings_file_existed"] for entry in rows):
            path.unlink()
            _sync_directory(path.parent)
        else:
            _atomic_replace(path, before, _serialize_json(settings))


def _prepare_source_from_journal(context, entry, install_key):
    ref = client_sources.source_ref_from_dict(entry["source_ref"])
    if entry["native"]:
        source = _native_backup(context, entry, install_key)
    else:
        source = _plugin_native(context, entry, install_key, projected=True)
    _validate_source_candidate(ref, entry["family"], True, source,
                               entry["source_install_hmac"], install_key)
    return source


def project_clients(context, selected, *, token, install_key, journal_path=None):
    """Project only selected routes after the service has passed verification."""
    selected = list(selected)
    key = _key_bytes(install_key)
    path = Path(journal_path) if journal_path is not None else projection_journal_path(context)
    existing = _journal_events(path, key)
    active = _active_transaction(existing)
    if active is not None:
        if existing[-1]["phase"] == "projected":
            verify_projections(context, selected, token=token, install_key=key, journal_path=path)
            return {"status": "PASS", "operation": "ALREADY_PROJECTED", "routes": len(active["entries"])}
        _fail("PROJECTION_RECOVERY_REQUIRED")
    lock_paths = {Path(candidate.ref.config) for candidate in selected}
    lock_paths.update(Path(client.settings or (Path(client.config).parent / ".claude" / "settings.json"))
                      for client in context.clients if client.kind == "claude")
    with ExitStack() as stack:
        for lock_path in sorted(lock_paths, key=str):
            stack.enter_context(locked(lock_path))
        routes, entries = _prepare(context, selected, token, key)
        _append_route_map_if_missing(context, routes)
        txid = secrets.token_hex(16)
        payload = {"entries": entries}
        _append_event(path, key, txid=txid, phase="prepared", payload=payload)
        _apply_settings(context, entries)
        _append_event(path, key, txid=txid, phase="settings-applied", payload={})
        candidates = {client_sources.source_key(candidate, token): candidate for candidate in selected}
        _apply_client_configs(context, entries, token, key, path, candidates)
        _append_event(path, key, txid=txid, phase="configs-applied", payload={})
        result = verify_projections(context, selected, token=token, install_key=key, journal_path=path)
        _append_event(path, key, txid=txid, phase="projected", payload={"verified": result["verified"]})
    return {"status": "PASS", "operation": "PROJECTED", "routes": len(entries)}


def verify_projections(context, selected, *, token, install_key, journal_path=None):
    key = _key_bytes(install_key)
    path, events, active = _read_projection(context, key, journal_path)
    if active is None:
        _fail("PROJECTION_NOT_FOUND")
    if events[-1]["phase"] not in ("configs-applied", "projected"):
        _fail("PROJECTION_INCOMPLETE")
    selected_keys = {client_sources.source_key(candidate, token) for candidate in selected}
    if selected_keys != {entry["source_route_hmac"] for entry in active["entries"]}:
        _fail("PROJECTION_SELECTION_MISMATCH")
    from portable_engine import read_routes
    route_rows = read_routes(context, token)
    route_by_key = {row["source_hmac"]: row for row in route_rows}
    for entry in active["entries"]:
        route = route_by_key.get(entry["source_route_hmac"])
        if (route is None or route["route_id"] != entry["route_id"]
                or route["source_ref"] != entry["source_ref"]):
            _fail("ROUTE_MAP_CONFLICT")
        ref = client_sources.source_ref_from_dict(entry["source_ref"])
        client = _client(context, ref.client)
        if ref.client == "claude":
            _, config = _read_json(client.config, source_inputs.MAX_CLAUDE_CONFIG_BYTES)
            route_slot = _lookup(config, _scope_selector(ref)[:-1]) if entry["native"] else config.get("mcpServers", {})
            current_route = route_slot.get(entry["route_id"])
            if type(current_route) is not dict or not hmac.compare_digest(
                    _content_hmac(current_route, key, b"projection-route-v1\n"), entry["route_hmac"]):
                _fail("PROJECTION_ROUTE_CONFLICT")
            if entry["native"]:
                backup = route_slot.get(entry["backup_name"])
                if type(backup) is not dict or not hmac.compare_digest(
                        _content_hmac(backup, key, b"projection-backup-v1\n"), entry["backup_hmac"]):
                    _fail("PROJECTION_SOURCE_CONFLICT")
            settings_path = Path(entry["settings_path"])
            _, settings = _read_json(settings_path, 1048576)
            if not _denial_present(settings, entry["denial_name"]):
                _fail("PROJECTION_DENIAL_MISSING")
        else:
            try:
                parsed = tomllib.loads(_read_path(client.config, source_inputs.MAX_CONFIG_BYTES).decode("utf-8"))
            except Exception:
                _fail("PROJECTION_CONFIG_INVALID")
            servers = parsed.get("mcp_servers", {})
            current_route = servers.get(entry["route_id"])
            if type(current_route) is not dict or not hmac.compare_digest(
                    _content_hmac(current_route, key, b"projection-route-v1\n"), entry["route_hmac"]):
                _fail("PROJECTION_ROUTE_CONFLICT")
            if entry["native"]:
                backup = servers.get(entry["backup_name"])
                if type(backup) is not dict or not hmac.compare_digest(
                        _content_hmac(backup, key, b"projection-backup-v1\n"), entry["backup_hmac"]):
                    _fail("PROJECTION_SOURCE_CONFLICT")
            else:
                ref_row = parsed.get("plugins", {}).get(ref.plugin_id, {}).get("mcp_servers", {}).get(ref.name, {})
                if ref_row.get("enabled") is not False:
                    _fail("PROJECTION_PLUGIN_NOT_DISABLED")
        _prepare_source_from_journal(context, entry, key)
    return {"status": "PASS", "verified": True, "routes": len(active["entries"])}


def rollback_clients(context, *, install_key, journal_path=None):
    """Restore authenticated native sources without contacting the manager."""
    key = _key_bytes(install_key)
    path, events, active = _read_projection(context, key, journal_path)
    if active is None:
        return {"status": "PASS", "operation": "NOTHING_TO_ROLL_BACK", "routes": 0}
    entries = active.get("entries")
    if type(entries) is not list or not entries:
        _fail("PROJECTION_JOURNAL_INVALID")
    lock_paths = {Path(entry["config_path"]) for entry in entries}
    lock_paths.update(Path(entry["settings_path"]) for entry in entries if entry["settings_path"])
    with ExitStack() as stack:
        for lock_path in sorted(lock_paths, key=str):
            stack.enter_context(locked(lock_path))
        # Validate every managed projection before the first write.
        for (kind, config_path), rows in _group(entries, "config_path", "client"):
            if kind == "claude":
                _, config = _read_json(config_path, source_inputs.MAX_CLAUDE_CONFIG_BYTES)
                _validate_json_projection_state(context, config, rows, key)
            else:
                text = _read_path(config_path, source_inputs.MAX_CONFIG_BYTES).decode("utf-8")
                parsed = tomllib.loads(text)
                _validate_codex_projection_state(context, parsed, rows, key)
        # Apply native restoration, then remove only denials this transaction added.
        for (kind, config_path), rows in _group(entries, "config_path", "client"):
            if kind == "claude":
                _restore_json_group(context, config_path, rows, key)
            else:
                _restore_codex_group(context, config_path, rows, key)
        _restore_settings(context, entries)
        _append_event(path, key, txid=events[-1]["txid"], phase="rolled-back",
                      payload={"restored": len(entries)})
    return {"status": "PASS", "operation": "ROLLED_BACK", "routes": len(entries)}


def _group(entries, path_key, client_key):
    grouped = {}
    for entry in entries:
        grouped.setdefault((entry[client_key], Path(entry[path_key])), []).append(entry)
    return sorted(grouped.items(), key=lambda item: (item[0][0], str(item[0][1])))


def _validate_json_projection_state(context, config, entries, install_key):
    for entry in entries:
        ref = client_sources.source_ref_from_dict(entry["source_ref"])
        slot = _lookup(config, _scope_selector(ref)[:-1]) if entry["native"] else config.get("mcpServers", {})
        route = slot.get(entry["route_id"])
        if entry["native"] and route is not None and entry["backup_name"] not in slot:
            _validate_source_candidate(ref, entry["family"], True, route,
                                       entry["source_install_hmac"], install_key)
            continue
        if route is None:
            if entry["native"] and entry["backup_name"] not in slot:
                current = slot.get(ref.name)
                _validate_source_candidate(ref, entry["family"], True, current,
                                           entry["source_install_hmac"], install_key)
                continue
            if not entry["native"]:
                _plugin_native(context, entry, install_key, projected=False)
                continue
            _fail("PROJECTION_CONFLICT")
        if type(route) is not dict or not hmac.compare_digest(
                _content_hmac(route, install_key, b"projection-route-v1\n"), entry["route_hmac"]):
            _fail("PROJECTION_CONFLICT")
        if entry["native"]:
            backup = slot.get(entry["backup_name"])
            if type(backup) is not dict or not hmac.compare_digest(
                    _content_hmac(backup, install_key, b"projection-backup-v1\n"), entry["backup_hmac"]):
                _fail("PROJECTION_CONFLICT")
        else:
            _plugin_native(context, entry, install_key, projected=True)


def _validate_codex_projection_state(context, config, entries, install_key):
    servers = config.get("mcp_servers", {})
    for entry in entries:
        ref = client_sources.source_ref_from_dict(entry["source_ref"])
        route = servers.get(entry["route_id"])
        if entry["native"] and route is not None and entry["backup_name"] not in servers:
            _validate_source_candidate(ref, entry["family"], True, route,
                                       entry["source_install_hmac"], install_key)
            continue
        if route is None:
            if entry["native"] and entry["backup_name"] not in servers:
                current = servers.get(ref.name)
                _validate_source_candidate(ref, entry["family"], True, current,
                                           entry["source_install_hmac"], install_key)
                continue
            if not entry["native"]:
                ref = client_sources.source_ref_from_dict(entry["source_ref"])
                if _override_state(_client(context, "codex"), ref, config) != entry["plugin_override_before"]:
                    _fail("PROJECTION_CONFLICT")
                _plugin_native(context, entry, install_key, projected=False)
                continue
            _fail("PROJECTION_CONFLICT")
        if type(route) is not dict or not hmac.compare_digest(
                _content_hmac(route, install_key, b"projection-route-v1\n"), entry["route_hmac"]):
            _fail("PROJECTION_CONFLICT")
        if entry["native"]:
            if entry["route_id"] != ref.name and ref.name in servers:
                _fail("PROJECTION_CONFLICT")
            backup = servers.get(entry["backup_name"])
            if type(backup) is not dict or not hmac.compare_digest(
                    _content_hmac(backup, install_key, b"projection-backup-v1\n"), entry["backup_hmac"]):
                _fail("PROJECTION_CONFLICT")
        else:
            if _override_state(_client(context, "codex"), ref, config) != {
                    "present": True, "enabled_present": True, "enabled": False}:
                _fail("PROJECTION_CONFLICT")
            _plugin_native(context, entry, install_key, projected=True)


def resolve_native_source(context, ref, *, install_key, journal_path=None):
    """Resolve a route's native source, authenticating any same-file backup."""
    key = _key_bytes(install_key)
    _, events, active = _read_projection(context, key, journal_path)
    if active is None:
        return client_sources.read_source(context, ref)
    ref_payload = client_sources.source_ref_dict(ref)
    rows = [entry for entry in active.get("entries", []) if entry.get("source_ref") == ref_payload]
    if not rows:
        return client_sources.read_source(context, ref)
    if len(rows) != 1:
        _fail("PROJECTION_JOURNAL_INVALID")
    entry = rows[0]
    if entry["native"]:
        source = _native_backup(context, entry, key)
    else:
        source = _plugin_native(context, entry, key, projected=True)
    _validate_source_candidate(ref, entry["family"], True, source,
                               entry["source_install_hmac"], key)
    return source


def restored_sources(context, *, install_key, projects=(), token=None, journal_path=None):
    """Rebuild the selected native sources for an unchanged-install plan.

    Only an authenticated completed projection can contribute restored source
    candidates. Managed routes and disabled plugin aliases are removed from the
    live inventory view before their verified original candidates are added.
    """
    key = _key_bytes(install_key)
    if token is None:
        token = key.hex()
    _, events, active = _read_projection(context, key, journal_path)
    if active is None:
        return client_sources.inventory_sources(context, projects=projects)
    if not events or events[-1]["phase"] != "projected":
        _fail("PROJECTION_RECOVERY_REQUIRED")
    selected = []
    excluded_refs = set()
    excluded_routes = set()
    for entry in active.get("entries", []):
        ref = client_sources.source_ref_from_dict(entry["source_ref"])
        excluded_refs.add(_json_bytes(client_sources.source_ref_dict(ref)))
        route_scope = ref.scope if entry["native"] else "global"
        if ref.client == "claude":
            prefix = _scope_selector(ref)[:-1] if entry["native"] else ("mcpServers",)
        else:
            prefix = ("mcp_servers",)
        excluded_routes.add((ref.client, route_scope, Path(ref.config), tuple(prefix) + (entry["route_id"],)))
        if entry["native"]:
            try:
                source = _native_backup(context, entry, key)
            except SafeError:
                source = client_sources.read_source(context, ref)
                _validate_source_candidate(ref, entry["family"], True, source,
                                           entry["source_install_hmac"], key)
        else:
            try:
                source = _plugin_native(context, entry, key, projected=True)
            except SafeError:
                source = _plugin_native(context, entry, key, projected=False)
        candidate = _validate_source_candidate(ref, entry["family"], True, source,
                                               entry["source_install_hmac"], key)
        selected.append(candidate)

    current = client_sources.inventory_sources(context, projects=projects)
    restored = []
    for candidate in current:
        ref_key = _json_bytes(client_sources.source_ref_dict(candidate.ref))
        route_key = (candidate.ref.client, candidate.ref.scope, Path(candidate.ref.config),
                     tuple(candidate.ref.selector))
        if ref_key in excluded_refs or route_key in excluded_routes:
            continue
        restored.append(candidate)
    restored.extend(selected)
    try:
        verify_projections(context, selected, token=token, install_key=key,
                           journal_path=journal_path)
    except SafeError:
        _fail("PROJECTION_RECOVERY_REQUIRED")
    return restored
