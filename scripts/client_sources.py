"""Credential-safe inventory and source references for Claude and Codex."""
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import hmac
import json
from pathlib import Path
import re

import langfuse_profile
import loki_profile
import migrate
import mysql_profile
import source_inputs
from pilot import SafeError


MAX_SOURCE_BYTES = 1048576
ROUTES_DOMAIN = "personal-mcp-manager/routes/v1"
SOURCE_DOMAIN = b"personal-mcp-manager/source/v1\n"
PROFILE_IDS = {
    "grafana": frozenset(("grafana-dev", "grafana-prd", "grafana-tools")),
    "langfuse": frozenset(langfuse_profile.PROFILES),
    "loki": frozenset(loki_profile.PROFILES),
    "mysql": frozenset(mysql_profile.PROFILES),
}
GRAFANA_ENV = {
    "grafana-dev": frozenset(("GRAFANA_URL", "GRAFANA_SERVICE_ACCOUNT_TOKEN")),
    "grafana-prd": frozenset(("GRAFANA_URL", "GRAFANA_SERVICE_ACCOUNT_TOKEN")),
    "grafana-tools": frozenset(("GRAFANA_URL", "GRAFANA_API_KEY")),
}
SERVER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
POLICY_FIELDS = frozenset(migrate.POLICY)


@dataclass(frozen=True, repr=False)
class SourceRef:
    client: str
    scope: str
    name: str
    config: Path
    selector: tuple[str, ...]
    plugin_id: str | None = None


@dataclass(repr=False)
class SourceCandidate:
    ref: SourceRef
    family: str
    enabled: bool
    source: dict = field(repr=False)
    policy: dict = field(repr=False)
    blockers: tuple[str, ...] = ()


def _fail(code="SOURCE_INPUT_INVALID"):
    raise SafeError(code)


def _canonical(value, *, maximum=MAX_SOURCE_BYTES):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError):
        _fail("SOURCE_INPUT_INVALID")
    if len(encoded) > maximum:
        _fail("SOURCE_INPUT_LIMIT")
    return encoded


def _key_bytes(token):
    if isinstance(token, str) and re.fullmatch(r"[0-9a-f]{64}", token):
        return bytes.fromhex(token)
    if isinstance(token, bytes) and len(token) >= 32:
        return token
    _fail("SOURCE_KEY_INVALID")


def _ref_payload(ref):
    if (not isinstance(ref, SourceRef) or ref.client not in ("claude", "codex")
            or ref.scope not in ("global", "project", "plugin")
            or not isinstance(ref.name, str) or not SERVER_NAME.fullmatch(ref.name)
            or not isinstance(ref.config, Path) or not ref.config.is_absolute()
            or not isinstance(ref.selector, tuple) or not ref.selector
            or any(not isinstance(item, str) or not item or "\0" in item for item in ref.selector)
            or (ref.plugin_id is not None and (not isinstance(ref.plugin_id, str)
                                               or not re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+", ref.plugin_id)))):
        _fail("SOURCE_REF_INVALID")
    return {"client": ref.client, "scope": ref.scope, "name": ref.name,
            "config": str(ref.config), "selector": list(ref.selector),
            "plugin_id": ref.plugin_id}


def source_ref_dict(ref):
    """Serialize a source locator without copying its configuration values."""
    return _ref_payload(ref)


def source_ref_from_dict(value):
    """Rebuild a strict, credential-free source locator from a routes record."""
    if type(value) is not dict or set(value) != {"client", "scope", "name", "config", "selector", "plugin_id"}:
        _fail("SOURCE_REF_INVALID")
    if (not isinstance(value["config"], str) or not Path(value["config"]).is_absolute()
            or type(value["selector"]) is not list):
        _fail("SOURCE_REF_INVALID")
    ref = SourceRef(value["client"], value["scope"], value["name"],
                    Path(value["config"]), tuple(value["selector"]), value["plugin_id"])
    if _ref_payload(ref) != value:
        _fail("SOURCE_REF_INVALID")
    return ref


def source_key(candidate, token):
    """Bind client scope, source contents and exact policy with a keyed digest."""
    if not isinstance(candidate, SourceCandidate) or type(candidate.source) is not dict or type(candidate.policy) is not dict:
        _fail("SOURCE_CANDIDATE_INVALID")
    value = {"ref": _ref_payload(candidate.ref), "family": candidate.family,
             "enabled": candidate.enabled, "source": candidate.source,
             "policy": candidate.policy}
    return hmac.new(_key_bytes(token), SOURCE_DOMAIN + _canonical(value), hashlib.sha256).hexdigest()


def _nested(value, selector):
    current = value
    for key in selector:
        if type(current) is not dict or key not in current:
            _fail("SOURCE_REFERENCE_MISSING")
        current = current[key]
    if type(current) is not dict:
        _fail("SOURCE_MAPPING_INVALID")
    _canonical(current)
    return deepcopy(current)


def _client_for_ref(context, ref):
    _ref_payload(ref)
    rows = [client for client in context.clients if client.kind == ref.client]
    if len(rows) != 1:
        _fail("SOURCE_CLIENT_INVALID")
    return rows[0]


def _load_ref_mapping(client, ref):
    if ref.scope == "global":
        if ref.plugin_id is not None or ref.config != Path(client.config):
            _fail("SOURCE_REFERENCE_INVALID")
        if ref.client == "codex":
            _, config = source_inputs.read_config(client.config)
        else:
            _, config = source_inputs.read_claude_config(client.config)
        expected = ("mcp_servers", ref.name) if ref.client == "codex" else ("mcpServers", ref.name)
        if ref.selector != expected:
            _fail("SOURCE_REFERENCE_INVALID")
        return _nested(config, ref.selector)

    if ref.scope == "project":
        if ref.client != "claude" or ref.plugin_id is not None or ref.config != Path(client.config):
            _fail("SOURCE_REFERENCE_INVALID")
        _, config = source_inputs.read_claude_config(client.config)
        if len(ref.selector) != 4 or ref.selector[0] != "projects" or ref.selector[2:] != ("mcpServers", ref.name):
            _fail("SOURCE_REFERENCE_INVALID")
        project = ref.selector[1]
        if not isinstance(project, str) or not Path(project).is_absolute() or project not in config.get("projects", {}):
            _fail("SOURCE_PROJECT_UNREGISTERED")
        return _nested(config, ref.selector)

    if ref.scope != "plugin" or ref.plugin_id is None:
        _fail("SOURCE_REFERENCE_INVALID")
    plugins = source_inputs.read_plugins(client=ref.client, roots=client.plugin_roots)
    matches = [plugin for plugin in plugins if plugin["id"] == ref.plugin_id]
    if len(matches) != 1:
        _fail("SOURCE_PLUGIN_MISSING")
    plugin = matches[0]
    source_path = Path(plugin["path"]) / plugin["sourcePath"]
    if ref.config != source_path or ref.selector != ("mcpServers", ref.name):
        _fail("SOURCE_REFERENCE_INVALID")
    source = _nested({"mcpServers": plugin["servers"]}, ref.selector)
    if ref.client == "codex":
        _, config = source_inputs.read_config(client.config)
        settings = config.get("plugins", {}).get(ref.plugin_id, {})
        if type(settings) is not dict:
            _fail("SOURCE_PLUGIN_SETTINGS_INVALID")
        overrides = settings.get("mcp_servers", {})
        if type(overrides) is not dict:
            _fail("SOURCE_PLUGIN_SETTINGS_INVALID")
        override = overrides.get(ref.name, {})
        if type(override) is not dict or set(override) - {"enabled"}:
            _fail("SOURCE_PLUGIN_OVERRIDE_UNSUPPORTED")
        source.update(deepcopy(override))
    return source


def read_source(context, ref):
    """Read one source afresh through its original, context-bound selector."""
    client = _client_for_ref(context, ref)
    return _load_ref_mapping(client, ref)


def _denied(settings, server_name):
    rows = settings.get("deniedMcpServers", [])
    if type(rows) is not list:
        _fail("CLAUDE_DENIALS_INVALID")
    return {"serverName": server_name} in rows or server_name in rows


def _plugin_enabled(client, plugin, config, settings):
    if client.kind == "codex":
        row = config.get("plugins", {}).get(plugin["id"], {})
        if type(row) is not dict:
            _fail("CODEX_PLUGIN_SETTINGS_INVALID")
        return row.get("enabled") is True
    enabled = settings.get("enabledPlugins", {})
    if type(enabled) is not dict:
        _fail("CLAUDE_PLUGIN_SETTINGS_INVALID")
    return enabled.get(plugin["id"]) is True


def _source_enabled(source, active=True, *, denied=False):
    if type(source) is not dict:
        return False
    enabled = source.get("enabled", True)
    disabled = source.get("disabled", False)
    return (active and not denied and type(enabled) is bool and enabled
            and type(disabled) is bool and not disabled)


def _plugin_source_rows(client, config, settings):
    rows = []
    plugins = source_inputs.read_plugins(client=client.kind, roots=client.plugin_roots)
    codex_plugins = config.get("plugins", {}) if client.kind == "codex" else {}
    if type(codex_plugins) is not dict:
        _fail("CODEX_PLUGIN_SETTINGS_INVALID")
    for plugin in plugins:
        identifier = plugin["id"]
        active = _plugin_enabled(client, plugin, config, settings)
        for name, raw in plugin["servers"].items():
            if not SERVER_NAME.fullmatch(name) or name.startswith("personal-manager-source-"):
                continue
            if type(raw) is not dict:
                _fail("PLUGIN_SOURCE_INVALID")
            source = deepcopy(raw)
            blocker = []
            if not plugin["reviewed"]:
                blocker.append("PLUGIN_VERSION_UNREVIEWED")
            if client.kind == "codex":
                override = codex_plugins.get(identifier, {}).get("mcp_servers", {}).get(name, {})
                if type(override) is not dict or set(override) - {"enabled"}:
                    blocker.append("PLUGIN_OVERRIDE_UNSUPPORTED")
                else:
                    source.update(deepcopy(override))
            else:
                short = identifier.split("@", 1)[0]
                denied = _denied(settings, f"plugin:{short}:{name}")
                if denied:
                    active = False
            ref = SourceRef(client.kind, "plugin", name,
                            Path(plugin["path"]) / plugin["sourcePath"],
                            ("mcpServers", name), identifier)
            family, family_blockers = _family(name, source, ref, plugin["reviewed"])
            blocker.extend(family_blockers)
            rows.append(SourceCandidate(ref, family, _source_enabled(source, active), source,
                                        _policy(source), tuple(dict.fromkeys(blocker))))
    return rows


def _policy(source):
    return deepcopy({key: value for key, value in source.items() if key in POLICY_FIELDS})


def _validate_grafana(name, source):
    env = source.get("env")
    if (name not in GRAFANA_ENV or source.get("command") != "uvx"
            or source.get("args") != ["mcp-grafana"] or type(env) is not dict
            or set(env) != GRAFANA_ENV[name]
            or any(not isinstance(value, str) or not value or "\0" in value for value in env.values())
            or set(source) - ({"command", "args", "env", "cwd"} | POLICY_FIELDS)):
        raise ValueError()


def _family(name, original, ref, plugin_reviewed=True):
    """Return a reviewed family label plus credential-free direct-use blockers."""
    if type(original) is not dict:
        return "unknown", ("SOURCE_MAPPING_INVALID",)
    source = deepcopy(original)
    if source.get("type", "stdio") != "stdio":
        return "unknown", ("SOURCE_TRANSPORT_UNSUPPORTED",)
    source.pop("type", None)
    source.pop("disabled", None)
    source.pop("enabled", None)
    try:
        _canonical(source)
    except SafeError:
        return "unknown", ("SOURCE_INPUT_LIMIT",)

    try:
        if name in GRAFANA_ENV:
            _validate_grafana(name, source)
            family = "grafana"
        elif name in langfuse_profile.PROFILES:
            langfuse_profile.validate_source(source, name)
            family = "langfuse"
        elif name in loki_profile.PROFILES:
            loki_profile.validate_source(source, name)
            family = "loki"
        elif name in mysql_profile.PROFILES:
            mysql_profile.validate_source(source, name)
            family = "mysql"
        else:
            return "unknown", ("SOURCE_PROFILE_UNSUPPORTED",)
    except SafeError as exc:
        reason = str(exc)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", reason):
            reason = "SOURCE_POLICY_UNSUPPORTED"
        return "unknown", (reason,)
    except Exception:
        return "unknown", ("SOURCE_REVIEW_FAILED",)
    blockers = []
    if not plugin_reviewed:
        blockers.append("PLUGIN_VERSION_UNREVIEWED")
    return family, tuple(blockers)


def _candidate(ref, source, active=True, plugin_reviewed=True, extra_blockers=()):
    if type(source) is not dict:
        _fail("SOURCE_MAPPING_INVALID")
    family, blockers = _family(ref.name, source, ref, plugin_reviewed)
    enabled = _source_enabled(source, active)
    return SourceCandidate(ref, family, enabled, deepcopy(source), _policy(source),
                          tuple(dict.fromkeys((*extra_blockers, *blockers))))


def inventory_sources(context, *, projects=()):
    """Inventory selected clients; project roots are opt-in and never scanned."""
    if not hasattr(context, "clients") or not isinstance(context.clients, (tuple, list)):
        _fail("SOURCE_CONTEXT_INVALID")
    clients = tuple(context.clients)
    if len({getattr(client, "kind", None) for client in clients}) != len(clients):
        _fail("SOURCE_CONTEXT_INVALID")
    selected_projects = set()
    for project in projects:
        path = Path(project)
        if not path.is_absolute() or path == Path("/"):
            _fail("SOURCE_PROJECT_INVALID")
        selected_projects.add(str(path))

    candidates = []
    for client in clients:
        if client.kind not in ("claude", "codex") or not isinstance(client.config, Path):
            _fail("SOURCE_CONTEXT_INVALID")
        if client.kind == "claude":
            _, config = source_inputs.read_claude_config(client.config)
            settings = {}
            if client.settings is not None:
                try:
                    Path(client.settings).lstat()
                except FileNotFoundError:
                    settings = {}
                except Exception:
                    _fail("SOURCE_SETTINGS_INVALID")
                else:
                    try:
                        settings = source_inputs.strict_json(source_inputs.protected_read(client.settings, 1048576).decode("utf-8"))
                    except Exception:
                        _fail("SOURCE_SETTINGS_INVALID")
            if type(settings) is not dict:
                _fail("SOURCE_SETTINGS_INVALID")
            servers = config.get("mcpServers", {})
            if type(servers) is not dict:
                _fail("SOURCE_CONFIG_INVALID")
            for name, source in servers.items():
                if not isinstance(name, str) or not SERVER_NAME.fullmatch(name) or name.startswith("personal-manager-source-"):
                    continue
                ref = SourceRef("claude", "global", name, Path(client.config), ("mcpServers", name))
                candidates.append(_candidate(ref, source, not _denied(settings, name)))
            config_projects = config.get("projects", {})
            if type(config_projects) is not dict:
                _fail("SOURCE_PROJECTS_INVALID")
            for project in sorted(selected_projects):
                project_config = config_projects.get(project)
                if project_config is None:
                    continue
                if type(project_config) is not dict or type(project_config.get("mcpServers", {})) is not dict:
                    _fail("SOURCE_PROJECT_INVALID")
                for name, source in project_config.get("mcpServers", {}).items():
                    if not isinstance(name, str) or not SERVER_NAME.fullmatch(name) or name.startswith("personal-manager-source-"):
                        continue
                    disabled = set(project_config.get("disabledMcpjsonServers", []))
                    active = name not in disabled
                    ref = SourceRef("claude", "project", name, Path(client.config),
                                    ("projects", project, "mcpServers", name))
                    candidates.append(_candidate(ref, source, active))
            candidates.extend(_plugin_source_rows(client, config, settings))
        else:
            _, config = source_inputs.read_config(client.config)
            servers = config.get("mcp_servers", {})
            if type(servers) is not dict:
                _fail("SOURCE_CONFIG_INVALID")
            for name, source in servers.items():
                if not isinstance(name, str) or not SERVER_NAME.fullmatch(name) or name.startswith("personal-manager-source-"):
                    continue
                ref = SourceRef("codex", "global", name, Path(client.config), ("mcp_servers", name))
                candidates.append(_candidate(ref, source))
            candidates.extend(_plugin_source_rows(client, config, {}))
    return candidates


def public_plan(candidates):
    """Return only source labels and bounded status/reason enums."""
    result = []
    for candidate in candidates:
        if not isinstance(candidate, SourceCandidate):
            _fail("SOURCE_CANDIDATE_INVALID")
        blockers = tuple(candidate.blockers)
        if any(not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", code) for code in blockers):
            _fail("SOURCE_BLOCKER_INVALID")
        status = "DISABLED" if not candidate.enabled else ("UNSUPPORTED" if blockers else "ELIGIBLE")
        result.append({"client": candidate.ref.client, "scope": candidate.ref.scope,
                       "name": candidate.ref.name, "family": candidate.family,
                       "enabled": candidate.enabled, "status": status,
                       "reason": blockers[0] if blockers else "NONE"})
    return result


def build_route_map(selected, token):
    """Create an authenticated credential-free route/source-ref mapping."""
    selected = list(selected)
    _key_bytes(token)
    if not selected:
        _fail("SOURCE_SELECTION_EMPTY")
    for candidate in selected:
        if (not isinstance(candidate, SourceCandidate) or not candidate.enabled
                or candidate.blockers or candidate.family not in PROFILE_IDS
                or candidate.ref.name not in PROFILE_IDS[candidate.family]):
            _fail("SOURCE_SELECTION_UNSUPPORTED")
    bases = [candidate.ref.name.lower() for candidate in selected]
    counts = {base: bases.count(base) for base in set(bases)}
    routes = []
    used = set()
    for candidate in selected:
        base = candidate.ref.name.lower()
        key = source_key(candidate, token)
        route_id = candidate.ref.name if counts[base] == 1 else base[:47] + "-" + key[:12]
        if not SERVER_NAME.fullmatch(route_id) or route_id in used:
            _fail("SOURCE_ROUTE_COLLISION")
        used.add(route_id)
        routes.append({"route_id": route_id, "profile_id": candidate.ref.name,
                       "family": candidate.family,
                       "source_ref": source_ref_dict(candidate.ref),
                       "source_hmac": key})
    payload = {"version": 1, "routes": routes}
    mac_input = {"domain": ROUTES_DOMAIN, "payload": payload}
    return {"payload": payload, "mac": migrate.mac(mac_input, token)}


def verify_route_map(value, token):
    """Validate a route-map envelope before it is used to resolve source refs."""
    if type(value) is not dict or set(value) != {"payload", "mac"}:
        _fail("ROUTE_MAP_INVALID")
    payload = value["payload"]
    if type(payload) is not dict or set(payload) != {"version", "routes"} or payload["version"] != 1 or type(payload["routes"]) is not list:
        _fail("ROUTE_MAP_INVALID")
    signature = value["mac"]
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        _fail("ROUTE_MAP_INVALID")
    expected = migrate.mac({"domain": ROUTES_DOMAIN, "payload": payload}, token)
    if not hmac.compare_digest(signature, expected):
        _fail("ROUTE_MAP_INVALID")
    seen = set()
    for route in payload["routes"]:
        fields = {"route_id", "profile_id", "family", "source_ref", "source_hmac"}
        if type(route) is not dict or set(route) != fields:
            _fail("ROUTE_MAP_INVALID")
        ref = source_ref_from_dict(route["source_ref"])
        if (not isinstance(route["route_id"], str) or not SERVER_NAME.fullmatch(route["route_id"])
                or route["route_id"] in seen or route["family"] not in PROFILE_IDS
                or route["profile_id"] not in PROFILE_IDS[route["family"]]
                or ref.name != route["profile_id"]
                or not isinstance(route["source_hmac"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", route["source_hmac"])):
            _fail("ROUTE_MAP_INVALID")
        seen.add(route["route_id"])
    return payload
