"""Source policy and owner environment for the standard Loki stdio package."""
import copy
import math
import posixpath

from migrate import POLICY, validate
from pilot import SafeError

PROFILES = {
    name: {"kind": "loki-session", "instruction": "Reviewed Loki " + name}
    for name in ("loki-stg", "loki-prd", "loki-tools")
}
ALLOWED_TOOLS = ("query_loki", "get_label_values", "get_labels")
ENV = {"LOKI_ADDR", "LOKI_DATASOURCE_ID", "LOKI_BEARER_TOKEN"}
INHERITED = ENV | {
    "HOME", "LOKI_CONFIG_PATH", "LOKI_USERNAME", "LOKI_PASSWORD",
    "LOKI_TENANT_ID", "LOKI_BEARER_TOKEN_FILE", "LOKI_CA_FILE",
    "LOKI_CERT_FILE", "LOKI_KEY_FILE", "LOKI_ORG_ID",
    "LOKI_TLS_SKIP_VERIFY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE",
    "SSL_CERT_DIR",
}
SOURCE_FIELDS = {"command", "args", "env", "cwd"} | POLICY


def _fail(code="LOKI_SOURCE_INVALID"):
    raise SafeError(code)


def _text(value):
    return isinstance(value, str) and bool(value) and "\0" not in value and len(value) <= 16384


def validate_source(source, backend):
    if backend not in PROFILES:
        _fail()
    validate(source)
    if (set(source) - SOURCE_FIELDS or source.get("command") != "npx"
            or source.get("args") != ["-y", "simple-loki-mcp"]):
        _fail()
    env = source.get("env")
    if (type(env) is not dict or set(env) != ENV
            or any(not _text(value) for value in env.values())):
        _fail()
    if "cwd" in source and (
            not _text(source["cwd"]) or not source["cwd"].startswith("/")
            or source["cwd"].startswith("//")):
        _fail()
    if source.get("enabled", True) is not True:
        _fail("LOKI_SOURCE_DISABLED")
    if "startup_timeout_ms" in source and "startup_timeout_sec" in source:
        _fail("LOKI_DEADLINE_AMBIGUOUS")
    for field in ("startup_timeout_ms", "startup_timeout_sec", "tool_timeout_sec"):
        if field in source and (
                not isinstance(source[field], (int, float))
                or not math.isfinite(source[field])
                or source[field] * (1 if field.endswith("_ms") else 1000) > 2147483647):
            _fail()
    for field in ("enabled_tools", "disabled_tools"):
        if field in source and (
                len(source[field]) != len(set(source[field]))
                or set(source[field]) - set(ALLOWED_TOOLS)):
            _fail()
    if "tools" in source and set(source["tools"]) - set(ALLOWED_TOOLS):
        _fail()


def source_policy(source, inherited_env):
    """Map admitted source values and standard inherited environment to a policy."""
    validate_source(source, "loki-stg")
    if (type(inherited_env) is not dict or not _text(inherited_env.get("HOME"))
            or not inherited_env["HOME"].startswith("/")):
        _fail("LOKI_HOME_REQUIRED")
    if any(not isinstance(key, str) for key in inherited_env):
        _fail("LOKI_ENV_INVALID")
    if any(key in {"NODE_OPTIONS", "NODE_PATH"} or key.startswith("DYLD_")
           for key in inherited_env):
        _fail("LOKI_ENV_INJECTION")
    env = {key: value for key, value in inherited_env.items() if key in INHERITED}
    if any(not isinstance(value, str) or "\0" in value or len(value) > 16384
           for value in env.values()):
        _fail()
    if any(key.startswith("LOKI_") and key not in INHERITED
           for key in inherited_env):
        _fail("LOKI_ENV_UNREVIEWED")
    env.update(source["env"])
    return {
        "env": copy.deepcopy(env),
        "cwd": source.get("cwd", "/"),
        **({} if "cwd" in source else {"cwdMode": "client"}),
        "scope": "session",
        "startupTimeoutMs": source.get("startup_timeout_ms", source.get("startup_timeout_sec", 10) * 1000),
        "toolTimeoutMs": source.get("tool_timeout_sec", 60) * 1000,
        "clientPolicy": copy.deepcopy({key: value for key, value in source.items() if key in POLICY}),
    }


def native_owner_environment(owner_env, owner_cwd):
    """Map owner CA settings using a bounded lexical path rooted at owner cwd."""
    def bounded_text(value, empty=False):
        if not isinstance(value, str) or "\0" in value or (not empty and not value):
            _fail("LOKI_ENV_INVALID")
        try:
            if len(value.encode("utf-8")) > 16384:
                _fail("LOKI_ENV_INVALID")
        except UnicodeEncodeError:
            _fail("LOKI_ENV_INVALID")
        return value

    def absolute(value):
        bounded_text(value)
        if not value.startswith("/") or value.startswith("//"):
            _fail("LOKI_ENV_INVALID")
        components = [part for part in value.split("/") if part and part != "."]
        result = "/" + "/".join(components)
        if value.endswith("/") and result != "/":
            result += "/"
        return result

    if type(owner_env) is not dict or any(not isinstance(key, str) for key in owner_env):
        _fail("LOKI_ENV_INVALID")
    if any(key in {"NODE_OPTIONS", "NODE_PATH"} or key.startswith("DYLD_")
           for key in owner_env):
        _fail("LOKI_ENV_INJECTION")
    if any(key.startswith("LOKI_") and key not in INHERITED for key in owner_env):
        _fail("LOKI_ENV_UNREVIEWED")
    for name in INHERITED.intersection(owner_env):
        bounded_text(owner_env[name], empty=True)
    cwd = absolute(owner_cwd)
    home = owner_env.get("HOME")
    absolute(home)
    env = {"HOME": home}
    for name in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"):
        if name not in owner_env:
            continue
        value = bounded_text(owner_env[name], empty=True)
        if not value:
            continue
        env[name] = absolute(
            value if value.startswith("/") else posixpath.join(cwd, value)
        )
    return env
