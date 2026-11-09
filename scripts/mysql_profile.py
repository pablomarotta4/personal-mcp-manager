"""Source validation for standard npm MySQL profiles."""
from pathlib import Path

from migrate import POLICY, validate
from mysql_environment import MYSQL_KEYS
from pilot import SafeError

PROFILES = {
    backend: {"kind": "mysql-session", "instruction": "Reviewed MySQL " + backend}
    for backend in (
        "mysql-primary-dev", "mysql-secondary-dev", "mysql-imported-dev",
        "mysql-plugin-dev",
    )
}
REQUIRED = frozenset({"MYSQL_HOST", "MYSQL_PORT", "MYSQL_DB", "MYSQL_USER", "MYSQL_PASS"})


def validate_source(source, backend):
    if backend not in PROFILES or type(source) is not dict:
        raise SafeError("MYSQL_SOURCE_INVALID")
    validate(source)
    if (source.get("command") != "npx"
            or source.get("args") != ["-y", "@benborla29/mcp-server-mysql"]
            or set(source) - POLICY - {"command", "args", "env", "cwd"}
            or source.get("enabled", True) is not True):
        raise SafeError("MYSQL_SOURCE_INVALID")
    env = source.get("env")
    if (type(env) is not dict or not REQUIRED <= set(env) or not set(env) <= MYSQL_KEYS
            or any(not isinstance(value, str) or "\0" in value for value in env.values())):
        raise SafeError("MYSQL_SOURCE_INVALID")
    for key in ("enabled_tools", "disabled_tools"):
        if key in source and (
                len(source[key]) != len(set(source[key]))
                or not set(source[key]) <= {"mysql_query"}):
            raise SafeError("MYSQL_TOOL_POLICY_INVALID")
    if "tools" in source and not set(source["tools"]) <= {"mysql_query"}:
        raise SafeError("MYSQL_TOOL_POLICY_INVALID")
    if "startup_timeout_ms" in source and "startup_timeout_sec" in source:
        raise SafeError("MYSQL_DEADLINE_AMBIGUOUS")
    if "cwd" in source and (
            not isinstance(source["cwd"], str) or not Path(source["cwd"]).is_absolute()
            or "\0" in source["cwd"]):
        raise SafeError("MYSQL_SOURCE_INVALID")
