"""Source validation for standard Langfuse stdio profiles."""
from pathlib import Path

from migrate import POLICY, validate
from pilot import SafeError

ENV = {"LANGFUSE_HOST", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"}
PROFILES = {
    name: {"instruction": "Reviewed Langfuse " + name}
    for name in (
        "langfuse-traces", "langfuse-api-dev", "api-traces",
        "worker-dev", "worker-prod", "agent-dev",
    )
}
SOURCE_FIELDS = {"command", "args", "env", "cwd"} | (POLICY - {"startup_timeout_ms"})
ALLOWED_FLAGS = {"--read-only", "--no-log-to-console"}


def _fail(code="LANGFUSE_SOURCE_INVALID"):
    raise SafeError(code)


def _text(value, maximum=16384):
    if not isinstance(value, str) or not value or "\0" in value:
        return False
    try:
        return len(value.encode("utf-16-le")) // 2 <= maximum
    except UnicodeError:
        return False


def validate_source(source, backend):
    if backend not in PROFILES or type(source) is not dict:
        _fail()
    validate(source)
    command = source.get("command")
    args = source.get("args")
    if (set(source) - SOURCE_FIELDS or not isinstance(command, str)
            or Path(command).name != "uvx" or type(args) is not list
            or args[:3] != ["--with", "mcp[cli]<2", "langfuse-mcp"]
            or len(args) > 64 or any(not _text(arg) for arg in args)
            or any(arg not in ALLOWED_FLAGS for arg in args[3:])):
        _fail()
    env = source.get("env")
    if (type(env) is not dict or set(env) != ENV
            or any(not _text(value) for value in env.values())):
        _fail()
    if any(value in arg for value in env.values() for arg in args):
        _fail("CREDENTIAL_IN_ARGUMENTS")
    if "cwd" in source and (
            not isinstance(source["cwd"], str) or not source["cwd"].startswith("/")
            or source["cwd"].startswith("//") or "\0" in source["cwd"]):
        _fail()
