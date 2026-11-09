"""Bounded, read-only CLI monitoring for portable installations."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.request
from typing import Any

from pilot import read_token

MAX_BODY_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = 256 * 1024
MAX_PROFILES = 64
MAX_SAFE_INTEGER = 2**53 - 1
MAX_WATCH_COUNT = 1000
MIN_INTERVAL = 0.25
MAX_INTERVAL = 60.0
GENERATION = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
PROFILE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
COUNTER_KEYS = ("catalogRequests", "toolAttempts", "toolSuccesses", "toolFailures")
MONITOR_GLOBAL_KEYS = (
    "version", "uptimeSeconds", "sessions", "idleSessions", "busySessions", "subscriptions", "profiles",
)
MONITOR_PROFILE_KEYS = (
    "sessions", "idleSessions", "busySessions", "subscriptions", "requests", "active", "backendLive", "retained",
)
STATUS_KEYS = frozenset({
    "draining", "quiescent", "pending", "requests", "active", "backendStarts", "backendLive", "retained",
    "trafficCounters", "monitoring",
})


class MonitorDataError(Exception):
    """Fixed, non-sensitive monitor error."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    ppid: int
    uid: int
    seconds: int
    microseconds: int
    path: str


@dataclass(frozen=True)
class ServiceIdentity:
    kind: str
    launcher: ProcessIdentity | None
    manager: ProcessIdentity


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _monitor_file(path: Path, maximum: int, *, mode: int) -> bytes:
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != mode or info.st_size > maximum
            or path.resolve(strict=True) != path):
        raise MonitorDataError("MONITOR_INSTALLATION_UNAVAILABLE")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        data = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        if (len(data) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise MonitorDataError("MONITOR_INSTALLATION_UNAVAILABLE")
        return data
    finally:
        os.close(fd)


def discover_context(installation_path: Path | None = None):
    """Load the selected portable descriptor or fail closed when it is absent."""
    candidate = (Path(__file__).resolve().parents[4] / "installation.json"
                 if installation_path is None else Path(installation_path))
    if not candidate.exists() and not candidate.is_symlink():
        raise MonitorDataError("MONITOR_INSTALLATION_UNAVAILABLE")
    try:
        from installation_context import load_context
        return load_context(candidate)
    except Exception:
        raise MonitorDataError("MONITOR_INSTALLATION_UNAVAILABLE") from None


def _nonnegative_integer(value: Any, *, nullable: bool = False) -> int | None:
    if nullable and value is None:
        return None
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    return value


def _counter_snapshot(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {"generation", "profiles"}:
        raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    generation = value["generation"]
    profiles = value["profiles"]
    if (not isinstance(generation, str) or not GENERATION.fullmatch(generation)
            or type(profiles) is not dict or len(profiles) > MAX_PROFILES):
        raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    result = {}
    for profile, row in profiles.items():
        if not isinstance(profile, str) or not PROFILE_ID.fullmatch(profile) or type(row) is not dict or set(row) != set(COUNTER_KEYS):
            raise MonitorDataError("MONITOR_RESPONSE_INVALID")
        result[profile] = {key: _nonnegative_integer(row[key]) for key in COUNTER_KEYS}
    return {"generation": generation, "profiles": result}


def _monitoring_snapshot(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(MONITOR_GLOBAL_KEYS) or value.get("version") != 1:
        raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    profiles = value["profiles"]
    if type(profiles) is not dict or len(profiles) > MAX_PROFILES:
        raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    uptime = value["uptimeSeconds"]
    if type(uptime) not in (int, float) or not math.isfinite(uptime) or uptime < 0 or uptime > MAX_SAFE_INTEGER:
        raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    result_profiles = {}
    for profile, row in profiles.items():
        if (not isinstance(profile, str) or not PROFILE_ID.fullmatch(profile)
                or type(row) is not dict or set(row) != set(MONITOR_PROFILE_KEYS)):
            raise MonitorDataError("MONITOR_RESPONSE_INVALID")
        result_profiles[profile] = {
            key: _nonnegative_integer(row[key], nullable=key in {"backendLive", "retained"})
            for key in MONITOR_PROFILE_KEYS
        }
        if result_profiles[profile]["sessions"] != (
                result_profiles[profile]["idleSessions"] + result_profiles[profile]["busySessions"]):
            raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    sessions = _nonnegative_integer(value["sessions"])
    idle = _nonnegative_integer(value["idleSessions"])
    busy = _nonnegative_integer(value["busySessions"])
    subscriptions = _nonnegative_integer(value["subscriptions"])
    if sessions != idle + busy:
        raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    return {
        "uptimeSeconds": float(uptime),
        "connections": {
            "status": "AVAILABLE", "sessions": sessions, "idleSessions": idle,
            "busySessions": busy, "subscriptions": subscriptions,
            "profiles": result_profiles,
        },
    }


def validate_status_snapshot(value: Any) -> dict[str, Any]:
    """Validate known status fields and project only bounded scalar metrics."""
    if type(value) is not dict or not {"draining", "quiescent", "pending", "requests", "active"} <= set(value):
        raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    if set(value) - STATUS_KEYS or type(value["draining"]) is not bool or type(value["quiescent"]) is not bool:
        raise MonitorDataError("MONITOR_RESPONSE_INVALID")
    counters = {key: _nonnegative_integer(value[key]) for key in ("pending", "requests", "active")}
    status: dict[str, Any] = {
        "health": "UP",
        "draining": value["draining"],
        "quiescent": value["quiescent"],
        **counters,
        "backendStarts": _nonnegative_integer(value.get("backendStarts"), nullable=True),
        "backendLive": _nonnegative_integer(value.get("backendLive"), nullable=True),
        "retained": _nonnegative_integer(value.get("retained"), nullable=True),
        "generation": None,
        "uptimeSeconds": None,
        "connections": {"status": "UNAVAILABLE", "sessions": None, "idleSessions": None,
                         "busySessions": None, "subscriptions": None, "profiles": None},
        "traffic": None,
    }
    if "trafficCounters" in value:
        status["traffic"] = _counter_snapshot(value["trafficCounters"])
        status["generation"] = status["traffic"]["generation"]
    if "monitoring" in value:
        monitoring = _monitoring_snapshot(value["monitoring"])
        status["uptimeSeconds"] = monitoring["uptimeSeconds"]
        status["connections"] = monitoring["connections"]
        if status["generation"] is None:
            status["generation"] = "uptime-only"
    return status


def generation_aware_delta(previous: dict[str, Any] | None, current: dict[str, Any], *, elapsed_seconds: float) -> dict[str, Any]:
    if (previous is None or previous.get("generation") != current.get("generation")
            or not current.get("generation") or elapsed_seconds <= 0):
        return {"status": "RESET", "profiles": {
            profile: {key: {"delta": None, "perSecond": None} for key in COUNTER_KEYS}
            for profile in (current.get("traffic") or {}).get("profiles", {})
        }}
    old_profiles = (previous.get("traffic") or {}).get("profiles", {})
    new_profiles = (current.get("traffic") or {}).get("profiles", {})
    if set(old_profiles) != set(new_profiles):
        return {"status": "RESET", "profiles": {
            profile: {key: {"delta": None, "perSecond": None} for key in COUNTER_KEYS}
            for profile in new_profiles
        }}
    output = {}
    reset = any(row[key] < old_profiles[profile][key]
                for profile, row in new_profiles.items() for key in COUNTER_KEYS)
    if reset:
        return {"status": "RESET", "profiles": {
            profile: {key: {"delta": None, "perSecond": None} for key in COUNTER_KEYS}
            for profile in new_profiles
        }}
    for profile, row in new_profiles.items():
        output[profile] = {}
        for key in COUNTER_KEYS:
            difference = row[key] - old_profiles[profile][key]
            output[profile][key] = {"delta": difference, "perSecond": round(difference / elapsed_seconds, 3)}
    return {"status": "OK", "profiles": output}


def _portable_service_identity(context) -> ServiceIdentity:
    import service_install

    record, native = service_install._manager_identity(context)
    service_install._assert_launchd_binding(context, record)
    launcher = native.process(record["launcher_pid"])
    manager = native.process(record["pid"])
    return ServiceIdentity("portable", launcher, manager)


def validate_service_identity(context) -> ServiceIdentity:
    """Prove the portable LaunchAgent PID and its direct manager child."""
    return _portable_service_identity(context)


def _control_get(context) -> dict[str, Any]:
    try:
        token = read_token(Path(context.runtime) / "token")
        request = urllib.request.Request(
            f"http://127.0.0.1:{context.port}/_control/status",
            headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
            method="GET",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(request, timeout=2) as response:
            if response.status != 200:
                raise MonitorDataError("MONITOR_SERVICE_UNAVAILABLE")
            raw = response.read(MAX_BODY_BYTES + 1)
            if len(raw) > MAX_BODY_BYTES:
                raise MonitorDataError("MONITOR_RESPONSE_INVALID")
            payload = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_pairs)
            if not isinstance(payload, dict):
                raise MonitorDataError("MONITOR_RESPONSE_INVALID")
            return payload
    except MonitorDataError:
        raise
    except Exception:
        raise MonitorDataError("MONITOR_SERVICE_UNAVAILABLE") from None


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise MonitorDataError("MONITOR_RESPONSE_INVALID")
        result[key] = value
    return result


def _paths(context) -> dict[str, str]:
    return {"installationRoot": str(context.root), "programRoot": str(context.release),
            "runtimeRoot": str(context.runtime)}


def _snapshot(context) -> tuple[dict[str, Any], int]:
    result = {
        "health": "DOWN",
        "service": {"kind": getattr(context, "kind", "portable"), "identity": "UNAVAILABLE", "launcherPid": None,
                    "managerPid": None, "managerExecutable": None},
        "paths": _paths(context),
        "draining": None, "quiescent": None, "pending": None, "requests": None, "active": None,
        "backendStarts": None, "backendLive": None, "retained": None, "generation": None,
        "uptimeSeconds": None,
        "connections": {"status": "UNAVAILABLE", "sessions": None, "idleSessions": None,
                        "busySessions": None, "subscriptions": None, "profiles": None},
        "traffic": None,
        "memory": {"status": "UNAVAILABLE", "managerRssBytes": None,
                   "ownedDescendantTreeRssBytes": None, "summedOwnedRssBytes": None,
                   "ownedDescendantProcessCount": None,
                   "measurement": "summed-resident-bytes-not-unique-physical-ram"},
    }
    try:
        before = validate_service_identity(context)
        result["service"] = {
            "kind": before.kind, "identity": "PASS",
            "launcherPid": before.launcher.pid if before.launcher else None,
            "managerPid": before.manager.pid,
            "managerExecutable": before.manager.path,
        }
        raw = _control_get(context)
        after = validate_service_identity(context)
        if before != after:
            raise MonitorDataError("MONITOR_SERVICE_IDENTITY_CHANGED")
        projected = validate_status_snapshot(raw)
        result.update(projected)
        from monitoring_memory import sample_owned_memory
        result["memory"] = sample_owned_memory(context, after)
        return result, 0
    except MonitorDataError as error:
        result["reason"] = str(error)
        return result, 1
    except Exception:
        result["reason"] = "MONITOR_SERVICE_UNAVAILABLE"
        return result, 1


def _render_text(value: dict[str, Any], *, command: str) -> str:
    lines = [f"health: {value['health']}"]
    if value.get("reason"):
        lines.append(f"reason: {value['reason']}")
    lines.extend((f"service: {value['service']['kind']} identity={value['service']['identity']}",
                  f"program: {value['paths']['programRoot']}",
                  f"runtime: {value['paths']['runtimeRoot']}"))
    if value["health"] == "UP":
        lines.extend((f"requests: {value['requests']} active: {value['active']} pending: {value['pending']}",
                      f"backends live: {_display(value['backendLive'])} starts: {_display(value['backendStarts'])} retained: {_display(value['retained'])}"))
    if command in {"connections", "watch"}:
        connections = value["connections"]
        if connections["status"] == "AVAILABLE":
            lines.append(f"sessions: {connections['sessions']} idle: {connections['idleSessions']} busy: {connections['busySessions']} subscriptions: {connections['subscriptions']}")
            for profile, row in connections["profiles"].items():
                lines.append(f"  {profile}: sessions={row['sessions']} subscriptions={row['subscriptions']} requests={row['requests']} active={row['active']} backends={_display(row['backendLive'])} retained={_display(row['retained'])}")
        else:
            lines.append("connections: UNAVAILABLE (manager does not expose session metrics)")
    memory = value["memory"]
    if memory["status"] == "AVAILABLE":
        lines.append(f"memory: manager={_mib(memory['managerRssBytes'])} MiB owned-descendants={_mib(memory['ownedDescendantTreeRssBytes'])} MiB processes={memory['ownedDescendantProcessCount']} summed-RSS={_mib(memory['summedOwnedRssBytes'])} MiB (not unique physical RAM)")
    else:
        lines.append("memory: UNAVAILABLE (process identity or sampling could not be proven)")
    if value.get("traffic") is not None and command == "watch":
        for profile, row in value["traffic"]["profiles"].items():
            lines.append(f"  {profile}: attempts={row['toolAttempts']} successes={row['toolSuccesses']} errors={row['toolFailures']}")
    if "delta" in value:
        lines.append(f"traffic delta: {value['delta']['status']}")
        for profile, row in value["delta"]["profiles"].items():
            lines.append(f"  {profile}: " + " ".join(
                f"{name}={_display(metric['delta'])} ({_display(metric['perSecond'])}/s)"
                for name, metric in row.items()))
    return "\n".join(lines)


def _display(value: Any) -> str:
    return "unavailable" if value is None else str(value)


def _mib(value: int) -> str:
    return f"{value / (1024 * 1024):.1f}"


def _emit(value: dict[str, Any], *, json_output: bool, command: str) -> None:
    if json_output:
        line = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(line.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise MonitorDataError("MONITOR_OUTPUT_TOO_LARGE")
        print(line)
    else:
        print(_render_text(value, command=command))


def _interval(value: float) -> float:
    if type(value) not in (float, int) or not MIN_INTERVAL <= value <= MAX_INTERVAL:
        raise ValueError("--interval must be between 0.25 and 60 seconds")
    return float(value)


def _count(value: int | None) -> int | None:
    if value is not None and (type(value) is not int or not 1 <= value <= MAX_WATCH_COUNT):
        raise ValueError(f"--count must be between 1 and {MAX_WATCH_COUNT}")
    return value


def run_monitor(context, *, command: str, json_output: bool = False, interval: float = 2.0, count: int | None = None) -> int:
    if command not in {"status", "connections", "watch"}:
        raise ValueError("unsupported monitor command")
    interval = _interval(interval)
    count = _count(count)
    if context is None:
        context = discover_context()
    if command != "watch":
        snapshot, exit_code = _snapshot(context)
        _emit(snapshot, json_output=json_output, command=command)
        return exit_code

    previous = None
    previous_time = None
    samples = 0
    exit_code = 0
    try:
        while count is None or samples < count:
            started = time.monotonic()
            current, status = _snapshot(context)
            if current.get("health") == "UP":
                elapsed = interval if previous_time is None else started - previous_time
                current["delta"] = generation_aware_delta(previous, current, elapsed_seconds=elapsed)
                previous = current
                previous_time = started
            else:
                current["delta"] = {"status": "UNAVAILABLE", "profiles": {}}
                previous = None
                previous_time = None
                exit_code = max(exit_code, status)
            _emit(current, json_output=json_output, command="watch")
            samples += 1
            if count is not None and samples >= count:
                break
            time.sleep(max(0.0, interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        return 0
    return exit_code


def add_monitor_arguments(parser: argparse.ArgumentParser, *, command: str) -> None:
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit bounded JSON")
    if command == "watch":
        parser.add_argument("--interval", type=float, default=2.0, help="poll interval (0.25 to 60 seconds)")
        parser.add_argument("--count", type=int, help=f"stop after 1 to {MAX_WATCH_COUNT} snapshots")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-manager")
    parser.add_argument("--installation", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "connections", "watch"):
        child = commands.add_parser(name)
        child.add_argument("--installation", type=Path, default=argparse.SUPPRESS)
        add_monitor_arguments(child, command=name)
    args = parser.parse_args(argv)
    try:
        context = discover_context(args.installation)
        return run_monitor(context, command=args.command, json_output=args.json_output,
                           interval=getattr(args, "interval", 2.0), count=getattr(args, "count", None))
    except Exception:
        print("MONITOR_UNAVAILABLE", file=sys.stderr)
        return 1
