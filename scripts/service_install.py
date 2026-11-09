"""Conflict-safe stable command and per-user LaunchAgent lifecycle."""
import base64
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import signal
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import replace

from pilot import SafeError, read_private, read_token, write_private


LABEL = "local.personal-mcp-manager"
START_TIMEOUT_SECONDS = 30
STOP_TIMEOUT_SECONDS = 25
MAINTENANCE_SECONDS = 660
MAX_SERVICE_OUTPUT = 131072
MAX_LAUNCHCTL_OUTPUT = 65536
BACKUP_DOMAIN = b"personal-mcp-manager/service-install-backup/v1\n"
UPDATE_DOMAIN = b"personal-mcp-manager/installation-update/v1\n"
UPDATE_STATES = ("prepared", "descriptor-published", "command-published",
                 "service-registered", "service-started", "verified", "skill-updated")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _fail(code):
    raise SafeError(code)


def _home(context):
    root = Path(context.root)
    if (root.name != "Personal MCP Manager" or root.parent.name != "Application Support"
            or root.parent.parent.name != "Library" or len(root.parents) < 3):
        _fail("INSTALLATION_ROOT_INVALID")
    home = root.parents[2]
    if home.resolve(strict=True) != home:
        _fail("INSTALLATION_HOME_INVALID")
    return home


def stable_command_path(context):
    return _home(context) / ".local" / "bin" / "mcp-manager"


def plist_path(context):
    return _home(context) / "Library" / "LaunchAgents" / (LABEL + ".plist")


def service_name(context):
    return "gui/" + str(os.getuid()) + "/" + LABEL


def make_plist(context):
    """Return a minimal, literal LaunchAgent property list."""
    return {
        "Label": LABEL,
        "ProgramArguments": [
            str(context.python),
            str(Path(context.release) / "scripts" / "manage.py"),
            "run",
            "--installation",
            str(Path(context.root) / "installation.json"),
        ],
        "RunAtLoad": True,
        "KeepAlive": False,
        "WorkingDirectory": str(context.release),
        "EnvironmentVariables": {"HOME": str(_home(context))},
    }


def _ensure_parent(path, *, create):
    path = Path(path)
    missing = []
    current = path
    while not (current.exists() or current.is_symlink()):
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        _fail("SERVICE_PARENT_UNSAFE")
    if current.resolve(strict=True) != current:
        _fail("SERVICE_PARENT_UNSAFE")
    info = current.lstat()
    if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        _fail("SERVICE_PARENT_UNSAFE")
    for child in reversed(missing):
        if not create:
            _fail("SERVICE_PARENT_MISSING")
        try:
            child.mkdir(mode=0o700)
        except FileExistsError:
            pass
    for component in reversed(missing):
        info = component.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or component.resolve(strict=True) != component):
            _fail("SERVICE_PARENT_UNSAFE")
    current = path
    root = Path(path.anchor)
    while current != root:
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or current.resolve(strict=True) != current
                or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022):
            _fail("SERVICE_PARENT_UNSAFE")
        current = current.parent


def _safe_file(path, *, expected_mode=None):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        _fail("SERVICE_FILE_UNREADABLE")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022 or path.resolve(strict=True) != path
            or (expected_mode is not None and stat.S_IMODE(info.st_mode) != expected_mode)):
        _fail("SERVICE_FILE_UNSAFE")
    return info


def _safe_bytes(path, *, expected_mode=None):
    if _safe_file(path, expected_mode=expected_mode) is None:
        return None
    try:
        return Path(path).read_bytes()
    except OSError:
        _fail("SERVICE_FILE_UNREADABLE")


def _sync_directory(path):
    path = Path(path)
    descriptor = None
    try:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or path.resolve(strict=True) != path
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            _fail("UPDATE_DIRECTORY_UNSAFE")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                             | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            _fail("UPDATE_DIRECTORY_CHANGED")
        os.fsync(descriptor)
    except SafeError:
        raise
    except OSError:
        _fail("UPDATE_DIRECTORY_SYNC_FAILED")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _atomic_file(path, data, *, mode):
    path = Path(path)
    _ensure_parent(path.parent, create=True)
    _safe_file(path)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".manager-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        info = _safe_file(path, expected_mode=mode)
        if info is None or path.read_bytes() != data:
            _fail("SERVICE_FILE_READBACK_FAILED")
    except SafeError:
        raise
    except Exception:
        raise SafeError("SERVICE_FILE_WRITE_FAILED") from None
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _wrapper_bytes(context):
    python = str(Path(context.python))
    manager = str(Path(context.release) / "scripts" / "mcp_manager.py")
    return ("#!/bin/sh\nset -eu\n# Personal MCP Manager owned wrapper v1\nexec "
            + shlex.quote(python) + " " + shlex.quote(manager) + ' "$@"\n').encode("utf-8")


def _owned_wrapper(path, context):
    try:
        raw = Path(path).read_bytes()
        text = raw.decode("utf-8", errors="strict")
        lines = text.splitlines()
        if len(lines) != 4 or lines[:3] != ["#!/bin/sh", "set -eu", "# Personal MCP Manager owned wrapper v1"]:
            return False
        if not lines[3].startswith("exec ") or not lines[3].endswith(' "$@"'):
            return False
        argv = shlex.split(lines[3][5:-5])
        if len(argv) != 2 or argv[0] != str(Path(context.python)):
            return False
        manager = Path(argv[1])
        releases = Path(context.root) / "app" / "releases"
        return (manager.name == "mcp_manager.py" and manager.is_absolute()
                and releases in manager.parents and manager.resolve(strict=True) == manager)
    except Exception:
        return False


def _install_key(context):
    try:
        from installation_context import read_install_key
        return read_install_key(context)
    except Exception:
        _fail("INSTALLATION_KEY_UNAVAILABLE")


def _backup_path(context, name):
    if name not in {"command", "plist"}:
        _fail("SERVICE_BACKUP_INVALID")
    return Path(context.runtime) / ("service-" + name + "-previous.json")


def _save_previous(context, key, *, name, path, raw, mode):
    backup_path = _backup_path(context, name)
    payload = {"version": 1, "name": name, "path": str(path), "mode": mode,
               "data": base64.b64encode(raw).decode("ascii")}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    envelope = {"payload": payload,
                "mac": hmac.new(key, BACKUP_DOMAIN + encoded, hashlib.sha256).hexdigest()}
    raw_backup = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    existing = _safe_file(backup_path, expected_mode=0o600)
    if existing is not None:
        try:
            current = json.loads(backup_path.read_text("utf-8"))
        except Exception:
            _fail("SERVICE_BACKUP_INVALID")
        if current != envelope:
            _fail("SERVICE_BACKUP_CONFLICT")
        return
    _atomic_file(backup_path, raw_backup, mode=0o600)


def _read_previous(context, key, *, name, path):
    backup_path = _backup_path(context, name)
    if _safe_file(backup_path, expected_mode=0o600) is None:
        return None
    try:
        envelope = json.loads(read_private(backup_path))
        payload = envelope["payload"]
        if type(payload) is not dict or set(payload) != {"version", "name", "path", "mode", "data"}:
            raise ValueError()
        if (payload["version"] != 1 or payload["name"] != name or payload["path"] != str(path)
                or type(payload["mode"]) is not int or not isinstance(payload["data"], str)):
            raise ValueError()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(key, BACKUP_DOMAIN + encoded, hashlib.sha256).hexdigest()
        if not isinstance(envelope.get("mac"), str) or not hmac.compare_digest(envelope["mac"], expected):
            raise ValueError()
        return payload["mode"], base64.b64decode(payload["data"], validate=True)
    except Exception:
        _fail("SERVICE_BACKUP_INVALID")


def install_command(context):
    """Install or idempotently verify the stable, shell-safe user command."""
    path = stable_command_path(context)
    _ensure_parent(path.parent, create=True)
    expected = _wrapper_bytes(context)
    info = _safe_file(path)
    if info is None:
        _atomic_file(path, expected, mode=0o700)
        return {"status": "INSTALLED", "path": str(path)}
    if stat.S_IMODE(info.st_mode) != 0o700:
        _fail("COMMAND_PATH_CONFLICT")
    current = path.read_bytes()
    if current == expected:
        return {"status": "ALREADY_INSTALLED", "path": str(path)}
    if not _owned_wrapper(path, context):
        _fail("COMMAND_PATH_CONFLICT")
    key = _install_key(context)
    _save_previous(context, key, name="command", path=path, raw=current,
                   mode=stat.S_IMODE(info.st_mode))
    _atomic_file(path, expected, mode=0o700)
    if path.read_bytes() != expected:
        _fail("COMMAND_INSTALL_READBACK_FAILED")
    return {"status": "UPDATED", "path": str(path)}


def rollback_command(context):
    path = stable_command_path(context)
    info = _safe_file(path)
    if info is None:
        return {"status": "NOT_INSTALLED", "path": str(path)}
    if stat.S_IMODE(info.st_mode) != 0o700 or path.read_bytes() != _wrapper_bytes(context):
        _fail("COMMAND_ROLLBACK_CONFLICT")
    key = _install_key(context)
    previous = _read_previous(context, key, name="command", path=path)
    if previous is None:
        path.unlink()
        return {"status": "REMOVED", "path": str(path)}
    mode, raw = previous
    _atomic_file(path, raw, mode=mode)
    _backup_path(context, "command").unlink(missing_ok=True)
    return {"status": "RESTORED", "path": str(path)}


def _plist_bytes(context):
    try:
        return plistlib.dumps(make_plist(context), fmt=plistlib.FMT_XML, sort_keys=True)
    except Exception:
        _fail("LAUNCHAGENT_PLIST_INVALID")


def _owned_plist(path, context):
    try:
        info = _safe_file(path, expected_mode=0o600)
        if info is None:
            return False
        value = plistlib.loads(Path(path).read_bytes())
        if type(value) is not dict:
            return False
        args = value.get("ProgramArguments")
        if type(args) is not list or len(args) != 5 or not isinstance(args[1], str):
            return False
        manager = Path(args[1])
        releases = Path(context.root) / "app" / "releases"
        release = manager.parent.parent
        if (not manager.is_absolute() or manager != release / "scripts" / "manage.py"
                or releases not in release.parents or release.resolve(strict=True) != release
                or manager.resolve(strict=True) != manager):
            return False
        expected = make_plist(context)
        expected["ProgramArguments"][1] = str(manager)
        expected["WorkingDirectory"] = str(release)
        return value == expected
    except Exception:
        return False


def _run_launchctl(*arguments):
    try:
        result = subprocess.run(["/bin/launchctl", *arguments], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5, check=False)
        if len(result.stdout) > MAX_LAUNCHCTL_OUTPUT or len(result.stderr) > MAX_LAUNCHCTL_OUTPUT:
            _fail("LAUNCHCTL_OUTPUT_INVALID")
        return result.returncode, result.stdout, result.stderr
    except SafeError:
        raise
    except (OSError, subprocess.SubprocessError):
        _fail("LAUNCHCTL_FAILED")


def _launchctl_service(context):
    code, stdout, stderr = _run_launchctl("print", service_name(context))
    if code == 0:
        try:
            return (stdout + stderr).decode("utf-8", errors="strict")
        except UnicodeError:
            _fail("LAUNCHCTL_OUTPUT_INVALID")
    text = (stdout + stderr).decode("utf-8", errors="replace").lower()
    if "could not find service" in text or "service not found" in text:
        return None
    _fail("LAUNCHCTL_FAILED")


def _launchctl_loaded_path(context):
    output = _launchctl_service(context)
    if output is None:
        return None
    matches = re.findall(r"(?m)^\s*path = (.+?)\s*$", output)
    if len(matches) != 1:
        _fail("LAUNCHAGENT_IDENTITY_UNPROVEN")
    return matches[0]


def _launchctl_pid(context):
    output = _launchctl_service(context)
    if output is None:
        return None
    matches = re.findall(r"(?m)^\s*pid = ([0-9]+)\s*$", output)
    if len(matches) != 1 or int(matches[0]) < 2:
        _fail("LAUNCHAGENT_IDENTITY_UNPROVEN")
    return int(matches[0])


def _assert_launchd_binding(context, record):
    if (_launchctl_loaded_path(context) != str(plist_path(context))
            or _launchctl_pid(context) != record["launcher_pid"]):
        _fail("LAUNCHAGENT_IDENTITY_UNPROVEN")


def _manager_record_path(context):
    return Path(context.runtime) / "manager-process.json"


def _manager_identity(context):
    try:
        value = json.loads(read_private(_manager_record_path(context)))
        keys = {"version", "pid", "uid", "start_seconds", "start_microseconds", "executable",
                "launcher_pid", "launcher_start_seconds", "launcher_start_microseconds", "launcher_executable"}
        if type(value) is not dict or set(value) != keys or value["version"] != 1:
            _fail("MANAGER_IDENTITY_UNPROVEN")
        fields = ("pid", "uid", "start_seconds", "start_microseconds", "launcher_pid",
                  "launcher_start_seconds", "launcher_start_microseconds")
        if any(type(value[key]) is not int for key in fields):
            _fail("MANAGER_IDENTITY_UNPROVEN")
        if (value["uid"] != os.getuid() or value["pid"] < 2 or value["launcher_pid"] < 2
                or not 0 <= value["start_microseconds"] < 1_000_000
                or not 0 <= value["launcher_start_microseconds"] < 1_000_000
                or value["executable"] != str(Path(context.node).resolve(strict=True))
                or value["launcher_executable"] != str(Path(context.python).resolve(strict=True))):
            _fail("MANAGER_IDENTITY_UNPROVEN")
        from owner_watch import NativeIdentity
        identity = NativeIdentity()
        child = identity.process(value["pid"])
        launcher = identity.process(value["launcher_pid"])
        if ((child.pid, child.uid, child.seconds, child.microseconds, child.path) !=
                (value["pid"], value["uid"], value["start_seconds"], value["start_microseconds"], value["executable"])
                or (launcher.pid, launcher.uid, launcher.seconds, launcher.microseconds, launcher.path) !=
                (value["launcher_pid"], os.getuid(), value["launcher_start_seconds"],
                 value["launcher_start_microseconds"], value["launcher_executable"])
                or child.ppid != launcher.pid):
            _fail("MANAGER_IDENTITY_UNPROVEN")
        if identity.process(value["launcher_pid"]) != launcher or identity.process(value["pid"]) != child:
            _fail("MANAGER_IDENTITY_CHANGED")
        return value, identity
    except SafeError:
        raise
    except Exception:
        _fail("MANAGER_IDENTITY_UNPROVEN")


def verify_service(context):
    """Verify installed command/plist, launchd binding and native process identity."""
    try:
        command = stable_command_path(context)
        info = _safe_file(command, expected_mode=0o700)
        if info is None or command.read_bytes() != _wrapper_bytes(context):
            _fail("COMMAND_INSTALLATION_INVALID")
        plist = plist_path(context)
        pinfo = _safe_file(plist, expected_mode=0o600)
        if pinfo is None or plistlib.loads(plist.read_bytes()) != make_plist(context):
            _fail("LAUNCHAGENT_PLIST_INVALID")
        loaded = _launchctl_loaded_path(context)
        if loaded != str(plist):
            _fail("LAUNCHAGENT_NOT_LOADED")
        record, _ = _manager_identity(context)
        _assert_launchd_binding(context, record)
        status = _control_request(context, "status", allow_stopped=False)
        if status is None:
            _fail("MANAGER_NOT_RUNNING")
        _validate_status(status)
        return {"status": "PASS", "service": "PASS", "identity": "PASS"}
    except SafeError as error:
        code = str(error)
        return {"status": "FAIL", "service": "FAIL", "identity": "FAIL", "reason": code}


def _validate_status(value):
    required = {"draining", "quiescent", "pending", "requests", "active"}
    if type(value) is not dict or not required <= set(value):
        _fail("MANAGER_STATUS_INVALID")
    if type(value["draining"]) is not bool or type(value["quiescent"]) is not bool:
        _fail("MANAGER_STATUS_INVALID")
    for key in ("pending", "requests", "active"):
        if type(value[key]) is not int or value[key] < 0:
            _fail("MANAGER_STATUS_INVALID")
    if "retained" in value and (type(value["retained"]) is not int or value["retained"] < 0):
        _fail("MANAGER_STATUS_INVALID")
    if value["quiescent"] and (any(value[key] != 0 for key in ("pending", "requests", "active"))
                               or value.get("retained", 0) != 0):
        _fail("MANAGER_STATUS_INVALID")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _control_request(context, operation, *, allow_stopped=True):
    if operation not in {"status", "drain", "resume"}:
        _fail("MANAGER_CONTROL_INVALID")
    token_path = Path(context.runtime) / "token"
    token = read_token(token_path)
    method = "GET" if operation == "status" else "POST"
    data = None if method == "GET" else b"{}"
    headers = {"Authorization": "Bearer " + token, "Host": "127.0.0.1:" + str(context.port)}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"http://127.0.0.1:{context.port}/_control/{operation}",
                                     data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=2) as response:
            if response.status != 200:
                _fail("MANAGER_CONTROL_FAILED")
            raw = response.read(MAX_SERVICE_OUTPUT + 1)
            if len(raw) > MAX_SERVICE_OUTPUT:
                _fail("MANAGER_STATUS_INVALID")
            from owner_watch import strict_json
            value = strict_json(raw.decode("utf-8", errors="strict"))
            if type(value) is not dict:
                _fail("MANAGER_STATUS_INVALID")
            if operation == "status":
                _validate_status(value)
            return value
    except urllib.error.HTTPError as error:
        if error.code == 401:
            _fail("MANAGER_AUTHENTICATION_FAILED")
        if 300 <= error.code < 400:
            _fail("MANAGER_REDIRECT_REFUSED")
        _fail("MANAGER_CONTROL_FAILED")
    except urllib.error.URLError as error:
        if allow_stopped and isinstance(error.reason, ConnectionRefusedError):
            return None
        _fail("MANAGER_CONTROL_UNAVAILABLE")
    except SafeError:
        raise
    except Exception:
        _fail("MANAGER_CONTROL_FAILED")


def _port_listener(context):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        try:
            return probe.connect_ex(("127.0.0.1", context.port)) == 0
        except OSError:
            return False


def _launchagent_owned(context):
    path = plist_path(context)
    info = _safe_file(path, expected_mode=0o600)
    if info is None or not _owned_plist(path, context) or path.read_bytes() != _plist_bytes(context):
        return False
    return True


def register_service(context):
    """Publish and load this exact LaunchAgent; never adopt an unknown label."""
    path = plist_path(context)
    _ensure_parent(path.parent, create=True)
    expected = _plist_bytes(context)
    info = _safe_file(path)
    existing_service = _launchctl_service(context)
    if existing_service is not None:
        loaded_path = _launchctl_loaded_path(context)
        if loaded_path != str(path):
            _fail("LAUNCHAGENT_LABEL_CONFLICT")
        if info is None or not _owned_plist(path, context):
            _fail("LAUNCHAGENT_LABEL_CONFLICT")
        if path.read_bytes() != expected:
            if _manager_record_path(context).exists() or _port_listener(context):
                _fail("SERVICE_UPDATE_REQUIRES_STOP")
            code, _, _ = _run_launchctl("bootout", service_name(context))
            if code != 0:
                _fail("LAUNCHAGENT_BOOTOUT_FAILED")
            if _launchctl_service(context) is not None:
                _fail("LAUNCHAGENT_BOOTOUT_UNPROVEN")
            existing_service = None
    if info is not None and path.read_bytes() != expected:
        if not _owned_plist(path, context):
            _fail("LAUNCHAGENT_PATH_CONFLICT")
        key = _install_key(context)
        _save_previous(context, key, name="plist", path=path, raw=path.read_bytes(),
                       mode=stat.S_IMODE(info.st_mode))
    if info is None or path.read_bytes() != expected:
        _atomic_file(path, expected, mode=0o600)
    if _launchctl_service(context) is None:
        code, _, _ = _run_launchctl("bootstrap", "gui/" + str(os.getuid()), str(path))
        if code != 0:
            _fail("LAUNCHAGENT_BOOTSTRAP_FAILED")
    if _launchctl_loaded_path(context) != str(path):
        _fail("LAUNCHAGENT_IDENTITY_UNPROVEN")
    return {"status": "PASS", "label": LABEL}


def _resume_after_failed_drain(context):
    try:
        _control_request(context, "resume", allow_stopped=False)
    except SafeError:
        _fail("DRAIN_RECOVERY_UNPROVEN")


def _stop_service(context):
    status = _control_request(context, "status")
    if status is None:
        if _manager_record_path(context).exists() or _port_listener(context):
            _fail("MANAGER_OWNERSHIP_UNCERTAIN")
        return {"status": "PASS", "action": "stop", "service": "STOPPED"}
    _validate_status(status)
    record, identity = _manager_identity(context)
    _assert_launchd_binding(context, record)
    try:
        _control_request(context, "drain", allow_stopped=False)
    except SafeError:
        _resume_after_failed_drain(context)
        raise
    deadline = time.monotonic() + MAINTENANCE_SECONDS
    drained = False
    while time.monotonic() < deadline:
        try:
            status = _control_request(context, "status", allow_stopped=False)
            _validate_status(status)
            if status["draining"] is not True:
                _fail("MANAGER_DRAIN_EXPIRED")
            if status["quiescent"] and status.get("retained", 0) == 0:
                drained = True
                break
        except SafeError:
            _resume_after_failed_drain(context)
            raise
        time.sleep(0.25)
    if not drained:
        _resume_after_failed_drain(context)
        _fail("MANAGER_DRAIN_TIMEOUT")
    try:
        current, current_identity = _manager_identity(context)
        if current != record:
            _fail("MANAGER_IDENTITY_CHANGED")
        launcher = current_identity.process(record["launcher_pid"])
        if (launcher.pid != record["launcher_pid"] or launcher.uid != os.getuid()
                or launcher.seconds != record["launcher_start_seconds"]
                or launcher.microseconds != record["launcher_start_microseconds"]
                or launcher.path != record["launcher_executable"]):
            _fail("MANAGER_IDENTITY_CHANGED")
        os.kill(record["launcher_pid"], signal.SIGTERM)
    except SafeError:
        _resume_after_failed_drain(context)
        raise
    except OSError:
        _resume_after_failed_drain(context)
        _fail("MANAGER_SIGNAL_FAILED")
    deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if not _manager_record_path(context).exists():
            return {"status": "PASS", "action": "stop", "service": "STOPPED"}
        try:
            fresh, fresh_identity = _manager_identity(context)
            if fresh != record:
                _fail("MANAGER_IDENTITY_CHANGED")
            fresh_identity.process(record["launcher_pid"])
        except SafeError as error:
            if str(error) == "MANAGER_IDENTITY_UNPROVEN" and not _manager_record_path(context).exists():
                return {"status": "PASS", "action": "stop", "service": "STOPPED"}
            _fail("MANAGER_STOP_UNPROVEN")
        time.sleep(0.25)
    _fail("MANAGER_STOP_UNPROVEN")


def _start_service(context):
    if not _launchagent_owned(context):
        _fail("LAUNCHAGENT_NOT_INSTALLED")
    current = _control_request(context, "status")
    if current is not None:
        _validate_status(current)
        try:
            record, _ = _manager_identity(context)
            _assert_launchd_binding(context, record)
        except SafeError:
            _fail("MANAGER_OWNERSHIP_UNCERTAIN")
        return {"status": "PASS", "action": "start", "service": "RUNNING"}
    if _port_listener(context):
        _fail("FOREIGN_LISTENER_CONFLICT")
    loaded_path = _launchctl_loaded_path(context)
    if loaded_path is None:
        code, _, _ = _run_launchctl("bootstrap", "gui/" + str(os.getuid()), str(plist_path(context)))
        if code != 0:
            _fail("LAUNCHAGENT_BOOTSTRAP_FAILED")
    elif loaded_path != str(plist_path(context)):
        _fail("LAUNCHAGENT_LABEL_CONFLICT")
    code, _, _ = _run_launchctl("kickstart", service_name(context))
    if code != 0:
        _fail("LAUNCHAGENT_START_FAILED")
    deadline = time.monotonic() + START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        current = _control_request(context, "status")
        if current is not None:
            _validate_status(current)
            _manager_identity(context)
            return {"status": "PASS", "action": "start", "service": "RUNNING"}
        if _port_listener(context):
            _fail("FOREIGN_LISTENER_CONFLICT")
        time.sleep(0.25)
    _fail("MANAGER_START_TIMEOUT")


def service_action(context, action):
    """Perform one bounded, authenticated local lifecycle operation."""
    if action == "status":
        status = _control_request(context, "status")
        if status is None:
            if _manager_record_path(context).exists() or _port_listener(context):
                _fail("MANAGER_OWNERSHIP_UNCERTAIN")
            return {"status": "PASS", "action": "status", "service": "STOPPED"}
        _validate_status(status)
        record, _ = _manager_identity(context)
        _assert_launchd_binding(context, record)
        return {"status": "PASS", "action": "status", "service": "RUNNING",
                "draining": status["draining"], "quiescent": status["quiescent"],
                "retained": status.get("retained", 0)}
    if action == "start":
        return _start_service(context)
    if action == "stop":
        return _stop_service(context)
    _fail("SERVICE_ACTION_UNSUPPORTED")


def rollback_service_files(context):
    """Restore saved owned wrapper/plist bytes after the manager has stopped."""
    if _manager_record_path(context).exists() or _port_listener(context):
        _fail("SERVICE_CLEANUP_UNPROVEN")
    plist = plist_path(context)
    loaded_path = _launchctl_loaded_path(context)
    if loaded_path is not None:
        if loaded_path != str(plist) or not _launchagent_owned(context):
            _fail("LAUNCHAGENT_LABEL_CONFLICT")
        code, _, _ = _run_launchctl("bootout", service_name(context))
        if code != 0:
            _fail("LAUNCHAGENT_BOOTOUT_FAILED")
        if _launchctl_service(context) is not None:
            _fail("LAUNCHAGENT_BOOTOUT_UNPROVEN")
    key = _install_key(context)
    restored = []
    for name, path in (("command", stable_command_path(context)), ("plist", plist_path(context))):
        if _safe_file(path) is None:
            continue
        expected = _wrapper_bytes(context) if name == "command" else _plist_bytes(context)
        current = path.read_bytes()
        if current != expected:
            _fail("SERVICE_ROLLBACK_CONFLICT")
        previous = _read_previous(context, key, name=name, path=path)
        if previous is None:
            path.unlink()
            restored.append(name + ":removed")
        else:
            mode, raw = previous
            _atomic_file(path, raw, mode=mode)
            restored.append(name + ":restored")
    for name in ("command", "plist"):
        _backup_path(context, name).unlink(missing_ok=True)
    return {"status": "PASS", "files": restored}


def update_journal_path(context):
    return Path(context.runtime) / "update-transaction.json"


def _update_json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        _fail("UPDATE_JOURNAL_INVALID")


def _update_mac(payload, install_key):
    if not isinstance(install_key, bytes) or len(install_key) < 32:
        _fail("UPDATE_KEY_INVALID")
    return hmac.new(install_key, UPDATE_DOMAIN + _update_json(payload), hashlib.sha256).hexdigest()


def _read_update(context, install_key):
    path = update_journal_path(context)
    if _safe_file(path, expected_mode=0o600) is None:
        return None
    try:
        raw = read_private(path)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError()
        from owner_watch import strict_json
        envelope = strict_json(raw.decode("utf-8", errors="strict"))
        if type(envelope) is not dict or set(envelope) != {"payload", "mac"}:
            raise ValueError()
        payload = envelope["payload"]
        keys = {"version", "root", "state", "old_release", "new_release",
                "descriptor_before", "descriptor_after", "command_before", "command_after",
                "plist_before", "plist_after", "skill_before_sha", "skill_after_sha"}
        if (type(payload) is not dict or set(payload) != keys or payload["version"] != 1
                or payload["root"] != str(context.root) or payload["state"] not in UPDATE_STATES
                or not isinstance(payload["old_release"], str)
                or not isinstance(payload["new_release"], str)
                or ((payload["skill_before_sha"] is None) != (payload["skill_after_sha"] is None))
                or (payload["skill_before_sha"] is not None and (
                    not isinstance(payload["skill_before_sha"], str)
                    or not HEX64.fullmatch(payload["skill_before_sha"])
                    or not isinstance(payload["skill_after_sha"], str)
                    or not HEX64.fullmatch(payload["skill_after_sha"])
                    or payload["skill_before_sha"] == payload["skill_after_sha"]))
                or (payload["state"] == "skill-updated" and payload["skill_before_sha"] is None)
                or not isinstance(envelope["mac"], str)
                or not hmac.compare_digest(envelope["mac"], _update_mac(payload, install_key))):
            raise ValueError()
        old_release, new_release = Path(payload["old_release"]), Path(payload["new_release"])
        releases = Path(context.root) / "app" / "releases"
        if (not old_release.is_absolute() or not new_release.is_absolute()
                or releases not in old_release.parents or releases not in new_release.parents
                or old_release == new_release or old_release.resolve(strict=True) != old_release
                or new_release.resolve(strict=True) != new_release):
            raise ValueError()
        byte_fields = ("descriptor_before", "descriptor_after", "command_before",
                       "command_after", "plist_before", "plist_after")
        decoded = {}
        limits = {"descriptor_before": 256 * 1024, "descriptor_after": 256 * 1024,
                  "command_before": 1024 * 1024, "command_after": 1024 * 1024,
                  "plist_before": 1024 * 1024, "plist_after": 1024 * 1024}
        for name in byte_fields:
            if not isinstance(payload[name], str):
                raise ValueError()
            raw_value = base64.b64decode(payload[name], validate=True)
            if not raw_value or len(raw_value) > limits[name]:
                raise ValueError()
            decoded[name] = raw_value
        from installation_context import InstallContext, _serialize_context
        current = replace(context, release=old_release)
        updated = replace(context, release=new_release)
        if (_serialize_context(current) != decoded["descriptor_before"]
                or _serialize_context(updated) != decoded["descriptor_after"]):
            raise ValueError()
        if (decoded["command_before"] != _wrapper_bytes(current)
                or decoded["command_after"] != _wrapper_bytes(updated)
                or decoded["plist_before"] != _plist_bytes(current)
                or decoded["plist_after"] != _plist_bytes(updated)):
            raise ValueError()
        return payload, decoded
    except SafeError:
        raise
    except Exception:
        _fail("UPDATE_JOURNAL_INVALID")


def begin_update(context, updated_context, *, install_key, skill_update=None):
    """Persist a credential-free authenticated before/after recovery record."""
    from installation_context import _serialize_context, load_context
    if (context.root != updated_context.root
            or replace(context, release=updated_context.release) != updated_context):
        _fail("UPDATE_CONTEXT_SCOPE_INVALID")
    if skill_update is None:
        skill_before_sha = skill_after_sha = None
    elif (type(skill_update) is tuple and len(skill_update) == 2
            and all(isinstance(value, str) and HEX64.fullmatch(value) for value in skill_update)
            and skill_update[0] != skill_update[1]):
        skill_before_sha, skill_after_sha = skill_update
    else:
        _fail("UPDATE_SKILL_TRANSITION_INVALID")
    current = load_context(Path(context.root) / "installation.json")
    if current != context:
        _fail("INSTALLATION_CONTEXT_CONFLICT")
    journal = update_journal_path(context)
    if journal.exists() or journal.is_symlink():
        _fail("UPDATE_RECOVERY_REQUIRED")
    command, plist = stable_command_path(context), plist_path(context)
    command_info = _safe_file(command, expected_mode=0o700)
    plist_info = _safe_file(plist, expected_mode=0o600)
    if (command_info is None or plist_info is None
            or command.read_bytes() != _wrapper_bytes(context)
            or plist.read_bytes() != _plist_bytes(context)
            or _launchctl_loaded_path(context) != str(plist)):
        _fail("UPDATE_OLD_SERVICE_UNVERIFIED")
    descriptor = Path(context.root) / "installation.json"
    payload = {
        "version": 1, "root": str(context.root), "state": "prepared",
        "old_release": str(context.release), "new_release": str(updated_context.release),
        "descriptor_before": base64.b64encode(read_private(descriptor)).decode("ascii"),
        "descriptor_after": base64.b64encode(_serialize_context(updated_context)).decode("ascii"),
        "command_before": base64.b64encode(command.read_bytes()).decode("ascii"),
        "command_after": base64.b64encode(_wrapper_bytes(updated_context)).decode("ascii"),
        "plist_before": base64.b64encode(plist.read_bytes()).decode("ascii"),
        "plist_after": base64.b64encode(_plist_bytes(updated_context)).decode("ascii"),
        "skill_before_sha": skill_before_sha,
        "skill_after_sha": skill_after_sha,
    }
    envelope = {"payload": payload, "mac": _update_mac(payload, install_key)}
    raw = _update_json(envelope)
    if len(raw) > 2 * 1024 * 1024:
        _fail("UPDATE_JOURNAL_INVALID")
    try:
        write_private(journal, raw, exclusive=True)
        if read_private(journal) != raw:
            _fail("UPDATE_JOURNAL_READBACK_FAILED")
        _sync_directory(Path(context.runtime))
    except SafeError:
        raise
    except Exception:
        _fail("UPDATE_JOURNAL_WRITE_FAILED")
    return {"status": "PASS", "state": "prepared"}


def advance_update(context, *, install_key, state):
    if state not in UPDATE_STATES:
        _fail("UPDATE_STATE_INVALID")
    current = _read_update(context, install_key)
    if current is None:
        _fail("UPDATE_JOURNAL_MISSING")
    payload, _ = current
    index = UPDATE_STATES.index(payload["state"])
    if index + 1 >= len(UPDATE_STATES) or UPDATE_STATES[index + 1] != state:
        _fail("UPDATE_STATE_TRANSITION_INVALID")
    before = read_private(update_journal_path(context))
    payload = dict(payload, state=state)
    after = _update_json({"payload": payload, "mac": _update_mac(payload, install_key)})
    from client_projection import _atomic_replace
    _atomic_replace(update_journal_path(context), before, after)
    return {"status": "PASS", "state": state}


def _restore_update_backups(updated_context, install_key, decoded):
    for name, path, expected in (
            ("command", stable_command_path(updated_context), decoded["command_before"]),
            ("plist", plist_path(updated_context), decoded["plist_before"])):
        backup = _read_previous(updated_context, install_key, name=name, path=path)
        if backup is None:
            _fail("UPDATE_BACKUP_MISSING")
        mode, raw = backup
        expected_mode = 0o700 if name == "command" else 0o600
        if mode != expected_mode or raw != expected:
            _fail("UPDATE_BACKUP_MISMATCH")
        _backup_path(updated_context, name).unlink()


def complete_update(context, *, install_key):
    current = _read_update(context, install_key)
    if current is None:
        _fail("UPDATE_JOURNAL_MISSING")
    payload, decoded = current
    skill_update = payload["skill_before_sha"] is not None
    if payload["state"] not in ({"verified", "skill-updated"} if skill_update else {"verified"}):
        _fail("UPDATE_NOT_VERIFIED")
    from installation_context import load_context
    updated = load_context(Path(context.root) / "installation.json")
    if updated.release != Path(payload["new_release"]):
        _fail("UPDATE_DESCRIPTOR_CONFLICT")
    if (stable_command_path(updated).read_bytes() != decoded["command_after"]
            or plist_path(updated).read_bytes() != decoded["plist_after"]
            or verify_service(updated).get("status") != "PASS"):
        _fail("UPDATE_VERIFICATION_FAILED")
    if skill_update:
        if payload["state"] == "verified":
            _apply_update_skill(updated, payload)
            advance_update(context, install_key=install_key, state="skill-updated")
        _verify_update_skill(updated, payload["skill_after_sha"])
    _restore_update_backups(updated, install_key, decoded)
    update_journal_path(updated).unlink()
    _sync_directory(Path(updated.runtime))
    return {"status": "PASS", "operation": "UPDATED", "release": str(updated.release)}


def recover_update(context, *, install_key):
    """Conditionally restore the old release and service after interrupted cutover."""
    current = _read_update(context, install_key)
    if current is None:
        return {"status": "PASS", "operation": "NOTHING_TO_RECOVER"}
    payload, decoded = current
    from installation_context import load_context, replace_context
    descriptor_path = Path(context.root) / "installation.json"
    actual_descriptor = read_private(descriptor_path)
    if actual_descriptor not in (decoded["descriptor_before"], decoded["descriptor_after"]):
        _fail("UPDATE_DESCRIPTOR_CONFLICT")
    actual_context = load_context(descriptor_path)
    old_context = replace(actual_context, release=Path(payload["old_release"]))
    new_context = replace(actual_context, release=Path(payload["new_release"]))

    if (payload["state"] == "verified" and actual_descriptor == decoded["descriptor_after"]
            and _safe_bytes(stable_command_path(new_context), expected_mode=0o700) == decoded["command_after"]
            and _safe_bytes(plist_path(new_context), expected_mode=0o600) == decoded["plist_after"]
            and verify_service(new_context).get("status") == "PASS"):
        completed = complete_update(new_context, install_key=install_key)
        return {"status": "PASS", "operation": "COMPLETED", "release": completed["release"]}

    state = service_action(actual_context, "status")
    if state.get("status") != "PASS":
        _fail("UPDATE_SERVICE_STATUS_UNPROVEN")
    if state.get("service") == "RUNNING":
        stopped = service_action(actual_context, "stop")
        if stopped.get("status") != "PASS" or stopped.get("service") != "STOPPED":
            _fail("UPDATE_SERVICE_STOP_UNPROVEN")
    elif state.get("service") != "STOPPED":
        _fail("UPDATE_SERVICE_STATUS_UNPROVEN")

    command_path, plist = stable_command_path(old_context), plist_path(old_context)
    command_info = _safe_file(command_path)
    plist_info = _safe_file(plist)
    if command_info is None or plist_info is None:
        _fail("UPDATE_SERVICE_FILES_MISSING")
    command_now, plist_now = command_path.read_bytes(), plist.read_bytes()
    if command_now not in (decoded["command_before"], decoded["command_after"]):
        _fail("UPDATE_COMMAND_CONFLICT")
    if plist_now not in (decoded["plist_before"], decoded["plist_after"]):
        _fail("UPDATE_PLIST_CONFLICT")
    loaded = _launchctl_loaded_path(actual_context)
    if loaded not in (None, str(plist)):
        _fail("LAUNCHAGENT_LABEL_CONFLICT")
    if loaded == str(plist) and plist_now == decoded["plist_after"]:
        code, _, _ = _run_launchctl("bootout", service_name(actual_context))
        if code != 0 or _launchctl_service(actual_context) is not None:
            _fail("UPDATE_BOOTOUT_UNPROVEN")

    from client_projection import _atomic_replace
    if command_now == decoded["command_after"]:
        _atomic_replace(command_path, command_now, decoded["command_before"])
    if plist_now == decoded["plist_after"]:
        _atomic_replace(plist, plist_now, decoded["plist_before"])
    if actual_descriptor == decoded["descriptor_after"]:
        replace_context(new_context, old_context)

    # Any backups must authenticate to the exact old files before they can be
    # discarded. Their contents are not needed after the journal restoration.
    for name, path, expected in (("command", command_path, decoded["command_before"]),
                                 ("plist", plist, decoded["plist_before"])):
        backup_path = _backup_path(new_context, name)
        if _safe_file(backup_path, expected_mode=0o600) is not None:
            previous = _read_previous(new_context, install_key, name=name, path=path)
            if previous is None or previous[1] != expected:
                _fail("UPDATE_BACKUP_MISMATCH")
            backup_path.unlink()

    registered = register_service(old_context)
    if registered.get("status") != "PASS":
        _fail("UPDATE_OLD_SERVICE_RESTORE_FAILED")
    started = service_action(old_context, "start")
    if started.get("status") != "PASS" or started.get("service") != "RUNNING":
        _fail("UPDATE_OLD_SERVICE_START_FAILED")
    if verify_service(old_context).get("status") != "PASS":
        _fail("UPDATE_OLD_SERVICE_VERIFY_FAILED")
    if payload["skill_before_sha"] is not None:
        _restore_update_skill(new_context, old_context, payload)
    update_journal_path(old_context).unlink()
    _sync_directory(Path(old_context.runtime))
    return {"status": "PASS", "operation": "ROLLED_BACK", "release": str(old_context.release)}


def _verify_update_skill(context, expected_sha):
    import artifact_install
    result = artifact_install.inspect_setup_skill(context)
    if (result.get("status") != "OWNED" or result.get("sha256") != expected_sha
            or result.get("replaceable") is not True):
        _fail("UPDATE_SKILL_VERIFY_FAILED")
    return result


def _apply_update_skill(updated_context, payload):
    import artifact_install
    before = payload["skill_before_sha"]
    after = payload["skill_after_sha"]
    try:
        existing = artifact_install.inspect_setup_skill(updated_context)
    except SafeError as error:
        if str(error) != "SETUP_SKILL_RECOVERY_REQUIRED":
            raise
        existing = {"status": "PREPARED"}
    if existing.get("status") == "OWNED":
        if existing.get("sha256") == before:
            if existing.get("replaceable") is not True:
                _fail("UPDATE_SKILL_CONFLICT")
            artifact_install.rollback_setup_skill(updated_context)
        elif existing.get("sha256") != after:
            _fail("UPDATE_SKILL_CONFLICT")
    elif existing.get("status") not in {"ALREADY_ABSENT", "PREPARED"}:
        _fail("UPDATE_SKILL_STATE_INVALID")
    result = artifact_install.install_setup_skill(updated_context)
    if result.get("status") not in {"INSTALLED", "ALREADY_INSTALLED"}:
        _fail("UPDATE_SKILL_INSTALL_FAILED")
    _verify_update_skill(updated_context, after)


def _restore_update_skill(updated_context, old_context, payload):
    import artifact_install
    before = payload["skill_before_sha"]
    after = payload["skill_after_sha"]
    try:
        existing = artifact_install.inspect_setup_skill(updated_context)
    except SafeError as error:
        if str(error) != "SETUP_SKILL_RECOVERY_REQUIRED":
            raise
        existing = {"status": "PREPARED"}
    if existing.get("status") == "OWNED":
        if existing.get("sha256") == after:
            artifact_install.rollback_setup_skill(updated_context)
        elif existing.get("sha256") != before:
            _fail("UPDATE_SKILL_CONFLICT")
    elif existing.get("status") not in {"ALREADY_ABSENT", "PREPARED"}:
        _fail("UPDATE_SKILL_STATE_INVALID")
    elif existing.get("status") == "PREPARED":
        artifact_install.rollback_setup_skill(updated_context)
    result = artifact_install.install_setup_skill(old_context)
    if result.get("status") not in {"INSTALLED", "ALREADY_INSTALLED"}:
        _fail("UPDATE_SKILL_RESTORE_FAILED")
    _verify_update_skill(old_context, before)


