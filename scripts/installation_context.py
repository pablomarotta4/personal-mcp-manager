"""Portable, credential-free paths and identity for one local installation."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import tempfile


DESCRIPTOR_NAME = "installation.json"
MAX_DESCRIPTOR_BYTES = 256 * 1024
PORT_MIN = 1
PORT_MAX = 65535
CODEX_REQUIREMENT = 'anchor apple generic and certificate leaf[subject.OU] = "2DC432GLL2" and identifier "codex"'
CLAUDE_REQUIREMENT = 'anchor apple generic and certificate leaf[subject.OU] = "Q6L2SF6YDW" and identifier "com.anthropic.claude-code"'
CODEX_RELATIVE_EXECUTABLE = Path("Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex")
CLAUDE_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,2}\Z")
PLUGIN_ID = re.compile(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+\Z")
BACKEND_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class InstallationContextError(Exception):
    """The installation descriptor or a discovered local path is unsafe."""


@dataclass(frozen=True)
class ClientPaths:
    kind: str
    config: Path
    settings: Path | None
    plugin_roots: tuple[Path, ...]
    owner_executables: tuple[Path, ...]


@dataclass(frozen=True)
class InstallContext:
    version: int
    root: Path
    release: Path
    runtime: Path
    artifacts: Path
    python: Path
    node: Path
    port: int
    clients: tuple[ClientPaths, ...]


@dataclass(frozen=True)
class InstallationStatePaths:
    lock: Path
    journal: Path
    key: Path


def default_root(home: Path) -> Path:
    return Path(home) / "Library/Application Support/Personal MCP Manager"


def helper_argv(context: InstallContext, backend: str) -> list[str]:
    if not isinstance(backend, str) or not BACKEND_ID.fullmatch(backend):
        raise InstallationContextError("BACKEND_ID_INVALID")
    return [
        str(context.python),
        str(context.release / "scripts/pilot.py"),
        "headers",
        "--installation",
        str(context.root / DESCRIPTOR_NAME),
        "--runtime",
        str(context.runtime),
        "--backend",
        backend,
    ]


def installation_state_paths(context: InstallContext) -> InstallationStatePaths:
    digest = hashlib.sha256(os.fsencode(context.root)).hexdigest()[:24]
    lock = Path(tempfile.gettempdir()).resolve() / f"mcp-manager-install-{os.getuid()}-{digest}.lock"
    return InstallationStatePaths(
        lock=lock,
        journal=context.root / "transactions/install.jsonl",
        key=context.runtime / "token",
    )


def _is_plain_directory(path: Path, *, owner: int | None = None, mode: int | None = None) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallationContextError("INSTALLATION_ROOT_INVALID") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise InstallationContextError("INSTALLATION_ROOT_INVALID")
    if owner is not None and info.st_uid != owner:
        raise InstallationContextError("INSTALLATION_OWNER_MISMATCH")
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise InstallationContextError("INSTALLATION_MODE_INVALID")
    return info


def _ensure_private_directory(path: Path) -> None:
    path = Path(os.path.abspath(os.fspath(path)))
    if path.exists() or path.is_symlink():
        info = _is_plain_directory(path, owner=os.getuid(), mode=0o700)
        if path.resolve(strict=True) != path:
            raise InstallationContextError("INSTALLATION_ROOT_SYMLINK")
        return
    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, mode=0o755)
    if parent.resolve(strict=True) != parent or not parent.is_dir():
        raise InstallationContextError("INSTALLATION_PARENT_INVALID")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise InstallationContextError("INSTALLATION_ROOT_CREATE_FAILED") from exc
    _is_plain_directory(path, owner=os.getuid(), mode=0o700)


def _strict_json(data: bytes) -> dict[str, object]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise InstallationContextError("INSTALLATION_JSON_DUPLICATE_FIELD")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=unique_pairs)
    except InstallationContextError:
        raise
    except (UnicodeError, ValueError, TypeError) as exc:
        raise InstallationContextError("INSTALLATION_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise InstallationContextError("INSTALLATION_JSON_INVALID")
    return value


def _path_value(value: object, name: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise InstallationContextError("INSTALLATION_PATH_INVALID")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise InstallationContextError("INSTALLATION_PATH_INVALID")
    return path


def _serialize_context(context: InstallContext) -> bytes:
    _validate_context(context)
    value = {
        "version": context.version,
        "root": str(context.root),
        "release": str(context.release),
        "runtime": str(context.runtime),
        "artifacts": str(context.artifacts),
        "python": str(context.python),
        "node": str(context.node),
        "port": context.port,
        "clients": [
            {
                "kind": client.kind,
                "config": str(client.config),
                "settings": str(client.settings) if client.settings is not None else None,
                "plugin_roots": [str(path) for path in client.plugin_roots],
                "owner_executables": [str(path) for path in client.owner_executables],
            }
            for client in context.clients
        ],
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _validate_context(context: InstallContext) -> None:
    if type(context.version) is not int or context.version != 1:
        raise InstallationContextError("INSTALLATION_VERSION_UNSUPPORTED")
    if type(context.port) is not int or not PORT_MIN <= context.port <= PORT_MAX:
        raise InstallationContextError("INSTALLATION_PORT_INVALID")
    for name in ("root", "release", "runtime", "artifacts", "python", "node"):
        value = getattr(context, name)
        if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts or "\x00" in os.fspath(value):
            raise InstallationContextError("INSTALLATION_PATH_INVALID")
    if context.root.name in {"", ".", ".."}:
        raise InstallationContextError("INSTALLATION_ROOT_INVALID")
    if not isinstance(context.clients, tuple):
        raise InstallationContextError("INSTALLATION_CLIENTS_INVALID")
    seen: set[str] = set()
    for client in context.clients:
        if not isinstance(client, ClientPaths) or client.kind not in {"claude", "codex"} or client.kind in seen:
            raise InstallationContextError("INSTALLATION_CLIENTS_INVALID")
        seen.add(client.kind)
        if not isinstance(client.config, Path) or not client.config.is_absolute():
            raise InstallationContextError("INSTALLATION_CLIENT_PATH_INVALID")
        if client.settings is not None and (not isinstance(client.settings, Path) or not client.settings.is_absolute()):
            raise InstallationContextError("INSTALLATION_CLIENT_PATH_INVALID")
        for paths in (client.plugin_roots, client.owner_executables):
            if not isinstance(paths, tuple) or any(not isinstance(path, Path) or not path.is_absolute() for path in paths):
                raise InstallationContextError("INSTALLATION_CLIENT_PATH_INVALID")


def write_context(context: InstallContext) -> None:
    """Create the owner-only root and publish a strict descriptor without clobbering."""
    _validate_context(context)
    root = Path(os.path.abspath(os.fspath(context.root)))
    if root != context.root:
        raise InstallationContextError("INSTALLATION_ROOT_NONCANONICAL")
    _ensure_private_directory(root)
    descriptor = root / DESCRIPTOR_NAME
    if descriptor.exists() or descriptor.is_symlink():
        raise InstallationContextError("INSTALLATION_DESCRIPTOR_EXISTS")
    raw = _serialize_context(context)
    temp = root / (".installation.json." + secrets.token_hex(12) + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temp, flags, 0o600)
    except OSError as exc:
        raise InstallationContextError("INSTALLATION_DESCRIPTOR_CREATE_FAILED") from exc
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                raise InstallationContextError("INSTALLATION_DESCRIPTOR_WRITE_FAILED")
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(temp, descriptor, follow_symlinks=False)
        os.unlink(temp)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as exc:
        os.unlink(temp)
        raise InstallationContextError("INSTALLATION_DESCRIPTOR_EXISTS") from exc
    except OSError as exc:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise InstallationContextError("INSTALLATION_DESCRIPTOR_PUBLISH_FAILED") from exc


def _read_protected(path: Path) -> bytes:
    try:
        path_info = path.lstat()
        if not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() or stat.S_IMODE(path_info.st_mode) != 0o600:
            raise InstallationContextError("INSTALLATION_DESCRIPTOR_UNSAFE")
        if path_info.st_size > MAX_DESCRIPTOR_BYTES:
            raise InstallationContextError("INSTALLATION_DESCRIPTOR_TOO_LARGE")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except InstallationContextError:
        raise
    except OSError as exc:
        raise InstallationContextError("INSTALLATION_DESCRIPTOR_UNREADABLE") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600:
            raise InstallationContextError("INSTALLATION_DESCRIPTOR_UNSAFE")
        if (before.st_dev, before.st_ino) != (path_info.st_dev, path_info.st_ino):
            raise InstallationContextError("INSTALLATION_DESCRIPTOR_REPLACED")
        pieces: list[bytes] = []
        remaining = MAX_DESCRIPTOR_BYTES + 1
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                break
            pieces.append(block)
            remaining -= len(block)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise InstallationContextError("INSTALLATION_DESCRIPTOR_CHANGED")
        data = b"".join(pieces)
        if len(data) > MAX_DESCRIPTOR_BYTES:
            raise InstallationContextError("INSTALLATION_DESCRIPTOR_TOO_LARGE")
        return data
    finally:
        os.close(fd)


def _client_from_json(value: object) -> ClientPaths:
    keys = {"kind", "config", "settings", "plugin_roots", "owner_executables"}
    if not isinstance(value, dict) or set(value) != keys:
        raise InstallationContextError("INSTALLATION_CLIENT_SCHEMA_INVALID")
    kind = value["kind"]
    if kind not in {"claude", "codex"}:
        raise InstallationContextError("INSTALLATION_CLIENT_KIND_INVALID")
    settings = None if value["settings"] is None else _path_value(value["settings"], "settings")
    plugin_roots = value["plugin_roots"]
    owner_executables = value["owner_executables"]
    if not isinstance(plugin_roots, list) or not isinstance(owner_executables, list):
        raise InstallationContextError("INSTALLATION_CLIENT_PATH_INVALID")
    return ClientPaths(
        kind=kind,
        config=_path_value(value["config"], "config"),
        settings=settings,
        plugin_roots=tuple(_path_value(path, "plugin_root") for path in plugin_roots),
        owner_executables=tuple(_path_value(path, "owner_executable") for path in owner_executables),
    )


def load_context(path: Path) -> InstallContext:
    """Load a strict, owner-only installation descriptor without following links."""
    path = Path(os.path.abspath(os.fspath(path)))
    if path.name != DESCRIPTOR_NAME:
        raise InstallationContextError("INSTALLATION_DESCRIPTOR_PATH_INVALID")
    root = path.parent
    root_info = _is_plain_directory(root, owner=os.getuid(), mode=0o700)
    if root.resolve(strict=True) != root:
        raise InstallationContextError("INSTALLATION_ROOT_SYMLINK")
    raw = _read_protected(path)
    value = _strict_json(raw)
    keys = {"version", "root", "release", "runtime", "artifacts", "python", "node", "port", "clients"}
    if set(value) != keys:
        raise InstallationContextError("INSTALLATION_SCHEMA_INVALID")
    descriptor_root = _path_value(value["root"], "root")
    if descriptor_root != root or (root_info.st_dev, root_info.st_ino) != (root.lstat().st_dev, root.lstat().st_ino):
        raise InstallationContextError("INSTALLATION_ROOT_MISMATCH")
    clients_value = value["clients"]
    if not isinstance(clients_value, list):
        raise InstallationContextError("INSTALLATION_CLIENTS_INVALID")
    context = InstallContext(
        version=value["version"],
        root=descriptor_root,
        release=_path_value(value["release"], "release"),
        runtime=_path_value(value["runtime"], "runtime"),
        artifacts=_path_value(value["artifacts"], "artifacts"),
        python=_path_value(value["python"], "python"),
        node=_path_value(value["node"], "node"),
        port=value["port"],
        clients=tuple(_client_from_json(client) for client in clients_value),
    )
    _validate_context(context)
    return context


def replace_context(previous: InstallContext, updated: InstallContext) -> None:
    """Atomically replace only the release path after an exact descriptor comparison.

    Callers must hold the per-installation lock while changing the descriptor.
    """
    _validate_context(previous)
    _validate_context(updated)
    if previous.root != updated.root or replace(previous, release=updated.release) != updated:
        raise InstallationContextError("INSTALLATION_CONTEXT_UPDATE_SCOPE_INVALID")
    root = Path(os.path.abspath(os.fspath(previous.root)))
    if root != previous.root:
        raise InstallationContextError("INSTALLATION_ROOT_NONCANONICAL")
    _is_plain_directory(root, owner=os.getuid(), mode=0o700)
    if root.resolve(strict=True) != root:
        raise InstallationContextError("INSTALLATION_ROOT_SYMLINK")
    descriptor = root / DESCRIPTOR_NAME
    expected = _serialize_context(previous)
    replacement = _serialize_context(updated)
    actual = _read_protected(descriptor)
    if actual != expected:
        raise InstallationContextError("INSTALLATION_CONTEXT_CONFLICT")
    if load_context(descriptor) != previous:
        raise InstallationContextError("INSTALLATION_CONTEXT_CONFLICT")
    try:
        original_info = descriptor.lstat()
    except OSError as exc:
        raise InstallationContextError("INSTALLATION_CONTEXT_CONFLICT") from exc
    temporary = root / (".installation.json." + secrets.token_hex(12) + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temporary, flags, 0o600)
    except OSError as exc:
        raise InstallationContextError("INSTALLATION_DESCRIPTOR_CREATE_FAILED") from exc
    try:
        offset = 0
        while offset < len(replacement):
            written = os.write(fd, replacement[offset:])
            if written <= 0:
                raise InstallationContextError("INSTALLATION_DESCRIPTOR_WRITE_FAILED")
            offset += written
        os.fsync(fd)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    try:
        current_info = descriptor.lstat()
        if (
            (current_info.st_dev, current_info.st_ino) != (original_info.st_dev, original_info.st_ino)
            or _read_protected(descriptor) != expected
        ):
            raise InstallationContextError("INSTALLATION_CONTEXT_CONFLICT")
        os.replace(temporary, descriptor)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except InstallationContextError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise InstallationContextError("INSTALLATION_DESCRIPTOR_REPLACE_FAILED") from exc
    if _read_protected(descriptor) != replacement or load_context(descriptor) != updated:
        raise InstallationContextError("INSTALLATION_DESCRIPTOR_READBACK_FAILED")


def _signature_valid(path: Path, requirement: str, *, timeout: int) -> bool:
    try:
        result = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", "-R", "=" + requirement, str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _trusted_file(path: Path, *, require_user_owned: bool) -> bool:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
            return False
        if path.resolve(strict=True) != path:
            return False
        if require_user_owned and info.st_uid != os.getuid():
            return False
        if info.st_mode & 0o022:
            return False
        for parent in path.parents:
            parent_info = parent.lstat()
            if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_mode & 0o022 or parent_info.st_uid not in (0, os.getuid()):
                return False
        return True
    except OSError:
        return False


def _client_config(home: Path, path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise InstallationContextError("CLIENT_CONFIG_UNREADABLE") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise InstallationContextError("CLIENT_CONFIG_UNSAFE")
    if path.resolve(strict=True) != path or home not in path.parents:
        raise InstallationContextError("CLIENT_CONFIG_PATH_INVALID")
    return True


def _directory_present(home: Path, path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise InstallationContextError("CLIENT_DIRECTORY_UNREADABLE") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise InstallationContextError("CLIENT_DIRECTORY_UNSAFE")
    if path.resolve(strict=True) != path or home not in path.parents:
        raise InstallationContextError("CLIENT_DIRECTORY_PATH_INVALID")
    return True


def _read_discovery_file(path: Path, maximum: int) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or info.st_size > maximum:
            raise InstallationContextError("PLUGIN_REGISTRY_UNSAFE")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except InstallationContextError:
        raise
    except OSError as exc:
        raise InstallationContextError("PLUGIN_REGISTRY_UNREADABLE") from exc
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            raise InstallationContextError("PLUGIN_REGISTRY_REPLACED")
        pieces = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                break
            pieces.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InstallationContextError("PLUGIN_REGISTRY_CHANGED")
        raw = b"".join(pieces)
        if len(raw) > maximum:
            raise InstallationContextError("PLUGIN_REGISTRY_TOO_LARGE")
        return raw
    finally:
        os.close(descriptor)


def _plugin_root_ready(root: Path, client: str, *, allowed_parent: Path, expected_id: str) -> bool:
    try:
        info = root.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise InstallationContextError("PLUGIN_ROOT_UNREADABLE") from exc
    if not stat.S_ISDIR(info.st_mode) or root.resolve(strict=True) != root or allowed_parent not in root.parents:
        raise InstallationContextError("PLUGIN_ROOT_UNSAFE")
    metadata_path = root / (".claude-plugin/plugin.json" if client == "claude" else ".codex-plugin/plugin.json")
    source_path = root / ".mcp.json"
    try:
        metadata_info = metadata_path.lstat()
        source_info = source_path.lstat()
    except OSError as exc:
        raise InstallationContextError("PLUGIN_ROOT_INCOMPLETE") from exc
    if (
        not stat.S_ISREG(metadata_info.st_mode)
        or not stat.S_ISREG(source_info.st_mode)
        or metadata_info.st_uid != os.getuid()
        or source_info.st_uid != os.getuid()
        or metadata_info.st_mode & 0o022
        or source_info.st_mode & 0o022
    ):
        raise InstallationContextError("PLUGIN_ROOT_UNSAFE")
    try:
        metadata = _strict_json(_read_discovery_file(metadata_path, 128 * 1024))
    except InstallationContextError:
        raise
    except Exception as exc:
        raise InstallationContextError("PLUGIN_METADATA_INVALID") from exc
    pieces = expected_id.split("@", 1)
    expected_name = pieces[0]
    if root.parent.name != expected_name or root.parent.parent.name != pieces[1]:
        raise InstallationContextError("PLUGIN_ROOT_ID_MISMATCH")
    if metadata.get("name") != expected_name or not isinstance(metadata.get("version"), str):
        raise InstallationContextError("PLUGIN_METADATA_MISMATCH")
    source_name = metadata.get("mcpServers", ".mcp.json")
    if source_name not in (".mcp.json", "./.mcp.json"):
        raise InstallationContextError("PLUGIN_SOURCE_PATH_UNSUPPORTED")
    return True


def _claude_plugin_roots(home: Path, settings_path: Path | None) -> tuple[Path, ...]:
    if settings_path is None:
        return ()
    try:
        settings = _strict_json(_read_discovery_file(settings_path, 4 * 1024 * 1024))
    except InstallationContextError:
        raise
    except Exception as exc:
        raise InstallationContextError("CLAUDE_PLUGIN_SETTINGS_INVALID") from exc
    enabled = settings.get("enabledPlugins", {})
    if not isinstance(enabled, dict):
        raise InstallationContextError("CLAUDE_PLUGIN_SETTINGS_INVALID")
    active_ids = set()
    for plugin_id, active in enabled.items():
        if not isinstance(plugin_id, str) or not PLUGIN_ID.fullmatch(plugin_id) or type(active) is not bool:
            raise InstallationContextError("CLAUDE_PLUGIN_SETTINGS_INVALID")
        if active:
            active_ids.add(plugin_id)
    if not active_ids:
        return ()
    plugins_root = home / ".claude/plugins"
    if not _directory_present(home, plugins_root):
        return ()
    registry_path = home / ".claude/plugins/installed_plugins.json"
    try:
        registry_path.lstat()
    except OSError:
        return ()
    registry = _strict_json(_read_discovery_file(registry_path, 4 * 1024 * 1024))
    plugins = registry.get("plugins")
    if not isinstance(plugins, dict):
        raise InstallationContextError("CLAUDE_PLUGIN_REGISTRY_INVALID")
    cache_root = home / ".claude/plugins/cache"
    if not _directory_present(home, cache_root):
        return ()
    roots: list[Path] = []
    for plugin_id in sorted(active_ids):
        entries = plugins.get(plugin_id)
        if not isinstance(entries, list):
            continue
        installed: set[Path] = set()
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("installPath"), str):
                continue
            raw_path = Path(entry["installPath"])
            if not raw_path.is_absolute():
                continue
            root = raw_path
            try:
                resolved_root = root.resolve(strict=True)
            except OSError:
                continue
            if resolved_root != root or cache_root not in root.parents:
                continue
            try:
                if _plugin_root_ready(root, "claude", allowed_parent=cache_root, expected_id=plugin_id):
                    installed.add(root)
            except InstallationContextError:
                continue
        if len(installed) == 1:
            roots.extend(installed)
    return tuple(sorted(set(roots)))


def _codex_plugin_roots(home: Path, config_path: Path) -> tuple[Path, ...]:
    try:
        import tomllib
        config = tomllib.loads(_read_discovery_file(config_path, 4 * 1024 * 1024).decode("utf-8", errors="strict"))
    except (ImportError, OSError, UnicodeError, ValueError) as exc:
        raise InstallationContextError("CODEX_CONFIG_INVALID") from exc
    plugin_settings = config.get("plugins", {})
    if not isinstance(plugin_settings, dict):
        raise InstallationContextError("CODEX_PLUGIN_SETTINGS_INVALID")
    cache_root = home / ".codex/plugins/cache"
    roots: list[Path] = []
    for plugin_id, settings in sorted(plugin_settings.items()):
        if not isinstance(plugin_id, str):
            raise InstallationContextError("CODEX_PLUGIN_SETTINGS_INVALID")
        if not PLUGIN_ID.fullmatch(plugin_id):
            enabled = settings.get("enabled", True) if isinstance(settings, dict) else True
            if enabled is True:
                raise InstallationContextError("CODEX_PLUGIN_ID_UNSUPPORTED")
            continue
        if not isinstance(settings, dict):
            raise InstallationContextError("CODEX_PLUGIN_SETTINGS_INVALID")
        enabled = settings.get("enabled", True)
        if type(enabled) is not bool:
            raise InstallationContextError("CODEX_PLUGIN_SETTINGS_INVALID")
        if not enabled:
            continue
        marketplace, plugin_name = plugin_id.split("@", 1)[1], plugin_id.split("@", 1)[0]
        plugin_parent = cache_root / marketplace / plugin_name
        if not _directory_present(home, plugin_parent):
            if enabled:
                raise InstallationContextError("CODEX_PLUGIN_ROOT_MISSING")
            continue
        candidates = []
        for version_root in sorted(plugin_parent.iterdir()):
            if not CLAUDE_VERSION.fullmatch(version_root.name):
                continue
            try:
                if _plugin_root_ready(version_root, "codex", allowed_parent=cache_root, expected_id=plugin_id):
                    candidates.append(version_root)
            except InstallationContextError as exc:
                if str(exc) == "PLUGIN_ROOT_INCOMPLETE":
                    raise InstallationContextError("CODEX_PLUGIN_ROOT_MISSING") from None
                raise InstallationContextError("CODEX_PLUGIN_ROOT_INVALID") from None
        requested_version = settings.get("version")
        if requested_version is not None:
            if not isinstance(requested_version, str):
                raise InstallationContextError("CODEX_PLUGIN_VERSION_INVALID")
            candidates = [path for path in candidates if path.name == requested_version]
        if len(candidates) > 1:
            raise InstallationContextError("CODEX_PLUGIN_ROOT_AMBIGUOUS")
        if not candidates:
            if enabled:
                raise InstallationContextError("CODEX_PLUGIN_ROOT_MISSING")
            continue
        roots.append(candidates[0])
    return tuple(sorted(set(roots)))


def discover_clients(home: Path, *, kinds: set[str] | None = None) -> tuple[ClientPaths, ...]:
    """Discover configured clients and only their locally verified vendor binaries."""
    home = Path(os.path.abspath(os.fspath(home)))
    if kinds is None:
        requested_kinds = {"claude", "codex"}
    elif not isinstance(kinds, (set, frozenset)) or not kinds <= {"claude", "codex"}:
        raise InstallationContextError("CLIENT_KINDS_INVALID")
    else:
        requested_kinds = set(kinds)
    try:
        info = home.lstat()
    except OSError as exc:
        raise InstallationContextError("HOME_PATH_INVALID") from exc
    if not stat.S_ISDIR(info.st_mode) or home.resolve(strict=True) != home:
        raise InstallationContextError("HOME_PATH_INVALID")
    if platform.system() != "Darwin":
        return ()

    clients: list[ClientPaths] = []
    codex_config = home / ".codex/config.toml"
    codex_configured = "codex" in requested_kinds and _client_config(home, codex_config)
    codex_is_present = codex_configured
    if codex_is_present:
        plugin_roots = _codex_plugin_roots(home, codex_config) if codex_configured else ()
        codex_paths: list[Path] = []
        candidates = (
            Path("/Applications/ChatGPT.app") / CODEX_RELATIVE_EXECUTABLE,
            home / "Applications/ChatGPT.app" / CODEX_RELATIVE_EXECUTABLE,
        )
        for candidate in candidates:
            if _trusted_file(candidate, require_user_owned=False) and _signature_valid(candidate, CODEX_REQUIREMENT, timeout=5):
                codex_paths.append(candidate)
        clients.append(ClientPaths(
            kind="codex",
            config=codex_config,
            settings=None,
            plugin_roots=plugin_roots,
            owner_executables=tuple(dict.fromkeys(codex_paths)),
        ))

    claude_config = home / ".claude.json"
    claude_settings = home / ".claude/settings.json"
    claude_plugins = home / ".claude/plugins"
    claude_requested = "claude" in requested_kinds
    claude_configured = claude_requested and _client_config(home, claude_config)
    claude_settings_configured = claude_requested and _client_config(home, claude_settings)
    claude_is_present = claude_requested and (
        claude_configured or claude_settings_configured or _directory_present(home, claude_plugins)
    )
    if claude_is_present:
        if not claude_configured:
            raise InstallationContextError("CLAUDE_CONFIG_MISSING")
        claude_paths: list[Path] = []
        versions = home / ".local/share/claude/versions"
        try:
            version_info = versions.lstat()
        except FileNotFoundError:
            version_info = None
        except OSError as exc:
            raise InstallationContextError("CLAUDE_VERSION_DIRECTORY_UNREADABLE") from exc
        if version_info is not None:
            if not stat.S_ISDIR(version_info.st_mode) or versions.resolve(strict=True) != versions:
                raise InstallationContextError("CLAUDE_VERSION_DIRECTORY_UNSAFE")
            for candidate in sorted(versions.iterdir()):
                if not CLAUDE_VERSION.fullmatch(candidate.name):
                    continue
                if _trusted_file(candidate, require_user_owned=True) and _signature_valid(candidate, CLAUDE_REQUIREMENT, timeout=15):
                    claude_paths.append(candidate)
        plugin_roots = _claude_plugin_roots(home, claude_settings if claude_settings_configured else None)
        clients.append(ClientPaths(
            kind="claude",
            config=claude_config,
            settings=claude_settings if _client_config(home, claude_settings) else None,
            plugin_roots=plugin_roots,
            owner_executables=tuple(claude_paths),
        ))

    return tuple(clients)


def read_install_key(context: InstallContext) -> bytes:
    """Read the existing manager token as bytes after strict owner/mode checks."""
    path = installation_state_paths(context).key
    try:
        path_info = path.lstat()
        if not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.getuid() or stat.S_IMODE(path_info.st_mode) != 0o600:
            raise InstallationContextError("INSTALLATION_KEY_UNSAFE")
        if path_info.st_size != 64:
            raise InstallationContextError("INSTALLATION_KEY_INVALID")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except InstallationContextError:
        raise
    except OSError as exc:
        raise InstallationContextError("INSTALLATION_KEY_UNREADABLE") from exc
    try:
        before = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (path_info.st_dev, path_info.st_ino):
            raise InstallationContextError("INSTALLATION_KEY_REPLACED")
        raw = os.read(fd, 65)
        after = os.fstat(fd)
        if len(raw) != 64 or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InstallationContextError("INSTALLATION_KEY_CHANGED")
        try:
            text = raw.decode("ascii")
        except UnicodeError as exc:
            raise InstallationContextError("INSTALLATION_KEY_INVALID") from exc
        if not HEX64.fullmatch(text):
            raise InstallationContextError("INSTALLATION_KEY_INVALID")
        return bytes.fromhex(text)
    finally:
        os.close(fd)


def load_or_create_install_key(context: InstallContext) -> bytes:
    """Create the fresh 256-bit manager token once, or read the existing one safely."""
    root = Path(os.path.abspath(os.fspath(context.root)))
    if root != context.root:
        raise InstallationContextError("INSTALLATION_ROOT_NONCANONICAL")
    _ensure_private_directory(root)
    runtime = Path(os.path.abspath(os.fspath(context.runtime)))
    if runtime != context.runtime or root not in runtime.parents:
        raise InstallationContextError("INSTALLATION_RUNTIME_PATH_INVALID")
    if runtime.exists() or runtime.is_symlink():
        _is_plain_directory(runtime, owner=os.getuid(), mode=0o700)
        if runtime.resolve(strict=True) != runtime:
            raise InstallationContextError("INSTALLATION_RUNTIME_SYMLINK")
    else:
        runtime.mkdir(mode=0o700)
    path = installation_state_paths(context).key
    if path.exists() or path.is_symlink():
        return read_install_key(context)
    encoded = secrets.token_hex(32).encode("ascii")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return read_install_key(context)
    except OSError as exc:
        raise InstallationContextError("INSTALLATION_KEY_CREATE_FAILED") from exc
    try:
        if os.write(fd, encoded) != len(encoded):
            raise InstallationContextError("INSTALLATION_KEY_WRITE_FAILED")
        os.fsync(fd)
    finally:
        os.close(fd)
    return bytes.fromhex(encoded.decode("ascii"))
