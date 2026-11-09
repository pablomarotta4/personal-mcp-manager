"""Single, fail-closed entry point for a portable per-user MCP manager install."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import replace
from typing import Mapping, Sequence


SUPPORTED_FAMILIES = frozenset({"grafana", "langfuse", "loki", "mysql"})
PLAN_FIELDS = frozenset({"client", "scope", "name", "family", "enabled", "status", "reason"})
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SELECTOR_PART = re.compile(r"[^:\x00\r\n]{1,512}\Z")
MAX_ARTIFACT_INPUT_PINS = 512
EXIT_PLAN_OR_REFUSAL = 2
EXIT_RECOVERY_REQUIRED = 3
EXIT_VERIFICATION_FAILED = 4


class InstallError(Exception):
    def __init__(self, code: str):
        self.code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) else "INSTALL_FAILED"
        super().__init__(self.code)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install a personal local MCP manager.")
    parser.add_argument("--client", choices=("claude", "codex", "both"))
    parser.add_argument("--source", action="append", default=[], metavar="CLIENT:SCOPE:NAME")
    parser.add_argument("--project", action="append", default=[], metavar="PATH")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="print the redacted plan without installing")
    mode.add_argument("--accept-plan", metavar="SHA256", help="accept the displayed current plan hash")
    parser.add_argument("--node", type=Path)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--port", type=int, default=18765)
    return parser


def _python_prerequisite() -> None:
    if sys.version_info < (3, 11):
        raise InstallError("PYTHON_3_11_REQUIRED")
    try:
        importlib.import_module("tomllib")
    except ImportError as exc:
        raise InstallError("PYTHON_3_11_REQUIRED") from exc


def _internal(name: str):
    try:
        return importlib.import_module(name)
    except Exception as exc:
        raise InstallError("INSTALL_COMPONENT_UNAVAILABLE") from exc


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise InstallError("PLAN_INVALID") from exc


def _selector(candidate) -> tuple[str, str, str]:
    try:
        ref = candidate.ref
        values = (ref.client, ref.scope, ref.name)
    except (AttributeError, TypeError) as exc:
        raise InstallError("SOURCE_INVENTORY_INVALID") from exc
    if any(not isinstance(value, str) or not SELECTOR_PART.fullmatch(value) for value in values):
        raise InstallError("SOURCE_SELECTOR_INVALID")
    return values


def _safe_public_rows(client_sources, candidates) -> list[dict[str, object]]:
    try:
        rows = client_sources.public_plan(candidates)
    except Exception as exc:
        raise InstallError("SOURCE_PLAN_UNAVAILABLE") from exc
    if not isinstance(rows, list):
        raise InstallError("SOURCE_PLAN_INVALID")
    safe: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) - PLAN_FIELDS:
            raise InstallError("SOURCE_PLAN_INVALID")
        if set(row) < {"client", "scope", "name", "family", "enabled", "status", "reason"}:
            raise InstallError("SOURCE_PLAN_INVALID")
        if any(not isinstance(row.get(key), str) for key in ("client", "scope", "name", "family", "status", "reason")):
            raise InstallError("SOURCE_PLAN_INVALID")
        if type(row.get("enabled")) is not bool:
            raise InstallError("SOURCE_PLAN_INVALID")
        safe.append({key: row[key] for key in ("client", "scope", "name", "family", "enabled", "status", "reason")})
    return sorted(safe, key=lambda row: (row["client"], row["scope"], row["name"], row["family"]))


def _parse_selector(value: str) -> tuple[str, str, str]:
    if not isinstance(value, str):
        raise InstallError("SOURCE_SELECTOR_INVALID")
    parts = value.split(":", 2)
    if len(parts) != 3 or parts[0] not in {"claude", "codex"} or any(not SELECTOR_PART.fullmatch(part) for part in parts):
        raise InstallError("SOURCE_SELECTOR_INVALID")
    return parts[0], parts[1], parts[2]


def _eligible(candidate) -> bool:
    try:
        family = candidate.family
        enabled = candidate.enabled
        blockers = candidate.blockers
    except AttributeError as exc:
        raise InstallError("SOURCE_INVENTORY_INVALID") from exc
    return family in SUPPORTED_FAMILIES and enabled is True and not blockers


def _select_sources(candidates, requested_clients: set[str], selectors: Sequence[str]):
    by_selector: dict[tuple[str, str, str], list[object]] = {}
    for candidate in candidates:
        selected = _selector(candidate)
        by_selector.setdefault(selected, []).append(candidate)
    if selectors:
        requested = [_parse_selector(value) for value in selectors]
        if len(set(requested)) != len(requested):
            raise InstallError("SOURCE_SELECTOR_DUPLICATE")
        selected_candidates = []
        for selector in requested:
            if selector[0] not in requested_clients:
                raise InstallError("SOURCE_CLIENT_NOT_SELECTED")
            matches = by_selector.get(selector, [])
            if len(matches) != 1:
                raise InstallError("SOURCE_SELECTOR_NOT_FOUND_OR_AMBIGUOUS")
            if not _eligible(matches[0]):
                raise InstallError("SOURCE_SELECTION_UNSUPPORTED")
            selected_candidates.append(matches[0])
        return selected_candidates
    return [
        candidate for candidate in candidates
        if _selector(candidate)[0] in requested_clients and _eligible(candidate)
    ]


def _resolve_executable(explicit: Path | None, name: str, current: Path | None = None) -> Path:
    raw = explicit or current
    if raw is None:
        located = shutil.which(name)
        raw = Path(located) if located else None
    if raw is None:
        raise InstallError(name.upper() + "_NOT_FOUND")
    try:
        path = Path(raw).resolve(strict=True)
        info = path.stat()
    except OSError as exc:
        raise InstallError("EXECUTABLE_NOT_FOUND") from exc
    if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise InstallError("EXECUTABLE_INVALID")
    return path


def _trusted_metadata_chain(executable_info, parent_infos: Sequence[object], *, uid: int) -> bool:
    if (
        not stat.S_ISREG(executable_info.st_mode)
        or not executable_info.st_mode & 0o111
        or executable_info.st_mode & 0o022
        or executable_info.st_uid not in (0, uid)
    ):
        return False
    return all(
        stat.S_ISDIR(info.st_mode)
        and not info.st_mode & 0o022
        and info.st_uid in (0, uid)
        for info in parent_infos
    )


def _trusted_executable(path: Path) -> bool:
    try:
        path = Path(path)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            return False
        info = path.lstat()
        parent_infos = [parent.lstat() for parent in path.parents]
        return _trusted_metadata_chain(info, parent_infos, uid=os.getuid())
    except OSError:
        return False


def _trusted_directory(path: Path) -> bool:
    try:
        info = path.lstat()
        return (
            stat.S_ISDIR(info.st_mode)
            and info.st_uid in (0, os.getuid())
            and not info.st_mode & 0o022
            and path.resolve(strict=True) == path
        )
    except OSError:
        return False


def _uv_python_candidates(home: Path) -> list[tuple[tuple[int, int, int], Path]]:
    root = home / ".local/share/uv/python"
    if not _trusted_directory(root):
        return []
    candidates: list[tuple[tuple[int, int, int], Path]] = []
    version_pattern = re.compile(r"cpython-([0-9]+)\.([0-9]+)\.([0-9]+)(?:-|\Z)")
    executable_pattern = re.compile(r"python3(?:\.[0-9]+)?\Z")
    try:
        versions = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError:
        return []
    for version_root in versions:
        match = version_pattern.match(version_root.name)
        if not match or not _trusted_directory(version_root):
            continue
        executable_root = version_root / "bin"
        if not _trusted_directory(executable_root):
            continue
        version = tuple(int(piece) for piece in match.groups())
        try:
            executables = sorted(executable_root.iterdir(), key=lambda path: path.name)
        except OSError:
            continue
        for executable in executables:
            if executable_pattern.fullmatch(executable.name) and _trusted_executable(executable):
                candidates.append((version, executable))
    return sorted(candidates, key=lambda pair: (pair[0], str(pair[1])), reverse=True)


def _resolve_python_executable(explicit: Path | None, *, current: Path | None, home: Path) -> Path:
    if explicit is not None:
        path = _resolve_executable(explicit, "python")
        if not _trusted_executable(path):
            raise InstallError("PYTHON_TRUST_UNVERIFIED")
        _runtime_version(path, "python")
        return path

    candidates = [path for _version, path in _uv_python_candidates(home)]
    if current is not None:
        try:
            current_path = _resolve_executable(current, "python")
        except InstallError:
            current_path = None
        if current_path is not None and current_path not in candidates and _trusted_executable(current_path):
            candidates.append(current_path)
    for fallback in (Path("/usr/bin/python3"), Path("/usr/local/bin/python3")):
        try:
            fallback_path = _resolve_executable(fallback, "python")
        except InstallError:
            continue
        if fallback_path not in candidates and _trusted_executable(fallback_path):
            candidates.append(fallback_path)
    for path in candidates:
        try:
            _runtime_version(path, "python")
        except InstallError:
            continue
        return path
    raise InstallError("PYTHON_TRUSTED_3_11_REQUIRED")


def _runtime_version(executable: Path, kind: str) -> tuple[int, ...]:
    try:
        result = subprocess.run(
            [str(executable), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=10,
            env={"PATH": str(executable.parent) + os.pathsep + "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError("RUNTIME_VERSION_CHECK_FAILED") from exc
    if result.returncode != 0:
        raise InstallError("RUNTIME_VERSION_CHECK_FAILED")
    match = re.search(r"([0-9]+)\.([0-9]+)(?:\.([0-9]+))?", result.stdout)
    if not match:
        raise InstallError("RUNTIME_VERSION_UNREADABLE")
    version = tuple(int(piece or 0) for piece in match.groups())
    required = (3, 11, 0) if kind == "python" else (22, 12, 0)
    if version < required:
        raise InstallError("PYTHON_3_11_REQUIRED" if kind == "python" else "NODE_22_12_REQUIRED")
    return version


def _runtime_architecture(executable: Path, kind: str) -> str:
    command = (
        [str(executable), "-c", "import platform; print(platform.machine())"]
        if kind == "python"
        else [str(executable), "-p", "process.arch"]
    )
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=10,
            env={"PATH": str(executable.parent) + os.pathsep + "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError("RUNTIME_ARCHITECTURE_CHECK_FAILED") from exc
    if result.returncode != 0 or len(result.stdout) > 128:
        raise InstallError("RUNTIME_ARCHITECTURE_CHECK_FAILED")
    architecture = result.stdout.strip().lower()
    if architecture not in {"arm64", "aarch64"}:
        raise InstallError("RUNTIME_ARCHITECTURE_UNSUPPORTED")
    return architecture


def _project_version(project_root: Path) -> str:
    try:
        value = json.loads((project_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise InstallError("PROJECT_PACKAGE_INVALID") from exc
    version = value.get("version") if isinstance(value, dict) else None
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise InstallError("PROJECT_VERSION_INVALID")
    return version


def _context_for(args, *, clients, home: Path):
    context_module = _internal("installation_context")
    exporter = _internal("export_source")
    project_root = Path(__file__).resolve().parents[1]
    try:
        if type(args.port) is not int or not 1 <= args.port <= 65535:
            raise InstallError("INSTALLATION_PORT_INVALID")
        python_path = _resolve_python_executable(args.python, current=Path(sys.executable), home=home)
        node_path = _resolve_executable(args.node, "node")
        source_digest = exporter.source_digest(project_root, portable_only=True)
        version = _project_version(project_root)
    except InstallError:
        raise
    except Exception as exc:
        raise InstallError("PROJECT_SOURCE_INVALID") from exc
    root = context_module.default_root(home)
    release = root / "app/releases" / f"{version}-{source_digest}"
    context = context_module.InstallContext(
        version=1,
        root=root,
        release=release,
        runtime=root / "runtime",
        artifacts=root / "artifacts",
        python=python_path,
        node=node_path,
        port=args.port,
        clients=tuple(clients),
    )
    return context, project_root, source_digest, version


def _project_paths(values: Sequence[str]) -> tuple[Path, ...]:
    result: list[Path] = []
    for value in values:
        path = Path(value)
        if not path.is_absolute():
            raise InstallError("PROJECT_PATH_MUST_BE_ABSOLUTE")
        try:
            resolved = path.resolve(strict=True)
            info = resolved.stat()
        except OSError as exc:
            raise InstallError("PROJECT_PATH_NOT_FOUND") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise InstallError("PROJECT_PATH_NOT_DIRECTORY")
        if resolved in result:
            raise InstallError("PROJECT_PATH_DUPLICATE")
        result.append(resolved)
    return tuple(result)


def _inventory_sources(client_sources, context, projects: Sequence[Path]):
    """Use authenticated native records for a matching installation rerun."""
    context_module = _internal("installation_context")
    root = Path(context.root)
    descriptor = root / "installation.json"
    if root.exists() or root.is_symlink():
        if descriptor.exists() or descriptor.is_symlink():
            try:
                stored = context_module.load_context(descriptor)
            except Exception as exc:
                raise InstallError("INSTALLATION_ROOT_CONFLICT") from exc
            if stored != context:
                raise InstallError("INSTALLATION_ROOT_CONFLICT")
            try:
                install_key = context_module.read_install_key(context)
                projection = _internal("client_projection")
                restored = getattr(projection, "restored_sources", None)
                if not callable(restored):
                    raise InstallError("CLIENT_PROJECTION_RESTORATION_UNAVAILABLE")
                candidates = restored(
                    context,
                    install_key=install_key,
                    projects=tuple(projects),
                    token=install_key.hex(),
                )
            except InstallError:
                raise
            except Exception as exc:
                code = getattr(exc, "code", None)
                if not isinstance(code, str):
                    candidate = str(exc)
                    code = candidate if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", candidate) else "SOURCE_INVENTORY_UNAVAILABLE"
                raise InstallError(code) from exc
            if not isinstance(candidates, list):
                raise InstallError("SOURCE_INVENTORY_INVALID")
            return candidates
        context_paths = context_module.installation_state_paths(context)
        if context_paths.journal.exists() or context_paths.journal.is_symlink():
            raise InstallError("INSTALLATION_RECOVERY_REQUIRED")
        raise InstallError("INSTALLATION_ROOT_CONFLICT")
    try:
        return client_sources.inventory_sources(context, projects=tuple(projects))
    except TypeError as exc:
        if projects:
            raise InstallError("PROJECT_SCOPE_UNSUPPORTED") from exc
        try:
            return client_sources.inventory_sources(context)
        except Exception as nested:
            raise InstallError("SOURCE_INVENTORY_UNAVAILABLE") from nested
    except Exception as exc:
        raise InstallError("SOURCE_INVENTORY_UNAVAILABLE") from exc


def _transaction_binding(context, selected, projects, *, plan_hash: str, release_digest: str) -> dict[str, str]:
    selected_refs = [
        {"client": client, "scope": scope, "name": name}
        for client, scope, name in map(_selector, selected)
    ]
    selected_refs.sort(key=lambda row: (row["client"], row["scope"], row["name"]))
    selected_clients = {row["client"] for row in selected_refs}
    targets = sorted(
        ({
            "client": client.kind,
            "config": str(client.config),
            "settings": str(client.settings) if client.settings is not None else None,
        } for client in context.clients if client.kind in selected_clients),
        key=lambda row: row["client"],
    )
    selection_digest = hashlib.sha256(_canonical_json(selected_refs)).hexdigest()
    projection_digest = hashlib.sha256(_canonical_json({
        "selection": selected_refs,
        "targets": targets,
        "projects": sorted(str(Path(path)) for path in projects),
    })).hexdigest()
    return {
        "planHash": plan_hash,
        "releaseDigest": release_digest,
        "selectionDigest": selection_digest,
        "projectionDigest": projection_digest,
    }


def _plan(args, *, client_sources=None):
    if client_sources is None:
        client_sources = _internal("client_sources")
    context_module = _internal("installation_context")
    home = Path.home().resolve(strict=True)
    projects = _project_paths(args.project)
    if args.client in {"claude", "codex"}:
        requested_clients = {args.client}
    elif args.client == "both":
        requested_clients = {"claude", "codex"}
    else:
        requested_clients = None
    detected = context_module.discover_clients(home, kinds=requested_clients)
    detected_kinds = {client.kind for client in detected}
    if requested_clients is None:
        requested_clients = detected_kinds
    if not requested_clients or not requested_clients <= detected_kinds:
        raise InstallError("REQUESTED_CLIENT_NOT_FOUND")
    clients = tuple(client for client in detected if client.kind in requested_clients)
    context, project_root, source_digest, version = _context_for(args, clients=clients, home=home)
    candidates = _inventory_sources(client_sources, context, projects)
    if not isinstance(candidates, list):
        raise InstallError("SOURCE_INVENTORY_INVALID")
    rows = _safe_public_rows(client_sources, candidates)
    selected = _select_sources(candidates, requested_clients, args.source)
    selected_refs = sorted([{"client": c, "scope": s, "name": n} for c, s, n in map(_selector, selected)], key=lambda value: (value["client"], value["scope"], value["name"]))
    plan = {
        "schema": 1,
        "clients": sorted(requested_clients),
        "projects": [str(path) for path in projects],
        "installerRelease": {"version": version, "digest": source_digest},
        "selected": selected_refs,
        "sources": rows,
    }
    plan_hash = hashlib.sha256(_canonical_json(plan)).hexdigest()
    return {
        "context": context,
        "projectRoot": project_root,
        "sourceDigest": source_digest,
        "releaseVersion": version,
        "candidates": candidates,
        "selected": selected,
        "projects": projects,
        "plan": plan,
        "planHash": plan_hash,
    }


def _record_status(value: object, *, expected: set[str] | None = None) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InstallError("INSTALL_COMPONENT_RESULT_INVALID")
    status = value.get("status")
    if not isinstance(status, str) or (expected is not None and status not in expected):
        raise InstallError("INSTALL_COMPONENT_RESULT_INVALID")
    return value


def _module_function(module_name: str, function_name: str):
    module = _internal(module_name)
    value = getattr(module, function_name, None)
    if not callable(value):
        raise InstallError("INSTALL_COMPONENT_UNAVAILABLE")
    return value


def _create_private_directory(path: Path) -> None:
    path = Path(os.path.abspath(os.fspath(path)))
    if path.exists() or path.is_symlink():
        try:
            info = path.lstat()
        except OSError as exc:
            raise InstallError("INSTALLATION_PATH_UNSAFE") from exc
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or path.resolve(strict=True) != path:
            raise InstallError("INSTALLATION_PATH_UNSAFE")
        return
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise InstallError("INSTALLATION_PATH_CREATE_FAILED") from exc
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise InstallError("INSTALLATION_PATH_UNSAFE")


def _run_quiet(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> None:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError("BUILD_COMMAND_FAILED") from exc
    if result.returncode != 0:
        raise InstallError("BUILD_COMMAND_FAILED")


def _tree_digests(root: Path) -> dict[str, str]:
    root = Path(os.path.abspath(os.fspath(root)))
    try:
        info = root.lstat()
    except OSError as exc:
        raise InstallError("BUILD_OUTPUT_MISSING") from exc
    if not stat.S_ISDIR(info.st_mode) or root.resolve(strict=True) != root:
        raise InstallError("BUILD_OUTPUT_UNSAFE")
    result: dict[str, str] = {}
    stack = [(root, Path())]
    while stack:
        directory, relative = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name, reverse=True)
        except OSError as exc:
            raise InstallError("BUILD_OUTPUT_UNREADABLE") from exc
        for entry in entries:
            child_relative = relative / entry.name
            path = root / child_relative
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise InstallError("BUILD_OUTPUT_UNREADABLE") from exc
            if stat.S_ISLNK(info.st_mode):
                try:
                    resolved = path.resolve(strict=True)
                except OSError as exc:
                    raise InstallError("BUILD_OUTPUT_SYMLINK_INVALID") from exc
                if root not in resolved.parents:
                    raise InstallError("BUILD_OUTPUT_SYMLINK_ESCAPE")
                result[child_relative.as_posix()] = hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()
            elif stat.S_ISDIR(info.st_mode):
                stack.append((path, child_relative))
            elif stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256()
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    before = os.fstat(descriptor)
                    if (before.st_dev, before.st_ino, before.st_size) != (info.st_dev, info.st_ino, info.st_size):
                        raise InstallError("BUILD_OUTPUT_CHANGED")
                    while True:
                        block = os.read(descriptor, 1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
                    after = os.fstat(descriptor)
                    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
                    ):
                        raise InstallError("BUILD_OUTPUT_CHANGED")
                finally:
                    os.close(descriptor)
                result[child_relative.as_posix()] = digest.hexdigest()
            else:
                raise InstallError("BUILD_OUTPUT_FILE_TYPE_INVALID")
    return dict(sorted(result.items()))


def _write_private_json(path: Path, value: Mapping[str, object], *, exclusive: bool = True) -> None:
    path = Path(os.path.abspath(os.fspath(path)))
    try:
        parent_info = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.getuid()
            or stat.S_IMODE(parent_info.st_mode) != 0o700
            or path.parent.resolve(strict=True) != path.parent
        ):
            raise InstallError("PRIVATE_FILE_PARENT_UNSAFE")
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError("PRIVATE_FILE_PARENT_UNSAFE") from exc
    raw = _canonical_json(value) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    if exclusive:
        flags |= os.O_EXCL
    else:
        flags |= os.O_TRUNC
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise InstallError("PRIVATE_FILE_CREATE_FAILED") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise InstallError("PRIVATE_FILE_UNSAFE")
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise InstallError("PRIVATE_FILE_WRITE_FAILED")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _read_private_json(path: Path, *, maximum: int, error_code: str) -> dict[str, object]:
    path = Path(os.path.abspath(os.fspath(path)))
    try:
        if path.parent.resolve(strict=True) != path.parent:
            raise InstallError(error_code)
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > maximum
        ):
            raise InstallError(error_code)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except InstallError:
        raise
    except OSError as exc:
        raise InstallError(error_code) from exc
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            raise InstallError(error_code)
        pieces = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                break
            pieces.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        raw = b"".join(pieces)
        if (
            len(raw) > maximum
            or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise InstallError(error_code)
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except InstallError:
        raise
    except (OSError, ValueError, UnicodeError) as exc:
        raise InstallError(error_code) from exc
    finally:
        os.close(descriptor)
    if not isinstance(value, dict):
        raise InstallError(error_code)
    return value


class InstallOperationsImpl:
    def __init__(self, request: Mapping[str, object], *, accept_plan: str, client_sources):
        self.request = request
        self.context = request["context"]
        self.original_context = self.context
        self.project_root = request["projectRoot"]
        self.source_digest = request["sourceDigest"]
        self.version = request["releaseVersion"]
        self.selected = list(request["selected"])
        self.projects = tuple(request["projects"])
        self.plan_hash = request["planHash"]
        self.accept_plan = accept_plan
        self.client_sources = client_sources
        self.stage_root: Path | None = None
        self.program_root: Path | None = None
        self.candidate_context = self.context
        self.artifact_workspace: Path | None = None
        self.artifacts: dict[str, dict[str, object]] = {}
        self.stage_records: dict[str, dict[str, object]] = {}
        self.doctor_result: dict[str, object] | None = None
        self.already_installed = False

    def _remember(self, phase: str, result: Mapping[str, object]) -> Mapping[str, object]:
        from install_transaction import _public_stage_record
        self.stage_records[phase] = _public_stage_record(result)
        return result

    def _service(self, function_name: str):
        return _module_function("service_install", function_name)

    def _receipt_path(self) -> Path:
        return self.context.root / "installation-receipt.json"

    def _read_receipt(self) -> dict[str, object]:
        value = _read_private_json(self._receipt_path(), maximum=64 * 1024, error_code="INSTALLATION_RECEIPT_INVALID")
        if not isinstance(value, dict) or set(value) != {"schema", "status", "planHash", "releaseDigest", "selectedCount", "doctor"}:
            raise InstallError("INSTALLATION_RECEIPT_INVALID")
        return value

    def _existing_install_matches(self) -> bool:
        context_module = _internal("installation_context")
        try:
            stored = context_module.load_context(self.context.root / "installation.json")
        except Exception:
            return False
        if stored != self.context:
            return False
        receipt = self._read_receipt()
        if receipt.get("schema") != 1 or receipt.get("planHash") != self.plan_hash or receipt.get("releaseDigest") != self.source_digest:
            return False
        key = context_module.read_install_key(self.context)
        service = _record_status(self._service("verify_service")(self.context), expected={"PASS"})
        if service.get("status") != "PASS":
            return False
        client_projection = _internal("client_projection")
        verify = getattr(client_projection, "verify_projections", None)
        if not callable(verify):
            raise InstallError("CLIENT_PROJECTION_VERIFIER_UNAVAILABLE")
        projection = _record_status(verify(self.context, self.selected, token=key.hex(), install_key=key))
        return projection.get("status") == "PASS"

    def preflight(self) -> Mapping[str, object]:
        if platform.system() != "Darwin" or platform.machine().lower() not in {"arm64", "aarch64"}:
            raise InstallError("APPLE_SILICON_MACOS_REQUIRED")
        dependencies = (
            ("service_install", "install_command"),
            ("service_install", "register_service"),
            ("service_install", "verify_service"),
            ("service_install", "service_action"),
            ("artifact_install", "acquire_family"),
            ("artifact_install", "install_setup_skill"),
            ("portable_engine", "_check_owner_socket_path"),
            ("portable_engine", "prepare_runtime"),
            ("portable_engine", "verify_candidate"),
            ("client_projection", "project_clients"),
            ("client_projection", "verify_projections"),
            ("client_projection", "rollback_clients"),
            ("installation_verify", "verify_installation"),
        )
        for module, function in dependencies:
            _module_function(module, function)
        _runtime_version(self.context.python, "python")
        _runtime_version(self.context.node, "node")
        _runtime_architecture(self.context.python, "python")
        _runtime_architecture(self.context.node, "node")
        clang = Path("/usr/bin/clang")
        if not clang.is_file() or not os.access(clang, os.X_OK):
            raise InstallError("APPLE_CLANG_REQUIRED")
        if not shutil.which("npm"):
            raise InstallError("NPM_NOT_FOUND")
        if not self.selected:
            raise InstallError("NO_SUPPORTED_SOURCES_SELECTED")
        if (
            self.context.root == self.project_root
            or self.context.root in self.project_root.parents
            or self.project_root in self.context.root.parents
        ):
            raise InstallError("PROJECT_WITHIN_INSTALL_ROOT")
        selected_kinds = {candidate.ref.client for candidate in self.selected}
        clients = {client.kind: client for client in self.context.clients}
        for kind in selected_kinds:
            if kind not in clients or not clients[kind].owner_executables:
                raise InstallError("CLIENT_OWNER_UNVERIFIED")
        root = self.context.root
        if root.exists() or root.is_symlink():
            try:
                root_info = root.lstat()
            except OSError as exc:
                raise InstallError("INSTALLATION_ROOT_UNSAFE") from exc
            if not stat.S_ISDIR(root_info.st_mode) or root.resolve(strict=True) != root:
                raise InstallError("INSTALLATION_ROOT_UNSAFE")
            descriptor = root / "installation.json"
            if descriptor.exists() and not descriptor.is_symlink():
                if self._existing_install_matches():
                    self.already_installed = True
                    return self._remember("preflight", {"status": "ALREADY_INSTALLED"})
            raise InstallError("INSTALLATION_ROOT_CONFLICT")
        try:
            _module_function("portable_engine", "_check_owner_socket_path")(
                self.context,
                session=any(candidate.family != "grafana" for candidate in self.selected),
            )
        except Exception as exc:
            code = str(exc)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
                code = "OWNER_SOCKET_PREFLIGHT_FAILED"
            raise InstallError(code) from None
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.settimeout(1)
            probe.bind(("127.0.0.1", self.context.port))
        except OSError as exc:
            raise InstallError("PORT_IN_USE") from exc
        finally:
            probe.close()
        return self._remember("preflight", {"status": "PASS"})

    def inventory(self) -> Mapping[str, object]:
        try:
            candidates = _inventory_sources(self.client_sources, self.context, self.projects)
        except InstallError:
            raise
        except Exception as exc:
            raise InstallError("SOURCE_INVENTORY_UNAVAILABLE") from exc
        if not isinstance(candidates, list):
            raise InstallError("SOURCE_INVENTORY_INVALID")
        if len(candidates) != len(self.request["candidates"]):
            raise InstallError("SOURCE_INVENTORY_CHANGED")
        def snapshot(values):
            rows = [(_selector(value), value.family, value.enabled, value.source, value.policy, tuple(value.blockers)) for value in values]
            if len({row[0] for row in rows}) != len(rows):
                raise InstallError("SOURCE_INVENTORY_AMBIGUOUS")
            return sorted(rows, key=lambda row: row[0])

        previous = snapshot(self.request["candidates"])
        current = snapshot(candidates)
        if current != previous:
            raise InstallError("SOURCE_INVENTORY_CHANGED")
        return self._remember("inventory", {"status": "PASS", "selectedCount": len(self.selected)})

    def confirm_plan(self) -> Mapping[str, object]:
        public_rows = _safe_public_rows(self.client_sources, self.request["candidates"])
        selected_refs = sorted([{"client": c, "scope": s, "name": n} for c, s, n in map(_selector, self.selected)], key=lambda value: (value["client"], value["scope"], value["name"]))
        plan = {
            "schema": 1,
            "clients": sorted({client.kind for client in self.context.clients}),
            "projects": [str(path) for path in self.projects],
            "installerRelease": {"version": self.version, "digest": self.source_digest},
            "selected": selected_refs,
            "sources": public_rows,
        }
        current_hash = hashlib.sha256(_canonical_json(plan)).hexdigest()
        if current_hash != self.plan_hash or self.accept_plan != current_hash:
            raise InstallError("PLAN_CHANGED_OR_NOT_ACCEPTED")
        return self._remember("confirm_plan", {"status": "PASS", "planHash": current_hash})

    def stage_release(self) -> Mapping[str, object]:
        exporter = _internal("export_source")
        try:
            before = exporter.source_manifest(self.project_root, portable_only=True)
            before_digest = hashlib.sha256(_canonical_json(before)).hexdigest()
            if before_digest != self.source_digest:
                raise InstallError("PROJECT_SOURCE_CHANGED")
        except InstallError:
            raise
        except Exception as exc:
            raise InstallError("PROJECT_SOURCE_INVALID") from exc
        app_root = self.context.root / "app"
        _create_private_directory(app_root)
        staging = app_root / "staging"
        _create_private_directory(staging)
        self.stage_root = staging / secrets.token_hex(16)
        _create_private_directory(self.stage_root)
        self.program_root = self.stage_root / "program"
        try:
            copied = exporter.export_source(self.project_root, self.program_root, portable_only=True)
        except Exception as exc:
            raise InstallError(getattr(exc, "code", "SOURCE_EXPORT_FAILED")) from exc
        copied_digest = hashlib.sha256(_canonical_json(copied)).hexdigest()
        if copied != before or copied_digest != self.source_digest:
            raise InstallError("PROJECT_SOURCE_CHANGED")
        cache = self.stage_root / "npm-cache"
        build_home = self.stage_root / "build-home"
        build_tmp = self.stage_root / "build-tmp"
        for path in (cache, build_home, build_tmp):
            _create_private_directory(path)
        npm = shutil.which("npm")
        if not npm:
            raise InstallError("NPM_NOT_FOUND")
        environment = {
            "HOME": str(build_home),
            "TMPDIR": str(build_tmp),
            "PATH": os.pathsep.join((str(self.context.node.parent), str(Path(npm).resolve().parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin")),
            "CI": "1",
            "NPM_CONFIG_USERCONFIG": "/dev/null",
            "NPM_CONFIG_CACHE": str(cache),
            "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
        }
        _run_quiet([
            npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund",
            "--userconfig=/dev/null", "--cache", str(cache), "--registry=https://registry.npmjs.org/",
        ], cwd=self.program_root, env=environment, timeout=900)
        _run_quiet([npm, "run", "build", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=self.program_root, env=environment, timeout=900)
        try:
            lock_digest = hashlib.sha256((self.program_root / "package-lock.json").read_bytes()).hexdigest()
            build_digest_map = _tree_digests(self.program_root / "dist")
            dependencies_digest_map = _tree_digests(self.program_root / "node_modules")
        except OSError as exc:
            raise InstallError("BUILD_OUTPUT_INVALID") from exc
        build_digest = hashlib.sha256(_canonical_json({"dist": build_digest_map, "node_modules": dependencies_digest_map})).hexdigest()
        manifest = {
            "schema": 1,
            "version": self.version,
            "sourceDigest": self.source_digest,
            "packageLockSha256": lock_digest,
            "buildDigest": build_digest,
            "dist": build_digest_map,
            "dependencies": dependencies_digest_map,
        }
        _write_private_json(self.program_root / ".release-manifest.json", manifest)
        # Build-only npm state stays out of the installed release.
        shutil.rmtree(cache)
        shutil.rmtree(build_home)
        shutil.rmtree(build_tmp)
        self.candidate_context = replace(self.context, release=self.program_root)
        return self._remember("stage_release", {"status": "PASS", "releaseDigest": self.source_digest})

    def acquire_artifacts(self) -> Mapping[str, object]:
        acquire = _module_function("artifact_install", "acquire_family")
        self.artifact_workspace = self.context.artifacts
        _create_private_directory(self.artifact_workspace)
        families = sorted({candidate.family for candidate in self.selected})
        for family in families:
            if family not in SUPPORTED_FAMILIES:
                raise InstallError("SOURCE_FAMILY_UNSUPPORTED")
            workspace = self.context.artifacts / family
            _create_private_directory(workspace)
            try:
                record = acquire(self.candidate_context, family, workspace)
            except Exception as exc:
                raise InstallError("ARTIFACT_ACQUISITION_FAILED") from exc
            self.artifacts[family] = _validate_artifact_record(record, family=family, workspace=workspace)
        return self._remember("acquire_artifacts", {"status": "PASS", "artifactCount": len(self.artifacts), "familyCount": len(families)})

    def prepare_runtime(self) -> Mapping[str, object]:
        context_module = _internal("installation_context")
        try:
            context_module.read_install_key(self.context)
        except Exception as exc:
            raise InstallError("INSTALLATION_KEY_UNAVAILABLE") from exc
        prepare = _module_function("portable_engine", "prepare_runtime")
        try:
            result = prepare(self.candidate_context, self.selected, self.artifacts)
        except Exception as exc:
            raise InstallError("RUNTIME_PREPARATION_FAILED") from exc
        return self._remember("prepare_runtime", _record_status(result))

    def verify_candidate(self) -> Mapping[str, object]:
        verify = _module_function("portable_engine", "verify_candidate")
        try:
            result = verify(self.candidate_context, self.selected)
        except Exception as exc:
            raise InstallError("CANDIDATE_VERIFICATION_FAILED") from exc
        result = _record_status(result)
        if result.get("status") != "PASS":
            raise InstallError("CANDIDATE_VERIFICATION_FAILED")
        return self._remember("verify_candidate", result)

    def publish_release(self) -> Mapping[str, object]:
        if self.program_root is None or self.stage_root is None:
            raise InstallError("RELEASE_NOT_STAGED")
        target = self.original_context.release
        release_parent = target.parent
        _create_private_directory(self.context.root / "app/releases")
        if target.exists() or target.is_symlink():
            try:
                info = target.lstat()
            except OSError as exc:
                raise InstallError("RELEASE_TARGET_UNSAFE") from exc
            if not stat.S_ISDIR(info.st_mode) or target.resolve(strict=True) != target:
                raise InstallError("RELEASE_TARGET_UNSAFE")
            manifest = _read_release_manifest(target)
            if manifest.get("sourceDigest") != self.source_digest:
                raise InstallError("RELEASE_TARGET_CONFLICT")
            raise InstallError("RELEASE_TARGET_CONFLICT")
        else:
            try:
                os.rename(self.program_root, target)
            except OSError as exc:
                raise InstallError("RELEASE_PUBLISH_FAILED") from exc
        self.context = replace(self.original_context, release=target)
        context_module = _internal("installation_context")
        try:
            context_module.write_context(self.context)
        except Exception as exc:
            raise InstallError("INSTALLATION_DESCRIPTOR_PUBLISH_FAILED") from exc
        return self._remember("publish_release", {"status": "PASS", "releaseDigest": self.source_digest})

    def install_command(self) -> Mapping[str, object]:
        try:
            result = self._service("install_command")(self.context)
        except Exception as exc:
            raise InstallError("COMMAND_INSTALL_FAILED") from exc
        result = _record_status(result)
        if result.get("status") not in {"INSTALLED", "ALREADY_INSTALLED", "UPDATED"}:
            raise InstallError("COMMAND_INSTALL_FAILED")
        return self._remember("install_command", {"status": "PASS"})

    def install_skill(self) -> Mapping[str, object]:
        install_skill = _module_function("artifact_install", "install_setup_skill")
        try:
            result = install_skill(self.context)
        except Exception as exc:
            raise InstallError("SETUP_SKILL_INSTALL_FAILED") from exc
        result = _record_status(result)
        if result.get("status") not in {"INSTALLED", "ALREADY_INSTALLED"}:
            raise InstallError("SETUP_SKILL_INSTALL_FAILED")
        return self._remember("install_skill", {"status": "PASS"})

    def register_service(self) -> Mapping[str, object]:
        try:
            registered = _record_status(self._service("register_service")(self.context))
        except Exception as exc:
            raise InstallError("SERVICE_REGISTRATION_FAILED") from exc
        if registered.get("status") != "PASS":
            raise InstallError("SERVICE_REGISTRATION_FAILED")
        try:
            started = _record_status(self._service("service_action")(self.context, "start"))
        except Exception as exc:
            raise InstallError("SERVICE_START_FAILED") from exc
        if started.get("status") != "PASS" or started.get("service") != "RUNNING":
            raise InstallError("SERVICE_START_FAILED")
        return self._remember("register_service", {"status": "PASS"})

    def verify_service(self) -> Mapping[str, object]:
        try:
            result = self._service("verify_service")(self.context)
        except Exception as exc:
            raise InstallError("SERVICE_VERIFICATION_FAILED") from exc
        result = _record_status(result)
        if result.get("status") != "PASS":
            raise InstallError("SERVICE_VERIFICATION_FAILED")
        return self._remember("verify_service", result)

    def project_clients(self) -> Mapping[str, object]:
        module = _internal("client_projection")
        project = getattr(module, "project_clients", None)
        if not callable(project):
            raise InstallError("CLIENT_PROJECTION_UNAVAILABLE")
        key = _internal("installation_context").read_install_key(self.context)
        try:
            result = project(self.context, self.selected, token=key.hex(), install_key=key, journal_path=None)
        except Exception as exc:
            raise InstallError("CLIENT_PROJECTION_FAILED") from exc
        result = _record_status(result)
        if result.get("status") != "PASS" or result.get("operation") not in {"PROJECTED", "ALREADY_PROJECTED"}:
            raise InstallError("CLIENT_PROJECTION_FAILED")
        routes = result.get("routes")
        if type(routes) is not int or not 1 <= routes <= 64:
            raise InstallError("CLIENT_PROJECTION_FAILED")
        return self._remember("project_clients", {"status": "PASS", "selectedCount": routes})

    def verify_projections(self) -> Mapping[str, object]:
        module = _internal("client_projection")
        verify = getattr(module, "verify_projections", None)
        if not callable(verify):
            raise InstallError("CLIENT_PROJECTION_VERIFIER_UNAVAILABLE")
        key = _internal("installation_context").read_install_key(self.context)
        try:
            result = verify(self.context, self.selected, token=key.hex(), install_key=key)
        except Exception as exc:
            raise InstallError("CLIENT_PROJECTION_VERIFICATION_FAILED") from exc
        result = _record_status(result)
        if result.get("status") != "PASS":
            raise InstallError("CLIENT_PROJECTION_VERIFICATION_FAILED")
        return self._remember("verify_projections", result)

    def doctor(self) -> Mapping[str, object]:
        verify = _module_function("installation_verify", "verify_installation")
        try:
            result = verify(self.context, safe_reads=False)
        except Exception as exc:
            raise InstallError("INSTALLATION_DOCTOR_FAILED") from exc
        checks = {"installed", "service", "catalog", "safeRead", "source", "ownership"}
        if not isinstance(result, Mapping) or set(result) != checks:
            raise InstallError("INSTALLATION_DOCTOR_RESULT_INVALID")
        allowed = {"PASS", "FAIL", "NEEDS_AUTH", "UNSUPPORTED", "NOT_TESTED"}
        normalized: dict[str, dict[str, object]] = {}
        for name, check in result.items():
            if not isinstance(check, Mapping) or set(check) - {"status", "reason", "routes"}:
                raise InstallError("INSTALLATION_DOCTOR_RESULT_INVALID")
            status = check.get("status")
            if not isinstance(status, str) or status not in allowed:
                raise InstallError("INSTALLATION_DOCTOR_RESULT_INVALID")
            safe_check: dict[str, object] = {"status": status}
            reason = check.get("reason")
            if reason is not None:
                if not isinstance(reason, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", reason):
                    raise InstallError("INSTALLATION_DOCTOR_RESULT_INVALID")
                safe_check["reason"] = reason
            routes = check.get("routes")
            if routes is not None:
                if type(routes) is not int or not 0 <= routes <= 64:
                    raise InstallError("INSTALLATION_DOCTOR_RESULT_INVALID")
                safe_check["routes"] = routes
            normalized[name] = safe_check
        self.doctor_result = normalized
        required = ("installed", "service", "catalog", "source", "ownership")
        statuses = {name: check["status"] for name, check in normalized.items()}
        if any(statuses[key] == "FAIL" for key in required) or statuses["safeRead"] == "FAIL":
            status = "FAIL"
        elif any(statuses[key] == "NEEDS_AUTH" for key in required) or statuses["safeRead"] == "NEEDS_AUTH":
            status = "NEEDS_AUTH"
        elif any(statuses[key] == "UNSUPPORTED" for key in required) or statuses["safeRead"] == "UNSUPPORTED":
            status = "UNSUPPORTED"
        elif all(statuses[key] == "PASS" for key in required):
            status = "PASS"
        else:
            status = "NOT_TESTED"
        verified_count = sum(value == "PASS" for value in statuses.values())
        return self._remember("doctor", {"status": status, "verifiedCount": verified_count})

    def commit_receipt(self) -> Mapping[str, object]:
        if self.doctor_result is None:
            raise InstallError("INSTALLATION_DOCTOR_MISSING")
        status = self.stage_records.get("doctor", {}).get("status", "FAIL")
        receipt = {
            "schema": 1,
            "status": status,
            "planHash": self.plan_hash,
            "releaseDigest": self.source_digest,
            "selectedCount": len(self.selected),
            "doctor": self.doctor_result,
        }
        _write_private_json(self._receipt_path(), receipt)
        return self._remember("commit_receipt", {
            "status": "PASS",
            "planHash": self.plan_hash,
            "releaseDigest": self.source_digest,
            "selectedCount": len(self.selected),
        })


def _validate_artifact_record(value: object, *, family: str, workspace: Path) -> dict[str, object]:
    keys = {
        "schema", "family", "profileId", "profileIds", "sourceIdentity", "artifactRoot",
        "closureDigest", "nativeCommand", "artifactSha256", "dependencyReportSha256",
        "catalogFingerprint", "catalog", "inputPins", "releaseInputsDigest", "artifactInputId",
        "transformVersion",
    }
    if not isinstance(value, Mapping) or set(value) != keys or value.get("schema") != 1 or value.get("family") != family:
        raise InstallError("ARTIFACT_RECORD_INVALID")
    profile = value.get("profileId")
    profiles = value.get("profileIds")
    if (
        not isinstance(profile, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", profile)
        or not isinstance(profiles, list)
        or not profiles
        or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", item) for item in profiles)
        or profile not in profiles
        or len(profiles) != len(set(profiles))
    ):
        raise InstallError("ARTIFACT_RECORD_INVALID")
    for key in ("closureDigest", "artifactSha256", "dependencyReportSha256", "catalogFingerprint", "releaseInputsDigest"):
        if not isinstance(value.get(key), str) or not HEX64.fullmatch(value[key]):
            raise InstallError("ARTIFACT_RECORD_INVALID")
    if (
        not isinstance(value.get("sourceIdentity"), str)
        or not value["sourceIdentity"]
        or len(value["sourceIdentity"]) > 255
        or any(ord(character) < 0x20 for character in value["sourceIdentity"])
        or not isinstance(value.get("artifactInputId"), str)
        or not value["artifactInputId"]
        or len(value["artifactInputId"]) > 255
        or not isinstance(value.get("transformVersion"), str)
        or not value["transformVersion"]
        or len(value["transformVersion"]) > 128
        or not isinstance(value.get("catalog"), Mapping)
    ):
        raise InstallError("ARTIFACT_RECORD_INVALID")
    try:
        catalog_bytes = _canonical_json(dict(value["catalog"]))
    except Exception as exc:
        raise InstallError("ARTIFACT_RECORD_INVALID") from exc
    if len(catalog_bytes) > 2 * 1024 * 1024:
        raise InstallError("ARTIFACT_RECORD_INVALID")
    root_value = value.get("artifactRoot")
    if not isinstance(root_value, str) or not Path(root_value).is_absolute():
        raise InstallError("ARTIFACT_RECORD_INVALID")
    artifact_root = Path(root_value)
    try:
        info = artifact_root.lstat()
        workspace_info = workspace.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) not in {0o500, 0o700}
            or artifact_root.resolve(strict=True) != artifact_root
            or not stat.S_ISDIR(workspace_info.st_mode)
            or workspace_info.st_uid != os.getuid()
            or stat.S_IMODE(workspace_info.st_mode) != 0o700
            or workspace.resolve(strict=True) != workspace
            or artifact_root.parent != workspace
            or workspace not in artifact_root.parents
            or artifact_root.name != value["closureDigest"]
        ):
            raise InstallError("ARTIFACT_ROOT_UNSAFE")
    except OSError as exc:
        raise InstallError("ARTIFACT_ROOT_UNSAFE") from exc
    command = value.get("nativeCommand")
    if not isinstance(command, list) or not command or len(command) > 128 or any(not isinstance(arg, str) or not arg or "\x00" in arg or len(arg) > 4096 for arg in command):
        raise InstallError("ARTIFACT_COMMAND_INVALID")
    executable = Path(command[0])
    try:
        executable_info = executable.lstat()
        if (
            not executable.is_absolute()
            or artifact_root not in executable.parents
            or executable.resolve(strict=True) != executable
            or not stat.S_ISREG(executable_info.st_mode)
            or executable_info.st_uid != os.getuid()
            or not os.access(executable, os.X_OK)
        ):
            raise InstallError("ARTIFACT_COMMAND_INVALID")
    except OSError as exc:
        raise InstallError("ARTIFACT_COMMAND_INVALID") from exc
    pins = value.get("inputPins")
    if not isinstance(pins, list) or not pins or len(pins) > MAX_ARTIFACT_INPUT_PINS:
        raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
    pin_ids: set[str] = set()
    for pin in pins:
        if not isinstance(pin, Mapping) or set(pin) != {"id", "kind", "name", "version", "origin", "integrity", "sha256"}:
            raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
        if any(
            not isinstance(pin[key], str)
            or not pin[key]
            or len(pin[key]) > 2048
            or any(ord(character) < 0x20 for character in pin[key])
            for key in ("id", "kind", "name", "version", "origin")
        ):
            raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
        if pin["kind"] == "npm-tarball":
            if not isinstance(pin["integrity"], str) or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", pin["integrity"]):
                raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
        elif pin["kind"] in {"python-wheel", "runtime-archive"}:
            if pin["integrity"] is not None:
                raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
        else:
            raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
        if not isinstance(pin["sha256"], str) or not HEX64.fullmatch(pin["sha256"]):
            raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
        if pin["id"] in pin_ids:
            raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
        pin_ids.add(pin["id"])
    if value["artifactInputId"] not in pin_ids:
        raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
    pin_digest = hashlib.sha256(_canonical_json([dict(pin) for pin in pins])).hexdigest()
    if pin_digest != value["releaseInputsDigest"]:
        raise InstallError("ARTIFACT_INPUT_PINS_INVALID")
    return dict(value)


def run_install(context, selected: list[object], *, accept_plan: str, projects: Sequence[Path] = ()) -> dict[str, object]:
    """Run a fresh install with real adapters, artifact acquisition and service operations."""
    if not isinstance(accept_plan, str) or not HEX64.fullmatch(accept_plan):
        raise InstallError("PLAN_HASH_INVALID")
    client_sources = _internal("client_sources")
    candidates = _inventory_sources(client_sources, context, projects)
    request = {
        "context": context,
        "projectRoot": Path(__file__).resolve().parents[1],
        "sourceDigest": _internal("export_source").source_digest(Path(__file__).resolve().parents[1], portable_only=True),
        "releaseVersion": _project_version(Path(__file__).resolve().parents[1]),
        "candidates": candidates,
        "selected": selected,
        "projects": tuple(projects),
        "planHash": accept_plan,
    }
    expected_release = context.root / "app/releases" / f"{request['releaseVersion']}-{request['sourceDigest']}"
    if context.release != expected_release:
        raise InstallError("PROJECT_SOURCE_CHANGED")
    operations = InstallOperationsImpl(request, accept_plan=accept_plan, client_sources=client_sources)
    context_module = _internal("installation_context")
    paths = context_module.installation_state_paths(context)
    from install_transaction import AuthenticatedJournal, InstallationLock, InstallTransactionError, run_transaction
    journal = AuthenticatedJournal(
        paths.journal,
        key_loader=lambda: context_module.load_or_create_install_key(context),
        binding=_transaction_binding(
            context, selected, projects,
            plan_hash=accept_plan,
            release_digest=request["sourceDigest"],
        ),
    )
    try:
        with InstallationLock(paths.lock):
            records = run_transaction(operations, journal)
    except InstallError as exc:
        if paths.journal.exists() or paths.journal.is_symlink():
            raise InstallError("INSTALLATION_RECOVERY_REQUIRED") from exc
        raise
    except InstallTransactionError as exc:
        if exc.code in {"INSTALL_LOCKED", "INSTALL_LOCK_UNAVAILABLE", "INSTALL_LOCK_UNSAFE", "INSTALL_LOCK_DIRECTORY_UNSAFE"}:
            raise InstallError("INSTALLATION_BUSY") from exc
        if paths.journal.exists() or paths.journal.is_symlink():
            raise InstallError("INSTALLATION_RECOVERY_REQUIRED") from exc
        raise InstallError(exc.code) from exc
    doctor = records.get("doctor", {})
    receipt = {
        "status": doctor.get("status", "FAIL"),
        "planHash": accept_plan,
        "releaseDigest": request["sourceDigest"],
        "selectedCount": len(selected),
        "verifiedCount": doctor.get("verifiedCount", 0),
        "checks": dict(operations.doctor_result or {}),
    }
    return receipt


def recover_install(context) -> dict[str, object]:
    """Authenticate the journal under the install lock and delegate conditional route recovery."""
    context_module = _internal("installation_context")
    paths = context_module.installation_state_paths(context)
    from install_transaction import InstallationLock, InstallTransactionError
    try:
        with InstallationLock(paths.lock, blocking=False):
            return _recover_install_locked(context, paths)
    except InstallTransactionError as exc:
        if exc.code == "INSTALL_LOCKED":
            raise InstallError("RECOVERY_LOCKED") from exc
        raise InstallError(exc.code) from exc


def _recover_install_locked(context, paths) -> dict[str, object]:
    if not paths.journal.exists() and not paths.journal.is_symlink():
        return {"status": "NOTHING_TO_RECOVER"}
    context_module = _internal("installation_context")
    try:
        key = context_module.read_install_key(context)
        from install_transaction import INSTALL_ORDER, read_journal
        records = read_journal(paths.journal, key)
    except Exception as exc:
        raise InstallError("RECOVERY_JOURNAL_UNTRUSTED") from exc
    if not records:
        raise InstallError("RECOVERY_JOURNAL_INVALID")
    binding = records[0].get("binding")
    if (
        not isinstance(binding, Mapping)
        or set(binding) != {"planHash", "releaseDigest", "selectionDigest", "projectionDigest"}
        or any(not isinstance(binding[name], str) or not HEX64.fullmatch(binding[name]) for name in binding)
        or not Path(context.release).name.endswith("-" + binding["releaseDigest"])
    ):
        raise InstallError("RECOVERY_JOURNAL_INVALID")
    expected = INSTALL_ORDER[3:]
    completed: set[str] = set()
    started: str | None = None
    failure_seen = False
    phase_index = 0
    try:
        for position, record in enumerate(records):
            phase = record["phase"]
            event = record["event"]
            if phase_index >= len(expected) or phase != expected[phase_index] or failure_seen:
                raise InstallError("RECOVERY_JOURNAL_INVALID")
            if event == "started" and started is None:
                started = phase
            elif event == "completed" and started == phase:
                completed.add(phase)
                started = None
                phase_index += 1
            elif event == "failed" and started == phase and position == len(records) - 1:
                failure_seen = True
            else:
                raise InstallError("RECOVERY_JOURNAL_INVALID")
    except (KeyError, TypeError) as exc:
        raise InstallError("RECOVERY_JOURNAL_INVALID") from exc
    if not records or (records[-1]["phase"] == "commit_receipt" and records[-1]["event"] == "completed"):
        return {"status": "COMPLETE" if records else "NOTHING_TO_RECOVER"}
    if started not in {"project_clients", "verify_projections"} and not ("project_clients" in completed and "verify_projections" not in completed):
        return {"status": "RECOVERY_REQUIRES_REVIEW", "lastPhase": records[-1]["phase"]}
    rollback = _module_function("client_projection", "rollback_clients")
    try:
        result = _record_status(rollback(context, install_key=key, journal_path=None))
    except Exception as exc:
        raise InstallError("CLIENT_ROLLBACK_FAILED") from exc
    if result.get("status") != "PASS" or result.get("operation") not in {"ROLLED_BACK", "NOTHING_TO_ROLL_BACK"}:
        return {"status": "RECOVERY_REQUIRES_REVIEW", "lastPhase": records[-1]["phase"]}
    return {"status": "NATIVE_ROUTES_RESTORED", "serviceCleanup": "PENDING"}


def _preflight_plan_summary(request: Mapping[str, object]) -> dict[str, object]:
    summary = dict(request["plan"])
    summary["planHash"] = request["planHash"]
    return summary


def main(argv: list[str] | None = None) -> int:
    try:
        _python_prerequisite()
    except InstallError as exc:
        print(exc.code, file=sys.stderr)
        return EXIT_PLAN_OR_REFUSAL
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        request = _plan(args)
        if args.plan:
            print(json.dumps(_preflight_plan_summary(request), sort_keys=True, indent=2))
            return EXIT_PLAN_OR_REFUSAL
        if not request["selected"]:
            raise InstallError("NO_SUPPORTED_SOURCES_SELECTED")
        if args.accept_plan is None:
            print(json.dumps(_preflight_plan_summary(request), sort_keys=True, indent=2))
            if not sys.stdin.isatty():
                raise InstallError("PLAN_REQUIRES_ACCEPTANCE")
            try:
                accepted = input("Install this plan? Type yes to continue: ").strip().lower()
            except EOFError:
                raise InstallError("PLAN_NOT_ACCEPTED")
            if accepted != "yes":
                raise InstallError("PLAN_NOT_ACCEPTED")
            accept_plan = request["planHash"]
        else:
            if not HEX64.fullmatch(args.accept_plan) or args.accept_plan != request["planHash"]:
                raise InstallError("PLAN_CHANGED_OR_NOT_ACCEPTED")
            accept_plan = args.accept_plan
        receipt = run_install(request["context"], request["selected"], accept_plan=accept_plan, projects=request["projects"])
        print(json.dumps(receipt, sort_keys=True))
        return EXIT_VERIFICATION_FAILED if receipt["status"] in {"FAIL", "UNSUPPORTED"} else 0
    except InstallError as exc:
        print(exc.code, file=sys.stderr)
        return EXIT_RECOVERY_REQUIRED if exc.code in {
            "CLIENT_PROJECTION_FAILED",
            "CLIENT_PROJECTION_VERIFICATION_FAILED",
            "INSTALLATION_RECOVERY_REQUIRED",
            "RECOVERY_JOURNAL_UNTRUSTED",
            "RECOVERY_JOURNAL_INVALID",
            "RECOVERY_LOCKED",
            "INCOMPLETE_TRANSACTION_RECOVERY_REQUIRED",
        } else EXIT_PLAN_OR_REFUSAL
    except Exception as exc:
        code = getattr(exc, "code", None)
        if not isinstance(code, str):
            candidate = str(exc)
            code = candidate if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", candidate) else "INSTALL_FAILED"
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
            code = "INSTALL_FAILED"
        print(code, file=sys.stderr)
        return EXIT_PLAN_OR_REFUSAL


def _read_release_manifest(release: Path) -> dict[str, object]:
    path = release / ".release-manifest.json"
    value = _read_private_json(path, maximum=32 * 1024 * 1024, error_code="RELEASE_MANIFEST_INVALID")
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise InstallError("RELEASE_MANIFEST_INVALID")
    expected_build = hashlib.sha256(_canonical_json({"dist": value.get("dist"), "node_modules": value.get("dependencies")})).hexdigest()
    if value.get("buildDigest") != expected_build:
        raise InstallError("RELEASE_MANIFEST_INVALID")
    if _tree_digests(release / "dist") != value.get("dist") or _tree_digests(release / "node_modules") != value.get("dependencies"):
        raise InstallError("RELEASE_CONTENT_CHANGED")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
