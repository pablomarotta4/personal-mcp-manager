"""Export only the reviewed, portable source closure for a standalone release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Iterable


ROOT_FILES = frozenset({
    ".gitignore", "install.sh", "package.json", "package-lock.json", "tsconfig.json",
    "LICENSE", "README.md", "THIRD_PARTY_NOTICES.txt",
})
SOURCE_ROOTS = frozenset({"src", "native", "scripts", "test"})
RUNTIME_DOCS = frozenset({
    "claude-loki.md",
    "langfuse-packaging.md",
    "loki-packaging.md",
    "runtime-maintenance.md",
    "service-verification.md",
    "service.md",
    "session-lifecycle.md",
})
RELEASE_FILES = frozenset({
    "release/families.json",
    "release/inputs.json",
    "release/catalogs/grafana.json",
    "release/catalogs/langfuse.json",
    "release/catalogs/loki.json",
    "release/catalogs/mysql.json",
    "release/locks/grafana-wheels.json",
    "release/locks/langfuse-wheels.json",
    "release/locks/loki.package-lock.json",
    "release/locks/mysql.package-lock.json",
})
# This second allowlist is the distributable release closure. Task 1 keeps a
# full recoverable source extraction; packages and installed releases use only
# modules/tests reachable from the portable manager plus the build and policy
# inputs they require.
PORTABLE_SCRIPT_FILES = frozenset({
    "artifact_install.py",
    "build-owner-identity.mjs",
    "build-supervisor.mjs",
    "client_projection.py",
    "client_sources.py",
    "export_source.py",
    "installation_context.py",
    "installation_verify.py",
    "install.py",
    "install_transaction.py",
    "langfuse-entry.py",
    "langfuse_profile.py",
    "loki_profile.py",
    "loki_owner_environment.py",
    "manage.py",
    "mcp_manager.py",
    "monitoring_cli.py",
    "monitoring_memory.py",
    "materialize-langfuse.py",
    "materialize-loki.py",
    "migrate.py",
    "mysql-entry.mjs",
    "mysql-runtime.py",
    "mysql_environment.py",
    "mysql_profile.py",
    "owner_watch.py",
    "package_release.py",
    "pilot.py",
    "portable-verify-config.mjs",
    "portable_engine.py",
    "portable_family.py",
    "portable_owner_environment.py",
    "provision-portable.mjs",
    "service_install.py",
    "setup_skill_install.py",
    "source_environment.py",
    "source_inputs.py",
    "verify-langfuse-dependencies.py",
    "verify-langfuse-closure.py",
    "verify-loki-dependencies.py",
})
PORTABLE_SCRIPT_TESTS = frozenset({
    "test_artifact_install.py",
    "test_client_projection.py",
    "test_client_sources.py",
    "test_export_source.py",
    "test_install.py",
    "test_install_coordinator.py",
    "test_install_e2e.py",
    "test_install_transaction.py",
    "test_installation_context.py",
    "test_installation_verify.py",
    "test_loki_owner_environment.py",
    "test_langfuse_entry.py",
    "test_mcp_manager.py",
    "test_monitoring_cli.py",
    "test_monitoring_memory.py",
    "test_owner_watch.py",
    "test_package_release.py",
    "test_portable_engine.py",
    "test_portable_entrypoints.py",
    "test_portable_environment.py",
    "test_portable_family.py",
    "test_portable_owner.py",
    "test_release_package_extract.py",
    "test_service_install.py",
    "test_setup_skill_install.py",
})
PORTABLE_NODE_TESTS = frozenset({
    "entry.test.mjs",
    "facade.test.mjs",
    "http.test.mjs",
    "manifest.test.mjs",
    "owner-channel.test.mjs",
    "owner-entry.test.mjs",
    "policy.test.mjs",
    "pool.test.mjs",
    "portable-policy-validation.test.mjs",
    "provision-portable.test.mjs",
    "proxy.test.mjs",
    "runtime.test.mjs",
    "supervisor-wire.test.mjs",
    "registration-capacity.test.mjs",
    "traffic-counters.test.mjs",
})
PORTABLE_NODE_TEST_SUPPORT = frozenset({
    "fixtures/backend.mjs",
    "fixtures/cwd-backend.mjs",
    "fixtures/native-backend.mjs",
    "fixtures/source-env-backend.mjs",
    "helpers.mjs",
    "helpers/private-dist.mjs",
})
PORTABLE_DOCS = frozenset({
    "installer-verification.md",
    "relocation.md",
    "setup-troubleshooting.md",
})
PORTABLE_FILES = frozenset({
    "install.sh", "package.json", "package-lock.json", "tsconfig.json", "LICENSE", "README.md",
    "scripts/artifact_install.py", "scripts/build-owner-identity.mjs", "scripts/build-supervisor.mjs",
    "scripts/client_projection.py", "scripts/client_sources.py", "scripts/export_source.py",
    "scripts/installation_context.py", "scripts/installation_verify.py",
    "scripts/install.py", "scripts/install_transaction.py", "scripts/langfuse-entry.py",
    "scripts/langfuse_profile.py", "scripts/loki_profile.py", "scripts/manage.py", "scripts/mcp_manager.py",
    "scripts/materialize-langfuse.py", "scripts/materialize-loki.py", "scripts/migrate.py",
    "scripts/mysql-entry.mjs", "scripts/mysql-runtime.py", "scripts/mysql_environment.py",
    "scripts/mysql_profile.py", "scripts/owner_watch.py", "scripts/package_release.py",
    "scripts/pilot.py", "scripts/portable-verify-config.mjs", "scripts/portable_engine.py", "scripts/portable_family.py",
    "scripts/portable_owner_environment.py", "scripts/provision-portable.mjs", "scripts/service_install.py",
    "scripts/source_environment.py", "scripts/source_inputs.py",
    "scripts/test_langfuse_entry.py",
    "scripts/verify-langfuse-dependencies.py",
    "scripts/verify-loki-dependencies.py",
    "docs/installer-verification.md", "docs/relocation.md", "docs/setup-troubleshooting.md",
    "test/helpers/private-dist.mjs",
    "skills/mcp-manager-setup/SKILL.md",
    *(f"scripts/{name}" for name in PORTABLE_SCRIPT_FILES | PORTABLE_SCRIPT_TESTS),
    *(f"test/{name}" for name in PORTABLE_NODE_TESTS),
    *(f"test/{name}" for name in PORTABLE_NODE_TEST_SUPPORT),
})
EXCLUDED_DIRS = frozenset({
    ".git", "__pycache__", "artifacts", "build", "cache", "coverage", "credentials",
    "dist", "evidence", "logs", "node_modules", "release-input-cache", "release_input_cache",
    "releaseinputcache", "runtime", "tokens", "transactions",
})
EXCLUDED_SUFFIXES = frozenset({".log", ".pyc"})
PRIVATE_KEY_SUFFIXES = frozenset({".asc", ".der", ".jks", ".key", ".keystore", ".p12", ".pem", ".pfx", ".ppk"})
CONFIG_SUFFIXES = frozenset({".conf", ".ini", ".json", ".properties", ".toml", ".yaml", ".yml"})
PRIVATE_KEY_NAMES = frozenset({"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"})
LOCAL_CONFIG_NAMES = frozenset({"config.local", "config_local", "local.config", "local_config", "localconfig"})
CHUNK_SIZE = 1024 * 1024


class ExportError(Exception):
    """A source tree or destination failed a portable export safety check."""


def allowed_source(relative: Path, *, portable_only: bool = False) -> bool:
    """Return whether a relative path is part of the explicit release allowlist."""
    if relative.is_absolute() or not relative.parts:
        return False
    is_root_gitignore = relative.parts == (".gitignore",)
    if any(part in {"", ".", ".."} or (part.startswith(".") and not is_root_gitignore) for part in relative.parts):
        return False
    if is_excluded_path(relative):
        return False
    if portable_only:
        path = relative.as_posix()
        if len(relative.parts) == 1:
            return relative.name in ROOT_FILES
        if relative.parts[0] in {"src", "native"}:
            return True
        if path in PORTABLE_FILES or any(file.startswith(path + "/") for file in PORTABLE_FILES):
            return True
        if relative.parts[0] == "release":
            return path in RELEASE_FILES or any(file.startswith(path + "/") for file in RELEASE_FILES)
        if relative.parts[0] == "docs" and len(relative.parts) == 2:
            return relative.name in PORTABLE_DOCS and relative.suffix == ".md"
        return path in PORTABLE_FILES
    if len(relative.parts) == 1:
        return relative.name in ROOT_FILES
    if relative.parts[0] in SOURCE_ROOTS:
        return True
    if relative.parts[0] == "release":
        path = relative.as_posix()
        return path in RELEASE_FILES or any(file.startswith(path + "/") for file in RELEASE_FILES)
    return relative.parts[0] == "docs" and len(relative.parts) == 2 and relative.name in RUNTIME_DOCS and relative.suffix == ".md"


def is_excluded_path(relative: Path) -> bool:
    """Return whether a path name identifies local secrets or generated state."""
    parts = tuple(part.casefold() for part in relative.parts)
    if any(part in EXCLUDED_DIRS for part in parts):
        return True
    if any(parent == "release" and child in {"input-cache", "input_cache", "inputcache"}
           for parent, child in zip(parts, parts[1:])):
        return True
    name = relative.name.casefold()
    suffix = Path(name).suffix
    if suffix in EXCLUDED_SUFFIXES or suffix in PRIVATE_KEY_SUFFIXES:
        return True
    if name in PRIVATE_KEY_NAMES or any(name.startswith(key_name + ".") for key_name in PRIVATE_KEY_NAMES):
        return True
    if name == ".env" or name.startswith(".env.") or name.endswith(".env") or ".env." in name:
        return True
    if name in {"credential", "credentials", "secret", "secrets"}:
        return True
    stem = name[: -len(suffix)] if suffix else name
    if suffix in CONFIG_SUFFIXES and (
        stem in {"credential", "credentials", "secret", "secrets"}
        or stem in LOCAL_CONFIG_NAMES
        or stem.endswith(".local")
        or stem.endswith("_local")
        or stem.endswith("-local")
    ):
        return True
    return False


def _canonical_directory(path: Path, *, code: str) -> Path:
    try:
        absolute = Path(os.path.abspath(os.fspath(path)))
        info = absolute.lstat()
    except OSError as exc:
        raise ExportError(code) from exc
    if not stat.S_ISDIR(info.st_mode) or absolute.resolve(strict=True) != absolute:
        raise ExportError(code)
    return absolute


def _source_candidates(source: Path, *, portable_only: bool = False) -> list[tuple[Path, Path]]:
    candidates: list[tuple[Path, Path]] = []
    root_files = ROOT_FILES if not portable_only else ROOT_FILES
    for name in sorted(root_files):
        relative = Path(name)
        path = source / relative
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ExportError("SOURCE_READ_FAILED") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ExportError("SOURCE_SYMLINK_REFUSED")
        if not stat.S_ISREG(info.st_mode):
            raise ExportError("SOURCE_FILE_TYPE_REFUSED")
        candidates.append((relative, path))

    source_roots = SOURCE_ROOTS if not portable_only else frozenset({"src", "native", "scripts", "test"})
    for root_name in sorted(source_roots | {"docs", "release", "skills"} if portable_only else source_roots | {"docs", "release"}):
        root = source / root_name
        try:
            root_info = root.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ExportError("SOURCE_READ_FAILED") from exc
        if stat.S_ISLNK(root_info.st_mode):
            raise ExportError("SOURCE_SYMLINK_REFUSED")
        if not stat.S_ISDIR(root_info.st_mode):
            if root_name in {"docs", "release"}:
                continue
            raise ExportError("SOURCE_FILE_TYPE_REFUSED")
        _walk_source(source, root, Path(root_name), candidates, portable_only=portable_only)
    return sorted(candidates, key=lambda item: item[0].as_posix())


def _walk_source(source: Path, current: Path, relative: Path, candidates: list[tuple[Path, Path]], *, portable_only: bool = False) -> None:
    try:
        with os.scandir(current) as entries:
            ordered = sorted(entries, key=lambda entry: entry.name)
    except OSError as exc:
        raise ExportError("SOURCE_READ_FAILED") from exc
    for entry in ordered:
        child_relative = relative / entry.name
        if not allowed_source(child_relative, portable_only=portable_only):
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise ExportError("SOURCE_READ_FAILED") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ExportError("SOURCE_SYMLINK_REFUSED")
        child_path = source / child_relative
        if stat.S_ISDIR(info.st_mode):
            _walk_source(source, child_path, child_relative, candidates, portable_only=portable_only)
        elif stat.S_ISREG(info.st_mode):
            candidates.append((child_relative, child_path))
        else:
            raise ExportError("SOURCE_FILE_TYPE_REFUSED")


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _stable_digest(path: Path) -> str:
    descriptor = -1
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or _fingerprint(path.lstat()) != _fingerprint(before):
            raise ExportError("SOURCE_FILE_TYPE_REFUSED")
        while True:
            block = os.read(descriptor, CHUNK_SIZE)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        if _fingerprint(before) != _fingerprint(after) or _fingerprint(after) != _fingerprint(path.lstat()):
            raise ExportError("SOURCE_CHANGED_DURING_READ")
        return digest.hexdigest()
    except ExportError:
        raise
    except OSError as exc:
        raise ExportError("SOURCE_READ_FAILED") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def source_manifest(source: Path, *, portable_only: bool = False) -> dict[str, str]:
    """Read a stable allowlisted source manifest without creating output files."""
    source = _canonical_directory(Path(source), code="SOURCE_DIRECTORY_INVALID")
    return {relative.as_posix(): _stable_digest(path) for relative, path in _source_candidates(source, portable_only=portable_only)}


def source_digest(source: Path, *, portable_only: bool = False) -> str:
    raw = json.dumps(source_manifest(source, portable_only=portable_only), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _copy_regular_file(source: Path, destination: Path) -> str:
    source_fd = -1
    destination_fd = -1
    digest = hashlib.sha256()
    try:
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ExportError("SOURCE_FILE_TYPE_REFUSED")
        if _fingerprint(source.lstat()) != _fingerprint(before):
            raise ExportError("SOURCE_CHANGED_DURING_COPY")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        while True:
            block = os.read(source_fd, CHUNK_SIZE)
            if not block:
                break
            digest.update(block)
            remaining = memoryview(block)
            while remaining:
                written = os.write(destination_fd, remaining)
                if written <= 0:
                    raise ExportError("DESTINATION_WRITE_FAILED")
                remaining = remaining[written:]
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        if _fingerprint(before) != _fingerprint(after) or _fingerprint(after) != _fingerprint(source.lstat()):
            raise ExportError("SOURCE_CHANGED_DURING_COPY")
        copied_digest = digest.hexdigest()
        os.lseek(source_fd, 0, os.SEEK_SET)
        reread = hashlib.sha256()
        while True:
            block = os.read(source_fd, CHUNK_SIZE)
            if not block:
                break
            reread.update(block)
        if reread.hexdigest() != copied_digest:
            raise ExportError("SOURCE_CHANGED_DURING_COPY")
        os.close(destination_fd)
        destination_fd = -1
        target_digest = hashlib.sha256()
        target_fd = os.open(destination, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            while True:
                block = os.read(target_fd, CHUNK_SIZE)
                if not block:
                    break
                target_digest.update(block)
        finally:
            os.close(target_fd)
        if target_digest.hexdigest() != copied_digest:
            raise ExportError("DESTINATION_VERIFY_FAILED")
        return copied_digest
    except ExportError:
        raise
    except OSError as exc:
        raise ExportError("SOURCE_OR_DESTINATION_IO_FAILED") from exc
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)


def export_source(source: Path, destination: Path, *, portable_only: bool = False) -> dict[str, str]:
    """Copy the allowlisted working tree and return verified relative SHA-256 digests."""
    source = _canonical_directory(Path(source), code="SOURCE_DIRECTORY_INVALID")
    destination = Path(os.path.abspath(os.fspath(destination)))
    parent = _canonical_directory(destination.parent, code="DESTINATION_PARENT_INVALID")
    if destination == source or source in destination.parents:
        raise ExportError("DESTINATION_WITHIN_SOURCE_REFUSED")
    if destination.exists() or destination.is_symlink():
        raise ExportError("DESTINATION_EXISTS")
    candidates = _source_candidates(source, portable_only=portable_only)
    try:
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise ExportError("DESTINATION_CREATE_FAILED") from exc
    root_info = destination.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o700:
        raise ExportError("DESTINATION_DIRECTORY_UNSAFE")
    copied_directories: set[Path] = set()
    files: dict[str, str] = {}
    try:
        for relative, source_path in candidates:
            if not allowed_source(relative, portable_only=portable_only):
                raise ExportError("UNSAFE_SOURCE_PATH")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            for parent_path in target.parents:
                if parent_path == destination:
                    break
                copied_directories.add(parent_path)
            files[relative.as_posix()] = _copy_regular_file(source_path, target)
        for directory in sorted(copied_directories, key=lambda path: len(path.parts), reverse=True):
            os.chmod(directory, 0o755, follow_symlinks=False)
        after_root = destination.lstat()
        if (after_root.st_dev, after_root.st_ino) != (root_info.st_dev, root_info.st_ino):
            raise ExportError("DESTINATION_REPLACED")
        return files
    except Exception:
        try:
            current = destination.lstat()
            if (current.st_dev, current.st_ino) == (root_info.st_dev, root_info.st_ino) and stat.S_ISDIR(current.st_mode):
                shutil.rmtree(destination)
        except OSError:
            pass
        raise


def _write_private_receipt(path: Path, value: dict[str, object]) -> None:
    path = Path(os.path.abspath(os.fspath(path)))
    if path.exists() or path.is_symlink():
        raise ExportError("RECEIPT_EXISTS")
    _canonical_directory(path.parent, code="RECEIPT_PARENT_INVALID")
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise ExportError("RECEIPT_WRITE_FAILED")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export reviewed portable manager source.")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        source = _canonical_directory(args.source, code="SOURCE_DIRECTORY_INVALID")
        destination = Path(os.path.abspath(os.fspath(args.destination)))
        receipt_path = args.receipt or destination.parent / ("." + destination.name + ".export-receipt.json")
        receipt_path = Path(os.path.abspath(os.fspath(receipt_path)))
        if source == receipt_path or source in receipt_path.parents or destination == receipt_path or destination in receipt_path.parents:
            raise ExportError("RECEIPT_MUST_BE_OUTSIDE_EXPORT")
        if receipt_path.exists() or receipt_path.is_symlink():
            raise ExportError("RECEIPT_EXISTS")
        files = export_source(args.source, args.destination)
        status = subprocess.run(
            ["git", "-C", str(args.source), "status", "--porcelain=v1", "-uall"],
            check=False,
            capture_output=True,
            timeout=10,
        )
        status_snapshot = status.stdout.decode("utf-8", errors="replace") if status.returncode == 0 else None
        _write_private_receipt(receipt_path, {
            "schema": 1,
            "fileDigests": files,
            "sourceStatus": status_snapshot,
        })
        print(json.dumps({"exportedFiles": len(files), "sourceStatusCaptured": status.returncode == 0}, sort_keys=True))
        return 0
    except ExportError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
