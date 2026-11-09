"""Build a deterministic source archive from the allowlisted working tree."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile

from export_source import ExportError, export_source, is_excluded_path


CHUNK_SIZE = 1024 * 1024
PRIVATE_PATH_MARKERS = (b"/" + b"Users/", b"/" + b"home/")
LOCAL_DYNAMIC_REFERENCE = re.compile(
    r"(?:_load_release_module\(|\.with_name\(|\bscripts\s*/\s*)\s*['\"]([^'\"]+\.(?:py|mjs|cjs))['\"]"
)
LOCAL_TYPESCRIPT_SCRIPT_REFERENCE = re.compile(r"['\"](scripts/[^'\"]+\.(?:py|mjs|cjs))['\"]")
PRIVATE_ARCHIVE_COMPONENTS = frozenset({
    ".git", ".staging", "artifacts", "build", "cache", "coverage", "dist", "evidence", "logs",
    "node_modules", "release-input-cache", "release_input_cache", "releaseinputcache", "runtime",
    "tokens", "transactions", "__pycache__",
})
REQUIRED_FAMILIES = frozenset({"grafana", "langfuse", "loki", "mysql"})
PRIVATE_KEY_MATERIAL = re.compile(rb"-----BEGIN (?:[A-Z0-9]+[ -])*PRIVATE KEY(?: BLOCK)?-----", re.IGNORECASE)
RECOGNIZABLE_CREDENTIAL_FORMATS = (
    re.compile(rb"(?<![A-Za-z0-9_])(?:gh(?:p|o|u|s|r)_[A-Za-z0-9_.-]{20,}|github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9_])"),
    re.compile(rb"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9])(?:xox(?:b|p|o|s|r|a)-|xapp-|xwfp-)[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])", re.IGNORECASE),
    re.compile(rb"(?<![A-Za-z0-9_-])(?:sk|pk)-lf-[A-Za-z0-9_-]{12,}(?![A-Za-z0-9_-])"),
)


class PackageError(Exception):
    """A source archive failed a release boundary check."""


def _canonical_directory(path: Path) -> Path:
    try:
        absolute = Path(os.path.abspath(os.fspath(path)))
        info = absolute.lstat()
        if not stat.S_ISDIR(info.st_mode) or absolute.resolve(strict=True) != absolute:
            raise PackageError("PACKAGE_DIRECTORY_INVALID")
        return absolute
    except PackageError:
        raise
    except (OSError, RuntimeError) as error:
        raise PackageError("PACKAGE_DIRECTORY_INVALID") from error


def _safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    is_root_gitignore = path.parts == (".gitignore",)
    if (not value or path.is_absolute() or path.as_posix() != value
            or any(part in {"", ".", ".."} or (part.startswith(".") and not is_root_gitignore) for part in path.parts)
            or PRIVATE_ARCHIVE_COMPONENTS.intersection(path.parts)
            or is_excluded_path(Path(path.as_posix()))):
        raise PackageError("PACKAGE_PATH_UNSAFE")
    return path


def _read_verified(root: Path, relative: PurePosixPath, expected: str) -> bytes:
    path = root.joinpath(*relative.parts)
    descriptor = -1
    try:
        before_path = path.lstat()
        if not stat.S_ISREG(before_path.st_mode):
            raise PackageError("PACKAGE_FILE_UNSAFE")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode)
                or (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino)):
            raise PackageError("PACKAGE_FILE_UNSAFE")
        chunks = []
        digest = hashlib.sha256()
        while block := os.read(descriptor, CHUNK_SIZE):
            chunks.append(block)
            digest.update(block)
        after = os.fstat(descriptor)
        current = path.lstat()
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if stamp(before) != stamp(after) or stamp(after) != stamp(current):
            raise PackageError("PACKAGE_FILE_CHANGED")
        if digest.hexdigest() != expected:
            raise PackageError("PACKAGE_SOURCE_DIGEST_MISMATCH")
        return b"".join(chunks)
    except PackageError:
        raise
    except OSError as error:
        raise PackageError("PACKAGE_FILE_UNREADABLE") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _reject_personal_paths(payload: bytes) -> None:
    if any(marker in payload for marker in PRIVATE_PATH_MARKERS):
        raise PackageError("PACKAGE_PERSONAL_PATH_REFUSED")


def _reject_private_key_material(payload: bytes) -> None:
    if PRIVATE_KEY_MATERIAL.search(payload):
        raise PackageError("PACKAGE_PRIVATE_KEY_REFUSED")


def _reject_recognizable_credentials(payload: bytes) -> None:
    if any(pattern.search(payload) for pattern in RECOGNIZABLE_CREDENTIAL_FORMATS):
        raise PackageError("PACKAGE_CREDENTIAL_FORMAT_REFUSED")


def _verify_dynamic_source_closure(exported: Path, files: dict[str, str]) -> None:
    """Require literal local dynamic-import and runtime-script targets in the archive."""
    for value, digest in files.items():
        relative = _safe_relative(value)
        if relative.parts[0] == "src":
            if relative.suffix != ".ts":
                continue
            payload = _read_verified(exported, relative, digest)
            try:
                source = payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise PackageError("PACKAGE_SOURCE_ENCODING_INVALID") from error
            for match in LOCAL_TYPESCRIPT_SCRIPT_REFERENCE.finditer(source):
                target = PurePosixPath(match.group(1))
                if (target.is_absolute() or target.as_posix() != match.group(1)
                        or any(part in {"", ".", ".."} for part in target.parts)):
                    raise PackageError("PACKAGE_DYNAMIC_PATH_UNSAFE")
                if target.as_posix() not in files:
                    raise PackageError("PACKAGE_CLOSURE_INCOMPLETE")
            continue
        if relative.parts[0] != "scripts" or relative.name.startswith("test_") or relative.suffix not in {".py", ".mjs", ".cjs"}:
            continue
        payload = _read_verified(exported, relative, digest)
        try:
            source = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PackageError("PACKAGE_SOURCE_ENCODING_INVALID") from error
        for match in LOCAL_DYNAMIC_REFERENCE.finditer(source):
            target = PurePosixPath(match.group(1))
            if target.is_absolute() or any(part in {"", ".", ".."} for part in target.parts):
                raise PackageError("PACKAGE_DYNAMIC_PATH_UNSAFE")
            if len(target.parts) == 1:
                target_path = PurePosixPath("scripts") / target
            else:
                target_path = relative.parent / target
            if target_path.as_posix() not in files:
                raise PackageError("PACKAGE_CLOSURE_INCOMPLETE")


def _write_tar(exported: Path, files: dict[str, str], target) -> int:
    directories = set()
    for value in files:
        relative = _safe_relative(value)
        for parent in relative.parents:
            if parent.parts:
                directories.add(parent.as_posix())
    count = 0
    with gzip.GzipFile(fileobj=target, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for value in sorted(directories, key=lambda name: (name.count("/"), name)):
                info = tarfile.TarInfo(value + "/")
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                info.pax_headers = {}
                archive.addfile(info)
            for value in sorted(files):
                relative = _safe_relative(value)
                payload = _read_verified(exported, relative, files[value])
                _reject_personal_paths(payload)
                _reject_private_key_material(payload)
                _reject_recognizable_credentials(payload)
                info = tarfile.TarInfo(relative.as_posix())
                info.size = len(payload)
                info.mode = 0o755 if os.access(exported.joinpath(*relative.parts), os.X_OK) else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                info.pax_headers = {}
                archive.addfile(info, __import__("io").BytesIO(payload))
                count += 1
    return count


def _load_complete_release_policy(source: Path, policy_loader=None) -> dict:
    try:
        if policy_loader is None:
            from artifact_install import load_release_policy
            policy = load_release_policy(source / "release")
        else:
            policy = policy_loader(source / "release")
    except Exception as error:
        raise PackageError("RELEASE_POLICY_INVALID") from error
    families = policy.get("families") if type(policy) is dict else None
    if type(families) is not dict or not REQUIRED_FAMILIES <= set(families):
        raise PackageError("RELEASE_POLICY_INCOMPLETE")
    return policy


def _temporary_file(parent: Path, prefix: str, content: bytes) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=prefix, dir=parent)
    path = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o644)
        return path
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _link_set(pairs: list[tuple[Path, Path]]) -> None:
    created = []
    try:
        for temporary, destination in pairs:
            os.link(temporary, destination, follow_symlinks=False)
            info = destination.lstat()
            created.append((destination, (info.st_dev, info.st_ino)))
    except FileExistsError as error:
        raise PackageError("PACKAGE_OUTPUT_EXISTS") from error
    except OSError as error:
        raise PackageError("PACKAGE_WRITE_FAILED") from error
    finally:
        # Roll back only output names linked by this invocation if any later
        # member of the sidecar set failed to publish.
        if len(created) != len(pairs):
            for path, identity in reversed(created):
                try:
                    info = path.lstat()
                    if (info.st_dev, info.st_ino) == identity:
                        path.unlink()
                except OSError:
                    pass


def package_release(source: Path, output: Path, *, policy_loader=None) -> dict[str, object]:
    """Archive a portable-only export of current source, including untracked edits."""
    source = _canonical_directory(Path(source))
    output = Path(os.path.abspath(os.fspath(output)))
    parent = _canonical_directory(output.parent)
    if output == source or source in output.parents:
        raise PackageError("PACKAGE_OUTPUT_INSIDE_SOURCE")
    checksum = Path(str(output) + ".sha256")
    manifest_path = Path(str(output) + ".manifest.json")
    if any(path.exists() or path.is_symlink() for path in (output, checksum, manifest_path)):
        raise PackageError("PACKAGE_OUTPUT_EXISTS")
    _load_complete_release_policy(source, policy_loader)

    try:
        with tempfile.TemporaryDirectory(prefix=".portable-source-", dir=parent) as temporary:
            exported = Path(temporary) / "source"
            try:
                files = export_source(source, exported, portable_only=True)
            except TypeError as error:
                raise PackageError("PORTABLE_EXPORT_UNAVAILABLE") from error
            except ExportError as error:
                raise PackageError("PORTABLE_EXPORT_FAILED") from error
            if type(files) is not dict or not files or "LICENSE" not in files:
                raise PackageError("PACKAGE_SOURCE_INCOMPLETE")
            _verify_dynamic_source_closure(exported, files)
            canonical_manifest = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
            source_digest = hashlib.sha256(canonical_manifest).hexdigest()
            descriptor, temporary_archive = tempfile.mkstemp(prefix=".portable-release-", dir=parent)
            try:
                with os.fdopen(descriptor, "wb") as archive_file:
                    count = _write_tar(exported, files, archive_file)
                    archive_file.flush()
                    os.fsync(archive_file.fileno())
                temporary_path = Path(temporary_archive)
                digest = hashlib.sha256()
                with temporary_path.open("rb") as archive_file:
                    while block := archive_file.read(CHUNK_SIZE):
                        digest.update(block)
                checksum_content = f"{digest.hexdigest()}  {output.name}\n".encode("utf-8")
                manifest_content = json.dumps({
                    "schema": 1,
                    "artifact": output.name,
                    "sha256": digest.hexdigest(),
                    "fileCount": count,
                    "sourceDigest": source_digest,
                    "files": files,
                }, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
                checksum_temp = _temporary_file(Path(temporary), ".checksum-", checksum_content)
                manifest_temp = _temporary_file(Path(temporary), ".manifest-", manifest_content)
                os.chmod(temporary_path, 0o644)
                _link_set([(temporary_path, output), (checksum_temp, checksum), (manifest_temp, manifest_path)])
            except BaseException:
                try:
                    os.unlink(temporary_archive)
                except OSError:
                    pass
                raise
        return {"path": str(output), "sha256": digest.hexdigest(), "fileCount": count,
                "sourceDigest": source_digest, "checksumPath": str(checksum),
                "manifestPath": str(manifest_path)}
    except PackageError:
        raise
    except OSError as error:
        raise PackageError("PACKAGE_WRITE_FAILED") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the standalone source archive from the working tree.")
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        print(json.dumps(package_release(arguments.source, arguments.output), sort_keys=True))
        return 0
    except PackageError as error:
        print(json.dumps({"status": "REFUSED", "reason": str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
