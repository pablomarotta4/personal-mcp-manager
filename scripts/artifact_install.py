"""Acquire only the reviewed, platform-specific release inputs.

The release policy is code-owned content. Client configuration may choose a
reviewed family/profile, but never supplies URLs, executable paths, package
names or resolver flags. Downloads go to a new private workspace and are
verified against the shipped lock before any admission record is returned.
"""
from __future__ import annotations

import base64
from email.parser import BytesParser
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from pilot import SafeError


_FAMILY = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_MAX_POLICY_BYTES = 1024 * 1024
_MAX_INPUT_BYTES = 1024 * 1024 * 1024
_ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "nodejs.org",
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}
_FAMILY_KEYS = {
    "profileId", "profileIds", "sourceIdentity", "lockFile", "lockSha256", "catalogFile",
    "catalogSha256", "catalogFingerprint", "transformVersion",
    "dependencyReportSha256", "artifactSha256", "artifactInputId", "artifactKind", "nativeSignature",
    "nativeCommand", "inputs",
}
_INPUT_KEYS = {"id", "kind", "name", "version", "origin", "integrity", "sha256", "path"}
_GRAFANA_DEPENDENCY_REPORT = {
    "schema": 1,
    "runtime": "standalone-native",
    "package": "mcp-grafana",
    "version": "2.0.2",
    "pythonRuntimeRequired": False,
    "nativeLibraries": "platform-system-loads-only",
}
_LANGFUSE_WRAPPER_SHA256 = "d08a88ef6ad5255d493fd84ff1cf6e5e85f59ab3183ef5c64fa073a572534e4d"
_LANGFUSE_TRANSFORM_VERSION = "langfuse-standalone-wheel-v2"
_LANGFUSE_DEPENDENCY_REPORT_SHA256 = "9e202e8fb51cdbfbba6bc36485324ad97e44815b73999320049711c41f5daef2"
_LANGFUSE_CATALOG_FINGERPRINT = "d8b0419ca4b529bfbecdfab8f901f4638d693d348adc8e88853001ba5aded5af"
_LANGFUSE_RUNTIME_ARCHIVE_SHA256 = "fdf98aad59d6fb99a0fc42a0392956bd7f246793003c1789b798f20e38b8ae75"
_LANGFUSE_INTERPRETER_SHA256 = "b2c50fdcd4f1d79413218f91bb67b16a70a987cbf109a1dbc239dcb9c4ec96cb"


def _fail(code: str) -> None:
    raise SafeError(code)


def _canonical(value: object) -> bytes:
    try:
        # Match src/manifest.ts canonicalization so catalog fingerprints are
        # identical for Unicode descriptions as well as ASCII fields.
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError) as error:
        raise SafeError("RELEASE_POLICY_INVALID") from error


def _relative(value: object) -> Path:
    if not isinstance(value, str) or not value or "\0" in value:
        _fail("RELEASE_POLICY_INVALID")
    posix = PurePosixPath(value)
    if posix.is_absolute() or any(part in ("", ".", "..") or part.startswith(".") for part in posix.parts):
        _fail("RELEASE_POLICY_INVALID")
    return Path(*posix.parts)


def _read_release_file(root: Path, relative: str) -> bytes:
    path = root / _relative(relative)
    try:
        trusted_root = root.resolve(strict=True)
        current = trusted_root
        parts = _relative(relative).parts
        for component in parts:
            current = current / component
            component_info = current.lstat()
            if stat.S_ISLNK(component_info.st_mode):
                _fail("RELEASE_POLICY_INVALID")
        if trusted_root not in current.parents:
            _fail("RELEASE_POLICY_INVALID")
        path = current
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_POLICY_BYTES:
            _fail("RELEASE_POLICY_INVALID")
        return path.read_bytes()
    except SafeError:
        raise
    except (OSError, RuntimeError) as error:
        raise SafeError("RELEASE_POLICY_INCOMPLETE") from error


def _json_document(raw: bytes) -> dict:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SafeError("RELEASE_POLICY_INVALID") from error
    if type(document) is not dict:
        _fail("RELEASE_POLICY_INVALID")
    return document


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX64.fullmatch(value))


def _validate_input(item: object) -> dict:
    if type(item) is not dict or set(item) != _INPUT_KEYS:
        _fail("RELEASE_POLICY_INCOMPLETE")
    if (not isinstance(item["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,95}", item["id"])
            or item["kind"] not in {"npm-tarball", "python-wheel", "runtime-archive"}
            or not isinstance(item["name"], str) or not re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", item["name"])
            or not isinstance(item["version"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}", item["version"])
            or not _valid_digest(item["sha256"])):
        _fail("RELEASE_POLICY_INVALID")
    path = _relative(item["path"])
    parsed = urllib.parse.urlsplit(item["origin"] if isinstance(item["origin"], str) else "")
    if (parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS or parsed.username or parsed.password
            or parsed.port is not None or parsed.query or parsed.fragment or not parsed.path.startswith("/")):
        _fail("RELEASE_ORIGIN_UNREVIEWED")
    if item["kind"] == "npm-tarball":
        integrity = item["integrity"]
        if (not isinstance(integrity, str) or not integrity.startswith("sha512-")
                or not re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", integrity)):
            _fail("RELEASE_INTEGRITY_INVALID")
        if parsed.hostname != "registry.npmjs.org":
            _fail("RELEASE_ORIGIN_UNREVIEWED")
        expected_path = "/" + urllib.parse.quote(item["name"], safe="@/") + "/-/" + item["name"].split("/")[-1] + "-" + item["version"] + ".tgz"
        if parsed.path != expected_path:
            _fail("RELEASE_ORIGIN_UNREVIEWED")
    elif item["integrity"] is not None or parsed.hostname not in {"files.pythonhosted.org", "nodejs.org", "github.com"}:
        _fail("RELEASE_ORIGIN_UNREVIEWED")
    return {**item, "_relative": path}


def load_release_policy(release: Path) -> dict:
    """Load the complete, strict policy and verify its lock/catalog hashes."""
    release = Path(release)
    try:
        if not release.is_dir() or release.is_symlink():
            _fail("RELEASE_POLICY_INCOMPLETE")
        families = _json_document(_read_release_file(release, "families.json"))
        inputs = _json_document(_read_release_file(release, "inputs.json"))
        if set(families) != {"schema", "platform", "acquisition", "runtimeNetworkResolution", "families"}:
            _fail("RELEASE_POLICY_INVALID")
        if (families["schema"] != 1 or families["platform"] != "darwin-arm64"
                or families["acquisition"] != "reviewed-locks-only" or families["runtimeNetworkResolution"] is not False
                or type(families["families"]) is not list or not families["families"]
                or any(not isinstance(name, str) or not _FAMILY.fullmatch(name) for name in families["families"])
                or len(set(families["families"])) != len(families["families"])):
            _fail("RELEASE_POLICY_INCOMPLETE")
        if set(inputs) != {"schema", "platform", "families"} or inputs["schema"] != 1 or inputs["platform"] != "darwin-arm64":
            _fail("RELEASE_POLICY_INCOMPLETE")
        if type(inputs["families"]) is not dict or set(inputs["families"]) != set(families["families"]):
            _fail("RELEASE_POLICY_INCOMPLETE")

        normalized = {}
        for family in families["families"]:
            profile = inputs["families"].get(family)
            if type(profile) is not dict or set(profile) != _FAMILY_KEYS:
                _fail("RELEASE_POLICY_INCOMPLETE")
            if (not isinstance(profile["profileId"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", profile["profileId"])
                    or type(profile["profileIds"]) is not list or not profile["profileIds"]
                    or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value)
                           for value in profile["profileIds"])
                    or profile["profileId"] not in profile["profileIds"]
                    or len(profile["profileIds"]) != len(set(profile["profileIds"]))
                    or not isinstance(profile["sourceIdentity"], str) or not profile["sourceIdentity"]
                    or len(profile["sourceIdentity"]) > 255
                    or not isinstance(profile["transformVersion"], str) or not profile["transformVersion"]
                    or not _valid_digest(profile["lockSha256"])
                    or not _valid_digest(profile["catalogSha256"])
                    or not _valid_digest(profile["catalogFingerprint"])
                    or not _valid_digest(profile["dependencyReportSha256"])
            or not _valid_digest(profile["artifactSha256"])
                    or not isinstance(profile["artifactInputId"], str)
                    or profile["artifactKind"] not in {"node-closure", "python-closure", "standalone-native"}):
                _fail("RELEASE_POLICY_INCOMPLETE")
            signature = profile["nativeSignature"]
            if profile["artifactKind"] == "standalone-native":
                if (type(signature) is not dict or set(signature) != {"architectures", "loads", "rpaths", "installIds"}
                        or any(type(signature[key]) is not list or any(not isinstance(item, str) for item in signature[key])
                               or signature[key] != sorted(set(signature[key]))
                               for key in signature)):
                    _fail("RELEASE_NATIVE_SIGNATURE_INVALID")
            elif signature is not None:
                _fail("RELEASE_NATIVE_SIGNATURE_INVALID")
            lock_raw = _read_release_file(release, profile["lockFile"])
            catalog_raw = _read_release_file(release, profile["catalogFile"])
            if hashlib.sha256(lock_raw).hexdigest() != profile["lockSha256"] or hashlib.sha256(catalog_raw).hexdigest() != profile["catalogSha256"]:
                _fail("RELEASE_POLICY_MISMATCH")
            lock = _json_document(lock_raw) if profile["lockFile"].endswith(".json") else None
            if lock is None:
                _fail("RELEASE_POLICY_INVALID")
            if type(profile["inputs"]) is not list or not profile["inputs"]:
                _fail("RELEASE_POLICY_INCOMPLETE")
            checked_inputs = [_validate_input(item) for item in profile["inputs"]]
            ids = [item["id"] for item in checked_inputs]
            paths = [item["_relative"].as_posix() for item in checked_inputs]
            if len(ids) != len(set(ids)) or len(paths) != len(set(paths)) or profile["artifactInputId"] not in ids:
                _fail("RELEASE_POLICY_INCOMPLETE")
            inputs_by_id = {item["id"]: item for item in checked_inputs}
            if profile["artifactKind"] == "node-closure":
                if lock.get("lockfileVersion") != 3 or type(lock.get("packages")) is not dict or "" not in lock["packages"]:
                    _fail("RELEASE_POLICY_INCOMPLETE")
                if inputs_by_id[profile["artifactInputId"]]["kind"] != "runtime-archive":
                    _fail("RELEASE_POLICY_INCOMPLETE")
            elif profile["artifactKind"] in {"python-closure", "standalone-native"}:
                if (set(lock) != {"schema", "platform", "wheels"} or lock["schema"] != 1
                        or lock["platform"] != "darwin-arm64" or type(lock["wheels"]) is not list
                        or not lock["wheels"]):
                    _fail("RELEASE_POLICY_INCOMPLETE")
                wheel_ids = []
                for wheel in lock["wheels"]:
                    if (type(wheel) is not dict or set(wheel) != {"inputId", "name", "version"}
                            or not isinstance(wheel["inputId"], str) or wheel["inputId"] not in inputs_by_id
                            or inputs_by_id[wheel["inputId"]]["kind"] != "python-wheel"
                            or inputs_by_id[wheel["inputId"]]["name"] != wheel["name"]
                            or inputs_by_id[wheel["inputId"]]["version"] != wheel["version"]):
                        _fail("RELEASE_POLICY_INVALID")
                    wheel_ids.append(wheel["inputId"])
                if (len(wheel_ids) != len(set(wheel_ids)) or set(wheel_ids) !=
                        {item["id"] for item in checked_inputs if item["kind"] == "python-wheel"}
                        or (profile["artifactKind"] == "standalone-native"
                            and inputs_by_id[profile["artifactInputId"]]["kind"] != "python-wheel")):
                    _fail("RELEASE_POLICY_INCOMPLETE")
                if profile["artifactKind"] == "python-closure":
                    runtime_inputs = [item for item in checked_inputs if item["kind"] == "runtime-archive"]
                    if (len(runtime_inputs) != 1 or runtime_inputs[0]["id"] != profile["artifactInputId"]
                            or runtime_inputs[0]["name"] != "python" or runtime_inputs[0]["version"] != "3.13.12"):
                        _fail("RELEASE_POLICY_INCOMPLETE")
            if family == "langfuse":
                expected_profile_ids = [
                    "langfuse-traces", "langfuse-api-dev", "agent-dev",
                    "worker-dev", "api-traces", "worker-prod",
                ]
                runtime_input = inputs_by_id.get(profile["artifactInputId"])
                if (profile["artifactKind"] != "python-closure" or profile["profileId"] != "langfuse-traces"
                        or profile["profileIds"] != expected_profile_ids
                        or profile["transformVersion"] != _LANGFUSE_TRANSFORM_VERSION
                        or profile["sourceIdentity"] != "langfuse-mcp:0.10.1/langfuse:4.17.0/python:3.13.12"
                        or profile["catalogFingerprint"] != _LANGFUSE_CATALOG_FINGERPRINT
                        or profile["dependencyReportSha256"] != _LANGFUSE_DEPENDENCY_REPORT_SHA256
                        or profile["artifactSha256"] != _LANGFUSE_INTERPRETER_SHA256
                        or runtime_input is None or runtime_input["kind"] != "runtime-archive"
                        or runtime_input["sha256"] != _LANGFUSE_RUNTIME_ARCHIVE_SHA256
                        or runtime_input["origin"] != "https://github.com/astral-sh/python-build-standalone/releases/download/20260211/cpython-3.13.12%2B20260211-aarch64-apple-darwin-install_only_stripped.tar.gz"):
                    _fail("RELEASE_POLICY_MISMATCH")
                langfuse_materializer = _load_release_module("materialize-langfuse.py", "_portable_policy_langfuse")
                wheel_pins = {re.sub(r"[-_.]+", "-", wheel["name"]).lower(): wheel["version"]
                              for wheel in lock["wheels"]}
                if wheel_pins != langfuse_materializer.DISTRIBUTIONS:
                    _fail("RELEASE_POLICY_MISMATCH")
            if profile["artifactKind"] == "standalone-native":
                expected_report = hashlib.sha256(_canonical(_GRAFANA_DEPENDENCY_REPORT)).hexdigest()
                if family != "grafana" or profile["dependencyReportSha256"] != expected_report:
                    _fail("RELEASE_DEPENDENCY_REPORT_MISMATCH")
            catalog = _json_document(catalog_raw)
            if (hashlib.sha256(_canonical(catalog)).hexdigest() != profile["catalogFingerprint"]
                    or profile["catalogSha256"] != profile["catalogFingerprint"]):
                _fail("RELEASE_POLICY_MISMATCH")
            normalized[family] = {
                **profile,
                "lock": lock,
                "lockBytes": lock_raw,
                "catalog": catalog,
                "catalogBytes": catalog_raw,
                "inputs": checked_inputs,
            }
        return {"schema": 1, "platform": "darwin-arm64", "families": normalized,
                "releaseRoot": release.resolve(strict=True)}
    except SafeError:
        raise
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise SafeError("RELEASE_POLICY_INCOMPLETE") from error


def _digest_download(path: Path, item: dict) -> None:
    digest = hashlib.sha256()
    sha512 = hashlib.sha512()
    size = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > _MAX_INPUT_BYTES:
                    _fail("RELEASE_INPUT_TOO_LARGE")
                digest.update(chunk)
                sha512.update(chunk)
    except OSError as error:
        raise SafeError("RELEASE_INPUT_UNAVAILABLE") from error
    if digest.hexdigest() != item["sha256"]:
        _fail("RELEASE_INPUT_MISMATCH")
    if item["integrity"] is not None:
        expected = base64.b64decode(item["integrity"].split("-", 1)[1], validate=True)
        if sha512.digest() != expected:
            _fail("RELEASE_INPUT_MISMATCH")


def _download_input(item: dict, destination: Path) -> None:
    """Fetch one pinned input without consulting a package-manager cache."""
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    request = urllib.request.Request(item["origin"], headers={"Accept": "application/octet-stream", "User-Agent": "personal-mcp-manager/1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in _ALLOWED_HOSTS:
                _fail("RELEASE_ORIGIN_UNREVIEWED")
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > _MAX_INPUT_BYTES:
                        _fail("RELEASE_INPUT_TOO_LARGE")
                    view = memoryview(chunk)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            _fail("RELEASE_INPUT_UNAVAILABLE")
                        view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except SafeError:
        raise
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        raise SafeError("RELEASE_INPUT_UNAVAILABLE") from error


def _validate_workspace(workspace: Path) -> Path:
    workspace = Path(workspace)
    try:
        info = workspace.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            _fail("ACQUISITION_WORKSPACE_UNTRUSTED")
        return workspace.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SafeError("ACQUISITION_WORKSPACE_UNTRUSTED") from error


def platform_installable(package: object, os_name: str = "darwin", cpu: str = "arm64") -> bool:
    """Apply npm's bounded os/cpu allow and deny lists for the target release."""
    if type(package) is not dict:
        _fail("PACKAGE_LOCK_INVALID")
    for field, target in (("os", os_name), ("cpu", cpu)):
        values = package.get(field)
        if values is None:
            continue
        if type(values) is not list or not values or any(
                not isinstance(value, str) or not re.fullmatch(r"!?[a-z0-9_-]{1,32}", value)
                for value in values):
            _fail("PACKAGE_PLATFORM_INVALID")
        positive = [value for value in values if not value.startswith("!")]
        negative = [value[1:] for value in values if value.startswith("!")]
        if len(positive) + len(negative) != len(set(values)):
            _fail("PACKAGE_PLATFORM_INVALID")
        if target in negative or (positive and target not in positive):
            return False
    return True


def _safe_tar_path(value: object) -> PurePosixPath:
    if (not isinstance(value, str) or not value or value.startswith("/") or "\\" in value
            or any(ord(character) < 32 for character in value)):
        _fail("PACKAGE_ARCHIVE_PATH_INVALID")
    normalized = value[:-1] if value.endswith("/") else value
    path = PurePosixPath(normalized)
    if path.as_posix() != normalized or any(part in ("", ".", "..") for part in path.parts):
        _fail("PACKAGE_ARCHIVE_PATH_INVALID")
    return path


def extract_npm_package(archive_path: Path, destination: Path, *, name: str, version: str,
                        skip_paths: tuple[str, ...] = ()) -> None:
    """Extract a single exact npm tarball without links or package execution."""
    if (not isinstance(name, str) or not re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", name)
            or not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z.+_-]{1,64}", version)):
        _fail("PACKAGE_IDENTITY_INVALID")
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        _fail("PACKAGE_DESTINATION_CONFLICT")
    destination.mkdir(mode=0o700, parents=True)
    files: set[str] = set()
    directories: set[str] = set()
    archive_root = None
    total = 0
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 50_000:
                _fail("PACKAGE_ARCHIVE_INVALID")
            for member in members:
                archive_path_name = _safe_tar_path(member.name)
                member_root = archive_path_name.parts[0]
                allowed_roots = {"package", PurePosixPath(name).name}
                version_parts = version.split(".")
                if len(version_parts) >= 2 and all(part.isdigit() for part in version_parts[:2]):
                    allowed_roots.add(f"{PurePosixPath(name).name} v{version_parts[0]}.{version_parts[1]}")
                if member_root not in allowed_roots or (archive_root is not None and member_root != archive_root):
                    _fail("PACKAGE_ARCHIVE_PATH_INVALID")
                archive_root = member_root
                relative = archive_path_name.parts[1:]
                if not relative:
                    if not member.isdir():
                        _fail("PACKAGE_ARCHIVE_INVALID")
                    continue
                relative_name = PurePosixPath(*relative).as_posix()
                if relative_name in skip_paths:
                    if not member.isfile():
                        _fail("PACKAGE_ARCHIVE_INVALID")
                    continue
                if (member.issym() or member.islnk() or member.isdev() or member.isfifo()
                        or not (member.isfile() or member.isdir()) or member.sparse is not None):
                    _fail("PACKAGE_ARCHIVE_MEMBER_INVALID")
                if member.isdir():
                    directories.add(relative_name)
                    target = destination.joinpath(*relative)
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                if relative_name in files or member.size < 0 or member.size > _MAX_INPUT_BYTES:
                    _fail("PACKAGE_ARCHIVE_MEMBER_INVALID")
                lower_name = PurePosixPath(relative_name).name.lower()
                if lower_name.startswith(".env") or lower_name in {".npmrc", ".my.cnf", ".logcli-config.yaml", "logcli-config.yaml"}:
                    _fail("PACKAGE_SECRET_FILE_REFUSED")
                total += member.size
                if total > _MAX_INPUT_BYTES:
                    _fail("PACKAGE_ARCHIVE_TOO_LARGE")
                target = destination.joinpath(*relative)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                content = archive.extractfile(member)
                if content is None:
                    _fail("PACKAGE_ARCHIVE_INVALID")
                mode = 0o755 if member.mode & 0o111 else 0o644
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
                try:
                    remaining = member.size
                    while remaining:
                        block = content.read(min(1024 * 1024, remaining))
                        if not block:
                            _fail("PACKAGE_ARCHIVE_TRUNCATED")
                        view = memoryview(block)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                _fail("PACKAGE_EXTRACT_FAILED")
                            view = view[written:]
                        remaining -= len(block)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                    content.close()
                files.add(relative_name)
        metadata_path = destination / "package.json"
        info = metadata_path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_POLICY_BYTES:
            _fail("PACKAGE_METADATA_INVALID")
        metadata = _json_document(metadata_path.read_bytes())
        if metadata.get("name") != name or metadata.get("version") != version:
            _fail("PACKAGE_IDENTITY_MISMATCH")
        for directory, dirs, _files in os.walk(destination, topdown=False):
            Path(directory).chmod(0o700)
    except SafeError:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError, UnicodeError) as error:
        raise SafeError("PACKAGE_ARCHIVE_INVALID") from error


def extract_node_binary(archive_path: Path, destination: Path, *, version: str) -> Path:
    """Extract only the reviewed Apple Silicon Node executable from its tarball."""
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        _fail("RUNTIME_VERSION_INVALID")
    expected = f"node-v{version}-darwin-arm64/bin/node"
    destination = Path(destination)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with tarfile.open(archive_path, mode="r:xz") as archive:
            found = None
            for member in archive:
                if member.name != expected:
                    continue
                if found is not None or not member.isfile() or member.size <= 0 or member.size > 256 * 1024 * 1024:
                    _fail("RUNTIME_ARCHIVE_INVALID")
                found = member
            if found is None:
                _fail("RUNTIME_ARCHIVE_INVALID")
            content = archive.extractfile(found)
            if content is None:
                _fail("RUNTIME_ARCHIVE_INVALID")
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o700)
            try:
                remaining = found.size
                while remaining:
                    block = content.read(min(1024 * 1024, remaining))
                    if not block:
                        _fail("RUNTIME_ARCHIVE_TRUNCATED")
                    view = memoryview(block)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            _fail("RUNTIME_EXTRACT_FAILED")
                        view = view[written:]
                    remaining -= len(block)
                os.fsync(fd)
            finally:
                os.close(fd)
                content.close()
        if not destination.stat().st_mode & 0o111:
            _fail("RUNTIME_EXECUTABLE_INVALID")
        return destination
    except SafeError:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError) as error:
        raise SafeError("RUNTIME_ARCHIVE_INVALID") from error


def extract_python_runtime_archive(archive_path: Path, destination: Path, *, version: str) -> Path:
    """Extract an exact Python standalone runtime without running package code."""
    if version != "3.13.12":
        _fail("RUNTIME_VERSION_UNREVIEWED")
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        _fail("RUNTIME_DESTINATION_CONFLICT")
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 50_000:
                _fail("RUNTIME_ARCHIVE_INVALID")
            entries = {}
            total = 0
            for member in members:
                normalized = _safe_tar_path(member.name)
                if normalized.parts[0] != "python":
                    _fail("RUNTIME_ARCHIVE_PATH_INVALID")
                relative_parts = normalized.parts[1:]
                if not relative_parts:
                    if not member.isdir():
                        _fail("RUNTIME_ARCHIVE_INVALID")
                    continue
                relative = PurePosixPath(*relative_parts)
                name = relative.as_posix()
                if name in entries or member.sparse is not None or member.mode & 0o7000:
                    _fail("RUNTIME_ARCHIVE_MEMBER_INVALID")
                if member.isdir():
                    entries[name] = ("directory", member, None)
                elif member.issym():
                    target = member.linkname
                    if (not target or target.startswith("/") or "\\" in target
                            or any(ord(char) < 32 for char in target)):
                        _fail("RUNTIME_ARCHIVE_LINK_INVALID")
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
                        _fail("RUNTIME_ARCHIVE_LINK_INVALID")
                    entries[name] = ("symlink", member, target)
                elif member.isfile() and 0 <= member.size <= 512 * 1024 * 1024:
                    total += member.size
                    if total > _MAX_INPUT_BYTES:
                        _fail("RUNTIME_ARCHIVE_TOO_LARGE")
                    entries[name] = ("file", member, None)
                else:
                    _fail("RUNTIME_ARCHIVE_MEMBER_INVALID")
            links = {name for name, (kind, _member, _target) in entries.items() if kind == "symlink"}
            for name in entries:
                parts = PurePosixPath(name).parts
                if any(PurePosixPath(*parts[:index]).as_posix() in links for index in range(1, len(parts))):
                    _fail("RUNTIME_ARCHIVE_LINK_PARENT")

            destination.mkdir(mode=0o700, parents=True)
            for name, (kind, _member, _target) in sorted(entries.items(), key=lambda item: (len(PurePosixPath(item[0]).parts), item[0])):
                if kind != "directory":
                    continue
                target = destination.joinpath(*PurePosixPath(name).parts)
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            for name, (kind, member, _target) in entries.items():
                if kind != "file":
                    continue
                target = destination.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                content = archive.extractfile(member)
                if content is None:
                    _fail("RUNTIME_ARCHIVE_INVALID")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                                     0o700 if member.mode & 0o111 else 0o600)
                try:
                    remaining = member.size
                    while remaining:
                        block = content.read(min(1024 * 1024, remaining))
                        if not block:
                            _fail("RUNTIME_ARCHIVE_TRUNCATED")
                        view = memoryview(block)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                _fail("RUNTIME_EXTRACT_FAILED")
                            view = view[written:]
                        remaining -= len(block)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                    content.close()
            for name, (kind, _member, target_name) in entries.items():
                if kind != "symlink":
                    continue
                target = destination.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                target.symlink_to(target_name)

        executable = destination / "bin/python3.13"
        header = destination / "include/python3.13/patchlevel.h"
        if (not executable.is_file() or executable.is_symlink() or not executable.stat().st_mode & 0o111
                or not header.is_file() or header.is_symlink() or header.stat().st_size > 1024 * 1024
                or not re.search(rb'^#define\s+PY_VERSION\s+"3\.13\.12"', header.read_bytes(), re.M)):
            _fail("RUNTIME_VERSION_MISMATCH")
        if inspect_grafana_native(executable)["architectures"] != ["arm64"]:
            _fail("RUNTIME_ARCHITECTURE_MISMATCH")
        return destination
    except SafeError:
        raise
    except (OSError, tarfile.TarError, EOFError, ValueError, UnicodeError) as error:
        raise SafeError("RUNTIME_ARCHIVE_INVALID") from error


def extract_python_wheel(wheel_path: Path, destination: Path, *, name: str, version: str) -> None:
    """Install wheel contents into an isolated site-packages tree without hooks."""
    if (not isinstance(name, str) or not re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", name)
            or not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}", version)):
        _fail("WHEEL_IDENTITY_INVALID")
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    names = set()
    metadata = None
    total = 0
    try:
        with zipfile.ZipFile(wheel_path, "r") as wheel:
            members = wheel.infolist()
            if not members or len(members) > 50_000:
                _fail("WHEEL_INVALID")
            for member in members:
                raw = member.filename
                if (not raw or raw.startswith("/") or "\\" in raw or any(ord(char) < 32 for char in raw)
                        or ".." in PurePosixPath(raw.rstrip("/")).parts
                        or PurePosixPath(raw.rstrip("/")).is_absolute()
                        or PurePosixPath(raw.rstrip("/")).as_posix() != raw.rstrip("/")):
                    _fail("WHEEL_PATH_INVALID")
                relative = PurePosixPath(raw.rstrip("/"))
                if not relative.parts or relative.parts[0].endswith(".data"):
                    _fail("WHEEL_SCHEME_UNSUPPORTED")
                if raw in names:
                    _fail("WHEEL_DUPLICATE_ENTRY")
                names.add(raw)
                mode = member.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR) or member.flag_bits & 1:
                    _fail("WHEEL_MEMBER_INVALID")
                if member.file_size < 0 or member.file_size > 128 * 1024 * 1024:
                    _fail("WHEEL_TOO_LARGE")
                if raw.endswith(".dist-info/METADATA"):
                    if metadata is not None or member.file_size > 2 * 1024 * 1024:
                        _fail("WHEEL_METADATA_INVALID")
                    metadata = wheel.read(member)
                if member.is_dir():
                    target = destination.joinpath(*relative.parts)
                    if target.exists() and not target.is_dir():
                        _fail("WHEEL_DESTINATION_CONFLICT")
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                if relative.suffix == ".pyc":
                    continue
                total += member.file_size
                if total > 512 * 1024 * 1024:
                    _fail("WHEEL_TOO_LARGE")
                target = destination.joinpath(*relative.parts)
                if target.exists() or target.is_symlink():
                    _fail("WHEEL_DESTINATION_CONFLICT")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                content = wheel.open(member, "r")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                                     0o700 if mode & 0o111 else 0o600)
                try:
                    remaining = member.file_size
                    while remaining:
                        block = content.read(min(1024 * 1024, remaining))
                        if not block:
                            _fail("WHEEL_TRUNCATED")
                        view = memoryview(block)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                _fail("WHEEL_EXTRACT_FAILED")
                            view = view[written:]
                        remaining -= len(block)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                    content.close()
        if metadata is None:
            _fail("WHEEL_METADATA_INVALID")
        parsed = BytesParser().parsebytes(metadata, headersonly=True)
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        wheel_name = re.sub(r"[-_.]+", "-", parsed.get("Name", "")).lower()
        if (len(parsed.get_all("Name", [])) != 1 or len(parsed.get_all("Version", [])) != 1
                or wheel_name != normalized or parsed["Version"] != version):
            _fail("WHEEL_IDENTITY_MISMATCH")
    except SafeError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError, ValueError, UnicodeError) as error:
        raise SafeError("WHEEL_INVALID") from error


def extract_grafana_executable(wheel_path: Path, destination: Path, *, expected_sha256: str) -> Path:
    """Copy only the reviewed standalone Grafana executable out of its wheel."""
    if not _valid_digest(expected_sha256):
        _fail("ARTIFACT_EXECUTABLE_PIN_INVALID")
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        _fail("ARTIFACT_DESTINATION_CONFLICT")
    metadata = None
    executable = None
    names = set()
    total = 0
    try:
        with zipfile.ZipFile(wheel_path, "r") as wheel:
            members = wheel.infolist()
            if not members or len(members) > 500:
                _fail("WHEEL_INVALID")
            for member in members:
                name = member.filename
                if (not name or name.startswith("/") or "\\" in name or any(ord(char) < 32 for char in name)
                        or ".." in PurePosixPath(name.rstrip("/")).parts
                        or PurePosixPath(name.rstrip("/")).is_absolute()
                        or PurePosixPath(name.rstrip("/")).as_posix() != name.rstrip("/")):
                    _fail("WHEEL_PATH_INVALID")
                if name in names:
                    _fail("WHEEL_DUPLICATE_ENTRY")
                names.add(name)
                mode = member.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    _fail("WHEEL_MEMBER_INVALID")
                if member.flag_bits & 1:
                    _fail("WHEEL_ENCRYPTED_ENTRY")
                if member.file_size < 0 or member.file_size > 128 * 1024 * 1024:
                    _fail("WHEEL_TOO_LARGE")
                total += member.file_size
                if total > 512 * 1024 * 1024:
                    _fail("WHEEL_TOO_LARGE")
                if name.endswith(".dist-info/METADATA"):
                    if metadata is not None or member.file_size > 2 * 1024 * 1024:
                        _fail("WHEEL_METADATA_INVALID")
                    metadata = wheel.read(member)
                if name == "mcp_grafana/bin/mcp-grafana":
                    if executable is not None or not member.file_size or not (mode & 0o111):
                        _fail("WHEEL_EXECUTABLE_INVALID")
                    executable = member
            if metadata is None or executable is None:
                _fail("WHEEL_CONTENT_INCOMPLETE")
            parsed = BytesParser().parsebytes(metadata, headersonly=True)
            if (len(parsed.get_all("Name", [])) != 1 or len(parsed.get_all("Version", [])) != 1
                    or parsed["Name"].lower().replace("_", "-") != "mcp-grafana" or parsed["Version"] != "2.0.2"):
                _fail("WHEEL_IDENTITY_MISMATCH")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = wheel.open(executable, "r")
            digest = hashlib.sha256()
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o700)
            size = 0
            try:
                while block := source.read(1024 * 1024):
                    size += len(block)
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            _fail("WHEEL_EXTRACT_FAILED")
                        view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
                source.close()
            if size != executable.file_size or digest.hexdigest() != expected_sha256:
                _fail("ARTIFACT_EXECUTABLE_MISMATCH")
            return destination
    except SafeError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError, ValueError, UnicodeError) as error:
        raise SafeError("WHEEL_INVALID") from error


def inspect_grafana_native(path: Path) -> dict:
    """Read the standalone binary's architecture and load signature statically."""
    path = Path(path)
    try:
        architectures = subprocess.run(["/usr/bin/lipo", "-archs", str(path)], check=True,
                                       capture_output=True, timeout=10).stdout.decode("ascii").split()
        text = subprocess.run(["/usr/bin/otool", "-l", str(path)], check=True,
                             capture_output=True, timeout=10).stdout.decode("utf-8")
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise SafeError("NATIVE_INSPECTION_FAILED") from error
    if not architectures or len(text) > 2 * 1024 * 1024:
        _fail("NATIVE_INSPECTION_FAILED")
    result = {"architectures": sorted(set(architectures)), "loads": [], "rpaths": [], "installIds": []}
    for block in text.split("Load command "):
        command = re.search(r"^\s*cmd (LC_[A-Z_]+)\s*$", block, re.M)
        if not command:
            continue
        if command[1] == "LC_RPATH":
            match = re.search(r"^\s*path (.*?) \(offset ", block, re.M)
            if match:
                result["rpaths"].append(match[1])
        elif command[1] in ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_LOAD_UPWARD_DYLIB", "LC_ID_DYLIB"):
            match = re.search(r"^\s*name (.*?) \(offset ", block, re.M)
            if match:
                result["installIds" if command[1] == "LC_ID_DYLIB" else "loads"].append(match[1])
    return {key: sorted(set(values)) for key, values in result.items()}


def _load_release_module(filename: str, module_name: str):
    path = Path(__file__).with_name(filename)
    if not path.is_file() or path.is_symlink():
        _fail("FAMILY_MATERIALIZER_UNAVAILABLE")
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        _fail("FAMILY_MATERIALIZER_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(module_name, None)
        raise SafeError("FAMILY_MATERIALIZER_UNAVAILABLE") from error
    return module


def _package_lock(policy: dict, family: str, staged_inputs: dict, source: Path) -> tuple[dict, dict]:
    """Build the exact target package tree from lock entries and verified tarballs."""
    profile = policy["families"][family]
    lock = profile["lock"]
    packages = lock.get("packages")
    if type(packages) is not dict or type(packages.get("")) is not dict:
        _fail("PACKAGE_LOCK_INVALID")
    item_by_key = {}
    item_by_id = {}
    for item in profile["inputs"]:
        if item["kind"] == "npm-tarball":
            key = (item["name"], item["version"], item["integrity"], item["origin"])
            if key in item_by_key or item["id"] in item_by_id:
                _fail("PACKAGE_INPUT_AMBIGUOUS")
            item_by_key[key] = item
            item_by_id[item["id"]] = item

    expected = {}
    used_input_ids = set()
    records = []
    for lock_path, package in sorted(packages.items()):
        if lock_path == "":
            continue
        safe_path = _relative(lock_path)
        if not lock_path.startswith("node_modules/") or type(package) is not dict or package.get("link") is True:
            _fail("PACKAGE_LOCK_INVALID")
        if not platform_installable(package):
            continue
        package_name = package.get("name")
        if not isinstance(package_name, str):
            package_name = lock_path.split("node_modules/")[-1]
        version = package.get("version")
        integrity = package.get("integrity")
        origin = package.get("resolved")
        if (not isinstance(version, str) or not isinstance(integrity, str) or not isinstance(origin, str)
                or lock_path.split("node_modules/")[-1] != package_name):
            _fail("PACKAGE_LOCK_INVALID")
        input_record = item_by_key.get((package_name, version, integrity, origin))
        if input_record is None:
            _fail("PACKAGE_INPUT_UNPINNED")
        staged = staged_inputs.get(input_record["id"])
        if staged is None:
            _fail("RELEASE_INPUT_UNAVAILABLE")
        staged_path = Path(staged)
        if staged_path.is_symlink() or not staged_path.is_file():
            _fail("RELEASE_INPUT_MISMATCH")
        _digest_download(staged_path, input_record)
        relative = safe_path.relative_to("node_modules")
        destination = source.joinpath(*relative.parts)
        skip = ("dist/.env",) if family == "mysql" and package_name == "@benborla29/mcp-server-mysql" else ()
        extract_npm_package(staged_path, destination, name=package_name, version=version, skip_paths=skip)
        report_path = lock_path.removeprefix("node_modules/")
        expected[report_path] = {"name": package_name, "version": version}
        used_input_ids.add(input_record["id"])
        records.append((package_name, version, destination))

    if not expected or not records or used_input_ids != set(item_by_id):
        _fail("PACKAGE_LOCK_INCOMPLETE")
    direct = packages[""].get("dependencies")
    if type(direct) is not dict or not direct:
        _fail("PACKAGE_LOCK_INVALID")
    for name, version_range in direct.items():
        matches = [record for record in records if record[0] == name]
        if len(matches) != 1 or matches[0][1] != version_range:
            _fail("PACKAGE_ROOT_DEPENDENCY_INVALID")
    return expected, {name: (version, destination) for name, version, destination in records}


def _node_runtime(profile: dict, staged_inputs: dict, source: Path) -> tuple[Path, str]:
    archives = [item for item in profile["inputs"] if item["kind"] == "runtime-archive" and item["name"] == "node"]
    if len(archives) != 1:
        _fail("RUNTIME_INPUT_UNPINNED")
    item = archives[0]
    staged = Path(staged_inputs.get(item["id"], ""))
    if not staged.is_file() or staged.is_symlink():
        _fail("RELEASE_INPUT_UNAVAILABLE")
    _digest_download(staged, item)
    node = extract_node_binary(staged, source / "node", version=item["version"])
    digest = hashlib.sha256(node.read_bytes()).hexdigest()
    if digest != profile["artifactSha256"]:
        _fail("RUNTIME_EXECUTABLE_MISMATCH")
    return node, digest


def _input_pins(profile: dict) -> list[dict]:
    return [{key: item[key] for key in ("id", "kind", "name", "version", "origin", "integrity", "sha256")}
            for item in profile["inputs"]]


def _standalone_document(family: str, profile: dict, pins: list[dict]) -> dict:
    return {
        "schema": 1,
        "family": family,
        "profileIds": list(profile["profileIds"]),
        "sourceIdentity": profile["sourceIdentity"],
        "artifactInputId": profile["artifactInputId"],
        "transformVersion": profile["transformVersion"],
        "artifactSha256": profile["artifactSha256"],
        "dependencyReportSha256": profile["dependencyReportSha256"],
        "catalogFingerprint": profile["catalogFingerprint"],
        "inputPins": pins,
        "nativeSignature": profile["nativeSignature"],
    }


def _materialize_grafana(policy: dict, staged_inputs: dict, staging: Path) -> dict:
    family = "grafana"
    profile = policy["families"].get(family)
    if profile is None or profile["artifactKind"] != "standalone-native":
        _fail("FAMILY_NOT_SUPPORTED")
    item = next((item for item in profile["inputs"] if item["id"] == profile["artifactInputId"]), None)
    if item is None or item["kind"] != "python-wheel":
        _fail("RELEASE_INPUT_UNPINNED")
    wheel = Path(staged_inputs.get(item["id"], ""))
    if wheel.is_symlink() or not wheel.is_file():
        _fail("RELEASE_INPUT_UNAVAILABLE")
    _digest_download(wheel, item)

    extracted = Path(staging) / "grafana-native"
    extract_grafana_executable(wheel, extracted, expected_sha256=profile["artifactSha256"])
    signature = inspect_grafana_native(extracted)
    if signature != profile["nativeSignature"]:
        _fail("NATIVE_SIGNATURE_MISMATCH")
    report_digest = hashlib.sha256(_canonical(_GRAFANA_DEPENDENCY_REPORT)).hexdigest()
    if report_digest != profile["dependencyReportSha256"]:
        _fail("DEPENDENCY_REPORT_MISMATCH")

    pins = _input_pins(profile)
    document = _standalone_document(family, profile, pins)
    closure_digest = hashlib.sha256(_canonical(document)).hexdigest()
    parent = Path(policy["artifactParent"])
    destination = parent / closure_digest
    if destination.exists() or destination.is_symlink():
        _fail("ARTIFACT_DESTINATION_CONFLICT")
    build = parent / (".standalone-" + os.urandom(12).hex())
    build.mkdir(mode=0o700)
    published = False
    try:
        binary_dir = build / "bin"
        binary_dir.mkdir(mode=0o700)
        binary = binary_dir / "mcp-grafana"
        with extracted.open("rb") as source, binary.open("xb") as output:
            while block := source.read(1024 * 1024):
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        binary.chmod(0o500)
        metadata = build / "artifact.json"
        descriptor = os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o400)
        try:
            content = _canonical(document)
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    _fail("ARTIFACT_METADATA_WRITE_FAILED")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        binary_dir.chmod(0o500)
        build.chmod(0o500)
        from manage import publish
        publish(build, destination)
        published = True
        from migrate import sync_directory
        sync_directory(parent, require_private=True)
        _verify_standalone_native(destination, closure_digest, document, profile)
    except BaseException:
        if not published and build.exists() and not build.is_symlink():
            for current, _dirs, _files in os.walk(build):
                Path(current).chmod(0o700)
            shutil.rmtree(build)
        raise
    return {
        "artifactRoot": destination,
        "closureDigest": closure_digest,
        "artifactSha256": profile["artifactSha256"],
        "dependencyReportSha256": report_digest,
    }


def _materialize_langfuse(policy: dict, staged_inputs: dict, staging: Path) -> dict:
    family = "langfuse"
    profile = policy["families"].get(family)
    if profile is None or profile["artifactKind"] != "python-closure":
        _fail("FAMILY_NOT_SUPPORTED")
    materializer = _load_release_module("materialize-langfuse.py", "_portable_materialize_langfuse")
    wheel_lock = profile["lock"]
    lock_wheels = wheel_lock["wheels"]
    wheel_records = {item["id"]: item for item in profile["inputs"] if item["kind"] == "python-wheel"}
    expected_distributions = {}
    for wheel in lock_wheels:
        item = wheel_records.get(wheel["inputId"])
        if item is None or item["name"] != wheel["name"] or item["version"] != wheel["version"]:
            _fail("WHEEL_LOCK_INVALID")
        normalized = re.sub(r"[-_.]+", "-", item["name"]).lower()
        expected_distributions[normalized] = item["version"]
        wheel_path = Path(staged_inputs.get(item["id"], ""))
        if wheel_path.is_symlink() or not wheel_path.is_file():
            _fail("RELEASE_INPUT_UNAVAILABLE")
        _digest_download(wheel_path, item)
        extract_python_wheel(wheel_path, Path(staging) / "app/site-packages", name=item["name"], version=item["version"])

    if expected_distributions != materializer.DISTRIBUTIONS:
        _fail("PACKAGE_LOCK_MISMATCH")
    runtime_inputs = [item for item in profile["inputs"] if item["kind"] == "runtime-archive"]
    if len(runtime_inputs) != 1 or runtime_inputs[0]["id"] != profile["artifactInputId"]:
        _fail("RUNTIME_INPUT_UNPINNED")
    runtime_item = runtime_inputs[0]
    runtime_archive = Path(staged_inputs.get(runtime_item["id"], ""))
    if runtime_archive.is_symlink() or not runtime_archive.is_file():
        _fail("RELEASE_INPUT_UNAVAILABLE")
    _digest_download(runtime_archive, runtime_item)
    python_root = extract_python_runtime_archive(runtime_archive, Path(staging) / "python", version=runtime_item["version"])
    interpreter = python_root / "bin/python3.13"
    interpreter_sha = hashlib.sha256(interpreter.read_bytes()).hexdigest()
    if interpreter_sha != profile["artifactSha256"]:
        _fail("RUNTIME_EXECUTABLE_MISMATCH")

    wrapper = Path(__file__).with_name("langfuse-entry.py")
    try:
        wrapper_info = wrapper.lstat()
        if stat.S_ISLNK(wrapper_info.st_mode) or not stat.S_ISREG(wrapper_info.st_mode):
            _fail("WRAPPER_INPUT_INVALID")
        wrapper_digest = hashlib.sha256(wrapper.read_bytes()).hexdigest()
    except OSError as error:
        raise SafeError("WRAPPER_INPUT_INVALID") from error
    if wrapper_digest != _LANGFUSE_WRAPPER_SHA256:
        _fail("WRAPPER_INPUT_UNREVIEWED")

    app_root = Path(staging) / "app/site-packages"
    snapshot = materializer.inventory(
        app_root,
        python_root,
        expected_runtime={"pip": "26.0.1"},
        approved_hooks={},
        wrapper_source=wrapper,
        wrapper_sha256=_LANGFUSE_WRAPPER_SHA256,
    )
    if not snapshot.document.get("native") or snapshot.document.get("pythonVersion") != "3.13.12":
        _fail("LANGFUSE_RUNTIME_CLOSURE_INVALID")
    final = materializer.materialize(snapshot, Path(policy["artifactParent"]))
    verifier_script = Path(__file__).with_name("verify-langfuse-dependencies.py")
    try:
        result = subprocess.run(
            [str(final / "python/bin/python3.13"), "-I", "-S", "-B", str(verifier_script),
             "--artifact", str(final), "--expected-digest", snapshot.digest],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=Path(staging),
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            timeout=120,
        )
        if result.returncode != 0 or len(result.stdout) > 32 * 1024:
            _fail("DEPENDENCY_REPORT_MISMATCH")
        report = json.loads(result.stdout.decode("utf-8"))
    except SafeError:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError) as error:
        raise SafeError("DEPENDENCY_REPORT_MISMATCH") from error
    actual_report_digest = hashlib.sha256(materializer.canonical(report)).hexdigest()
    if (report.get("verdict") != "PASS" or report.get("artifactDigest") != snapshot.digest
            or actual_report_digest != profile["dependencyReportSha256"]):
        _fail("DEPENDENCY_REPORT_MISMATCH")
    materializer.verify(final, expected_digest=snapshot.digest)
    return {
        "artifactRoot": final,
        "closureDigest": snapshot.digest,
        "artifactSha256": interpreter_sha,
        "dependencyReportSha256": actual_report_digest,
    }


def _read_owned_artifact_file(path: Path, *, maximum: int, mode: int) -> bytes:
    descriptor = -1
    try:
        before_path = path.lstat()
        if (not stat.S_ISREG(before_path.st_mode) or before_path.st_uid != os.getuid()
                or stat.S_IMODE(before_path.st_mode) != mode or before_path.st_nlink != 1):
            _fail("ARTIFACT_FILE_UNTRUSTED")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino)
                or before.st_size > maximum):
            _fail("ARTIFACT_FILE_UNTRUSTED")
        chunks = []
        total = 0
        while block := os.read(descriptor, min(1024 * 1024, maximum - total + 1)):
            chunks.append(block)
            total += len(block)
            if total > maximum:
                _fail("ARTIFACT_FILE_TOO_LARGE")
        after = os.fstat(descriptor)
        current = path.lstat()
        stamp = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)
        if stamp(before) != stamp(after) or stamp(after) != stamp(current):
            _fail("ARTIFACT_FILE_CHANGED")
        return b"".join(chunks)
    except SafeError:
        raise
    except OSError as error:
        raise SafeError("ARTIFACT_FILE_UNTRUSTED") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_standalone_native(root: Path, digest: str, document: dict, profile: dict) -> None:
    root = Path(root)
    try:
        info = root.lstat()
        if (root.name != digest or root.resolve(strict=True) != root or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o500):
            _fail("ARTIFACT_ROOT_INVALID")
        expected_paths = {"artifact.json", "bin", "bin/mcp-grafana"}
        actual_paths = set()
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                path = Path(directory) / name
                member = path.relative_to(root).as_posix()
                member_info = path.lstat()
                if stat.S_ISLNK(member_info.st_mode):
                    _fail("ARTIFACT_TREE_INVALID")
                actual_paths.add(member)
        if actual_paths != expected_paths:
            _fail("ARTIFACT_TREE_INVALID")
        bin_info = (root / "bin").lstat()
        if (not stat.S_ISDIR(bin_info.st_mode) or bin_info.st_uid != os.getuid()
                or stat.S_IMODE(bin_info.st_mode) != 0o500):
            _fail("ARTIFACT_TREE_INVALID")
        metadata = _read_owned_artifact_file(root / "artifact.json", maximum=_MAX_POLICY_BYTES, mode=0o400)
        if metadata != _canonical(document) or hashlib.sha256(metadata).hexdigest() != digest:
            _fail("ARTIFACT_METADATA_MISMATCH")
        executable = root / "bin/mcp-grafana"
        binary = _read_owned_artifact_file(executable, maximum=128 * 1024 * 1024, mode=0o500)
        if hashlib.sha256(binary).hexdigest() != profile["artifactSha256"]:
            _fail("ARTIFACT_EXECUTABLE_MISMATCH")
        if inspect_grafana_native(executable) != profile["nativeSignature"]:
            _fail("NATIVE_SIGNATURE_MISMATCH")
        if hashlib.sha256(_canonical(_GRAFANA_DEPENDENCY_REPORT)).hexdigest() != profile["dependencyReportSha256"]:
            _fail("DEPENDENCY_REPORT_MISMATCH")
    except SafeError:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise SafeError("ARTIFACT_ROOT_INVALID") from error


_ARTIFACT_RECORD_KEYS = {
    "schema", "family", "profileId", "profileIds", "sourceIdentity", "artifactRoot", "closureDigest",
    "nativeCommand", "artifactSha256", "dependencyReportSha256", "catalogFingerprint", "catalog",
    "inputPins", "releaseInputsDigest", "artifactInputId", "transformVersion",
}


def _verify_existing_closure(family: str, root: Path, digest: str) -> dict:
    if family == "loki":
        module = _load_release_module("materialize-loki.py", "_portable_materialize_loki")
    elif family == "mysql":
        module = _load_release_module("mysql-runtime.py", "_portable_mysql_runtime")
    elif family == "langfuse":
        module = _load_release_module("materialize-langfuse.py", "_portable_materialize_langfuse")
    else:
        _fail("FAMILY_MATERIALIZER_UNAVAILABLE")
    verifier = module if family == "langfuse" else module.integrity
    return verifier.verify(root, expected_digest=digest)


def _langfuse_expected_distributions(profile: dict) -> dict:
    result = {}
    for wheel in profile["lock"]["wheels"]:
        name = re.sub(r"[-_.]+", "-", wheel["name"]).lower()
        if name in result:
            _fail("WHEEL_LOCK_INVALID")
        result[name] = wheel["version"]
    return result


def verify_artifact_admission(context, artifact: dict) -> None:
    """Rebind an installed artifact to current code-owned release pins and verify its tree."""
    if type(artifact) is not dict or set(artifact) != _ARTIFACT_RECORD_KEYS or artifact.get("schema") != 1:
        _fail("ARTIFACT_ADMISSION_INVALID")
    family = artifact.get("family")
    if not isinstance(family, str) or not _FAMILY.fullmatch(family):
        _fail("ARTIFACT_ADMISSION_INVALID")
    policy = load_release_policy(Path(context.release) / "release")
    profile = policy["families"].get(family)
    if profile is None:
        _fail("FAMILY_NOT_SUPPORTED")
    pins = _input_pins(profile)
    inputs_digest = hashlib.sha256(_canonical(pins)).hexdigest()
    for key, expected in (
            ("profileId", profile["profileId"]), ("profileIds", profile["profileIds"]),
            ("sourceIdentity", profile["sourceIdentity"]), ("artifactSha256", profile["artifactSha256"]),
            ("dependencyReportSha256", profile["dependencyReportSha256"]),
            ("catalogFingerprint", profile["catalogFingerprint"]), ("catalog", profile["catalog"]),
            ("inputPins", pins), ("releaseInputsDigest", inputs_digest),
            ("artifactInputId", profile["artifactInputId"]), ("transformVersion", profile["transformVersion"])):
        if _canonical(artifact.get(key)) != _canonical(expected):
            _fail("ARTIFACT_RELEASE_PIN_MISMATCH")

    root = Path(artifact["artifactRoot"])
    digest = artifact["closureDigest"]
    if (not root.is_absolute() or not _valid_digest(digest) or root.name != digest
            or root.parent != Path(context.artifacts) / family):
        _fail("ARTIFACT_ROOT_INVALID")
    try:
        parent = root.parent
        parent_info = parent.lstat()
        if (parent.is_symlink() or parent.resolve(strict=True) != parent or not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700
                or root.resolve(strict=True) != root):
            _fail("ARTIFACT_ROOT_INVALID")
    except (OSError, RuntimeError) as error:
        raise SafeError("ARTIFACT_ROOT_INVALID") from error

    expected_command = _expand_command(profile["nativeCommand"], root)
    if artifact["nativeCommand"] != expected_command:
        _fail("ARTIFACT_COMMAND_MISMATCH")

    if profile["artifactKind"] == "standalone-native":
        document = _standalone_document(family, profile, pins)
        expected_digest = hashlib.sha256(_canonical(document)).hexdigest()
        if digest != expected_digest:
            _fail("ARTIFACT_DIGEST_MISMATCH")
        _verify_standalone_native(root, digest, document, profile)
    elif profile["artifactKind"] == "node-closure":
        document = _verify_existing_closure(family, root, digest)
        if (document.get("dependencyReportDigest") != profile["dependencyReportSha256"]
                or hashlib.sha256(_canonical(document.get("dependencyReport"))).hexdigest() != profile["dependencyReportSha256"]):
            _fail("DEPENDENCY_REPORT_MISMATCH")
        executable = Path(expected_command[0])
        if not executable.is_relative_to(root):
            _fail("ARTIFACT_COMMAND_MISMATCH")
        mode = stat.S_IMODE(executable.lstat().st_mode)
        data = _read_owned_artifact_file(executable, maximum=256 * 1024 * 1024, mode=mode)
        if not mode & 0o111 or hashlib.sha256(data).hexdigest() != profile["artifactSha256"]:
            _fail("ARTIFACT_EXECUTABLE_MISMATCH")
    elif profile["artifactKind"] == "python-closure" and family == "langfuse":
        document = _verify_existing_closure(family, root, digest)
        if (document.get("pythonVersion") != "3.13.12"
                or document.get("distributions") != _langfuse_expected_distributions(profile)
                or document.get("runtimeDistributions") != {"pip": "26.0.1"}
                or profile["dependencyReportSha256"] != _LANGFUSE_DEPENDENCY_REPORT_SHA256):
            _fail("DEPENDENCY_REPORT_MISMATCH")
        entries = {item.get("path"): item for item in document.get("entries", []) if type(item) is dict}
        wrapper = entries.get("manager/langfuse-entry.py")
        if (wrapper is None or wrapper.get("kind") != "file"
                or wrapper.get("sha256") != _LANGFUSE_WRAPPER_SHA256):
            _fail("WRAPPER_INPUT_UNREVIEWED")
        executable = root / "python/bin/python3.13"
        mode = stat.S_IMODE(executable.lstat().st_mode)
        data = _read_owned_artifact_file(executable, maximum=256 * 1024 * 1024, mode=mode)
        if not mode & 0o111 or hashlib.sha256(data).hexdigest() != profile["artifactSha256"]:
            _fail("ARTIFACT_EXECUTABLE_MISMATCH")
    else:
        _fail("FAMILY_MATERIALIZER_UNAVAILABLE")


def _materialize_npm_family(policy: dict, family: str, staged_inputs: dict, staging: Path) -> dict:
    if family not in {"loki", "mysql"}:
        _fail("FAMILY_NOT_SUPPORTED")
    profile = policy["families"][family]
    source = Path(staging) / "source"
    app = source / "node_modules"
    runtime = source / "runtime"
    app.mkdir(mode=0o700, parents=True)
    runtime.mkdir(mode=0o700)
    expected_packages, _package_records = _package_lock(policy, family, staged_inputs, app)
    node, node_sha = _node_runtime(profile, staged_inputs, runtime)

    if family == "loki":
        materializer = _load_release_module("materialize-loki.py", "_portable_materialize_loki")
        snapshot = materializer.inventory(
            app, node,
            expected_tree=materializer.tree_pin(app),
            expected_packages=expected_packages,
            expected_node_sha256=profile["artifactSha256"],
        )
        report_digest = hashlib.sha256(materializer.integrity.canonical(snapshot.document["dependencyReport"])).hexdigest()
        if report_digest != profile["dependencyReportSha256"]:
            _fail("DEPENDENCY_REPORT_MISMATCH")
        final = materializer.materialize(snapshot, Path(policy["artifactParent"]))
        document = materializer.integrity.verify(final, expected_digest=snapshot.digest)
    else:
        mysql = _load_release_module("mysql-runtime.py", "_portable_mysql_runtime")
        wrapper = source / "mysql-entry.mjs"
        wrapper_data = Path(__file__).with_name("mysql-entry.mjs").read_bytes()
        if not wrapper_data or len(wrapper_data) > 1024 * 1024:
            _fail("WRAPPER_INPUT_INVALID")
        wrapper.write_bytes(wrapper_data)
        wrapper.chmod(0o400)
        # npm's reviewed esbuild install hook copies the platform binary into the
        # generic package's bin path. Reproduce that exact byte-only transform.
        native_binary = app / "@esbuild/darwin-arm64/bin/esbuild"
        destination = app / "esbuild/bin/esbuild"
        native_info = native_binary.lstat()
        native_data = native_binary.read_bytes()
        if (not stat.S_ISREG(native_info.st_mode) or native_info.st_nlink != 1
                or hashlib.sha256(native_data).hexdigest() != mysql.ESBUILD_SHA
                or destination.is_symlink() or not destination.is_file()):
            _fail("MYSQL_ESBUILD_INPUT_UNREVIEWED")
        fd = os.open(destination, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
        try:
            view = memoryview(native_data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    _fail("MYSQL_ESBUILD_COPY_FAILED")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        destination.chmod(0o755)

        entries, _origins, _identities = mysql.tree(app)
        report = mysql.dependency_report(app)
        report_digest = hashlib.sha256(mysql.integrity.canonical(report)).hexdigest()
        if report_digest != profile["dependencyReportSha256"]:
            _fail("DEPENDENCY_REPORT_MISMATCH")
        identities = {path: {"name": record["name"], "version": record["version"]}
                      for path, record in report["packages"].items()}
        if identities != expected_packages:
            _fail("PACKAGE_LOCK_MISMATCH")
        pins = {"entries": entries, "dependencyReport": report,
                "wrapperSha256": hashlib.sha256(wrapper_data).hexdigest()}
        snapshot = mysql.inventory(root=app, node=node, wrapper=wrapper, pins=pins)
        if snapshot.document["dependencyReportDigest"] != profile["dependencyReportSha256"]:
            _fail("DEPENDENCY_REPORT_MISMATCH")
        final = mysql.integrity.materialize(
            snapshot, Path(policy["artifactParent"]), recheck=mysql.unchanged,
            source_reader=mysql.source_read,
        )
        document = mysql.integrity.verify(final, expected_digest=snapshot.digest)

    if (not isinstance(document, dict) or document.get("dependencyReportDigest") != profile["dependencyReportSha256"]
            or hashlib.sha256(Path(final, "closure.json").read_bytes()).hexdigest() == ""):
        _fail("ARTIFACT_ADMISSION_INVALID")
    return {
        "artifactRoot": final,
        "closureDigest": snapshot.digest,
        "artifactSha256": node_sha,
        "dependencyReportSha256": report_digest,
    }


def _expand_command(command: list[str], artifact_root: Path) -> list[str]:
    result = []
    for argument in command:
        if not isinstance(argument, str) or "\0" in argument or "${" in argument.replace("${ARTIFACT_ROOT}", ""):
            _fail("RELEASE_COMMAND_INVALID")
        result.append(argument.replace("${ARTIFACT_ROOT}", str(artifact_root)))
    if not result or not Path(result[0]).is_absolute() or not Path(result[0]).is_relative_to(artifact_root):
        _fail("RELEASE_COMMAND_INVALID")
    return result


def _materialize_family(_policy: dict, _family: str, _inputs: dict, _workspace: Path) -> dict:
    """Dispatch only to complete family-specific, reviewed materializers."""
    kind = _policy["families"][_family]["artifactKind"]
    if kind == "node-closure":
        return _materialize_npm_family(_policy, _family, _inputs, _workspace)
    if kind == "python-closure" and _family == "langfuse":
        return _materialize_langfuse(_policy, _inputs, _workspace)
    if kind == "standalone-native" and _family == "grafana":
        return _materialize_grafana(_policy, _inputs, _workspace)
    _fail("FAMILY_MATERIALIZER_UNAVAILABLE")


def install_setup_skill(context) -> dict:
    from setup_skill_install import install_setup_skill as install
    return install(context)


def rollback_setup_skill(context) -> dict:
    from setup_skill_install import rollback_setup_skill as rollback
    return rollback(context)


def inspect_setup_skill(context) -> dict:
    from setup_skill_install import inspect_setup_skill as inspect
    return inspect(context)


def acquire_family(context, family: str, workspace: Path, *, downloader=None, materializer=None) -> dict:
    """Acquire and materialize a selected release family into private staging.

    ``downloader`` and ``materializer`` are narrow test seams. The production
    downloader is the cache-free HTTPS reader above; package managers never see
    client-provided package names or commands.
    """
    if not isinstance(family, str) or not _FAMILY.fullmatch(family):
        _fail("FAMILY_NOT_SUPPORTED")
    policy = load_release_policy(Path(context.release) / "release")
    family_policy = policy["families"].get(family)
    if family_policy is None:
        _fail("FAMILY_NOT_SUPPORTED")
    canonical_parent = Path(workspace)
    if canonical_parent.name != family or not _FAMILY.fullmatch(canonical_parent.name):
        _fail("ACQUISITION_WORKSPACE_UNTRUSTED")
    artifacts_root = _validate_workspace(canonical_parent.parent)
    created_parent = False
    try:
        canonical_parent.lstat()
    except FileNotFoundError:
        try:
            canonical_parent.mkdir(mode=0o700)
            created_parent = True
        except OSError as error:
            raise SafeError("ACQUISITION_WORKSPACE_UNTRUSTED") from error
    canonical_parent = _validate_workspace(canonical_parent)
    if canonical_parent.parent != artifacts_root:
        _fail("ACQUISITION_WORKSPACE_UNTRUSTED")
    staging = canonical_parent / (".acquire-" + os.urandom(12).hex())
    staging.mkdir(mode=0o700)
    fetch = downloader or _download_input
    build = materializer or _materialize_family
    staged_inputs = {}
    try:
        for item in family_policy["inputs"]:
            target = staging / "inputs" / item["_relative"]
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                fetch(item, target)
            except SafeError:
                raise
            except (OSError, urllib.error.URLError, TimeoutError) as error:
                raise SafeError("RELEASE_INPUT_UNAVAILABLE") from error
            info = target.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                _fail("RELEASE_INPUT_MISMATCH")
            _digest_download(target, item)
            staged_inputs[item["id"]] = target
        materialization_policy = {**policy, "artifactParent": canonical_parent}
        result = build(materialization_policy, family, staged_inputs, staging)
        if type(result) is not dict or set(result) != {"artifactRoot", "closureDigest", "artifactSha256", "dependencyReportSha256"}:
            _fail("ARTIFACT_ADMISSION_INVALID")
        artifact_root = Path(result["artifactRoot"]).resolve(strict=True)
        if (not artifact_root.is_relative_to(canonical_parent) or artifact_root.parent != canonical_parent
                or artifact_root.name != result["closureDigest"] or not artifact_root.is_dir()):
            _fail("ARTIFACT_ROOT_INVALID")
        for name in ("closureDigest", "artifactSha256", "dependencyReportSha256"):
            if not _valid_digest(result[name]):
                _fail("ARTIFACT_ADMISSION_INVALID")
        if result["dependencyReportSha256"] != family_policy["dependencyReportSha256"]:
            _fail("DEPENDENCY_REPORT_MISMATCH")
        if result["artifactSha256"] != family_policy["artifactSha256"]:
            _fail("ARTIFACT_EXECUTABLE_MISMATCH")
        artifact_input = next(item for item in family_policy["inputs"] if item["id"] == family_policy["artifactInputId"])
        input_pins = [{key: item[key] for key in ("id", "kind", "name", "version", "origin", "integrity", "sha256")}
                      for item in family_policy["inputs"]]
        inputs_digest = hashlib.sha256(_canonical(input_pins)).hexdigest()
        record = {
            "schema": 1,
            "family": family,
            "profileId": family_policy["profileId"],
            "profileIds": list(family_policy["profileIds"]),
            "sourceIdentity": family_policy["sourceIdentity"],
            "artifactRoot": str(artifact_root),
            "closureDigest": result["closureDigest"],
            "nativeCommand": _expand_command(family_policy["nativeCommand"], artifact_root),
            "artifactSha256": result["artifactSha256"],
            "dependencyReportSha256": result["dependencyReportSha256"],
            "catalogFingerprint": family_policy["catalogFingerprint"],
            "catalog": family_policy["catalog"],
            "inputPins": input_pins,
            "releaseInputsDigest": inputs_digest,
            "artifactInputId": artifact_input["id"],
            "transformVersion": family_policy["transformVersion"],
        }
        shutil.rmtree(staging)
        return record
    except BaseException:
        # Remove only this invocation's private acquisition staging. A final
        # digest directory remains available for the transaction's recovery
        # logic if admission failed after publication.
        if staging.exists() and not staging.is_symlink():
            shutil.rmtree(staging)
        if created_parent:
            try:
                canonical_parent.rmdir()
            except OSError:
                pass
        raise
    else:
        if staging.exists() and not staging.is_symlink():
            shutil.rmtree(staging)
