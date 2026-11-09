"""Authenticated, serialized phase execution for a fresh installation."""

from __future__ import annotations

from contextlib import AbstractContextManager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Protocol


INSTALL_ORDER = (
    "preflight",
    "inventory",
    "confirm_plan",
    "stage_release",
    "acquire_artifacts",
    "prepare_runtime",
    "verify_candidate",
    "publish_release",
    "install_command",
    "install_skill",
    "register_service",
    "verify_service",
    "project_clients",
    "verify_projections",
    "doctor",
    "commit_receipt",
)
MAX_JOURNAL_LINE = 16 * 1024
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PHASE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
SAFE_STATUS = frozenset({
    "ALREADY_INSTALLED",
    "COMPLETE",
    "FAIL",
    "NEEDS_AUTH",
    "NOT_TESTED",
    "PASS",
    "REFUSED",
    "UNSUPPORTED",
})
SAFE_RECEIPT_FIELDS = frozenset({
    "status",
    "reason",
    "selectedCount",
    "unsupportedCount",
    "installedCount",
    "verifiedCount",
    "familyCount",
    "artifactCount",
    "planHash",
    "releaseDigest",
})
BINDING_FIELDS = frozenset({"planHash", "releaseDigest", "selectionDigest", "projectionDigest"})


class InstallTransactionError(Exception):
    """A transaction could not be authenticated or safely continued."""

    def __init__(self, code: str):
        self.code = code if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code) else "INSTALL_TRANSACTION_FAILED"
        super().__init__(self.code)


class InstallOperations(Protocol):
    """Explicit stage operations. Implementations keep secret inputs in memory only."""

    def preflight(self) -> Mapping[str, object]: ...
    def inventory(self) -> Mapping[str, object]: ...
    def confirm_plan(self) -> Mapping[str, object]: ...
    def stage_release(self) -> Mapping[str, object]: ...
    def acquire_artifacts(self) -> Mapping[str, object]: ...
    def prepare_runtime(self) -> Mapping[str, object]: ...
    def verify_candidate(self) -> Mapping[str, object]: ...
    def publish_release(self) -> Mapping[str, object]: ...
    def install_command(self) -> Mapping[str, object]: ...
    def install_skill(self) -> Mapping[str, object]: ...
    def register_service(self) -> Mapping[str, object]: ...
    def verify_service(self) -> Mapping[str, object]: ...
    def project_clients(self) -> Mapping[str, object]: ...
    def verify_projections(self) -> Mapping[str, object]: ...
    def doctor(self) -> Mapping[str, object]: ...
    def commit_receipt(self) -> Mapping[str, object]: ...


def _canonical(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise InstallTransactionError("STAGE_RECORD_INVALID") from exc


def _validated_binding(value: Mapping[str, object] | None) -> dict[str, str] | None:
    if value is None:
        return None
    if (
        not isinstance(value, Mapping)
        or set(value) != BINDING_FIELDS
        or any(not isinstance(value[key], str) or not HEX64.fullmatch(value[key]) for key in BINDING_FIELDS)
    ):
        raise InstallTransactionError("JOURNAL_BINDING_INVALID")
    return {key: value[key] for key in sorted(BINDING_FIELDS)}


def _status_of(result: Mapping[str, object]) -> str | None:
    status = result.get("status")
    if status is None:
        return None
    if not isinstance(status, str) or status not in SAFE_STATUS:
        raise InstallTransactionError("STAGE_STATUS_INVALID")
    return status


def _public_stage_record(result: Mapping[str, object]) -> dict[str, object]:
    """Return only the receipt fields allowed to cross the installer boundary."""
    if not isinstance(result, Mapping):
        raise InstallTransactionError("STAGE_RECORD_INVALID")
    _canonical(result)
    public: dict[str, object] = {}
    for key in SAFE_RECEIPT_FIELDS & set(result):
        value = result[key]
        if key == "status":
            if not isinstance(value, str) or value not in SAFE_STATUS:
                raise InstallTransactionError("STAGE_STATUS_INVALID")
            public[key] = value
        elif key == "reason":
            if not isinstance(value, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value):
                raise InstallTransactionError("STAGE_REASON_INVALID")
            public[key] = value
        elif key.endswith("Count"):
            if type(value) is not int or value < 0 or value > 1_000_000:
                raise InstallTransactionError("STAGE_COUNT_INVALID")
            public[key] = value
        elif key in {"planHash", "releaseDigest"}:
            if not isinstance(value, str) or not HEX64.fullmatch(value):
                raise InstallTransactionError("STAGE_DIGEST_INVALID")
            public[key] = value
    return public


def _owner_private_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallTransactionError("JOURNAL_UNAVAILABLE") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise InstallTransactionError("JOURNAL_UNSAFE")
    return info


def _ensure_private_directory(path: Path) -> None:
    path = Path(os.path.abspath(os.fspath(path)))
    if path.exists() or path.is_symlink():
        try:
            info = path.lstat()
        except OSError as exc:
            raise InstallTransactionError("JOURNAL_DIRECTORY_UNSAFE") from exc
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or path.resolve(strict=True) != path:
            raise InstallTransactionError("JOURNAL_DIRECTORY_UNSAFE")
        return
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise InstallTransactionError("JOURNAL_DIRECTORY_CREATE_FAILED") from exc
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise InstallTransactionError("JOURNAL_DIRECTORY_UNSAFE")


class AuthenticatedJournal:
    """Append-only hash-chained journal whose records contain no operation payloads."""

    def __init__(self, path: Path, key: bytes | None = None, *, key_loader=None, binding=None):
        if key is None and not callable(key_loader):
            raise InstallTransactionError("JOURNAL_KEY_INVALID")
        if key is not None and (not isinstance(key, bytes) or len(key) < 32):
            raise InstallTransactionError("JOURNAL_KEY_INVALID")
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.key = key
        self.key_loader = key_loader
        self.binding = _validated_binding(binding)
        self.sequence = 0
        self.previous = "0" * 64
        self.armed = False

    def arm(self) -> None:
        if self.armed:
            return
        if self.key is None:
            try:
                self.key = self.key_loader()
            except Exception as exc:
                raise InstallTransactionError("JOURNAL_KEY_UNAVAILABLE") from exc
            if not isinstance(self.key, bytes) or len(self.key) < 32:
                raise InstallTransactionError("JOURNAL_KEY_INVALID")
        parent = self.path.parent
        if not parent.exists():
            _ensure_private_directory(parent)
        else:
            _ensure_private_directory(parent)
        if self.path.exists() or self.path.is_symlink():
            _owner_private_file(self.path)
            raise InstallTransactionError("INCOMPLETE_TRANSACTION_RECOVERY_REQUIRED")
        self.armed = True

    def append(self, event: str, phase: str, *, reason: str | None = None) -> dict[str, object]:
        if not self.armed:
            self.arm()
        if event not in {"started", "completed", "failed"} or not PHASE.fullmatch(phase):
            raise InstallTransactionError("JOURNAL_EVENT_INVALID")
        if reason is not None and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason):
            raise InstallTransactionError("JOURNAL_REASON_INVALID")
        payload: dict[str, object] = {
            "version": 1,
            "sequence": self.sequence,
            "event": event,
            "phase": phase,
            "previousHmac": self.previous,
        }
        if self.binding is not None:
            payload["binding"] = self.binding
        if reason is not None:
            payload["reason"] = reason
        signature = hmac.new(self.key, b"mcp-manager-install-journal-v1\0" + _canonical(payload), hashlib.sha256).hexdigest()
        record = dict(payload, recordHmac=signature)
        raw = _canonical(record) + b"\n"
        if len(raw) > MAX_JOURNAL_LINE:
            raise InstallTransactionError("JOURNAL_RECORD_TOO_LARGE")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise InstallTransactionError("JOURNAL_WRITE_FAILED") from exc
        try:
            _owner_private_file(self.path)
            written = os.write(fd, raw)
            if written != len(raw):
                raise InstallTransactionError("JOURNAL_WRITE_FAILED")
            os.fsync(fd)
        finally:
            os.close(fd)
        parent_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.sequence += 1
        self.previous = signature
        return record


def read_journal(path: Path, key: bytes) -> list[dict[str, object]]:
    if not isinstance(key, bytes) or len(key) < 32:
        raise InstallTransactionError("JOURNAL_KEY_INVALID")
    path = Path(os.path.abspath(os.fspath(path)))
    info = _owner_private_file(path)
    if info.st_size > MAX_JOURNAL_BYTES:
        raise InstallTransactionError("JOURNAL_TOO_LARGE")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise InstallTransactionError("JOURNAL_UNREADABLE") from exc
    try:
        before = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            raise InstallTransactionError("JOURNAL_REPLACED")
        raw = os.read(fd, MAX_JOURNAL_BYTES + 1)
        after = os.fstat(fd)
        if len(raw) > MAX_JOURNAL_BYTES or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InstallTransactionError("JOURNAL_CHANGED")
    finally:
        os.close(fd)
    records: list[dict[str, object]] = []
    previous = "0" * 64
    binding: dict[str, str] | None = None
    binding_initialized = False
    for sequence, line in enumerate(raw.splitlines()):
        if not line or len(line) > MAX_JOURNAL_LINE:
            raise InstallTransactionError("JOURNAL_RECORD_INVALID")
        try:
            value = json.loads(line.decode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise InstallTransactionError("JOURNAL_RECORD_INVALID") from exc
        if not isinstance(value, dict) or set(value) not in (
            {"version", "sequence", "event", "phase", "previousHmac", "recordHmac"},
            {"version", "sequence", "event", "phase", "previousHmac", "reason", "recordHmac"},
            {"version", "sequence", "event", "phase", "previousHmac", "binding", "recordHmac"},
            {"version", "sequence", "event", "phase", "previousHmac", "reason", "binding", "recordHmac"},
        ):
            raise InstallTransactionError("JOURNAL_RECORD_INVALID")
        if "binding" in value and value["binding"] is None:
            raise InstallTransactionError("JOURNAL_BINDING_INVALID")
        try:
            record_binding = _validated_binding(value.get("binding"))
        except InstallTransactionError:
            raise
        if not binding_initialized:
            binding = record_binding
            binding_initialized = True
        elif record_binding != binding:
            raise InstallTransactionError("JOURNAL_BINDING_CHANGED")
        signature = value.get("recordHmac")
        payload = dict(value)
        payload.pop("recordHmac", None)
        expected = hmac.new(key, b"mcp-manager-install-journal-v1\0" + _canonical(payload), hashlib.sha256).hexdigest()
        if (
            type(value.get("version")) is not int
            or value["version"] != 1
            or type(value.get("sequence")) is not int
            or value["sequence"] != sequence
            or value.get("event") not in {"started", "completed", "failed"}
            or not isinstance(value.get("phase"), str)
            or not PHASE.fullmatch(value["phase"])
            or value.get("previousHmac") != previous
            or not isinstance(signature, str)
            or not hmac.compare_digest(signature, expected)
        ):
            raise InstallTransactionError("JOURNAL_AUTHENTICATION_FAILED")
        if "reason" in value and (not isinstance(value["reason"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value["reason"])):
            raise InstallTransactionError("JOURNAL_RECORD_INVALID")
        previous = signature
        records.append(value)
    if raw and not raw.endswith(b"\n"):
        raise InstallTransactionError("JOURNAL_TRUNCATED")
    return records


class InstallationLock(AbstractContextManager["InstallationLock"]):
    """A private flock that prevents two local installers from mutating one root."""

    def __init__(self, path: Path, *, blocking: bool = True):
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.blocking = blocking
        self.fd: int | None = None

    def __enter__(self) -> "InstallationLock":
        parent = self.path.parent
        if not parent.is_dir() or parent.resolve(strict=True) != parent:
            raise InstallTransactionError("INSTALL_LOCK_DIRECTORY_UNSAFE")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(self.path, flags, 0o600)
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise InstallTransactionError("INSTALL_LOCK_UNSAFE")
            flock = fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB)
            try:
                fcntl.flock(self.fd, flock)
            except OSError as exc:
                raise InstallTransactionError("INSTALL_LOCKED") from exc
            return self
        except InstallTransactionError:
            self._close()
            raise
        except OSError as exc:
            self._close()
            raise InstallTransactionError("INSTALL_LOCK_UNAVAILABLE") from exc

    def _close(self) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self._close()
        return False


def run_transaction(operations: InstallOperations, journal: AuthenticatedJournal) -> dict[str, dict[str, object]]:
    """Run the exact reviewed stage order, stopping at the first failed operation."""
    results: dict[str, dict[str, object]] = {}
    for index, name in enumerate(INSTALL_ORDER):
        operation = getattr(operations, name, None)
        if not callable(operation):
            raise InstallTransactionError("INSTALL_OPERATION_MISSING")
        if index >= 3:
            journal.append("started", name)
        try:
            raw_result = operation()
            if not isinstance(raw_result, Mapping):
                raise InstallTransactionError("STAGE_RECORD_INVALID")
            record = _public_stage_record(raw_result)
            _status_of(record)
        except Exception as exc:
            if index >= 3:
                reason = getattr(exc, "code", None)
                safe_reason = reason if isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason) else "STAGE_FAILED"
                journal.append("failed", name, reason=safe_reason)
            raise
        results[name] = record
        if name == "confirm_plan" and results.get("preflight", {}).get("status") == "ALREADY_INSTALLED":
            doctor = getattr(operations, "doctor", None)
            if not callable(doctor):
                raise InstallTransactionError("INSTALL_OPERATION_MISSING")
            doctor_record = doctor()
            if not isinstance(doctor_record, Mapping):
                raise InstallTransactionError("STAGE_RECORD_INVALID")
            results["doctor"] = _public_stage_record(doctor_record)
            return results
        if index >= 3:
            journal.append("completed", name)
        if name == "confirm_plan" and journal.key is None:
            journal.arm()
        if record.get("status") in {"FAIL", "REFUSED", "UNSUPPORTED"} and name != "doctor":
            raise InstallTransactionError("INSTALL_STAGE_REFUSED")
    return results
