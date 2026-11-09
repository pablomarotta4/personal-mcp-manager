"""Conditional setup-skill installation without adopting or deleting user work."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat

from pilot import SafeError, read_private, write_private
from source_inputs import protected_read
from service_install import _ensure_parent, _home, _safe_file


DOMAIN = b"personal-mcp-manager/setup-skills/v1\n"
MAX_SKILL_BYTES = 128 * 1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _paths(context):
    home = _home(context)
    kinds = [client.kind for client in context.clients]
    if not kinds or len(kinds) != len(set(kinds)) or set(kinds) - {"claude", "codex"}:
        raise SafeError("SETUP_SKILL_CLIENTS_INVALID")
    return [home / (".claude" if kind == "claude" else ".codex")
            / "skills/mcp-manager-setup/SKILL.md" for kind in sorted(kinds)]


def _parent(path, *, create=False):
    current = Path(path)
    while not current.exists() and not current.is_symlink():
        current = current.parent
    _ensure_parent(current, create=False)
    if create:
        _ensure_parent(Path(path), create=True)


def _digest(path):
    return hashlib.sha256(protected_read(path, MAX_SKILL_BYTES)).hexdigest()


def _receipt_path(context):
    return Path(context.runtime) / "setup-skills.json"


def _key(context):
    from installation_context import read_install_key
    return read_install_key(context)


def _save(context, payload, *, exclusive=False):
    envelope = {"payload": payload,
                "mac": hmac.new(_key(context), DOMAIN + _canonical(payload), hashlib.sha256).hexdigest()}
    raw = _canonical(envelope)
    write_private(_receipt_path(context), raw, exclusive=exclusive)
    if read_private(_receipt_path(context)) != raw:
        raise SafeError("SETUP_SKILL_READBACK_FAILED")


def _load(context):
    path = _receipt_path(context)
    if not path.exists() and not path.is_symlink():
        return None
    try:
        from owner_watch import strict_json
        envelope = strict_json(read_private(path))
        if type(envelope) is not dict or set(envelope) != {"payload", "mac"}:
            raise ValueError()
        payload = envelope["payload"]
        if type(payload) is not dict or set(payload) != {"version", "state", "sha256", "entries"}:
            raise ValueError()
        expected = hmac.new(_key(context), DOMAIN + _canonical(payload), hashlib.sha256).hexdigest()
        if not isinstance(envelope["mac"], str) or not hmac.compare_digest(expected, envelope["mac"]):
            raise ValueError()
        if (payload["version"] != 1 or payload["state"] not in {"PREPARED", "COMPLETE"}
                or not isinstance(payload["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", payload["sha256"])
                or type(payload["entries"]) is not list):
            raise ValueError()
        paths = _paths(context)
        if len(payload["entries"]) != len(paths):
            raise ValueError()
        for entry, target in zip(payload["entries"], paths):
            if (type(entry) is not dict or set(entry) != {"path", "created", "created_directory"}
                    or entry["path"] != str(target) or type(entry["created"]) is not bool
                    or type(entry["created_directory"]) is not bool):
                raise ValueError()
        return payload
    except Exception:
        raise SafeError("SETUP_SKILL_RECEIPT_UNTRUSTED") from None


def _check_targets(payload, *, allow_created_absent):
    for entry in payload["entries"]:
        path = Path(entry["path"])
        _parent(path.parent)
        info = _safe_file(path)
        if info is None:
            if not entry["created"] or not allow_created_absent:
                raise SafeError("SETUP_SKILL_CONFLICT")
        elif _digest(path) != payload["sha256"]:
            raise SafeError("SETUP_SKILL_CONFLICT")
        elif entry["created"] and stat.S_IMODE(info.st_mode) != 0o600:
            raise SafeError("SETUP_SKILL_CONFLICT")


def install_setup_skill(context):
    source = Path(context.release) / "skills/mcp-manager-setup/SKILL.md"
    raw = protected_read(source, MAX_SKILL_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    existing = _load(context)
    if existing is not None:
        if existing["sha256"] != digest:
            raise SafeError("SETUP_SKILL_UPDATE_REQUIRES_ROLLBACK")
        _check_targets(existing, allow_created_absent=existing["state"] == "PREPARED")
        if existing["state"] == "COMPLETE":
            return {"status": "ALREADY_INSTALLED", "clients": len(existing["entries"])}
        payload = existing
    else:
        entries = []
        for path in _paths(context):
            _parent(path.parent)
            info = _safe_file(path)
            if info is not None and _digest(path) != digest:
                raise SafeError("SETUP_SKILL_CONFLICT")
            if info is None and path.parent.exists() and next(path.parent.iterdir(), None) is not None:
                raise SafeError("SETUP_SKILL_DIRECTORY_CONFLICT")
            entries.append({"path": str(path), "created": info is None,
                            "created_directory": not path.parent.exists()})
        payload = {"version": 1, "state": "PREPARED", "sha256": digest, "entries": entries}
        _save(context, payload, exclusive=True)
    for entry in payload["entries"]:
        path = Path(entry["path"])
        _parent(path.parent, create=True)
        if _safe_file(path) is None:
            # Existing matching files are never replaced or claimed as owned.
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        if _digest(path) != digest:
            raise SafeError("SETUP_SKILL_READBACK_FAILED")
    _check_targets(payload, allow_created_absent=False)
    payload["state"] = "COMPLETE"
    _save(context, payload)
    return {"status": "INSTALLED", "clients": len(payload["entries"])}


def rollback_setup_skill(context):
    payload = _load(context)
    if payload is None:
        return {"status": "ALREADY_ABSENT"}
    # Validate every selected destination before removing any owned file.
    _check_targets(payload, allow_created_absent=True)
    for entry in payload["entries"]:
        path = Path(entry["path"])
        if entry["created"] and path.exists():
            if _digest(path) != payload["sha256"]:
                raise SafeError("SETUP_SKILL_CONFLICT")
            path.unlink()
        if entry["created_directory"] and path.parent.exists():
            try:
                path.parent.rmdir()
            except OSError:
                pass  # Preserve any later user-created directory contents.
    if _load(context) != payload:
        raise SafeError("SETUP_SKILL_RECEIPT_CHANGED")
    _receipt_path(context).unlink()
    return {"status": "ROLLED_BACK", "clients": len(payload["entries"])}


def inspect_setup_skill(context):
    """Verify receipt and targets without adopting files or changing anything.

    OWNED describes the authenticated receipt. Only replaceable=True means every
    target was actually created by this installation rather than pre-existing.
    """
    payload = _load(context)
    if payload is None:
        return {"status": "ALREADY_ABSENT"}
    if payload["state"] != "COMPLETE":
        raise SafeError("SETUP_SKILL_RECOVERY_REQUIRED")
    _check_targets(payload, allow_created_absent=False)
    return {"status": "OWNED", "sha256": payload["sha256"],
            "replaceable": all(entry["created"] for entry in payload["entries"])}
