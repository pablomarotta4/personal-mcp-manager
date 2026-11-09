"""Portable user-facing lifecycle commands for one Personal MCP Manager."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import tempfile
from dataclasses import replace

from pilot import SafeError


EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_RECOVERY_REQUIRED = 3
EXIT_ACTION_REQUIRED = 4
COMMANDS = ("status", "doctor", "start", "stop", "rollback", "uninstall",
            "recover", "update", "mode", "connections", "watch")
RECOVERY_CODES = {
    "PROJECTION_RECOVERY_REQUIRED", "PROJECTION_JOURNAL_INVALID",
    "RECOVERY_JOURNAL_UNTRUSTED", "RECOVERY_JOURNAL_INVALID",
    "RECOVERY_LOCKED", "INSTALLATION_RECOVERY_REQUIRED",
    "UPDATE_RECOVERY_REQUIRED", "UPDATE_JOURNAL_INVALID",
    "UPDATE_CANDIDATE_RECOVERY_REQUIRED", "UPDATE_CANDIDATE_JOURNAL_INVALID",
    "UPDATE_CANDIDATE_CLEANUP_UNPROVEN",
}
CANDIDATE_DOMAIN = b"personal-mcp-manager/update-candidate-runtime/v1\n"
CANDIDATE_NAME = re.compile(r"mc-[0-9]+-[0-9a-f]{12}\Z")
MAX_UNIX_SOCKET_PATH = 104


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-manager",
        description="Manage the local Personal MCP Manager installation.",
    )
    parser.add_argument("--installation", type=Path,
                        help="installation descriptor (defaults to this release's installation)")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        child = commands.add_parser(name)
        child.add_argument("--installation", type=Path, default=argparse.SUPPRESS,
                           help="installation descriptor")
        if name == "doctor":
            child.add_argument("--safe-reads", action="store_true",
                               help="run the fixed, read-only provider probes")
        elif name == "mode":
            child.add_argument("mode", choices=("manager", "default"),
                               help="project or restore the originally selected routes")
        elif name == "update":
            child.add_argument("--source", type=Path, required=True,
                               help="absolute unpacked release source tree; update never fetches a release")
        elif name in {"status", "connections", "watch"}:
            from monitoring_cli import add_monitor_arguments
            add_monitor_arguments(child, command=name)
    return parser


def _installation_path(args) -> Path:
    if args.installation is not None:
        return args.installation
    # The command lives at <root>/app/releases/<version>/scripts/mcp_manager.py.
    return Path(__file__).resolve().parents[4] / "installation.json"


def _load_context(args):
    from installation_context import load_context
    try:
        return load_context(_installation_path(args))
    except Exception as error:
        code = getattr(error, "code", None)
        if isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", code):
            raise SafeError(code) from None
        value = str(error)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", value):
            raise SafeError(value) from None
        raise SafeError("INSTALLATION_CONTEXT_INVALID") from None


def _public_check_map(value):
    names = ("installed", "service", "catalog", "safeRead", "source", "ownership")
    if type(value) is not dict or set(value) != set(names):
        raise SafeError("INSTALLATION_DOCTOR_RESULT_INVALID")
    result = {}
    statuses = {"PASS", "FAIL", "NEEDS_AUTH", "UNSUPPORTED", "NOT_TESTED"}
    for name in names:
        check = value[name]
        if type(check) is not dict or set(check) - {"status", "reason", "routes"}:
            raise SafeError("INSTALLATION_DOCTOR_RESULT_INVALID")
        if check.get("status") not in statuses:
            raise SafeError("INSTALLATION_DOCTOR_RESULT_INVALID")
        row = {"status": check["status"]}
        if "reason" in check:
            reason = check["reason"]
            if not isinstance(reason, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", reason):
                raise SafeError("INSTALLATION_DOCTOR_RESULT_INVALID")
            row["reason"] = reason
        if "routes" in check:
            routes = check["routes"]
            if type(routes) is list:
                if len(routes) > 64 or any(
                    type(route) is not dict
                    or set(route) - {"status", "reason", "route_id", "tool"}
                    or route.get("status") not in statuses
                    or ("reason" in route and (not isinstance(route["reason"], str)
                        or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", route["reason"])))
                    or ("route_id" in route and (not isinstance(route["route_id"], str)
                        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", route["route_id"])))
                    or ("tool" in route and (not isinstance(route["tool"], str)
                        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", route["tool"])))
                    for route in routes
                ):
                    raise SafeError("INSTALLATION_DOCTOR_RESULT_INVALID")
                row["routes"] = len(routes)
            elif type(routes) is int and 0 <= routes <= 64:
                row["routes"] = routes
            else:
                raise SafeError("INSTALLATION_DOCTOR_RESULT_INVALID")
        result[name] = row
    return result


def _doctor(context, *, safe_reads=False):
    from installation_verify import verify_installation_details
    details = verify_installation_details(context, safe_reads=safe_reads)
    checks = _public_check_map(details.get("checks"))
    overall = details.get("status")
    if overall not in {"PASS", "FAIL", "NEEDS_AUTH", "UNSUPPORTED", "NOT_TESTED"}:
        raise SafeError("INSTALLATION_DOCTOR_RESULT_INVALID")
    return {"status": overall, "checks": checks}


def _runtime_selection(context):
    """Reconstruct exactly the authenticated routes already admitted by install."""
    import portable_engine
    import client_sources
    from client_projection import resolve_native_source
    from installation_context import read_install_key
    from pilot import read_token

    token = read_token(Path(context.runtime) / "token")
    routes = portable_engine.read_routes(context, token)
    registry = portable_engine.read_registry(context, token)
    if {row["route_id"] for row in routes} != set(registry):
        raise SafeError("RUNTIME_ROUTE_MISMATCH")
    for route in routes:
        if type(registry[route["route_id"]]) is not dict or registry[route["route_id"]].get("route") != route:
            raise SafeError("RUNTIME_ROUTE_MISMATCH")
    install_key = read_install_key(context)
    selected = []
    for route in routes:
        candidate = portable_engine._resolve_candidate(context, route, token, resolve_native_source)
        # _resolve_candidate adds the reviewed profile_id for policy building;
        # projection accepts the strict source candidate and keeps that ID in
        # the authenticated route map generated from the same selection.
        selected.append(client_sources.SourceCandidate(
            candidate.ref, candidate.family, candidate.enabled, candidate.source,
            candidate.policy, candidate.blockers,
        ))
    return token, install_key, routes, selected, registry


def _mode_manager(context):
    import service_install
    from client_projection import project_clients, verify_projections

    service = service_install.verify_service(context)
    if service.get("status") != "PASS":
        raise SafeError(service.get("reason", "SERVICE_NOT_READY"))
    token, install_key, routes, selected, _ = _runtime_selection(context)
    projected = project_clients(context, selected, token=token, install_key=install_key)
    verified = verify_projections(context, selected, token=token, install_key=install_key)
    if projected.get("status") != "PASS" or verified.get("status") != "PASS":
        raise SafeError("PROJECTION_VERIFICATION_FAILED")
    return {"status": "PASS", "mode": "manager",
            "operation": projected["operation"], "routes": len(routes)}


def _service_cleanup_status(context):
    import service_install
    try:
        status = service_install.service_action(context, "status")
    except Exception as error:
        code = str(error)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", code):
            code = "SERVICE_STATUS_UNPROVEN"
        return {"status": "NOT_TESTED", "reason": code}
    if status.get("status") != "PASS":
        return {"status": "NOT_TESTED", "reason": "SERVICE_STATUS_UNPROVEN"}
    if status.get("service") == "STOPPED":
        return {"status": "PASS", "service": "STOPPED"}
    if status.get("service") == "RUNNING":
        return {"status": "PENDING", "reason": "SERVICE_STOP_REQUIRED"}
    return {"status": "NOT_TESTED", "reason": "SERVICE_STATUS_UNPROVEN"}


def _rollback(context, *, mode=False):
    from client_projection import rollback_clients
    from installation_context import read_install_key

    try:
        result = rollback_clients(context, install_key=read_install_key(context))
    except Exception:
        raise SafeError("CLIENT_ROLLBACK_FAILED") from None
    if result.get("status") != "PASS" or result.get("operation") not in {
            "ROLLED_BACK", "NOTHING_TO_ROLL_BACK"}:
        raise SafeError("CLIENT_ROLLBACK_FAILED")
    service = _service_cleanup_status(context)
    output = {"status": "PASS", "clients": {
        "operation": result["operation"], "routes": result.get("routes", 0)},
        "serviceCleanup": service}
    if mode:
        output["mode"] = "default"
    return output


def _uninstall(context):
    """Restore client routes, stop only the proven service, then remove owned hooks."""
    import service_install
    from client_projection import rollback_clients
    from installation_context import read_install_key

    try:
        restored = rollback_clients(context, install_key=read_install_key(context))
    except Exception:
        raise SafeError("CLIENT_ROLLBACK_FAILED") from None
    if restored.get("status") != "PASS" or restored.get("operation") not in {
            "ROLLED_BACK", "NOTHING_TO_ROLL_BACK"}:
        raise SafeError("CLIENT_ROLLBACK_FAILED")
    stopped = service_install.service_action(context, "stop")
    if stopped.get("status") != "PASS" or stopped.get("service") != "STOPPED":
        raise SafeError("SERVICE_STOP_UNPROVEN")
    try:
        import artifact_install
        remove_skill = getattr(artifact_install, "rollback_setup_skill", None)
        if callable(remove_skill):
            skill = remove_skill(context)
            if skill.get("status") not in {"ROLLED_BACK", "ALREADY_ABSENT"}:
                raise SafeError("SETUP_SKILL_CLEANUP_CONFLICT")
        else:
            skill = {"status": "NOT_TESTED", "reason": "SETUP_SKILL_CLEANUP_UNAVAILABLE"}
    except SafeError:
        raise
    except Exception:
        raise SafeError("SETUP_SKILL_CLEANUP_UNPROVEN") from None
    service_files = service_install.rollback_service_files(context)
    if service_files.get("status") != "PASS":
        raise SafeError("SERVICE_FILE_CLEANUP_UNPROVEN")
    # Release and runtime state may contain recovery evidence or files added
    # after install. Keep the support root until an explicit owner can inspect it.
    return {"status": "PARTIAL", "clients": {
                "operation": restored["operation"], "routes": restored.get("routes", 0)},
            "service": {"status": "PASS", "service": "STOPPED"},
            "serviceFiles": service_files, "setupSkill": skill,
            "retained": "INSTALLATION_DATA_RETAINED"}


def _recover(context):
    import service_install
    from installation_context import installation_state_paths, read_install_key
    from install_transaction import InstallationLock

    paths = installation_state_paths(context)
    try:
        with InstallationLock(paths.lock, blocking=False):
            candidate = _recover_candidate_runtime(context, read_install_key(context))
            update_journal = service_install.update_journal_path(context)
            if update_journal.exists() or update_journal.is_symlink():
                update = service_install.recover_update(
                    context, install_key=read_install_key(context))
            else:
                update = {"operation": "NOTHING_TO_RECOVER"}
    except Exception as error:
        code = str(error)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", code):
            code = "UPDATE_RECOVERY_FAILED"
        raise SafeError(code) from None
    try:
        from install import recover_install
        installation = recover_install(context)
    except Exception as error:
        code = str(error)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", code):
            code = "INSTALLATION_RECOVERY_FAILED"
        raise SafeError(code) from None
    return {"status": "PASS", "candidate": candidate, "update": update, "installation": installation,
            "serviceCleanup": _service_cleanup_status(context)}


def _update_source_info(source_path, context, install):
    source_path = Path(source_path)
    try:
        absolute = Path(os.path.abspath(os.fspath(source_path)))
        info = absolute.lstat()
        if (absolute != source_path or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or absolute.resolve(strict=True) != absolute or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise ValueError()
        if (absolute == context.root or absolute in context.root.parents
                or context.root in absolute.parents):
            raise ValueError()
        exporter = __import__("export_source")
        manifest = exporter.source_manifest(absolute, portable_only=True)
        digest = hashlib.sha256(install._canonical_json(manifest)).hexdigest()
        version = install._project_version(absolute)
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version):
            raise ValueError()
        return absolute, digest, version
    except Exception:
        raise SafeError("UPDATE_SOURCE_INVALID") from None


def _candidate_artifacts(context, routes, registry):
    import artifact_install
    artifacts = {}
    for route in routes:
        route_id = route["route_id"]
        record = registry.get(route_id)
        if type(record) is not dict or type(record.get("artifact")) is not dict:
            raise SafeError("RUNTIME_ROUTE_MISMATCH")
        artifact = record["artifact"]
        if artifact.get("family") != route["family"]:
            raise SafeError("RUNTIME_ROUTE_MISMATCH")
        current = artifacts.get(route["family"])
        if current is not None and current != artifact:
            raise SafeError("RUNTIME_ARTIFACT_CONFLICT")
        artifacts[route["family"]] = artifact
    try:
        for artifact in artifacts.values():
            artifact_install.verify_artifact_admission(context, artifact)
    except Exception:
        raise SafeError("UPDATE_ARTIFACT_INCOMPATIBLE") from None
    return artifacts


def _plan_update_skill(context, updated_context):
    import artifact_install
    existing = artifact_install.inspect_setup_skill(context)
    if existing.get("status") == "ALREADY_ABSENT":
        return None
    if existing.get("status") != "OWNED":
        raise SafeError("UPDATE_SKILL_STATE_INVALID")
    from source_inputs import protected_read
    raw = protected_read(
        Path(updated_context.release) / "skills/mcp-manager-setup/SKILL.md", 128 * 1024)
    new_digest = hashlib.sha256(raw).hexdigest()
    if new_digest == existing.get("sha256"):
        return None
    if existing.get("replaceable") is not True:
        raise SafeError("UPDATE_SKILL_CONFLICT")
    return existing["sha256"], new_digest


def _candidate_journal_path(context):
    return Path(context.runtime) / "update-candidate.json"


def _candidate_payload(context, root):
    return {"version": 1, "installation_root": str(context.root),
            "candidate_root": str(root), "candidate_runtime": str(Path(root) / "r")}


def _candidate_mac(payload, install_key):
    if not isinstance(install_key, bytes) or len(install_key) < 32:
        raise SafeError("UPDATE_CANDIDATE_KEY_INVALID")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hmac.new(install_key, CANDIDATE_DOMAIN + raw, hashlib.sha256).hexdigest()


def _read_candidate_record(context, install_key):
    from source_inputs import protected_read
    path = _candidate_journal_path(context)
    try:
        raw = protected_read(path, 16 * 1024, private=True,
                             error_code="UPDATE_CANDIDATE_JOURNAL_INVALID")
        from owner_watch import strict_json
        envelope = strict_json(raw.decode("utf-8", errors="strict"))
        if (type(envelope) is not dict or set(envelope) != {"payload", "mac"}
                or type(envelope["payload"]) is not dict
                or set(envelope["payload"]) != {
                    "version", "installation_root", "candidate_root", "candidate_runtime"}):
            raise ValueError()
        payload = envelope["payload"]
        if (type(payload["version"]) is not int or payload["version"] != 1
                or payload["installation_root"] != str(context.root)
                or not isinstance(envelope["mac"], str)
                or not hmac.compare_digest(envelope["mac"], _candidate_mac(payload, install_key))):
            raise ValueError()
        base = Path(tempfile.gettempdir()).resolve(strict=True)
        root = Path(payload["candidate_root"])
        runtime = Path(payload["candidate_runtime"])
        base_info = base.lstat()
        if (root.parent != base or not CANDIDATE_NAME.fullmatch(root.name)
                or not root.name.startswith(f"mc-{os.getuid()}-")
                or runtime != root / "r" or not stat.S_ISDIR(base_info.st_mode)
                or base.resolve(strict=True) != base or base_info.st_uid != os.getuid()
                or stat.S_IMODE(base_info.st_mode) != 0o700):
            raise ValueError()
        try:
            root_info = root.lstat()
        except FileNotFoundError:
            root_info = None
        if root_info is not None and (not stat.S_ISDIR(root_info.st_mode)
                or root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o700
                or root.resolve(strict=True) != root):
            raise ValueError()
        return payload, raw
    except SafeError:
        raise
    except Exception:
        raise SafeError("UPDATE_CANDIDATE_JOURNAL_INVALID") from None


def _remove_candidate_record(context, expected_raw):
    from source_inputs import protected_read
    path = _candidate_journal_path(context)
    try:
        current = protected_read(path, 16 * 1024, private=True,
                                 error_code="UPDATE_CANDIDATE_JOURNAL_INVALID")
        if current != expected_raw:
            raise SafeError("UPDATE_CANDIDATE_JOURNAL_CHANGED")
        path.unlink()
        import service_install
        service_install._sync_directory(Path(context.runtime))
    except SafeError:
        raise
    except Exception:
        raise SafeError("UPDATE_CANDIDATE_JOURNAL_CLEANUP_UNPROVEN") from None


def _candidate_runtime(context, install_key, *, session=True):
    import install
    from installation_context import read_install_key
    from pilot import read_private, write_private
    import portable_engine
    import source_inputs

    portable_engine._check_owner_socket_path(context, session=session)
    journal_path = _candidate_journal_path(context)
    try:
        if journal_path.exists() or journal_path.is_symlink():
            raise SafeError("UPDATE_CANDIDATE_RECOVERY_REQUIRED")
        base = Path(tempfile.gettempdir()).resolve(strict=True)
        base_info = base.lstat()
        if (not stat.S_ISDIR(base_info.st_mode) or base_info.st_uid != os.getuid()
                or stat.S_IMODE(base_info.st_mode) != 0o700 or base.resolve(strict=True) != base):
            raise SafeError("UPDATE_CANDIDATE_TEMP_ROOT_UNSAFE")
        root = base / f"mc-{os.getuid()}-{secrets.token_hex(6)}"
        payload = _candidate_payload(context, root)
        envelope = {"payload": payload, "mac": _candidate_mac(payload, install_key)}
        raw_record = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, allow_nan=False).encode("utf-8")
        write_private(journal_path, raw_record, exclusive=True)
        import service_install
        service_install._sync_directory(Path(context.runtime))
        created_root = False
        try:
            os.mkdir(root, 0o700)
            created_root = True
            info = root.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700 or root.resolve(strict=True) != root):
                raise SafeError("UPDATE_CANDIDATE_TEMP_ROOT_UNSAFE")
            runtime = root / "r"
            install._create_private_directory(runtime)
            portable_engine._check_owner_socket_path(replace(context, runtime=runtime), session=session)
            token = read_private(Path(context.runtime) / "token")
            write_private(runtime / "token", token, exclusive=True)
            journal = Path(context.runtime) / "client-projections.jsonl"
            projection_journal = source_inputs.protected_read(
                journal, 16 * 1048576, private=True, error_code="PROJECTION_JOURNAL_INVALID")
            write_private(runtime / "client-projections.jsonl", projection_journal, exclusive=True)
            service_install._sync_directory(runtime)
            if read_install_key(replace(context, runtime=runtime)) != install_key:
                raise SafeError("UPDATE_CANDIDATE_KEY_MISMATCH")
            return root, runtime
        except Exception:
            if created_root:
                _remove_candidate_runtime(root, context, install_key)
            else:
                _remove_candidate_record(context, raw_record)
            raise
    except SafeError:
        raise
    except Exception:
        raise SafeError("UPDATE_CANDIDATE_PREPARATION_FAILED") from None


def _remove_candidate_runtime(root, context, install_key):
    root = Path(root)
    try:
        payload, raw_record = _read_candidate_record(context, install_key)
        if payload["candidate_root"] != str(root):
            raise SafeError("UPDATE_CANDIDATE_JOURNAL_MISMATCH")
        runtime = Path(payload["candidate_runtime"])
        if root.exists() or root.is_symlink():
            info = root.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700 or root.resolve(strict=True) != root
                    or runtime.parent != root or runtime.name != "r"):
                raise SafeError("UPDATE_CANDIDATE_CLEANUP_UNPROVEN")
            import manage
            ownership = runtime / "ownership"
            if ownership.exists() or ownership.is_symlink():
                manage.ownership_empty(ownership)
            if any((runtime / name).exists() or (runtime / name).is_symlink()
                   for name in ("owner.sock", "manager-process.json")):
                raise SafeError("UPDATE_CANDIDATE_CLEANUP_UNPROVEN")
            parent = root.parent
            shutil.rmtree(root)
            fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            if root.exists() or root.is_symlink():
                raise SafeError("UPDATE_CANDIDATE_CLEANUP_UNPROVEN")
        _remove_candidate_record(context, raw_record)
    except SafeError:
        raise
    except Exception:
        raise SafeError("UPDATE_CANDIDATE_CLEANUP_UNPROVEN") from None


def _recover_candidate_runtime(context, install_key):
    path = _candidate_journal_path(context)
    if not path.exists() and not path.is_symlink():
        return {"status": "PASS", "operation": "NOTHING_TO_RECOVER"}
    payload, _ = _read_candidate_record(context, install_key)
    _remove_candidate_runtime(Path(payload["candidate_root"]), context, install_key)
    return {"status": "PASS", "operation": "CANDIDATE_CLEANED"}


def _publish_update_release(context, source, source_digest, version, selected):
    import install
    import client_sources
    request = {"context": context, "projectRoot": source, "sourceDigest": source_digest,
               "releaseVersion": version, "selected": list(selected), "projects": (),
               "planHash": source_digest}
    builder = install.InstallOperationsImpl(request, accept_plan=source_digest,
                                            client_sources=client_sources)
    try:
        result = builder.stage_release()
        if result.get("status") != "PASS" or builder.program_root is None or builder.stage_root is None:
            raise SafeError("UPDATE_STAGE_FAILED")
        target = Path(context.root) / "app" / "releases" / f"{version}-{source_digest}"
        install._create_private_directory(target.parent)
        if target.exists() or target.is_symlink():
            manifest = install._read_release_manifest(target)
            if manifest.get("sourceDigest") != source_digest or manifest.get("version") != version:
                raise SafeError("UPDATE_RELEASE_CONFLICT")
            shutil.rmtree(builder.stage_root)
        else:
            os.rename(builder.program_root, target)
            import service_install
            service_install._sync_directory(target.parent)
            shutil.rmtree(builder.stage_root)
        if not target.is_dir() or target.is_symlink() or target.resolve(strict=True) != target:
            raise SafeError("UPDATE_RELEASE_PUBLISH_FAILED")
        manifest = install._read_release_manifest(target)
        if manifest.get("sourceDigest") != source_digest or manifest.get("version") != version:
            raise SafeError("UPDATE_RELEASE_VERIFY_FAILED")
        return replace(context, release=target)
    except SafeError:
        if builder.stage_root is not None and builder.stage_root.exists():
            try:
                shutil.rmtree(builder.stage_root)
            except Exception:
                raise SafeError("UPDATE_STAGING_CLEANUP_UNPROVEN") from None
        raise
    except Exception:
        if builder.stage_root is not None and builder.stage_root.exists():
            try:
                shutil.rmtree(builder.stage_root)
            except Exception:
                raise SafeError("UPDATE_STAGING_CLEANUP_UNPROVEN") from None
        raise SafeError("UPDATE_STAGE_FAILED") from None


def _update(context, source_path):
    import install
    import install_transaction
    import portable_engine
    import service_install
    from client_projection import verify_projections
    from installation_context import installation_state_paths, read_install_key, replace_context

    paths = installation_state_paths(context)
    try:
        lock = install_transaction.InstallationLock(paths.lock, blocking=False)
        lock.__enter__()
    except Exception:
        raise SafeError("UPDATE_LOCKED") from None
    try:
        journal = service_install.update_journal_path(context)
        if journal.exists() or journal.is_symlink():
            raise SafeError("UPDATE_RECOVERY_REQUIRED")
        candidate_journal = _candidate_journal_path(context)
        if candidate_journal.exists() or candidate_journal.is_symlink():
            raise SafeError("UPDATE_RECOVERY_REQUIRED")
        source, source_digest, version = _update_source_info(source_path, context, install)
        current_manifest = install._read_release_manifest(context.release)
        if (current_manifest.get("sourceDigest") == source_digest
                and current_manifest.get("version") == version):
            if context.release.name != f"{version}-{source_digest}":
                raise SafeError("UPDATE_RELEASE_PATH_INVALID")
            return {"status": "PASS", "operation": "NO_OP", "release": str(context.release)}

        token, install_key, routes, selected, registry = _runtime_selection(context)
        session = any(route["family"] != "grafana" for route in routes)
        portable_engine._check_owner_socket_path(context, session=session)
        projection = verify_projections(context, selected, token=token, install_key=install_key)
        if projection.get("status") != "PASS":
            raise SafeError("UPDATE_PROJECTION_UNVERIFIED")
        updated_context = _publish_update_release(context, source, source_digest, version, selected)
        artifacts = _candidate_artifacts(updated_context, routes, registry)
        skill_update = _plan_update_skill(context, updated_context)

        # First prove the new code can reconstruct policies at the installed
        # paths, then prove a candidate in an isolated runtime with the same
        # authenticated token and native-source journal.
        try:
            portable_engine.load_runtime(updated_context)
            candidate_root, candidate_runtime = _candidate_runtime(
                context, install_key, session=session)
            candidate_context = replace(updated_context, runtime=candidate_runtime)
            prepared = portable_engine.prepare_runtime(candidate_context, selected, artifacts)
            if prepared.get("status") != "PREPARED":
                raise SafeError("UPDATE_CANDIDATE_PREPARATION_FAILED")
            checked = portable_engine.verify_candidate(candidate_context, selected)
            if (checked.get("status") != "PASS" or checked.get("cleanup") != "PASS"
                    or checked.get("service") != "PASS"):
                raise SafeError("UPDATE_CANDIDATE_VERIFICATION_FAILED")
            _remove_candidate_runtime(candidate_root, context, install_key)
        except SafeError:
            if "candidate_root" in locals() and candidate_root.exists():
                _remove_candidate_runtime(candidate_root, context, install_key)
            raise
        except Exception:
            if "candidate_root" in locals() and candidate_root.exists():
                try:
                    _remove_candidate_runtime(candidate_root, context, install_key)
                except SafeError:
                    raise
            raise SafeError("UPDATE_CANDIDATE_VERIFICATION_FAILED") from None

        # Re-resolve and re-authenticate source refs immediately before drain.
        token, fresh_key, fresh_routes, fresh_selected, fresh_registry = _runtime_selection(context)
        if (fresh_key != install_key or fresh_routes != routes
                or verify_projections(context, fresh_selected, token=token, install_key=fresh_key).get("status") != "PASS"):
            raise SafeError("UPDATE_SOURCE_CHANGED")
        service_status = service_install.service_action(context, "status")
        if service_status.get("status") != "PASS" or service_status.get("service") != "RUNNING":
            raise SafeError("UPDATE_SERVICE_NOT_RUNNING")
        if service_install.verify_service(context).get("status") != "PASS":
            raise SafeError("UPDATE_OLD_SERVICE_UNVERIFIED")
        stopped = service_install.service_action(context, "stop")
        if stopped.get("status") != "PASS" or stopped.get("service") != "STOPPED":
            raise SafeError("UPDATE_DRAIN_UNPROVEN")

        try:
            service_install.begin_update(context, updated_context, install_key=install_key,
                                         skill_update=skill_update)
        except Exception:
            try:
                service_install.service_action(context, "start")
                if service_install.verify_service(context).get("status") != "PASS":
                    raise SafeError("UPDATE_OLD_SERVICE_RESTART_UNPROVEN")
            except Exception:
                raise SafeError("UPDATE_RECOVERY_REQUIRED") from None
            raise SafeError("UPDATE_JOURNAL_CREATE_FAILED") from None
        try:
            replace_context(context, updated_context)
            service_install.advance_update(context, install_key=install_key, state="descriptor-published")
            command = service_install.install_command(updated_context)
            if command.get("status") not in {"UPDATED", "ALREADY_INSTALLED"}:
                raise SafeError("UPDATE_COMMAND_INSTALL_FAILED")
            service_install.advance_update(context, install_key=install_key, state="command-published")
            registered = service_install.register_service(updated_context)
            if registered.get("status") != "PASS":
                raise SafeError("UPDATE_SERVICE_REGISTER_FAILED")
            service_install.advance_update(context, install_key=install_key, state="service-registered")
            started = service_install.service_action(updated_context, "start")
            if started.get("status") != "PASS" or started.get("service") != "RUNNING":
                raise SafeError("UPDATE_SERVICE_START_FAILED")
            service_install.advance_update(context, install_key=install_key, state="service-started")
            verified = service_install.verify_service(updated_context)
            if verified.get("status") != "PASS":
                raise SafeError("UPDATE_SERVICE_VERIFY_FAILED")
            service_install.advance_update(context, install_key=install_key, state="verified")
            result = service_install.complete_update(updated_context, install_key=install_key)
            return {"status": "PASS", "operation": "UPDATED", "release": result["release"],
                    "routes": len(routes)}
        except Exception:
            try:
                recovered = service_install.recover_update(context, install_key=install_key)
            except Exception:
                raise SafeError("UPDATE_RECOVERY_REQUIRED") from None
            if recovered.get("operation") == "COMPLETED":
                return {"status": "PASS", "operation": "UPDATED",
                        "release": str(updated_context.release), "routes": len(routes)}
            if recovered.get("operation") != "ROLLED_BACK":
                raise SafeError("UPDATE_RECOVERY_REQUIRED")
            raise SafeError("UPDATE_FAILED_ROLLED_BACK") from None
    except SafeError:
        raise
    except Exception:
        raise SafeError("UPDATE_FAILED") from None
    finally:
        lock.__exit__(None, None, None)


def run_command(args, context):
    import service_install

    if args.command == "status":
        return service_install.service_action(context, "status")
    if args.command == "doctor":
        return _doctor(context, safe_reads=args.safe_reads)
    if args.command in {"start", "stop"}:
        return service_install.service_action(context, args.command)
    if args.command == "rollback":
        return _rollback(context)
    if args.command == "mode":
        return _mode_manager(context) if args.mode == "manager" else _rollback(context, mode=True)
    if args.command == "recover":
        return _recover(context)
    if args.command == "uninstall":
        return _uninstall(context)
    if args.command == "update":
        return _update(context, args.source)
    raise SafeError("COMMAND_UNSUPPORTED")


def _emit(value):
    try:
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    except (TypeError, ValueError):
        raise SafeError("COMMAND_RESULT_INVALID") from None


def main(argv=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "relocate":
        print("RELOCATION_UNSUPPORTED", file=sys.stderr)
        return EXIT_REFUSED
    parser = build_parser()
    args = parser.parse_args(arguments)
    if args.command in {"status", "connections", "watch"}:
        try:
            from monitoring_cli import discover_context, run_monitor
            context = discover_context(_installation_path(args))
            return run_monitor(context, command=args.command, json_output=args.json_output,
                               interval=getattr(args, "interval", 2.0), count=getattr(args, "count", None))
        except Exception:
            print("MONITOR_UNAVAILABLE", file=sys.stderr)
            return EXIT_REFUSED
    try:
        context = _load_context(args)
        result = run_command(args, context)
        _emit(result)
        if result.get("status") == "PARTIAL":
            return EXIT_ACTION_REQUIRED
        return EXIT_OK
    except Exception as error:
        code = str(error)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", code):
            candidate = getattr(error, "code", None)
            code = candidate if isinstance(candidate, str) and re.fullmatch(
                r"[A-Z][A-Z0-9_]{0,95}", candidate) else "COMMAND_FAILED"
        print(code, file=sys.stderr)
        if code in RECOVERY_CODES:
            return EXIT_RECOVERY_REQUIRED
        if "VERIFICATION" in code or "UNPROVEN" in code:
            return EXIT_ACTION_REQUIRED
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
