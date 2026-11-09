import argparse
import builtins
from contextlib import ExitStack, redirect_stderr
import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

import mcp_manager


class McpManagerTests(unittest.TestCase):
    def setUp(self):
        self.context = SimpleNamespace(runtime=Path("/synthetic/runtime"))

    def args(self, command, *rest):
        return mcp_manager.build_parser().parse_args([command, *rest])

    def test_parser_exposes_operational_commands_and_scoped_mode(self):
        parser = mcp_manager.build_parser()
        for command in mcp_manager.COMMANDS:
            with self.subTest(command=command):
                extra = (["manager"] if command == "mode" else
                         ["--source", "/synthetic/release"] if command == "update" else [])
                args = parser.parse_args([command] + extra)
                self.assertEqual(args.command, command)
        safe = parser.parse_args(["doctor", "--safe-reads"])
        self.assertTrue(safe.safe_reads)
        self.assertEqual(parser.parse_args(["mode", "default"]).mode, "default")
        self.assertEqual(parser.parse_args(["status", "--installation", "/synthetic/installation.json"]).installation,
                         Path("/synthetic/installation.json"))
        self.assertTrue(parser.parse_args(["status", "--json"]).json_output)
        watch = parser.parse_args(["watch", "--json", "--interval", "3", "--count", "2"])
        self.assertEqual((watch.interval, watch.count), (3, 2))

    def test_status_dispatches_to_read_only_monitor(self):
        import monitoring_cli

        with patch.object(monitoring_cli, "discover_context", return_value=self.context) as discover, \
             patch.object(monitoring_cli, "run_monitor", return_value=0) as monitor:
            code = mcp_manager.main(["status", "--json"])

        self.assertEqual(code, 0)
        discover.assert_called_once()
        monitor.assert_called_once_with(self.context, command="status", json_output=True,
                                        interval=2.0, count=None)

    def test_relocate_is_refused_without_importing_migration_modules(self):
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name.startswith(("relocate_", "legacy_")):
                raise AssertionError("unsupported migration import")
            return original_import(name, *args, **kwargs)

        for arguments in (["relocate"], ["relocate", "--plan"], ["relocate", "--activate"],
                          ["relocate", "--recover-service"]):
            with self.subTest(arguments=arguments), \
                 patch("builtins.__import__", side_effect=guarded_import), \
                 redirect_stderr(io.StringIO()) as stderr:
                code = mcp_manager.main(arguments)
                self.assertEqual(code, mcp_manager.EXIT_REFUSED)
                self.assertEqual(stderr.getvalue(), "RELOCATION_UNSUPPORTED\n")

    def test_service_command_uses_only_the_portable_installation_context(self):
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name.startswith("legacy_"):
                raise AssertionError("unsupported adapter import")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=guarded_import), \
             patch.object(mcp_manager, "_load_context", return_value=self.context) as load, \
             patch.object(mcp_manager, "run_command", return_value={"status": "PASS"}) as run, \
             patch.object(mcp_manager, "_emit") as emit:
            code = mcp_manager.main(["start"])

        self.assertEqual(code, mcp_manager.EXIT_OK)
        load.assert_called_once()
        run.assert_called_once()
        emit.assert_called_once_with({"status": "PASS"})

    def test_rollback_restores_clients_then_reports_running_service_without_stopping(self):
        from client_projection import rollback_clients

        with patch("installation_context.read_install_key", return_value=b"x" * 32), \
             patch("client_projection.rollback_clients", return_value={
                 "status": "PASS", "operation": "ROLLED_BACK", "routes": 2}) as restore, \
             patch("service_install.service_action", return_value={
                 "status": "PASS", "action": "status", "service": "RUNNING"}) as service:
            result = mcp_manager.run_command(self.args("rollback"), self.context)

        self.assertEqual(result["clients"], {"operation": "ROLLED_BACK", "routes": 2})
        self.assertEqual(result["serviceCleanup"], {
            "status": "PENDING", "reason": "SERVICE_STOP_REQUIRED"})
        restore.assert_called_once()
        service.assert_called_once_with(self.context, "status")

    def test_default_mode_is_authenticated_offline_rollback_not_legacy_switch(self):
        with patch("installation_context.read_install_key", return_value=b"x" * 32), \
             patch("client_projection.rollback_clients", return_value={
                 "status": "PASS", "operation": "NOTHING_TO_ROLL_BACK", "routes": 0}), \
             patch("service_install.service_action", side_effect=RuntimeError("service unavailable")) as service:
            result = mcp_manager.run_command(self.args("mode", "default"), self.context)

        self.assertEqual(result["mode"], "default")
        self.assertEqual(result["clients"]["operation"], "NOTHING_TO_ROLL_BACK")
        self.assertEqual(result["serviceCleanup"], {
            "status": "NOT_TESTED", "reason": "SERVICE_STATUS_UNPROVEN"})
        service.assert_called_once_with(self.context, "status")

    def test_manager_mode_verifies_service_before_authenticated_existing_selection(self):
        import service_install
        import client_projection

        selected = [object()]
        routes = [{"route_id": "grafana-dev"}]
        with patch("service_install.verify_service", return_value={"status": "PASS"}) as verify_service, \
             patch.object(mcp_manager, "_runtime_selection", return_value=("token", b"k" * 32, routes, selected, {})) as runtime, \
             patch("client_projection.project_clients", return_value={
                 "status": "PASS", "operation": "ALREADY_PROJECTED"}) as project, \
             patch("client_projection.verify_projections", return_value={"status": "PASS"}) as verify:
            result = mcp_manager.run_command(self.args("mode", "manager"), self.context)

        self.assertEqual(result, {"status": "PASS", "mode": "manager",
                                  "operation": "ALREADY_PROJECTED", "routes": 1})
        verify_service.assert_called_once_with(self.context)
        runtime.assert_called_once_with(self.context)
        project.assert_called_once_with(self.context, selected, token="token", install_key=b"k" * 32)
        verify.assert_called_once_with(self.context, selected, token="token", install_key=b"k" * 32)

    def test_manager_mode_does_not_resolve_or_project_if_service_identity_fails(self):
        with patch("service_install.verify_service", return_value={
                "status": "FAIL", "reason": "LAUNCHAGENT_IDENTITY_UNPROVEN"}), \
             patch.object(mcp_manager, "_runtime_selection", side_effect=AssertionError("must not load")):
            with self.assertRaisesRegex(Exception, "LAUNCHAGENT_IDENTITY_UNPROVEN"):
                mcp_manager.run_command(self.args("mode", "manager"), self.context)

    def test_uninstall_restores_then_stops_then_removes_only_owned_hooks(self):
        import artifact_install
        import service_install

        events = []
        with patch("installation_context.read_install_key", return_value=b"x" * 32), \
             patch("client_projection.rollback_clients", side_effect=lambda *a, **k: events.append("restore") or {
                 "status": "PASS", "operation": "ROLLED_BACK", "routes": 1}), \
             patch("service_install.service_action", side_effect=lambda *a: events.append("stop") or {
                 "status": "PASS", "service": "STOPPED"}), \
             patch("artifact_install.rollback_setup_skill", side_effect=lambda *a: events.append("skill") or {
                 "status": "ROLLED_BACK"}, create=True), \
             patch("service_install.rollback_service_files", side_effect=lambda *a: events.append("hooks") or {
                 "status": "PASS", "files": ["command:removed", "plist:removed"]}):
            result = mcp_manager._uninstall(self.context)

        self.assertEqual(events, ["restore", "stop", "skill", "hooks"])
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["retained"], "INSTALLATION_DATA_RETAINED")

    def test_uninstall_does_not_touch_hooks_when_native_restore_conflicts(self):
        import service_install

        with patch("installation_context.read_install_key", return_value=b"x" * 32), \
             patch("client_projection.rollback_clients", side_effect=Exception("PROJECTION_CONFLICT")), \
             patch("service_install.service_action") as stop, \
             patch("service_install.rollback_service_files") as remove:
            with self.assertRaisesRegex(Exception, "CLIENT_ROLLBACK_FAILED"):
                mcp_manager._uninstall(self.context)
        stop.assert_not_called()
        remove.assert_not_called()

    def test_update_command_dispatches_only_explicit_absolute_source_to_update_flow(self):
        source = Path("/synthetic/unpacked-release")
        with patch.object(mcp_manager, "_update", return_value={
                "status": "PASS", "operation": "NO_OP"}) as update:
            result = mcp_manager.run_command(
                self.args("update", "--source", str(source)), self.context)
        self.assertEqual(result, {"status": "PASS", "operation": "NO_OP"})
        update.assert_called_once_with(self.context, source)

    def test_update_same_release_is_a_noop_without_resolution_or_service_actions(self):
        import install
        import install_transaction
        import service_install

        digest = "a" * 64
        release = Path("/synthetic/releases/0.1.0-" + digest)
        context = SimpleNamespace(root=Path("/synthetic/root"), runtime=Path("/synthetic/runtime"),
                                  release=release)
        class Lock:
            def __init__(self, *args, **kwargs):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        with patch("installation_context.installation_state_paths",
                   return_value=SimpleNamespace(lock=Path("/synthetic/lock"))), \
             patch("install_transaction.InstallationLock", Lock), \
             patch("service_install.update_journal_path", return_value=Path("/missing/update.json")), \
             patch.object(mcp_manager, "_update_source_info",
                          return_value=(Path("/synthetic/source"), digest, "0.1.0")), \
             patch("install._read_release_manifest", return_value={
                 "sourceDigest": digest, "version": "0.1.0"}), \
             patch.object(mcp_manager, "_runtime_selection", side_effect=AssertionError("no-op resolved sources")), \
             patch("service_install.service_action", side_effect=AssertionError("no-op touched service")):
            result = mcp_manager._update(context, Path("/synthetic/source"))

        self.assertEqual(result, {"status": "PASS", "operation": "NO_OP",
                                  "release": str(release)})

    def _fake_install_lock(self):
        class Lock:
            def __init__(self, *args, **kwargs):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        return Lock

    def _update_context(self, home):
        from installation_context import InstallContext
        root = home / "Library" / "Application Support" / "Personal MCP Manager"
        old_release = root / "app" / "releases" / ("0.1.0-" + "a" * 64)
        old_release.mkdir(parents=True, mode=0o700)
        return InstallContext(1, root, old_release, root / "runtime", root / "artifacts",
                             Path("/usr/bin/python3"), Path("/usr/bin/node"), 18765, ())

    def test_changed_update_prepares_and_verifies_candidate_before_quiescent_cutover(self):
        with tempfile.TemporaryDirectory(prefix="mcp-update-flow-") as temporary:
            home = Path(temporary).resolve()
            home.chmod(0o700)
            context = self._update_context(home)
            updated = replace(context, release=context.root / "app/releases" / ("0.2.0-" + "b" * 64))
            candidate_root = context.root / "transactions/candidate-fixture"
            candidate_runtime = candidate_root / "runtime"
            events = []

            def service_action(_context, action):
                events.append("service_" + action)
                if action == "status":
                    return {"status": "PASS", "service": "RUNNING"}
                if action == "stop":
                    return {"status": "PASS", "service": "STOPPED"}
                return {"status": "PASS", "service": "RUNNING"}

            runtime_selection = ("token", b"k" * 32, [], [], {})
            with ExitStack() as stack:
                stack.enter_context(patch("installation_context.installation_state_paths",
                    return_value=SimpleNamespace(lock=home / "lock")))
                stack.enter_context(patch("install_transaction.InstallationLock",
                                          self._fake_install_lock()))
                stack.enter_context(patch("service_install.update_journal_path",
                                          return_value=home / "missing-update.json"))
                stack.enter_context(patch.object(mcp_manager, "_update_source_info",
                    return_value=(home / "source", "b" * 64, "0.2.0")))
                stack.enter_context(patch("install._read_release_manifest", return_value={
                    "sourceDigest": "a" * 64, "version": "0.1.0"}))
                stack.enter_context(patch.object(mcp_manager, "_runtime_selection",
                    side_effect=[runtime_selection, runtime_selection]))
                stack.enter_context(patch("client_projection.verify_projections",
                                          return_value={"status": "PASS"}))
                stack.enter_context(patch("portable_engine._check_owner_socket_path",
                    side_effect=lambda *_args, **_kwargs: events.append("socket_path_checked")))
                stack.enter_context(patch.object(mcp_manager, "_publish_update_release",
                    side_effect=lambda *args: events.append("release_published") or updated))
                stack.enter_context(patch.object(mcp_manager, "_candidate_artifacts", return_value={}))
                stack.enter_context(patch("artifact_install.inspect_setup_skill",
                    return_value={"status": "ALREADY_ABSENT"}))
                stack.enter_context(patch("portable_engine.load_runtime",
                    side_effect=lambda *_args: events.append("existing_policy_compatibility")))
                stack.enter_context(patch.object(mcp_manager, "_candidate_runtime",
                    return_value=(candidate_root, candidate_runtime)))
                stack.enter_context(patch("portable_engine.prepare_runtime",
                    side_effect=lambda *_args: events.append("candidate_prepared")
                    or {"status": "PREPARED"}))
                stack.enter_context(patch("portable_engine.verify_candidate",
                    side_effect=lambda *_args: events.append("candidate_verified")
                    or {"status": "PASS", "cleanup": "PASS", "service": "PASS"}))
                stack.enter_context(patch.object(mcp_manager, "_remove_candidate_runtime",
                    side_effect=lambda *_args: events.append("candidate_removed")))
                stack.enter_context(patch("service_install.service_action", side_effect=service_action))
                stack.enter_context(patch("service_install.verify_service",
                    side_effect=lambda _ctx: events.append("service_verified") or {"status": "PASS"}))
                stack.enter_context(patch("service_install.begin_update",
                    side_effect=lambda *_args, **_kwargs: events.append("journal_prepared")
                    or {"status": "PASS"}))
                stack.enter_context(patch("installation_context.replace_context",
                    side_effect=lambda *_args: events.append("descriptor_published")))
                stack.enter_context(patch("service_install.advance_update",
                    side_effect=lambda _ctx, **kwargs: events.append(kwargs["state"])
                    or {"status": "PASS"}))
                stack.enter_context(patch("service_install.install_command",
                    side_effect=lambda *_args: events.append("command_published")
                    or {"status": "UPDATED"}))
                stack.enter_context(patch("service_install.register_service",
                    side_effect=lambda *_args: events.append("service_registered")
                    or {"status": "PASS"}))
                stack.enter_context(patch("service_install.complete_update",
                    side_effect=lambda *_args, **_kwargs: events.append("committed")
                    or {"status": "PASS", "release": str(updated.release)}))
                result = mcp_manager._update(context, home / "source")

        self.assertEqual(result, {"status": "PASS", "operation": "UPDATED",
                                  "release": str(updated.release), "routes": 0})
        self.assertLess(events.index("socket_path_checked"), events.index("release_published"))
        self.assertLess(events.index("candidate_verified"), events.index("service_stop"))
        self.assertLess(events.index("candidate_removed"), events.index("service_stop"))
        self.assertLess(events.index("journal_prepared"), events.index("descriptor_published"))
        self.assertEqual(events[-1], "committed")

    def test_changed_update_candidate_failure_never_stops_existing_service(self):
        import install
        import portable_engine
        import service_install
        import install_transaction

        with tempfile.TemporaryDirectory(prefix="mcp-update-refusal-") as temporary:
            home = Path(temporary).resolve()
            home.chmod(0o700)
            context = self._update_context(home)
            updated = replace(context, release=context.root / "app/releases" / ("0.2.0-" + "b" * 64))
            candidate_root = context.root / "transactions/candidate-fixture"
            selection = ("token", b"k" * 32, [], [], {})
            with patch("installation_context.installation_state_paths",
                       return_value=SimpleNamespace(lock=home / "lock")), \
                 patch("install_transaction.InstallationLock", self._fake_install_lock()), \
                 patch("service_install.update_journal_path", return_value=home / "missing-update.json"), \
                 patch.object(mcp_manager, "_update_source_info",
                              return_value=(home / "source", "b" * 64, "0.2.0")), \
                 patch("install._read_release_manifest", return_value={
                     "sourceDigest": "a" * 64, "version": "0.1.0"}), \
                 patch.object(mcp_manager, "_runtime_selection", return_value=selection), \
                 patch("client_projection.verify_projections", return_value={"status": "PASS"}), \
                 patch.object(mcp_manager, "_publish_update_release", return_value=updated), \
                 patch.object(mcp_manager, "_candidate_artifacts", return_value={}), \
                 patch("artifact_install.inspect_setup_skill", return_value={"status": "ALREADY_ABSENT"}), \
                 patch("portable_engine.load_runtime"), \
                 patch.object(mcp_manager, "_candidate_runtime",
                              return_value=(candidate_root, candidate_root / "runtime")), \
                 patch("portable_engine.prepare_runtime", return_value={"status": "PREPARED"}), \
                 patch("portable_engine.verify_candidate", return_value={"status": "FAIL"}), \
                 patch.object(mcp_manager, "_remove_candidate_runtime"), \
                 patch("service_install.service_action") as service_action:
                with self.assertRaisesRegex(Exception, "UPDATE_CANDIDATE_VERIFICATION_FAILED"):
                    mcp_manager._update(context, home / "source")

        service_action.assert_not_called()

    def test_update_skill_preflight_only_replaces_a_fully_owned_matching_receipt(self):
        import hashlib
        import artifact_install

        with tempfile.TemporaryDirectory(prefix="mcp-update-skill-") as temporary:
            release = Path(temporary).resolve() / "release"
            release.mkdir(mode=0o700)
            source = release / "skills/mcp-manager-setup/SKILL.md"
            source.parent.mkdir(parents=True)
            raw = b"new standalone skill\n"
            source.write_bytes(raw)
            context = SimpleNamespace(release=release)
            old_sha = "a" * 64
            with patch("artifact_install.inspect_setup_skill", return_value={
                    "status": "OWNED", "sha256": old_sha, "replaceable": True}):
                transition = mcp_manager._plan_update_skill(context, context)
            self.assertEqual(transition, (old_sha, hashlib.sha256(raw).hexdigest()))

            with patch("artifact_install.inspect_setup_skill", return_value={
                    "status": "OWNED", "sha256": old_sha, "replaceable": False}):
                with self.assertRaisesRegex(Exception, "UPDATE_SKILL_CONFLICT"):
                    mcp_manager._plan_update_skill(context, context)

    def _candidate_fixture(self, home):
        from installation_context import InstallContext
        from pilot import write_private
        home.mkdir(parents=True, mode=0o700, exist_ok=True)
        home.chmod(0o700)
        root = home
        runtime = root / "r"
        runtime.mkdir(mode=0o700)
        token = b"ab" * 32
        write_private(runtime / "token", token, exclusive=True)
        write_private(runtime / "client-projections.jsonl", b"[]\n", exclusive=True)
        context = InstallContext(1, root, root / "app/releases/fixture", runtime,
                                 root / "artifacts", Path("/usr/bin/python3"),
                                 Path("/usr/bin/node"), 18765, ())
        return context, bytes.fromhex(token.decode())

    def test_candidate_runtime_is_short_canonical_and_has_authenticated_cleanup_receipt(self):
        import json

        with tempfile.TemporaryDirectory(prefix="mcp-candidate-home-") as temporary:
            home = Path(temporary).resolve()
            home.chmod(0o700)
            context, key = self._candidate_fixture(home)
            candidate_root, candidate_runtime = mcp_manager._candidate_runtime(context, key)
            try:
                self.assertEqual(candidate_root.parent, Path(tempfile.gettempdir()).resolve(strict=True))
                self.assertLess(len(os.fsencode(candidate_runtime / "owner.sock")), 104)
                self.assertEqual((candidate_runtime / "token").read_bytes(), (context.runtime / "token").read_bytes())
                self.assertEqual((candidate_runtime / "client-projections.jsonl").read_bytes(), b"[]\n")
                payload, _raw = mcp_manager._read_candidate_record(context, key)
                self.assertEqual(payload["candidate_root"], str(candidate_root))
                self.assertEqual(payload["candidate_runtime"], str(candidate_runtime))
            finally:
                mcp_manager._remove_candidate_runtime(candidate_root, context, key)
                self.assertFalse((context.runtime / "update-candidate.json").exists())

    def test_candidate_cleanup_retains_authenticated_record_when_owner_socket_remains(self):
        with tempfile.TemporaryDirectory(prefix="mcp-candidate-leftover-") as temporary:
            home = Path(temporary).resolve()
            home.chmod(0o700)
            context, key = self._candidate_fixture(home)
            candidate_root, candidate_runtime = mcp_manager._candidate_runtime(context, key)
            socket_path = candidate_runtime / "owner.sock"
            socket_path.write_text("synthetic residue")
            socket_path.chmod(0o600)

            with self.assertRaisesRegex(Exception, "UPDATE_CANDIDATE_CLEANUP_UNPROVEN"):
                mcp_manager._remove_candidate_runtime(candidate_root, context, key)

            self.assertTrue(candidate_root.exists())
            self.assertTrue((context.runtime / "update-candidate.json").exists())
            socket_path.unlink()
            mcp_manager._remove_candidate_runtime(candidate_root, context, key)

    def test_candidate_cleanup_refuses_tampered_path_binding_and_preserves_receipt(self):
        with tempfile.TemporaryDirectory(prefix="mcp-candidate-tamper-") as temporary:
            home = Path(temporary).resolve()
            home.chmod(0o700)
            context, key = self._candidate_fixture(home)
            candidate_root, _candidate_runtime = mcp_manager._candidate_runtime(context, key)
            record_path = context.runtime / "update-candidate.json"
            original = record_path.read_bytes()
            envelope = json.loads(original)
            envelope["payload"]["candidate_runtime"] = str(candidate_root / "elsewhere")
            record_path.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":")))
            record_path.chmod(0o600)

            with self.assertRaisesRegex(Exception, "UPDATE_CANDIDATE_JOURNAL_INVALID"):
                mcp_manager._remove_candidate_runtime(candidate_root, context, key)

            self.assertTrue(candidate_root.exists())
            self.assertTrue(record_path.exists())
            record_path.write_bytes(original)
            record_path.chmod(0o600)
            mcp_manager._remove_candidate_runtime(candidate_root, context, key)

    def test_candidate_runtime_refuses_an_unusable_installed_owner_socket_path(self):
        from dataclasses import replace

        with tempfile.TemporaryDirectory(prefix="mcp-candidate-long-path-") as temporary:
            home = Path(temporary).resolve()
            home.chmod(0o700)
            context, key = self._candidate_fixture(home)
            long_runtime = Path("/") / ("x" * 112) / "runtime"
            with self.assertRaisesRegex(Exception, "OWNER_SOCKET_PATH_TOO_LONG"):
                mcp_manager._candidate_runtime(replace(context, runtime=long_runtime), key)

    def test_recover_handles_update_journal_under_lock_before_install_journal(self):
        import install
        import install_transaction
        import service_install

        with tempfile.TemporaryDirectory(prefix="mcp-recover-order-") as temporary:
            home = Path(temporary).resolve()
            context = SimpleNamespace(root=home, runtime=home / "runtime")
            update_journal = home / "runtime/update-transaction.json"
            update_journal.parent.mkdir()
            update_journal.write_text("authenticated by test double")
            events = []
            class Lock:
                def __init__(self, *args, **kwargs):
                    pass
                def __enter__(self):
                    events.append("lock")
                    return self
                def __exit__(self, *args):
                    events.append("unlock")
                    return False
            with patch("installation_context.installation_state_paths",
                       return_value=SimpleNamespace(lock=home / "lock")), \
                 patch("installation_context.read_install_key", return_value=b"k" * 32), \
                 patch("install_transaction.InstallationLock", Lock), \
                 patch("service_install.update_journal_path", return_value=update_journal), \
                 patch("service_install.recover_update", side_effect=lambda *_args, **_kwargs:
                       events.append("update") or {"operation": "ROLLED_BACK"}), \
                 patch("install.recover_install", side_effect=lambda *_args:
                       events.append("installation") or {"status": "NOTHING_TO_RECOVER"}), \
                 patch.object(mcp_manager, "_rollback", side_effect=AssertionError(
                     "recover must not switch clients to default mode")), \
                 patch.object(mcp_manager, "_service_cleanup_status", return_value={"status": "PASS"}):
                result = mcp_manager._recover(context)

        self.assertEqual(events, ["lock", "update", "unlock", "installation"])
        self.assertEqual(result["update"]["operation"], "ROLLED_BACK")
        self.assertNotIn("clients", result)

    def test_doctor_executes_safe_reads_once_and_returns_only_sanitized_checks(self):
        checks = {name: {"status": "NOT_TESTED", "reason": "SIGNED_CLIENT_REQUIRED"}
                  for name in ("installed", "service", "catalog", "safeRead", "source", "ownership")}
        details = {"status": "NOT_TESTED", "checks": checks}
        with patch("installation_verify.verify_installation_details", return_value=details) as verify:
            result = mcp_manager._doctor(self.context, safe_reads=True)
        verify.assert_called_once_with(self.context, safe_reads=True)
        self.assertEqual(set(result), {"status", "checks"})
        self.assertEqual(result["checks"]["safeRead"]["reason"], "SIGNED_CLIENT_REQUIRED")

    def test_doctor_summarizes_per_route_safe_read_records_without_returning_them(self):
        checks = {name: {"status": "PASS"}
                  for name in ("installed", "service", "catalog", "source", "ownership")}
        checks["safeRead"] = {"status": "NOT_TESTED", "routes": [
            {"status": "NOT_TESTED", "reason": "SIGNED_CLIENT_REQUIRED", "route_id": "loki-stg"}
        ]}
        with patch("installation_verify.verify_installation_details", return_value={
                "status": "NOT_TESTED", "checks": checks}) as verify:
            result = mcp_manager._doctor(self.context, safe_reads=True)
        verify.assert_called_once_with(self.context, safe_reads=True)
        self.assertEqual(result["checks"]["safeRead"], {"status": "NOT_TESTED", "routes": 1})

    def test_error_output_never_prints_untrusted_exception_text(self):
        import monitoring_cli

        with patch.object(monitoring_cli, "discover_context", side_effect=RuntimeError("secret-value")), \
             patch("sys.stderr") as stderr:
            code = mcp_manager.main(["status"])
        self.assertEqual(code, mcp_manager.EXIT_REFUSED)
        rendered = "".join(str(row.args[0]) for row in stderr.write.call_args_list)
        self.assertNotIn("secret-value", rendered)
        self.assertIn("MONITOR_UNAVAILABLE", rendered)


if __name__ == "__main__":
    unittest.main()
