"""Coordinator fixture tests with local client data and isolated install roots."""

from contextlib import ExitStack, redirect_stdout
import json
import io
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import install
from install import InstallError, InstallOperationsImpl
from installation_context import installation_state_paths


PROJECT = Path(__file__).resolve().parents[1]
NODE = Path(shutil.which("node") or "/usr/bin/true").resolve()


class InstallCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="portable-installer-fixture-")
        self.configure_home(Path(self.temporary.name).resolve())

    def configure_home(self, home):
        self.home = Path(home).resolve()
        self.home.mkdir(parents=True, exist_ok=True)
        self.home.chmod(0o700)
        self.claude_config = self.home / ".claude.json"
        self.claude_config.write_text(json.dumps({"mcpServers": {
            "grafana-dev": {
                "command": "uvx",
                "args": ["mcp-grafana"],
                "env": {
                    "GRAFANA_URL": "https://synthetic.invalid",
                    "GRAFANA_SERVICE_ACCOUNT_TOKEN": "fixture-credential-only-in-test",
                },
            },
        }}))
        self.claude_config.chmod(0o600)
        claude_dir = self.home / ".claude"
        claude_dir.mkdir(mode=0o700)
        self.settings = claude_dir / "settings.json"
        self.settings.write_text("{}\n")
        self.settings.chmod(0o600)
        self.claude_version = self.home / ".local/share/claude/versions/2.1.0"
        self.claude_version.parent.mkdir(parents=True)
        self.claude_version.write_text("synthetic executable fixture")
        self.claude_version.chmod(0o700)
        # The coordinator is fully seam-injected here; never bind a real listener.
        self.port = 48163
        self.args = install.build_parser().parse_args([
            "--client", "claude", "--node", str(NODE), "--python", sys.executable,
            "--port", str(self.port),
        ])

    def tearDown(self):
        self.temporary.cleanup()

    def discover_plan(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch("install.Path.home", return_value=self.home))
            stack.enter_context(mock.patch("install._resolve_python_executable", return_value=Path(sys.executable).resolve()))
            stack.enter_context(mock.patch("installation_context.platform.system", return_value="Darwin"))
            stack.enter_context(mock.patch("installation_context._signature_valid", return_value=True))
            return install._plan(self.args)

    def test_both_selection_refuses_when_either_requested_client_is_missing(self):
        args = install.build_parser().parse_args([
            "--client", "both", "--node", str(NODE), "--python", sys.executable,
            "--port", str(self.port),
        ])
        with mock.patch("install.Path.home", return_value=self.home), \
             mock.patch("install._resolve_python_executable", return_value=Path(sys.executable).resolve()), \
             mock.patch("installation_context._signature_valid", return_value=True):
            with self.assertRaises(InstallError) as caught:
                install._plan(args)
        self.assertEqual(caught.exception.code, "REQUESTED_CLIENT_NOT_FOUND")

    def test_stateful_install_preflights_owner_socket_path_before_staging(self):
        from dataclasses import replace

        request = self.discover_plan()
        request = dict(request)
        request["selected"] = [replace(request["selected"][0], family="mysql")]
        operations = InstallOperationsImpl(
            request, accept_plan=request["planHash"], client_sources=__import__("client_sources"),
        )
        calls = []

        def reject_long_path(context, *, session):
            calls.append((context, session))
            raise RuntimeError("OWNER_SOCKET_PATH_TOO_LONG")

        with self.execution_environment(), \
             mock.patch("portable_engine._check_owner_socket_path", side_effect=reject_long_path), \
             mock.patch.object(InstallOperationsImpl, "_service", return_value=lambda context: False), \
             mock.patch("install.shutil.which", return_value="/usr/bin/npm"):
            with self.assertRaises(InstallError) as caught:
                operations.preflight()

        self.assertEqual(caught.exception.code, "OWNER_SOCKET_PATH_TOO_LONG")
        self.assertEqual(calls, [(request["context"], True)])
        self.assertFalse(request["context"].root.exists())

    def test_preflight_refuses_an_existing_unrecognized_install_root(self):
        request = self.discover_plan()
        root = request["context"].root
        root.mkdir(parents=True, mode=0o700)
        operations = InstallOperationsImpl(
            request, accept_plan=request["planHash"], client_sources=__import__("client_sources"),
        )

        with self.execution_environment(), \
             mock.patch("portable_engine._check_owner_socket_path", return_value=None), \
             mock.patch("install.shutil.which", return_value="/usr/bin/npm"):
            with self.assertRaises(InstallError) as caught:
                operations.preflight()

        self.assertEqual(caught.exception.code, "INSTALLATION_ROOT_CONFLICT")
        self.assertTrue(root.is_dir())

    def test_preflight_refuses_a_loopback_port_already_in_use(self):
        request = self.discover_plan()
        operations = InstallOperationsImpl(
            request, accept_plan=request["planHash"], client_sources=__import__("client_sources"),
        )

        class BusySocket:
            def settimeout(self, _timeout):
                return None

            def bind(self, _address):
                raise OSError("synthetic occupied port")

            def close(self):
                return None

        with self.execution_environment(), \
             mock.patch("install._module_function", return_value=lambda *_args, **_kwargs: None), \
             mock.patch("install.socket.socket", return_value=BusySocket()), \
             mock.patch("install.shutil.which", return_value="/usr/bin/npm"):
            with self.assertRaises(InstallError) as caught:
                operations.preflight()

        self.assertEqual(caught.exception.code, "PORT_IN_USE")

    def execution_environment(self):
        stack = ExitStack()
        stack.enter_context(mock.patch("install.platform.system", return_value="Darwin"))
        stack.enter_context(mock.patch("install.platform.machine", return_value="arm64"))
        stack.enter_context(mock.patch("install._runtime_version", return_value=(22, 12, 0)))
        stack.enter_context(mock.patch("install._runtime_architecture", return_value="arm64"))
        # This fixture exercises coordinator ordering without opening a port.
        stack.enter_context(mock.patch("install.socket.socket", return_value=mock.Mock()))
        return stack

    def adapters(self, *, fail_at=None, calls=None, register_status="PASS", patch_stage=True):
        """Patch only external setup seams; retain the actual coordinator and journal."""
        calls = calls if calls is not None else []
        service = {
            "install_command": lambda context: {"status": "INSTALLED", "path": "/synthetic/bin/mcp-manager"},
            "register_service": lambda context: (calls.append("register") or {"status": register_status}),
            "service_action": lambda context, action: (calls.append(action) or {"status": "PASS", "service": "RUNNING"}),
            "verify_service": lambda context: {"status": "PASS", "service": "PASS", "identity": "PASS"},
        }

        def service_lookup(_operations, name):
            return service[name]

        def stage_result(name):
            def operation(operations):
                if fail_at == name:
                    raise InstallError("SYNTHETIC_STAGE_FAILURE")
                if name == "publish_release":
                    from installation_context import write_context
                    write_context(operations.context)
                if name == "stage_release":
                    operations.candidate_context = operations.context
                    return operations._remember(name, {"status": "PASS", "releaseDigest": operations.source_digest})
                if name == "acquire_artifacts":
                    operations.artifacts = {"grafana": {}}
                    return operations._remember(name, {"status": "PASS", "artifactCount": 1, "familyCount": 1})
                return operations._remember(name, {"status": "PASS"})
            return operation

        def install_skill(operations):
            if fail_at == "install_skill":
                raise InstallError("SYNTHETIC_STAGE_FAILURE")
            return operations._remember("install_skill", {"status": "PASS"})

        def doctor(operations):
            checks = {
                "installed": {"status": "PASS"},
                "service": {"status": "PASS"},
                "catalog": {"status": "PASS", "routes": len(operations.selected)},
                "safeRead": {"status": "NOT_TESTED", "reason": "DOCTOR_SAFE_READS_NOT_REQUESTED"},
                "source": {"status": "PASS", "routes": len(operations.selected)},
                "ownership": {"status": "PASS"},
            }
            operations.doctor_result = checks
            return operations._remember("doctor", {"status": "PASS", "verifiedCount": 5})

        stack = ExitStack()
        stack.enter_context(mock.patch.object(InstallOperationsImpl, "_service", service_lookup))
        original_module_function = install._module_function

        def module_function(module, name):
            if (module, name) == ("artifact_install", "install_setup_skill"):
                return lambda context: {"status": "INSTALLED"}
            return original_module_function(module, name)

        stack.enter_context(mock.patch("install._module_function", side_effect=module_function))
        if patch_stage:
            stack.enter_context(mock.patch.object(InstallOperationsImpl, "stage_release", stage_result("stage_release")))
        stack.enter_context(mock.patch.object(InstallOperationsImpl, "acquire_artifacts", stage_result("acquire_artifacts")))
        stack.enter_context(mock.patch.object(InstallOperationsImpl, "prepare_runtime", stage_result("prepare_runtime")))
        stack.enter_context(mock.patch.object(InstallOperationsImpl, "verify_candidate", stage_result("verify_candidate")))
        stack.enter_context(mock.patch.object(InstallOperationsImpl, "publish_release", stage_result("publish_release")))
        stack.enter_context(mock.patch.object(InstallOperationsImpl, "install_skill", install_skill))
        stack.enter_context(mock.patch.object(InstallOperationsImpl, "doctor", doctor))
        return stack, service, calls

    def projection_adapters(self, *, fail=False, restored=None):
        import client_projection

        result = {"status": "PASS", "operation": "PROJECTED", "routes": 1}
        project = mock.Mock(side_effect=RuntimeError("fixture projection failure")) if fail else mock.Mock(return_value=result)
        verify = mock.Mock(return_value={"status": "PASS", "verified": True, "routes": 1})
        restore = mock.Mock(return_value=restored or [])
        rollback = mock.Mock(return_value={"status": "PASS", "operation": "NOTHING_TO_ROLL_BACK", "routes": 0})
        return (
            mock.patch.object(client_projection, "project_clients", project),
            mock.patch.object(client_projection, "verify_projections", verify),
            mock.patch.object(client_projection, "restored_sources", restore),
            mock.patch.object(client_projection, "rollback_clients", rollback),
            project,
            verify,
            restore,
            rollback,
        )

    def test_actual_transaction_commits_and_identical_cli_plan_reruns_without_staging(self):
        request = self.discover_plan()
        original_selected = request["selected"]
        service_calls = []
        stack, _, _ = self.adapters(calls=service_calls)
        projections = self.projection_adapters(restored=original_selected)
        try:
            for patcher in projections[:4]:
                stack.enter_context(patcher)
            cli_args = [
                "--client", "claude", "--node", str(NODE), "--python", sys.executable,
                "--port", str(self.port), "--accept-plan", request["planHash"],
            ]
            with mock.patch("install.Path.home", return_value=self.home), \
                 mock.patch("install._resolve_python_executable", return_value=Path(sys.executable).resolve()), \
                 mock.patch("installation_context._signature_valid", return_value=True), \
                 self.execution_environment(), redirect_stdout(io.StringIO()):
                self.assertEqual(install.main(cli_args), 0)
            self.assertEqual(service_calls, ["register", "start"])
            journal_path = installation_state_paths(request["context"]).journal
            journal_mtime = journal_path.stat().st_mtime_ns

            second_request = self.discover_plan()
            self.assertEqual(second_request["planHash"], request["planHash"])
            self.assertEqual(second_request["selected"], original_selected)
            with mock.patch.object(InstallOperationsImpl, "stage_release", side_effect=AssertionError("must not rebuild")), \
                 mock.patch("install.Path.home", return_value=self.home), \
                 mock.patch("install._resolve_python_executable", return_value=Path(sys.executable).resolve()), \
                 mock.patch("installation_context._signature_valid", return_value=True), \
                 self.execution_environment(), redirect_stdout(io.StringIO()):
                self.assertEqual(install.main(cli_args), 0)
            self.assertEqual(journal_path.stat().st_mtime_ns, journal_mtime)
            self.assertEqual(service_calls, ["register", "start"])
        finally:
            stack.close()

    def test_candidate_registration_and_projection_failures_stop_and_preserve_recovery_journal(self):
        cases = ("verify_candidate", "register_service", "project_clients")
        for failure in cases:
            with self.subTest(failure=failure):
                temporary = tempfile.TemporaryDirectory(prefix="portable-installer-failure-")
                self.addCleanup(temporary.cleanup)
                self.configure_home(Path(temporary.name).resolve())
                request = self.discover_plan()
                calls = []
                stack, service, _ = self.adapters(fail_at=failure, calls=calls,
                    register_status="FAIL" if failure == "register_service" else "PASS")
                projections = self.projection_adapters(fail=failure == "project_clients")
                try:
                    for patcher in projections[:4]:
                        stack.enter_context(patcher)
                    with self.execution_environment():
                        with self.assertRaises(InstallError) as caught:
                            install.run_install(
                                request["context"], request["selected"],
                                accept_plan=request["planHash"], projects=request["projects"],
                            )
                    self.assertEqual(caught.exception.code, "INSTALLATION_RECOVERY_REQUIRED")
                    journal_path = installation_state_paths(request["context"]).journal
                    self.assertTrue(journal_path.exists())
                    journal_text = journal_path.read_text()
                    self.assertNotIn("fixture-credential-only-in-test", journal_text)
                    if failure == "register_service":
                        self.assertEqual(calls, ["register"])
                        projections[4].assert_not_called()
                    if failure == "project_clients":
                        recovered = install.recover_install(request["context"])
                        self.assertEqual(recovered["status"], "NATIVE_ROUTES_RESTORED")
                finally:
                    stack.close()

    def test_build_failure_stops_coordinator_without_publishing_or_registering(self):
        request = self.discover_plan()
        calls = []
        stack, _, _ = self.adapters(calls=calls, patch_stage=False)
        try:
            with mock.patch("install._run_quiet", side_effect=InstallError("BUILD_COMMAND_FAILED")) as build, \
                 self.execution_environment():
                with self.assertRaises(InstallError) as caught:
                    install.run_install(
                        request["context"], request["selected"],
                        accept_plan=request["planHash"], projects=request["projects"],
                    )
            self.assertEqual(caught.exception.code, "INSTALLATION_RECOVERY_REQUIRED")
            self.assertEqual(build.call_count, 1)
            self.assertFalse((request["context"].root / "installation.json").exists())
            self.assertEqual(calls, [])
            journal = installation_state_paths(request["context"]).journal
            self.assertTrue(journal.is_file())
            self.assertNotIn("fixture-credential-only-in-test", journal.read_text())
        finally:
            stack.close()

    def test_stage_release_uses_private_export_and_build_outputs_without_running_npm(self):
        from installation_context import ClientPaths, InstallContext
        from export_source import source_digest
        from install import _project_version, _read_release_manifest

        root = self.home / "manager"
        root.mkdir(mode=0o700)
        source_hash = source_digest(PROJECT, portable_only=True)
        context = InstallContext(
            1, root, root / "app/releases" / (_project_version(PROJECT) + "-" + source_hash),
            root / "runtime", root / "artifacts", Path(sys.executable).resolve(), NODE,
            self.port, (ClientPaths("claude", self.claude_config, self.settings, (), (self.claude_version,)),),
        )
        request = {
            "context": context, "projectRoot": PROJECT, "sourceDigest": source_hash,
            "releaseVersion": _project_version(PROJECT), "selected": [], "projects": (),
            "planHash": "a" * 64,
        }
        operations = InstallOperationsImpl(request, accept_plan="a" * 64, client_sources=object())
        commands = []
        invocations = []

        def build(argv, *, cwd, **kwargs):
            commands.append(argv[1])
            invocations.append((argv, cwd, kwargs))
            if argv[1] == "ci":
                output = cwd / "node_modules/fixture"
                output.mkdir(parents=True)
                (output / "index.js").write_text("module.exports = true;\n")
            elif argv[1] == "run":
                output = cwd / "dist"
                output.mkdir()
                (output / "index.js").write_text("export {};\n")

        with mock.patch("install._run_quiet", side_effect=build):
            result = operations.stage_release()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(commands, ["ci", "run"])
        self.assertEqual(invocations[0][0][1:4], ["ci", "--ignore-scripts", "--no-audit"])
        self.assertEqual(invocations[1][0][1:4], ["run", "build", "--ignore-scripts"])
        self.assertNotEqual(invocations[0][2]["env"]["HOME"], str(self.home))
        manifest = _read_release_manifest(operations.program_root)
        self.assertEqual(manifest["sourceDigest"], source_hash)
        self.assertTrue((operations.program_root / "scripts/install.py").is_file())
        self.assertFalse((operations.program_root / "runtime/token").exists())


if __name__ == "__main__":
    unittest.main()
