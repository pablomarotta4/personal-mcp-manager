import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]


class InstallEntryTests(unittest.TestCase):
    def test_cli_parser_accepts_only_supported_selection_options(self):
        from install import build_parser

        options = build_parser().parse_args([
            "--client", "both",
            "--source", "claude:global:mysql-primary-dev",
            "--project", "/synthetic/project with spaces",
            "--node", "/synthetic/node",
            "--python", "/synthetic/python",
            "--port", "19999",
            "--accept-plan", "a" * 64,
        ])
        self.assertEqual(options.client, "both")
        self.assertEqual(options.source, ["claude:global:mysql-primary-dev"])
        self.assertEqual(options.project, ["/synthetic/project with spaces"])
        self.assertEqual(options.port, 19999)

    def test_install_sh_locates_python_entrypoint_in_a_path_with_shell_metacharacters(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "O'Brien $(false) manager"
            (root / "scripts").mkdir(parents=True)
            wrapper = root / "install.sh"
            shutil.copyfile(PROJECT / "install.sh", wrapper)
            wrapper.chmod(0o755)
            capture = root / "argv.json"
            (root / "scripts/install.py").write_text(
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "Path(os.environ['CAPTURE_ARGV']).write_text(json.dumps(sys.argv[1:]))\n"
            )
            environment = dict(os.environ, MCP_MANAGER_PYTHON=sys.executable, CAPTURE_ARGV=str(capture))
            result = subprocess.run([str(wrapper), "--plan"], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(__import__("json").loads(capture.read_text()), ["--plan"])

    def test_install_sh_fails_cleanly_for_missing_explicit_python(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            wrapper = root / "install.sh"
            shutil.copyfile(PROJECT / "install.sh", wrapper)
            wrapper.chmod(0o755)
            (root / "scripts").mkdir()
            result = subprocess.run(
                [str(root / "install.sh"), "--plan"],
                env=dict(os.environ, MCP_MANAGER_PYTHON=str(root / "missing-python")),
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing-python", result.stderr)

    def test_incomplete_transaction_returns_recovery_exit_code(self):
        from install import InstallError, main

        request = {
            "context": object(),
            "selected": [object()],
            "projects": (),
            "planHash": "a" * 64,
            "plan": {},
        }
        with mock.patch("install._plan", return_value=request), mock.patch(
            "install.run_install", side_effect=InstallError("INSTALLATION_RECOVERY_REQUIRED")
        ):
            self.assertEqual(main(["--accept-plan", "a" * 64]), 3)

    def test_unsupported_required_verification_returns_failure_exit_code(self):
        from install import main

        request = {"context": object(), "selected": [object()], "projects": (), "planHash": "a" * 64, "plan": {}}
        receipt = {"status": "UNSUPPORTED", "planHash": "a" * 64, "selectedCount": 1, "checks": {"catalog": "UNSUPPORTED"}}
        with mock.patch("install._plan", return_value=request), mock.patch("install.run_install", return_value=receipt):
            self.assertEqual(main(["--accept-plan", "a" * 64]), 4)

    def test_discovery_refusal_reports_only_safe_error_code(self):
        from contextlib import redirect_stderr
        from io import StringIO
        from install import main

        output = StringIO()
        with mock.patch("install._plan", side_effect=RuntimeError("CODEX_PLUGIN_ROOT_MISSING")), redirect_stderr(output):
            result = main(["--plan"])
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue().strip(), "CODEX_PLUGIN_ROOT_MISSING")


class ArtifactRecordValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.workspace = self.root / "artifacts/mysql"
        self.workspace.mkdir(parents=True, mode=0o700)
        self.digest = "a" * 64
        self.artifact_root = self.workspace / self.digest
        self.artifact_root.mkdir(mode=0o700)
        executable = self.artifact_root / "bin/daemon"
        executable.parent.mkdir(mode=0o700)
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o700)
        self.record = {
            "schema": 1,
            "family": "mysql",
            "profileId": "mysql-reviewed",
            "profileIds": ["mysql-reviewed", "mysql-alternate"],
            "sourceIdentity": "mysql/npm/mysql-server",
            "artifactRoot": str(self.artifact_root),
            "closureDigest": self.digest,
            "nativeCommand": [str(executable), "--stdio"],
            "artifactSha256": "b" * 64,
            "dependencyReportSha256": "c" * 64,
            "catalogFingerprint": "d" * 64,
            "catalog": {"tools": ["query"]},
            "inputPins": [{
                "id": "mysql-server",
                "kind": "npm-tarball",
                "name": "@example/mysql",
                "version": "1.2.3",
                "origin": "https://registry.npmjs.org/example.tgz",
                "integrity": "sha512-" + "A" * 86 + "==",
                "sha256": "e" * 64,
            }],
            "releaseInputsDigest": "f" * 64,
            "artifactInputId": "mysql-server",
            "transformVersion": "1",
        }
        canonical_pins = __import__("json").dumps(
            self.record["inputPins"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        self.record["releaseInputsDigest"] = hashlib.sha256(canonical_pins).hexdigest()

    def tearDown(self):
        self.temporary.cleanup()

    def test_valid_admitted_artifact_record_is_accepted(self):
        from install import _validate_artifact_record

        self.assertEqual(
            _validate_artifact_record(self.record, family="mysql", workspace=self.workspace),
            self.record,
        )

    def test_sealed_readonly_artifact_root_is_accepted(self):
        from install import _validate_artifact_record

        self.artifact_root.chmod(0o500)
        self.assertEqual(
            _validate_artifact_record(self.record, family="mysql", workspace=self.workspace),
            self.record,
        )

    def test_reviewed_runtime_pin_may_have_no_npm_integrity_field(self):
        from install import _validate_artifact_record

        self.record["inputPins"] = [{
            "id": "node-runtime",
            "kind": "runtime-archive",
            "name": "node",
            "version": "25.3.0",
            "origin": "https://nodejs.org/dist/v25.3.0/node-v25.3.0-darwin-arm64.tar.xz",
            "integrity": None,
            "sha256": "e" * 64,
        }]
        self.record["artifactInputId"] = "node-runtime"
        canonical_pins = __import__("json").dumps(
            self.record["inputPins"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        self.record["releaseInputsDigest"] = hashlib.sha256(canonical_pins).hexdigest()

        self.assertEqual(
            _validate_artifact_record(self.record, family="mysql", workspace=self.workspace),
            self.record,
        )

    def test_malformed_profile_whitelist_is_refused_without_type_error(self):
        from install import InstallError, _validate_artifact_record

        self.record["profileIds"] = ["mysql-reviewed", []]
        with self.assertRaises(InstallError):
            _validate_artifact_record(self.record, family="mysql", workspace=self.workspace)

    def test_native_command_must_start_at_verified_artifact_root(self):
        from install import InstallError, _validate_artifact_record

        self.record["nativeCommand"] = ["/usr/bin/python3", "--stdio"]
        with self.assertRaises(InstallError):
            _validate_artifact_record(self.record, family="mysql", workspace=self.workspace)

    def test_artifact_input_must_be_in_unique_pinned_inputs(self):
        from install import InstallError, _validate_artifact_record

        self.record["artifactInputId"] = "unreviewed"
        with self.assertRaises(InstallError):
            _validate_artifact_record(self.record, family="mysql", workspace=self.workspace)

    def test_duplicate_artifact_input_ids_are_refused(self):
        from install import InstallError, _validate_artifact_record

        self.record["inputPins"].append(dict(self.record["inputPins"][0]))
        canonical_pins = __import__("json").dumps(
            self.record["inputPins"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        self.record["releaseInputsDigest"] = hashlib.sha256(canonical_pins).hexdigest()
        with self.assertRaises(InstallError):
            _validate_artifact_record(self.record, family="mysql", workspace=self.workspace)

    def test_reviewed_transitive_input_set_can_exceed_128_pins(self):
        from install import _validate_artifact_record

        template = self.record["inputPins"][0]
        self.record["inputPins"] = [
            {**template, "id": f"mysql-package-{index}", "name": f"package-{index}"}
            for index in range(129)
        ]
        self.record["artifactInputId"] = "mysql-package-0"
        canonical_pins = __import__("json").dumps(
            self.record["inputPins"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        self.record["releaseInputsDigest"] = hashlib.sha256(canonical_pins).hexdigest()

        self.assertEqual(
            _validate_artifact_record(self.record, family="mysql", workspace=self.workspace),
            self.record,
        )

    def test_unbounded_catalog_is_refused(self):
        from install import InstallError, _validate_artifact_record

        self.record["catalog"] = {"payload": "x" * (2 * 1024 * 1024 + 1)}
        with self.assertRaises(InstallError):
            _validate_artifact_record(self.record, family="mysql", workspace=self.workspace)


class RuntimeTrustTests(unittest.TestCase):
    def test_runtime_metadata_rejects_group_writable_ancestor(self):
        from install import _trusted_metadata_chain

        executable = SimpleNamespace(st_mode=__import__("stat").S_IFREG | 0o755, st_uid=os.getuid())
        safe_directory = SimpleNamespace(st_mode=__import__("stat").S_IFDIR | 0o755, st_uid=0)
        writable_directory = SimpleNamespace(st_mode=__import__("stat").S_IFDIR | 0o775, st_uid=os.getuid())
        self.assertTrue(_trusted_metadata_chain(executable, [safe_directory], uid=os.getuid()))
        self.assertFalse(_trusted_metadata_chain(executable, [safe_directory, writable_directory], uid=os.getuid()))

    def test_resolver_prefers_trusted_per_user_uv_python(self):
        from install import _resolve_python_executable

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            uv_bin = home / ".local/share/uv/python/cpython-3.13.12-macos-aarch64-none/bin"
            uv_bin.mkdir(parents=True)
            uv_python = uv_bin / "python3.13"
            uv_python.write_text("#!/bin/sh\nexit 0\n")
            uv_python.chmod(0o700)
            current = home / "system-python"
            current.write_text("#!/bin/sh\nexit 0\n")
            current.chmod(0o700)
            trusted = lambda path: Path(path) == uv_python
            with mock.patch("install._trusted_executable", side_effect=trusted), mock.patch(
                "install._runtime_version", return_value=(3, 13, 12)
            ):
                self.assertEqual(_resolve_python_executable(None, current=current, home=home), uv_python)

    def test_explicit_untrusted_python_is_refused(self):
        from install import InstallError, _resolve_python_executable

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            executable = home / "python"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o700)
            with mock.patch("install._trusted_executable", return_value=False), self.assertRaises(InstallError):
                _resolve_python_executable(executable, current=None, home=home)


class PrivateFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def test_private_json_writer_handles_short_writes(self):
        from install import _write_private_json

        path = self.root / "receipt.json"
        real_write = os.write

        def short_write(fd, data):
            return real_write(fd, data[: max(1, len(data) // 3)])

        with mock.patch("install.os.write", side_effect=short_write):
            _write_private_json(path, {"status": "PASS"})
        self.assertEqual(__import__("json").loads(path.read_text()), {"status": "PASS"})

    def test_private_json_writer_refuses_symlinked_parent(self):
        from install import InstallError, _write_private_json

        target = self.root / "target"
        target.mkdir(mode=0o700)
        link = self.root / "linked"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(InstallError):
            _write_private_json(link / "receipt.json", {"status": "PASS"})

    def test_runtime_architecture_probe_refuses_rosetta_or_wrong_arch(self):
        from install import InstallError, _runtime_architecture

        completed = SimpleNamespace(returncode=0, stdout="x86_64\n")
        with mock.patch("install.subprocess.run", return_value=completed), self.assertRaises(InstallError):
            _runtime_architecture(Path("/trusted/node"), "node")


class ServiceStartOrderingTests(unittest.TestCase):
    def test_register_stage_starts_only_after_successful_registration(self):
        from install import InstallOperationsImpl

        calls = []
        service = SimpleNamespace(
            register_service=lambda context: (calls.append("register") or {"status": "PASS"}),
            service_action=lambda context, action: (calls.append(action) or {"status": "PASS", "service": "RUNNING"}),
        )
        operations = object.__new__(InstallOperationsImpl)
        operations.context = object()
        operations.stage_records = {}
        with mock.patch.object(InstallOperationsImpl, "_service", side_effect=lambda name: getattr(service, name)):
            result = operations.register_service()
        self.assertEqual(calls, ["register", "start"])
        self.assertEqual(result["status"], "PASS")

    def test_failed_registration_never_starts_service(self):
        from install import InstallError, InstallOperationsImpl

        calls = []
        service = SimpleNamespace(
            register_service=lambda context: (calls.append("register") or {"status": "FAIL"}),
            service_action=lambda context, action: (calls.append(action) or {"status": "PASS", "service": "RUNNING"}),
        )
        operations = object.__new__(InstallOperationsImpl)
        operations.context = object()
        operations.stage_records = {}
        with mock.patch.object(InstallOperationsImpl, "_service", side_effect=lambda name: getattr(service, name)), self.assertRaises(InstallError):
            operations.register_service()
        self.assertEqual(calls, ["register"])


class InstallRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "manager"
        self.release_digest = "a" * 64
        self.context = SimpleNamespace(
            root=self.root,
            runtime=self.root / "runtime",
            release=self.root / "app/releases" / ("1.0.0-" + self.release_digest),
        )
        self.binding = {
            "planHash": "b" * 64,
            "releaseDigest": self.release_digest,
            "selectionDigest": "c" * 64,
            "projectionDigest": "d" * 64,
        }
        from installation_context import installation_state_paths, load_or_create_install_key

        self.key = load_or_create_install_key(self.context)
        self.paths = installation_state_paths(self.context)

    def tearDown(self):
        self.temporary.cleanup()

    def test_interrupted_client_projection_uses_conditional_rollback(self):
        from install import recover_install
        from install_transaction import INSTALL_ORDER, AuthenticatedJournal

        journal = AuthenticatedJournal(self.paths.journal, self.key, binding=self.binding)
        for phase in INSTALL_ORDER[3:INSTALL_ORDER.index("project_clients")]:
            journal.append("started", phase)
            journal.append("completed", phase)
        journal.append("started", "project_clients")
        calls = []
        rollback = lambda context, **kwargs: (calls.append((context, kwargs)) or {"status": "PASS", "operation": "ROLLED_BACK", "routes": 2})
        with mock.patch("install._module_function", return_value=rollback):
            result = recover_install(self.context)
        self.assertEqual(result, {"status": "NATIVE_ROUTES_RESTORED", "serviceCleanup": "PENDING"})
        self.assertEqual(calls[0][0], self.context)
        self.assertEqual(calls[0][1]["install_key"], self.key)

    def test_failure_before_projection_preserves_evidence_for_review(self):
        from install import recover_install
        from install_transaction import AuthenticatedJournal

        journal = AuthenticatedJournal(self.paths.journal, self.key, binding=self.binding)
        journal.append("started", "stage_release")
        journal.append("failed", "stage_release", reason="BUILD_COMMAND_FAILED")
        with mock.patch("install._module_function") as component:
            result = recover_install(self.context)
        component.assert_not_called()
        self.assertEqual(result["status"], "RECOVERY_REQUIRES_REVIEW")

    def test_recovery_uses_same_nonblocking_install_lock(self):
        from install import InstallError, recover_install
        from install_transaction import InstallationLock

        with InstallationLock(self.paths.lock):
            with self.assertRaises(InstallError) as caught:
                recover_install(self.context)
        self.assertEqual(caught.exception.code, "RECOVERY_LOCKED")


class InstallationDoctorTests(unittest.TestCase):
    def operations(self):
        from install import InstallOperationsImpl

        operations = object.__new__(InstallOperationsImpl)
        operations.context = object()
        operations.stage_records = {}
        operations.doctor_result = None
        return operations

    def test_doctor_accepts_redacted_check_records(self):
        from install import InstallOperationsImpl

        checks = {
            "installed": {"status": "PASS"},
            "service": {"status": "PASS"},
            "catalog": {"status": "PASS", "routes": 2},
            "safeRead": {"status": "NOT_TESTED", "reason": "DOCTOR_SAFE_READS_NOT_REQUESTED"},
            "source": {"status": "PASS", "routes": 2},
            "ownership": {"status": "PASS"},
        }
        with mock.patch("install._module_function", return_value=lambda context, **kwargs: checks):
            operations = self.operations()
            result = operations.doctor()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(operations.doctor_result, checks)

    def test_doctor_refuses_unrecognized_reason_fields(self):
        from install import InstallError

        checks = {
            name: {"status": "PASS"} for name in
            ("installed", "service", "catalog", "safeRead", "source", "ownership")
        }
        checks["safeRead"] = {"status": "NOT_TESTED", "reason": "synthetic-secret"}
        with mock.patch("install._module_function", return_value=lambda context, **kwargs: checks):
            with self.assertRaises(InstallError):
                self.operations().doctor()


class RestoredSourceInventoryTests(unittest.TestCase):
    def test_matching_install_uses_authenticated_restored_source_inventory(self):
        from install import _inventory_sources
        from installation_context import ClientPaths, InstallContext, load_or_create_install_key, write_context

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            root = home / "manager"
            context = InstallContext(
                1, root, root / "app/releases" / ("1.0.0-" + "a" * 64), root / "runtime",
                root / "artifacts", Path("/usr/bin/python3"), Path("/usr/bin/node"), 18765,
                (ClientPaths("claude", home / ".claude.json", None, (), ()),),
            )
            write_context(context)
            key = load_or_create_install_key(context)
            restored = [object()]
            client_sources = SimpleNamespace(inventory_sources=mock.Mock(side_effect=AssertionError("fresh inventory")))
            projection = SimpleNamespace(restored_sources=mock.Mock(return_value=restored))
            context_module = __import__("installation_context")
            with mock.patch(
                "install._internal",
                side_effect=lambda name: context_module if name == "installation_context" else projection,
            ):
                result = _inventory_sources(client_sources, context, ())
            self.assertEqual(result, restored)
            projection.restored_sources.assert_called_once_with(
                context, install_key=key, projects=(), token=key.hex()
            )
            client_sources.inventory_sources.assert_not_called()

    def test_fresh_install_uses_native_inventory_adapter(self):
        from install import _inventory_sources
        from installation_context import ClientPaths, InstallContext

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            root = home / "manager"
            context = InstallContext(
                1, root, root / "release", root / "runtime", root / "artifacts",
                Path("/usr/bin/python3"), Path("/usr/bin/node"), 18765,
                (ClientPaths("claude", home / ".claude.json", None, (), ()),),
            )
            rows = [object()]
            client_sources = SimpleNamespace(inventory_sources=mock.Mock(return_value=rows))
            with mock.patch("install._internal", return_value=__import__("installation_context")):
                result = _inventory_sources(client_sources, context, ())
            self.assertEqual(result, rows)
            client_sources.inventory_sources.assert_called_once_with(context, projects=())


if __name__ == "__main__":
    unittest.main()
