import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


class ExportSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.destination = self.root / "standalone"
        self.source.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def test_explicit_release_closure_keeps_portable_runtime_and_drops_private_adapters(self):
        from export_source import PORTABLE_FILES

        expected = {
            "scripts/monitoring_cli.py",
            "scripts/monitoring_memory.py",
            "scripts/mcp_manager.py",
            "scripts/service_install.py",
            "scripts/test_monitoring_cli.py",
            "scripts/test_mcp_manager.py",
            "scripts/test_service_install.py",
            "scripts/test_monitoring_memory.py",
            "scripts/loki_owner_environment.py",
            "scripts/test_loki_owner_environment.py",
            "scripts/test_client_sources.py",
            "scripts/test_portable_family.py",
            "scripts/test_portable_engine.py",
            "scripts/test_installation_verify.py",
            "scripts/test_owner_watch.py",
            "docs/relocation.md",
        }
        self.assertTrue(expected <= PORTABLE_FILES)

    def test_exports_untracked_runtime_sources_and_selected_docs_without_private_state(self):
        from export_source import export_source

        (self.source / "src").mkdir()
        (self.source / "scripts").mkdir()
        (self.source / "docs").mkdir()
        (self.source / "runtime").mkdir()
        (self.source / "src/new-untracked.ts").write_text("export const fresh = 1;\n")
        (self.source / "scripts/new-untracked.py").write_text("fresh = True\n")
        (self.source / "docs/service.md").write_text("runtime contract\n")
        (self.source / "docs/evidence.json").write_text("private evidence\n")
        (self.source / "runtime/token").write_text("synthetic-private-token")
        (self.source / ".env").write_text("TOKEN=synthetic-private-token\n")
        (self.source / "package.json").write_text('{"name":"fixture"}\n')

        files = export_source(self.source, self.destination)

        self.assertIn("src/new-untracked.ts", files)
        self.assertIn("scripts/new-untracked.py", files)
        self.assertIn("docs/service.md", files)
        self.assertEqual(files["src/new-untracked.ts"], hashlib.sha256(b"export const fresh = 1;\n").hexdigest())
        self.assertFalse((self.destination / "runtime").exists())
        self.assertFalse((self.destination / ".env").exists())
        self.assertFalse((self.destination / "docs/evidence.json").exists())
        self.assertEqual((self.source / "runtime/token").read_text(), "synthetic-private-token")

    def test_exports_only_the_root_gitignore_among_hidden_files(self):
        from export_source import export_source

        (self.source / ".gitignore").write_text(".env\nnode_modules/\n")
        (self.source / ".private-note").write_text("synthetic private note\n")
        (self.source / "scripts").mkdir()
        (self.source / "scripts/.private-config").write_text("synthetic private config\n")
        (self.source / "scripts/public.py").write_text("public = True\n")

        files = export_source(self.source, self.destination)

        self.assertIn(".gitignore", files)
        self.assertEqual((self.destination / ".gitignore").read_text(), ".env\nnode_modules/\n")
        self.assertIn("scripts/public.py", files)
        self.assertNotIn(".private-note", files)
        self.assertNotIn("scripts/.private-config", files)

    def test_exports_the_first_party_root_gitignore(self):
        from export_source import export_source

        public_source = Path(__file__).resolve().parents[1]
        destination = self.root / "first-party-export"

        files = export_source(public_source, destination, portable_only=True)

        self.assertIn(".gitignore", files)
        self.assertEqual((destination / ".gitignore").read_bytes(), (public_source / ".gitignore").read_bytes())

    def test_excludes_credentials_local_configs_private_keys_and_generated_trees(self):
        from export_source import export_source

        (self.source / "scripts").mkdir()
        (self.source / "src").mkdir()
        (self.source / "scripts/public.py").write_text("public = True\n")
        private_files = (
            "scripts/credentials.json",
            "scripts/config.local.json",
            "scripts/sample.pem",
            "src/runtime/module.ts",
            "src/artifacts/output.ts",
            "src/transactions/record.json",
            "src/evidence/result.json",
            "src/logs/service.txt",
            "src/cache/temp.ts",
            "src/build/output.ts",
            "src/dist/output.ts",
            "src/node_modules/example/index.ts",
            "src/__pycache__/module.pyc",
            "scripts/release-input-cache/policy.json",
            "scripts/releaseinputcache/policy.json",
            "release/input-cache/policy.json",
        )
        for relative in private_files:
            target = self.source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("synthetic private fixture\n")

        files = export_source(self.source, self.destination)

        self.assertEqual(set(files), {"scripts/public.py"})
        for relative in private_files:
            self.assertFalse((self.destination / relative).exists(), relative)

    def test_refuses_existing_destination_without_changing_it(self):
        from export_source import ExportError, export_source

        self.destination.mkdir()
        sentinel = self.destination / "sentinel"
        sentinel.write_text("keep")
        with self.assertRaises(ExportError):
            export_source(self.source, self.destination)
        self.assertEqual(sentinel.read_text(), "keep")

    def test_exports_only_explicitly_reviewed_release_policy_and_lock_files(self):
        from export_source import export_source

        (self.source / "release/catalogs").mkdir(parents=True)
        (self.source / "release/locks").mkdir()
        approved = (
            "release/families.json",
            "release/inputs.json",
            "release/catalogs/mysql.json",
            "release/locks/mysql.package-lock.json",
            "release/locks/langfuse-wheels.json",
        )
        for relative in approved:
            target = self.source / relative
            target.write_text("{}\n")
        (self.source / "release/catalogs/private.json").write_text('{"secret":"synthetic"}\n')
        (self.source / "release/locks/unreviewed.json").write_text("{}\n")

        files = export_source(self.source, self.destination)

        for relative in approved:
            self.assertIn(relative, files)
        self.assertNotIn("release/catalogs/private.json", files)
        self.assertNotIn("release/locks/unreviewed.json", files)
        self.assertFalse((self.destination / "release/catalogs/private.json").exists())

    def test_portable_release_uses_explicit_runtime_and_test_closure(self):
        from export_source import export_source

        (self.source / "scripts").mkdir()
        (self.source / "scripts/install.py").write_text("portable = True\n")
        (self.source / "scripts/test_install.py").write_text("portable_test = True\n")
        (self.source / "scripts/legacy-provisioner.py").write_text("personal = '/Users' + '/' + 'private'\n")
        for name in ("test_manage.py", "test_pilot.py", "test_source_inputs.py"):
            (self.source / "scripts" / name).write_text("legacy fixture\n")
        (self.source / "test").mkdir()
        (self.source / "test/policy.test.mjs").write_text("portable();\n")
        (self.source / "test/verify-private-path.test.mjs").write_text("personal();\n")
        (self.source / "test/fixtures").mkdir()
        (self.source / "test/fixtures/backend.mjs").write_text("portable fixture\n")
        (self.source / "test/helpers").mkdir()
        (self.source / "test/helpers/private-dist.mjs").write_text("portable test helper\n")
        (self.source / "test/fixtures/private-adapter-protocol-stub.py").write_text("synthetic fixture\n")
        (self.source / "docs").mkdir()
        (self.source / "docs/installer-verification.md").write_text("verification\n")
        (self.source / "docs/local-migration.md").write_text("synthetic local setup details\n")
        (self.source / "scripts/verify-langfuse-dependencies.py").write_text("portable verifier\n")
        (self.source / "scripts/verify-langfuse-closure.py").write_text("portable closure verifier\n")
        (self.source / "scripts/loki_owner_environment.py").write_text("portable owner guard\n")
        (self.source / "scripts/test_loki_owner_environment.py").write_text("portable owner test\n")
        (self.source / "scripts/test_langfuse_entry.py").write_text("portable entry test\n")
        (self.source / "docs/private-plan.md").write_text("exclude\n")
        (self.source / "skills/mcp-manager-setup").mkdir(parents=True)
        (self.source / "skills/mcp-manager-setup/SKILL.md").write_text("setup\n")
        (self.source / "release").mkdir()
        (self.source / "release/families.json").write_text("{}\n")

        files = export_source(self.source, self.destination, portable_only=True)

        for relative in (
            "scripts/install.py", "scripts/test_install.py", "test/policy.test.mjs",
            "test/fixtures/backend.mjs", "docs/installer-verification.md",
            "scripts/verify-langfuse-dependencies.py", "test/helpers/private-dist.mjs",
            "scripts/verify-langfuse-closure.py",
            "scripts/loki_owner_environment.py", "scripts/test_loki_owner_environment.py",
            "scripts/test_langfuse_entry.py",
            "skills/mcp-manager-setup/SKILL.md",
            "release/families.json",
        ):
            self.assertIn(relative, files)
        for relative in (
            "scripts/legacy-provisioner.py", "test/verify-private-path.test.mjs",
            "test/fixtures/private-adapter-protocol-stub.py", "docs/private-plan.md",
            "docs/local-migration.md", "scripts/test_manage.py", "scripts/test_pilot.py",
            "scripts/test_source_inputs.py",
        ):
            self.assertNotIn(relative, files)

    def test_rejects_symlink_in_an_allowed_source_tree(self):
        from export_source import ExportError, export_source

        (self.source / "scripts").mkdir()
        external = self.root / "outside.py"
        external.write_text("private")
        (self.source / "scripts/linked.py").symlink_to(external)
        with self.assertRaises(ExportError):
            export_source(self.source, self.destination)
        self.assertFalse(self.destination.exists())

    def test_detects_source_modified_during_copy(self):
        from export_source import ExportError, export_source

        (self.source / "src").mkdir()
        source_file = self.source / "src/racing.ts"
        source_file.write_bytes(b"a" * 1024 * 1024)
        write = os.write
        changed = False

        def mutate_before_destination_write(fd, content):
            nonlocal changed
            if not changed:
                changed = True
                with source_file.open("ab") as stream:
                    stream.write(b"changed")
                    stream.flush()
                    os.fsync(stream.fileno())
            return write(fd, content)

        with mock.patch("export_source.os.write", side_effect=mutate_before_destination_write):
            with self.assertRaises(ExportError):
                export_source(self.source, self.destination)
        self.assertTrue(changed)


if __name__ == "__main__":
    unittest.main()
