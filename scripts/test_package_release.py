import hashlib
from io import BytesIO
import json
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


class PackageReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.temporary_root = Path(self.temporary.name).resolve()
        self.root = self.temporary_root / "source"
        self.root.mkdir()
        (self.root / "package.json").write_text('{"name":"portable-mcp-manager","version":"1.2.3"}\n')
        (self.root / "LICENSE").write_text("MIT License\nPermission is hereby granted.\n")
        (self.root / "THIRD_PARTY_NOTICES.txt").write_text("Fixture catalog attributions\n")
        (self.root / "README.md").write_text("Standalone package\n")
        (self.root / "src").mkdir()
        (self.root / "src/untracked.ts").write_text("export const release = true;\n")
        (self.root / "runtime").mkdir()
        (self.root / "runtime/token").write_text("synthetic-private-token")
        (self.root / "artifacts").mkdir()
        (self.root / "artifacts/cached").write_text("synthetic artifact cache")
        (self.root / ".git").mkdir()
        (self.root / ".git/config").write_text("private git state")
        (self.root / "docs/evidence").mkdir(parents=True)
        (self.root / "docs/evidence/local.json").write_text('{"evidence":"private"}')
        (self.root / "release/.staging").mkdir(parents=True)
        (self.root / "release/.staging/input.tgz").write_bytes(b"private cache")

    @staticmethod
    def fixture_policy(_release):
        return {"families": {name: {} for name in ("grafana", "langfuse", "loki", "mysql")}}

    def test_packages_working_tree_and_excludes_personal_state(self):
        from package_release import package_release

        output = self.temporary_root / "portable.tar.gz"
        result = package_release(self.root, output, policy_loader=self.fixture_policy)

        with tarfile.open(output, "r:gz") as archive:
            names = set(archive.getnames())
            self.assertIn("LICENSE", names)
            self.assertEqual(archive.extractfile("THIRD_PARTY_NOTICES.txt").read(),
                             b"Fixture catalog attributions\n")
            self.assertIn("README.md", names)
            self.assertIn("src/untracked.ts", names)
            self.assertFalse(any(name.startswith(("runtime/", "artifacts/", ".git/", "docs/evidence/", "release/.staging/")) for name in names))
            file_names = [name for name in names if archive.getmember(name).isfile()]
            payload = b"".join(archive.extractfile(name).read() for name in file_names)
            self.assertNotIn(b"synthetic-private-token", payload)
            self.assertNotIn(b"/" + b"Users/", payload)
        self.assertEqual(result["sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(result["fileCount"], len(file_names))
        self.assertEqual(Path(result["checksumPath"]).read_text(), result["sha256"] + "  " + output.name + "\n")
        manifest = json.loads(Path(result["manifestPath"]).read_text())
        self.assertEqual(manifest["sha256"], result["sha256"])
        self.assertIn("LICENSE", manifest["files"])
        self.assertEqual(manifest["files"]["THIRD_PARTY_NOTICES.txt"],
                         hashlib.sha256(b"Fixture catalog attributions\n").hexdigest())

    def test_packages_gitignore_and_excludes_synthetic_private_fixtures(self):
        from package_release import package_release

        (self.root / ".gitignore").write_text(".env*\nnode_modules/\n")
        (self.root / "src/keep.ts").write_text("export const safe = true;\n")
        private_files = (
            "src/credentials.json",
            "src/config.local.json",
            "src/sample.pem",
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
            "src/release-input-cache/policy.json",
            "release/input-cache/policy.json",
        )
        for relative in private_files:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("synthetic private fixture\n")
        declared_release_files = (
            "release/families.json",
            "release/inputs.json",
            "release/catalogs/mysql.json",
            "release/locks/mysql.package-lock.json",
        )
        for relative in declared_release_files:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("{}\n")

        output = self.temporary_root / "sanitized.tar.gz"
        result = package_release(self.root, output, policy_loader=self.fixture_policy)

        with tarfile.open(output, "r:gz") as archive:
            names = set(archive.getnames())
            self.assertIn(".gitignore", names)
            self.assertIn("src/keep.ts", names)
            for relative in private_files:
                self.assertNotIn(relative, names)
            for relative in declared_release_files:
                self.assertIn(relative, names)
            self.assertEqual(archive.extractfile(".gitignore").read(), b".env*\nnode_modules/\n")
        manifest = json.loads(Path(result["manifestPath"]).read_text())
        self.assertIn(".gitignore", manifest["files"])
        self.assertNotIn("src/credentials.json", manifest["files"])

    def test_first_party_root_gitignore_is_in_the_portable_tar(self):
        from export_source import export_source
        from package_release import _write_tar

        public_source = Path(__file__).resolve().parents[1]
        exported = self.temporary_root / "first-party-export"
        files = export_source(public_source, exported, portable_only=True)
        archive_bytes = BytesIO()

        _write_tar(exported, files, archive_bytes)
        archive_bytes.seek(0)

        with tarfile.open(fileobj=archive_bytes, mode="r:gz") as archive:
            gitignore = archive.extractfile(".gitignore")
            self.assertIsNotNone(gitignore)
            self.assertEqual(gitignore.read(), (public_source / ".gitignore").read_bytes())

    def test_archive_is_reproducible_for_same_working_tree(self):
        from package_release import package_release

        (self.root / ".gitignore").write_text(".env*\nnode_modules/\n")
        first = self.temporary_root / "first.tar.gz"
        second = self.temporary_root / "second.tar.gz"
        package_release(self.root, first, policy_loader=self.fixture_policy)
        package_release(self.root, second, policy_loader=self.fixture_policy)

        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_rejects_existing_output_and_never_overwrites_it(self):
        from package_release import PackageError, package_release

        output = self.temporary_root / "existing.tar.gz"
        output.write_bytes(b"keep")
        with self.assertRaises(PackageError):
            package_release(self.root, output, policy_loader=self.fixture_policy)
        self.assertEqual(output.read_bytes(), b"keep")

    def test_rejects_personal_absolute_paths_in_exported_source(self):
        from package_release import PackageError, package_release

        private_path = "/" + "Users/" + "another-person/.codex/state"
        (self.root / "src/untracked.ts").write_text("const path = " + repr(private_path) + ";\n")
        output = self.temporary_root / "unsafe.tar.gz"
        with self.assertRaises(PackageError) as caught:
            package_release(self.root, output, policy_loader=self.fixture_policy)
        self.assertEqual(str(caught.exception), "PACKAGE_PERSONAL_PATH_REFUSED")
        self.assertFalse(output.exists())

    def test_rejects_plaintext_private_key_formats_without_returning_key_material(self):
        from package_release import PackageError, package_release

        begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
        end = "-----END " + "RSA PRIVATE KEY-----"
        (self.root / "src/leaked.ts").write_text(
            "const key = " + repr(begin + "\\nsynthetic-placeholder\\n" + end) + ";\n"
        )
        output = self.temporary_root / "unsafe-key.tar.gz"

        with self.assertRaises(PackageError) as caught:
            package_release(self.root, output, policy_loader=self.fixture_policy)

        self.assertEqual(str(caught.exception), "PACKAGE_PRIVATE_KEY_REFUSED")
        self.assertNotIn(begin, str(caught.exception))
        self.assertFalse(output.exists())

    def test_rejects_recognizable_service_key_formats_without_returning_values(self):
        from package_release import PackageError, package_release

        samples = (
            ("github-classic", "gh" + "p_" + "A" * 36),
            ("github-fine-grained", "github" + "_pat_" + "B" * 30),
            ("github-app", "gh" + "s_" + "12345_" + "C" * 30 + "." + "D" * 30 + "." + "E" * 30),
            ("aws-long-lived", "AK" + "IA" + "F" * 16),
            ("aws-temporary", "AS" + "IA" + "G" * 16),
            ("slack-bot", "xo" + "xb-" + "H" * 24),
            ("slack-app", "xap" + "p-" + "I" * 24),
            ("langfuse-public", "p" + "k-" + "lf-" + "J" * 24),
            ("langfuse-secret", "s" + "k-" + "lf-" + "K" * 24),
        )
        source = self.root / "src/service-config.ts"
        source.parent.mkdir(parents=True, exist_ok=True)

        for index, (kind, value) in enumerate(samples):
            with self.subTest(kind=kind):
                source.write_text("export const sample = " + json.dumps(value) + ";\n")
                output = self.temporary_root / f"unsafe-key-{index}.tar.gz"

                with self.assertRaises(PackageError) as caught:
                    package_release(self.root, output, policy_loader=self.fixture_policy)

                self.assertEqual(str(caught.exception), "PACKAGE_CREDENTIAL_FORMAT_REFUSED")
                self.assertNotIn(value, str(caught.exception))
                self.assertFalse(output.exists())

    def test_production_packaging_requires_complete_real_release_policy(self):
        from package_release import PackageError, package_release

        output = self.temporary_root / "incomplete.tar.gz"
        with self.assertRaises(PackageError):
            package_release(self.root, output)
        self.assertFalse(output.exists())

    def test_dynamic_file_import_targets_must_be_in_the_archive(self):
        from package_release import PackageError, _verify_dynamic_source_closure

        exported = self.temporary_root / "exported"
        (exported / "scripts").mkdir(parents=True)
        entry = b'module = Path(__file__).with_name("materializer.py")\n'
        (exported / "scripts/entry.py").write_bytes(entry)
        files = {"scripts/entry.py": hashlib.sha256(entry).hexdigest()}
        with self.assertRaises(PackageError):
            _verify_dynamic_source_closure(exported, files)
        helper = b"trusted = True\n"
        (exported / "scripts/materializer.py").write_bytes(helper)
        files["scripts/materializer.py"] = hashlib.sha256(helper).hexdigest()
        _verify_dynamic_source_closure(exported, files)

    def test_typescript_runtime_script_references_must_be_in_the_archive(self):
        from package_release import PackageError, _verify_dynamic_source_closure

        exported = self.temporary_root / "typescript-export"
        (exported / "src").mkdir(parents=True)
        source = b"const script = resolve(repo, 'scripts/verify-langfuse-closure.py');\n"
        (exported / "src/closure-verifier.ts").write_bytes(source)
        files = {"src/closure-verifier.ts": hashlib.sha256(source).hexdigest()}

        with self.assertRaises(PackageError):
            _verify_dynamic_source_closure(exported, files)

        helper = b"raise SystemExit(0)\n"
        (exported / "scripts").mkdir()
        (exported / "scripts/verify-langfuse-closure.py").write_bytes(helper)
        files["scripts/verify-langfuse-closure.py"] = hashlib.sha256(helper).hexdigest()
        _verify_dynamic_source_closure(exported, files)

if __name__ == "__main__":
    unittest.main()
