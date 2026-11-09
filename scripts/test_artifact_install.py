import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from pilot import SafeError


def write_release(root: Path, *, payload: bytes = b"reviewed fixture input") -> Path:
    release = root / "release"
    (release / "locks").mkdir(parents=True)
    (release / "catalogs").mkdir()
    lock = {"name": "fixture-loki", "version": "1.0.0", "lockfileVersion": 3,
            "requires": True, "packages": {"": {"dependencies": {"simple-loki-mcp": "0.0.9"}}}}
    lock_bytes = json.dumps(lock, sort_keys=True, separators=(",", ":")).encode()
    (release / "locks/loki.package-lock.json").write_bytes(lock_bytes)
    catalog = {"serverInfo": {"name": "simple-loki-mcp", "version": "0.0.9"},
               "capabilities": {"tools": {}}, "tools": [], "resources": [], "resourceTemplates": []}
    catalog_bytes = json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
    (release / "catalogs/loki.json").write_bytes(catalog_bytes)
    input_sha = hashlib.sha256(payload).hexdigest()
    import base64
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
    families = {
        "schema": 1,
        "platform": "darwin-arm64",
        "acquisition": "reviewed-locks-only",
        "runtimeNetworkResolution": False,
        "families": ["loki"],
    }
    inputs = {
        "schema": 1,
        "platform": "darwin-arm64",
        "families": {
            "loki": {
                "profileId": "loki-stg",
                "profileIds": ["loki-stg", "loki-prd", "loki-tools"],
                "sourceIdentity": "simple-loki-mcp:0.0.9/node:25.3.0",
                "lockFile": "locks/loki.package-lock.json",
                "lockSha256": hashlib.sha256(lock_bytes).hexdigest(),
                "catalogFile": "catalogs/loki.json",
                "catalogSha256": hashlib.sha256(catalog_bytes).hexdigest(),
                "catalogFingerprint": hashlib.sha256(catalog_bytes).hexdigest(),
                "transformVersion": "portable-npm-v1",
                "dependencyReportSha256": "b" * 64,
                "artifactSha256": "d" * 64,
                "artifactInputId": "node-runtime",
                "artifactKind": "node-closure",
                "nativeSignature": None,
                "nativeCommand": ["${ARTIFACT_ROOT}/runtime/bin/node", "${ARTIFACT_ROOT}/entry.mjs"],
                "inputs": [{
                    "id": "package",
                    "kind": "npm-tarball",
                    "name": "simple-loki-mcp",
                    "version": "0.0.9",
                    "origin": "https://registry.npmjs.org/simple-loki-mcp/-/simple-loki-mcp-0.0.9.tgz",
                    "integrity": integrity,
                    "sha256": input_sha,
                    "path": "packages/simple-loki-mcp-0.0.9.tgz",
                }, {
                    "id": "node-runtime",
                    "kind": "runtime-archive",
                    "name": "node",
                    "version": "25.3.0",
                    "origin": "https://nodejs.org/dist/v25.3.0/node-v25.3.0-darwin-arm64.tar.xz",
                    "integrity": None,
                    "sha256": input_sha,
                    "path": "packages/node-v25.3.0.tar.xz",
                }],
            }
        },
    }
    (release / "inputs.json").write_text(json.dumps(inputs))
    (release / "families.json").write_text(json.dumps(families))
    return release


class ArtifactInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.release = write_release(self.root)
        self.context = SimpleNamespace(release=self.root / "application")
        (self.context.release / "release").parent.mkdir()
        self.context.release = self.release.parent
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.workspace = self.artifacts / "loki"

    def tearDown(self):
        self.temporary.cleanup()

    def test_acquisition_fetches_reviewed_inputs_into_private_workspace(self):
        from artifact_install import acquire_family

        requested = []

        def downloader(item, destination):
            requested.append(item["origin"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"reviewed fixture input")

        def materializer(policy, family, staged_inputs, workspace):
            artifact_root = policy["artifactParent"] / ("c" * 64)
            (artifact_root / "runtime/bin").mkdir(parents=True)
            (artifact_root / "runtime/bin/node").write_bytes(b"fixture node")
            (artifact_root / "manager").mkdir()
            (artifact_root / "manager/entry.mjs").write_text("export {}\n")
            return {
                "artifactRoot": artifact_root,
                "closureDigest": "c" * 64,
                "artifactSha256": "d" * 64,
                "dependencyReportSha256": "b" * 64,
            }

        result = acquire_family(self.context, "loki", self.workspace,
                                downloader=downloader, materializer=materializer)

        self.assertEqual(requested, [
            "https://registry.npmjs.org/simple-loki-mcp/-/simple-loki-mcp-0.0.9.tgz",
            "https://nodejs.org/dist/v25.3.0/node-v25.3.0-darwin-arm64.tar.xz",
        ])
        self.assertEqual(result["schema"], 1)
        self.assertEqual(result["family"], "loki")
        self.assertEqual(result["profileId"], "loki-stg")
        self.assertEqual(result["profileIds"], ["loki-stg", "loki-prd", "loki-tools"])
        self.assertEqual(result["closureDigest"], "c" * 64)
        self.assertEqual(result["artifactSha256"], "d" * 64)
        self.assertEqual(result["dependencyReportSha256"], "b" * 64)
        self.assertTrue(Path(result["artifactRoot"]).is_relative_to(self.workspace.resolve()))
        self.assertEqual(result["nativeCommand"][0], str(Path(result["artifactRoot"]) / "runtime/bin/node"))
        self.assertEqual(result["inputPins"][0]["integrity"].split("-", 1)[0], "sha512")

    def test_changed_input_digest_refuses_before_returning_admission(self):
        from artifact_install import acquire_family

        def downloader(item, destination):
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"substituted package")

        with self.assertRaises(SafeError) as caught:
            acquire_family(self.context, "loki", self.workspace, downloader=downloader)

        self.assertEqual(str(caught.exception), "RELEASE_INPUT_MISMATCH")

    def test_unavailable_download_does_not_admit_family(self):
        from artifact_install import acquire_family

        def unavailable(_item, _destination):
            raise OSError("network unavailable")

        with self.assertRaises(SafeError) as caught:
            acquire_family(self.context, "loki", self.workspace, downloader=unavailable)

        self.assertEqual(str(caught.exception), "RELEASE_INPUT_UNAVAILABLE")

    def test_unselected_custom_family_is_refused_without_fetching(self):
        from artifact_install import acquire_family

        calls = []

        def downloader(item, destination):
            calls.append(item)

        with self.assertRaises(SafeError) as caught:
            acquire_family(self.context, "custom-db", self.artifacts / "custom-db", downloader=downloader)

        self.assertEqual(str(caught.exception), "FAMILY_NOT_SUPPORTED")
        self.assertEqual(calls, [])

    def test_partial_or_placeholder_release_policy_is_refused(self):
        from artifact_install import load_release_policy

        (self.release / "inputs.json").write_text(json.dumps({"schema": 1, "platform": "darwin-arm64", "families": {}}))

        with self.assertRaises(SafeError) as caught:
            load_release_policy(self.release)

        self.assertEqual(str(caught.exception), "RELEASE_POLICY_INCOMPLETE")

    def test_shipped_release_policy_loads_all_supported_families(self):
        from artifact_install import load_release_policy

        release = Path(__file__).resolve().parents[1] / "release"
        policy = load_release_policy(release)

        self.assertEqual(sorted(policy["families"]), ["grafana", "langfuse", "loki", "mysql"])

    def test_publish_moves_staging_without_replacing_existing_runtime(self):
        from manage import publish

        stage = self.root / "staging"
        runtime = self.root / "runtime"
        stage.mkdir()
        (stage / "marker").write_text("new runtime")
        publish(stage, runtime)
        self.assertEqual((runtime / "marker").read_text(), "new runtime")
        self.assertFalse(stage.exists())

        collision = self.root / "collision"
        collision.mkdir()
        (collision / "marker").write_text("must remain staged")
        with self.assertRaises(SafeError) as caught:
            publish(collision, runtime)

        self.assertEqual(str(caught.exception), "PUBLISH_COLLISION_OR_FAILURE")
        self.assertEqual((runtime / "marker").read_text(), "new runtime")
        self.assertEqual((collision / "marker").read_text(), "must remain staged")

    def test_legacy_migration_cli_reports_unsupported(self):
        script = Path(__file__).with_name("migrate.py")
        result = subprocess.run(
            [sys.executable, str(script)], capture_output=True, text=True, check=False
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.strip(), "LEGACY_MIGRATION_UNSUPPORTED")

    def test_scoped_npm_package_origin_keeps_scope_path_segments(self):
        from artifact_install import _validate_input
        import base64

        package = b"reviewed scoped package"
        item = {
            "id": "scoped-package",
            "kind": "npm-tarball",
            "name": "@scope/example",
            "version": "1.2.3",
            "origin": "https://registry.npmjs.org/@scope/example/-/example-1.2.3.tgz",
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(package).digest()).decode(),
            "sha256": hashlib.sha256(package).hexdigest(),
            "path": "inputs/npm/scoped.tgz",
        }

        self.assertEqual(_validate_input(item)["_relative"].as_posix(), "inputs/npm/scoped.tgz")

    def test_langfuse_transform_version_is_code_owned(self):
        import shutil
        from artifact_install import load_release_policy

        source = Path(__file__).resolve().parents[1] / "release"
        with TemporaryDirectory() as temporary:
            release = Path(temporary) / "release"
            shutil.copytree(source, release)
            path = release / "inputs.json"
            document = json.loads(path.read_text())
            document["families"]["langfuse"]["transformVersion"] = "unreviewed-transform"
            path.write_text(json.dumps(document, sort_keys=True))

            with self.assertRaises(SafeError) as caught:
                load_release_policy(release)

        self.assertEqual(str(caught.exception), "RELEASE_POLICY_MISMATCH")

    def test_langfuse_wrapper_hash_matches_the_code_owned_pin(self):
        from artifact_install import _LANGFUSE_WRAPPER_SHA256

        wrapper = Path(__file__).with_name("langfuse-entry.py")
        self.assertEqual(_LANGFUSE_WRAPPER_SHA256, hashlib.sha256(wrapper.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
