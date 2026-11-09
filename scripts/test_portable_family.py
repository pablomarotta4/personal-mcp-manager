"""Reviewed family templates stay separate from source-specific route names."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from pilot import SafeError


class PortableFamilyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.context = SimpleNamespace(runtime=self.root, artifacts=self.root)
        self.artifact_root = self.root / ("a" * 64)
        self.artifact = {"family": "loki", "profileIds": ["loki-prd"],
            "artifactRoot": str(self.artifact_root), "closureDigest": "a" * 64,
            "nativeCommand": [str(self.artifact_root / "runtime/bin/node")],
            "catalog": {"tools": [{"name": name} for name in ("query_loki", "get_label_values", "get_labels")]}}
        self.candidate = SimpleNamespace(family="loki", profile_id="loki-prd", policy={},
            source={"command": "npx", "args": ["-y", "simple-loki-mcp"],
                    "env": {"LOKI_ADDR": "https://synthetic.invalid", "LOKI_DATASOURCE_ID": "synthetic", "LOKI_BEARER_TOKEN": "synthetic-token"}})

    def build(self, route="loki-prd-0123456789ab"):
        from portable_family import build_portable_policy
        return build_portable_policy(self.context, self.candidate, self.artifact, route,
            self.root, "a" * 64, admission_verifier=lambda context, artifact: None,
            owner_environment={"HOME": str(self.root)})

    def test_loki_alias_uses_explicit_reviewed_profile_and_native_layout(self):
        policy = self.build()
        self.assertEqual(policy["reviewedProfile"], "loki-prd")
        self.assertEqual(policy["command"], str(self.artifact_root / "runtime/bin/node"))
        self.assertEqual(policy["args"][-1], str(self.artifact_root / "app/node_modules/simple-loki-mcp/dist/src/index.js"))
        self.assertEqual(policy["scope"], "session")

    def test_profile_outside_reviewed_family_is_refused(self):
        self.candidate.profile_id = "loki-stg"
        with self.assertRaises(SafeError):
            self.build()

    def test_langfuse_aliases_keep_separate_data_directories(self):
        self.candidate.family = "langfuse"
        self.candidate.profile_id = "langfuse-traces"
        self.candidate.source = {"command": "uvx", "args": ["--with", "mcp[cli]<2", "langfuse-mcp"],
            "env": {"LANGFUSE_HOST": "https://synthetic.invalid", "LANGFUSE_PUBLIC_KEY": "synthetic-pk", "LANGFUSE_SECRET_KEY": "synthetic-sk"}}
        self.artifact.update(family="langfuse", profileIds=["langfuse-traces"],
            nativeCommand=[str(self.artifact_root / "python/bin/python3.13")], catalog={"tools": [{"name": "fetch_traces"}]})
        first = self.build("langfuse-traces-0123456789ab")
        second = self.build("langfuse-traces-0123456789ac")
        self.assertNotEqual(first["args"][5], second["args"][5])
        self.assertEqual(first["args"][7], "langfuse-traces")

    def test_langfuse_read_only_policy_preserves_native_tool_exclusion(self):
        self.candidate.family = "langfuse"
        self.candidate.profile_id = "langfuse-traces"
        self.candidate.source = {"command": "uvx", "args": ["--with", "mcp[cli]<2", "langfuse-mcp", "--read-only"],
            "env": {"LANGFUSE_HOST": "https://synthetic.invalid", "LANGFUSE_PUBLIC_KEY": "fixture-pk", "LANGFUSE_SECRET_KEY": "fixture-sk"}}
        self.artifact.update(family="langfuse", profileIds=["langfuse-traces"],
            nativeCommand=[str(self.artifact_root / "python/bin/python3.13")],
            catalog={"tools": [{"name": name} for name in ("fetch_traces", "create_dataset", "update_prompt_labels", "delete_dataset_run")]})
        readonly = self.build("langfuse-traces-0123456789ab")
        self.assertEqual(readonly["allowedTools"], ["fetch_traces"])
        self.candidate.source["args"].remove("--read-only")
        self.assertEqual(len(self.build("langfuse-traces-0123456789ab")["allowedTools"]), 4)


if __name__ == "__main__":
    unittest.main()
