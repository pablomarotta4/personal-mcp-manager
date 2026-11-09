import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pilot import setup_token, write_private


class InstallationVerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mcp-install-verify-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.home.chmod(0o700)
        self.root = self.home / "Library" / "Application Support" / "Personal MCP Manager"
        self.root.mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        self.release = self.root / "app" / "releases" / "release-one"
        self.release.mkdir(parents=True, mode=0o700)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        (self.runtime / "manifests").mkdir(mode=0o700)
        (self.runtime / "ownership").mkdir(mode=0o700)
        setup_token(self.runtime)
        config = self.home / ".claude.json"
        config.write_text(json.dumps({"mcpServers": {"grafana-dev": {
            "command": "uvx", "args": ["mcp-grafana"], "env": {
                "GRAFANA_URL": "https://synthetic.invalid",
                "GRAFANA_SERVICE_ACCOUNT_TOKEN": "synthetic-secret",
            }}}}))
        config.chmod(0o600)
        from installation_context import ClientPaths
        client = ClientPaths(kind="claude", config=config, settings=None,
                             plugin_roots=(), owner_executables=())
        self.context = SimpleNamespace(version=1, root=self.root, release=self.release,
            runtime=self.runtime, artifacts=self.root / "artifacts", python=Path("/usr/bin/python3"),
            node=Path("/usr/bin/node"), port=18765, clients=(client,))

        from client_sources import SourceCandidate, SourceRef, build_route_map
        self.candidate = SourceCandidate(
            SourceRef("claude", "global", "grafana-dev", config, ("mcpServers", "grafana-dev")),
            "grafana", True, {"command": "uvx", "args": ["mcp-grafana"], "env": {
                "GRAFANA_URL": "https://synthetic.invalid",
                "GRAFANA_SERVICE_ACCOUNT_TOKEN": "synthetic-secret",
            }}, {})
        token = (self.runtime / "token").read_text()
        envelope = build_route_map([self.candidate], token)
        self.route = envelope["payload"]["routes"][0]
        write_private(self.runtime / "routes.json", json.dumps(envelope).encode())
        tools = [{"name": "list_datasources", "annotations": {"readOnlyHint": True},
                  "inputSchema": {"type": "object"}}]
        manifest = {"backendId": "grafana-dev", "allowedTools": ["list_datasources"],
                    "description": {"tools": tools}, "fingerprint": "f" * 64}
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        write_private(self.runtime / "manifests/grafana-dev.json", raw)
        record = {"route": self.route, "artifact": {"family": "grafana"},
                  "metadata": {"fingerprint": "f" * 64, "allowedTools": ["list_datasources"]},
                  "manifestSha256": hashlib.sha256(raw).hexdigest()}
        from portable_engine import write_registry
        write_registry(self.context, {"grafana-dev": record}, token)
        from installation_context import write_context
        write_context(self.context)

    def test_default_doctor_is_structured_and_never_calls_safe_read(self):
        import installation_verify

        with patch.object(installation_verify, "_perform_safe_reads", side_effect=AssertionError("provider call")), \
             patch("service_install.verify_service", return_value={"status": "PASS", "service": "PASS", "identity": "PASS"}), \
             patch("manage.ownership_empty", return_value=True):
            result = installation_verify.verify_installation(self.context)

        self.assertEqual(set(result), {
            "installed", "service", "catalog", "safeRead", "source", "ownership"})
        self.assertEqual(result["safeRead"]["status"], "NOT_TESTED")
        self.assertEqual(result["catalog"]["status"], "PASS")
        self.assertEqual(result["catalog"]["routes"], 1)

    def test_live_session_ownership_is_read_only_not_a_false_failure(self):
        import installation_verify

        sessions = self.runtime / "ownership" / "sessions"
        sessions.mkdir(mode=0o700)
        lease = sessions / ("a" * 64)
        lease.mkdir(mode=0o700)
        result = installation_verify._check_ownership(self.context)
        self.assertEqual(result["status"], "NOT_TESTED")
        self.assertEqual(result["reason"], "OWNERSHIP_ACTIVE")
        self.assertTrue(lease.exists())

    def test_stateful_safe_reads_are_not_attempted_without_signed_client_ancestry(self):
        import installation_verify

        self.route["family"] = "loki"
        self.route["profile_id"] = "loki-stg"
        with patch("owner_watch.request_owner", side_effect=Exception("not in signed client ancestry")), \
             patch.object(installation_verify, "_mcp_rpc", side_effect=AssertionError("must not call provider")):
            value = installation_verify._safe_read_route(self.context, self.route, "a" * 64, {})
        self.assertEqual(value["status"], "NOT_TESTED")
        self.assertEqual(value["reason"], "SIGNED_CLIENT_REQUIRED")

    def test_stateful_catalog_is_not_claimed_without_signed_client_ancestry(self):
        import installation_verify

        self.route["family"] = "loki"
        with patch("owner_watch.request_owner", side_effect=Exception("not in signed client ancestry")):
            value = installation_verify._check_catalog(
                self.context, [self.route], {self.route["route_id"]: {"manifestSha256":
                    hashlib.sha256((self.runtime / "manifests/grafana-dev.json").read_bytes()).hexdigest()}}
            )
        self.assertEqual(value["status"], "NOT_TESTED")
        self.assertEqual(value["reason"], "SIGNED_CLIENT_REQUIRED")

    def test_safe_probe_arguments_are_fixed_per_reviewed_family(self):
        from installation_verify import _probe_for_route

        cases = [
            ({"family": "grafana", "profile_id": "grafana-dev"},
             ("list_datasources", {})),
            ({"family": "loki", "profile_id": "loki-prd"}, ("get_labels", {})),
            ({"family": "mysql", "profile_id": "mysql-primary-dev"},
             ("mysql_query", {"sql": "SELECT 1"})),
            ({"family": "langfuse", "profile_id": "langfuse-traces"},
             ("fetch_traces", {"age": 10})),
        ]
        for route, expected in cases:
            self.assertEqual(_probe_for_route(route), expected)
        self.assertIsNone(_probe_for_route({"family": "custom-db", "profile_id": "custom-db"}))


if __name__ == "__main__":
    unittest.main()
