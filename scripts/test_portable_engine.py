"""Authenticated portable route metadata and secret-free runtime preparation."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import migrate
from pilot import SafeError, setup_token, read_token, write_private


class PortableEngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime = Path(self.temporary.name).resolve()
        self.runtime.chmod(0o700)
        setup_token(self.runtime)
        self.token = read_token(self.runtime / "token")
        self.context = SimpleNamespace(runtime=self.runtime)

    def routes(self, family="loki"):
        payload = {"version": 1, "routes": [{"route_id": "loki-prd", "family": family}]}
        envelope = {"payload": payload, "mac": migrate.mac({"domain": "personal-mcp-manager/routes/v1", "payload": payload}, self.token)}
        write_private(self.runtime / "routes.json", json.dumps(envelope).encode())

    def test_owner_required_for_session_family_but_not_stateless_grafana(self):
        from portable_engine import requires_owner
        self.routes("loki")
        self.assertTrue(requires_owner(self.context, "loki-prd"))
        self.routes("grafana")
        self.assertFalse(requires_owner(self.context, "loki-prd"))

    def test_tampered_routes_refused_before_header_issue(self):
        from portable_engine import requires_owner
        self.routes()
        path = self.runtime / "routes.json"
        value = json.loads(path.read_bytes())
        value["payload"]["routes"][0]["family"] = "grafana"
        write_private(path, json.dumps(value).encode())
        with self.assertRaisesRegex(SafeError, "ROUTES_AUTHENTICATION_FAILED"):
            requires_owner(self.context, "loki-prd")

    def test_unknown_route_does_not_receive_global_token_header(self):
        from portable_engine import requires_owner
        self.routes()
        with self.assertRaisesRegex(SafeError, "ROUTE_NOT_ADMITTED"):
            requires_owner(self.context, "unknown")

    def test_registry_hmac_binds_all_artifact_and_source_metadata(self):
        from portable_engine import write_registry, read_registry
        records = {"loki-prd": {"artifact": {"artifactRoot": "/synthetic/pinned"}, "source_hmac": "a" * 64}}
        write_registry(self.context, records, self.token)
        self.assertEqual(read_registry(self.context, self.token), records)
        path = self.runtime / "registry.json"
        value = json.loads(path.read_bytes())
        value["payload"]["profiles"]["loki-prd"]["artifact"]["artifactRoot"] = "/unreviewed"
        write_private(path, json.dumps(value).encode())
        with self.assertRaisesRegex(SafeError, "REGISTRY_AUTHENTICATION_FAILED"):
            read_registry(self.context, self.token)

    def test_prepare_persists_source_reference_and_never_the_source_credentials(self):
        from client_sources import SourceCandidate, SourceRef
        from portable_engine import prepare_runtime, read_registry
        candidate = SourceCandidate(SourceRef("claude", "global", "mysql-primary-dev",
            Path("/synthetic/.claude.json"), ("mcpServers", "mysql-primary-dev")),
            "mysql", True, {"command": "npx", "args": ["-y", "@benborla29/mcp-server-mysql"],
                             "env": {"MYSQL_PASS": "synthetic-private-password"}}, {})
        context = SimpleNamespace(runtime=self.runtime, release=self.runtime,
            root=self.runtime, artifacts=self.runtime / "artifacts")
        def provision(context, candidate, artifact, route, stage, token):
            (stage / "ownership").mkdir(mode=0o700)
            manifest = {"backendId": route, "fingerprint": "a" * 64,
                        "allowedTools": ["mysql_query"], "description": {"tools": []}}
            write_private(stage / "manifests" / (route + ".json"), json.dumps(manifest).encode())
            return {"fingerprint": "a" * 64, "allowedTools": ["mysql_query"]}
        artifact = {"family": "mysql", "artifactRoot": "/synthetic/reviewed"}
        result = prepare_runtime(context, [candidate], {"mysql": artifact}, provisioner=provision)
        self.assertEqual(result["profile_count"], 1)
        record = read_registry(context, self.token)["mysql-primary-dev"]
        self.assertEqual(record["route"]["source_ref"]["client"], "claude")
        for path in self.runtime.rglob("*.json"):
            self.assertNotIn(b"synthetic-private-password", path.read_bytes())

    def test_unproven_provision_cleanup_never_publishes_registry(self):
        from client_sources import SourceCandidate, SourceRef
        from portable_engine import prepare_runtime
        candidate = SourceCandidate(SourceRef("claude", "global", "loki-prd",
            Path("/synthetic/.claude.json"), ("mcpServers", "loki-prd")), "loki", True,
            {"command": "npx", "args": ["-y", "simple-loki-mcp"], "env": {}}, {})
        def dirty(context, candidate, artifact, route, stage, token):
            (stage / "ownership").mkdir(mode=0o700)
            write_private(stage / "ownership/uncertain.json", b'{}')
            write_private(stage / "manifests" / (route + ".json"), b'{}')
            return {}
        with self.assertRaises(SafeError):
            prepare_runtime(self.context, [candidate], {"loki": {}}, provisioner=dirty)
        self.assertFalse((self.runtime / "registry.json").exists())

    def test_runtime_refuses_changed_manifest_before_resolving_credentials(self):
        from portable_engine import load_runtime, write_registry
        self.routes()
        route = json.loads((self.runtime / "routes.json").read_bytes())["payload"]["routes"][0]
        (self.runtime / "manifests").mkdir(mode=0o700)
        write_private(self.runtime / "manifests/loki-prd.json", b'{"changed":true}')
        write_registry(self.context, {"loki-prd": {"route": route, "manifestSha256": "0" * 64}}, self.token)
        def forbidden(*args, **kwargs):
            self.fail("A changed manifest reached source credential resolution")
        with self.assertRaisesRegex(SafeError, "RUNTIME_MANIFEST_CHANGED"):
            load_runtime(self.context, source_resolver=forbidden)

    def test_multi_family_registry_is_not_truncated_at_legacy_config_limit(self):
        from portable_engine import write_registry, read_registry
        records = {"grafana-dev": {"catalog": "x" * 280000}}
        write_registry(self.context, records, self.token)
        self.assertEqual(read_registry(self.context, self.token), records)

    def test_candidate_preserves_reviewed_native_environment_without_code_loading_inputs(self):
        from portable_engine import _candidate_environment
        with patch.dict("os.environ", {"HOME": str(self.runtime),
                "HTTP_PROXY": "http://synthetic.invalid:8080", "LOKI_PASSWORD": "fixture-secret",
                "NODE_OPTIONS": "--require=unreviewed", "UNRELATED_TOKEN": "unrelated-secret"}, clear=True):
            environment = _candidate_environment()
        self.assertEqual(environment["HOME"], str(self.runtime))
        self.assertEqual(environment["HTTP_PROXY"], "http://synthetic.invalid:8080")
        self.assertEqual(environment["LOKI_PASSWORD"], "fixture-secret")
        self.assertNotIn("NODE_OPTIONS", environment)
        self.assertNotIn("UNRELATED_TOKEN", environment)

    def test_stateful_socket_path_limit_is_checked_before_process_launch(self):
        from portable_engine import _check_owner_socket_path
        context = SimpleNamespace(runtime=Path("/synthetic/") / ("x" * 104))
        with self.assertRaisesRegex(SafeError, "OWNER_SOCKET_PATH_TOO_LONG"):
            _check_owner_socket_path(context, session=True)
        _check_owner_socket_path(context, session=False)


if __name__ == "__main__":
    unittest.main()
