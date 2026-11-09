import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from pilot import SafeError


class ClientSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="mcp-client-sources-", dir=Path(__file__).resolve().parents[1]
        )
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def context(self, *clients):
        return SimpleNamespace(clients=clients)

    def client(self, kind, config, settings=None, plugin_roots=()):
        return SimpleNamespace(kind=kind, config=config, settings=settings,
                               plugin_roots=tuple(plugin_roots), owner_executables=())

    def test_same_name_unequal_credentials_or_access_have_distinct_keys(self):
        from client_sources import SourceCandidate, SourceRef, source_key, public_plan

        ref = SourceRef("claude", "global", "mysql-primary-dev", Path("/synthetic/claude.json"),
                        ("mcpServers", "mysql-primary-dev"))
        read = SourceCandidate(ref, "mysql", True,
                               {"command": "npx", "env": {"MYSQL_PASS": "synthetic-a"}},
                               {"write": False})
        write = SourceCandidate(ref, "mysql", True,
                                {"command": "npx", "env": {"MYSQL_PASS": "synthetic-b"}},
                                {"write": True})

        self.assertNotEqual(source_key(read, "a" * 64), source_key(write, "a" * 64))
        public = json.dumps(public_plan([read, write]))
        self.assertNotIn("synthetic-a", public)
        self.assertNotIn("synthetic-b", public)
        self.assertNotIn("MYSQL_PASS", public)
        self.assertNotIn("/synthetic/claude.json", public)

    def test_route_map_keeps_same_name_cross_client_sources_distinct(self):
        from client_sources import (SourceCandidate, SourceRef, build_route_map,
                                    verify_route_map)

        claude = SourceCandidate(
            SourceRef("claude", "global", "loki-stg", Path("/synthetic/claude.json"),
                      ("mcpServers", "loki-stg")),
            "loki", True,
            {"command": "npx", "args": ["-y", "simple-loki-mcp"],
             "env": {"LOKI_BEARER_TOKEN": "synthetic-read"}},
            {"enabled_tools": ["get_labels"]},
        )
        codex = SourceCandidate(
            SourceRef("codex", "global", "loki-stg", Path("/synthetic/config.toml"),
                      ("mcp_servers", "loki-stg")),
            "loki", True,
            {"command": "npx", "args": ["-y", "simple-loki-mcp"],
             "env": {"LOKI_BEARER_TOKEN": "synthetic-write"}},
            {"enabled_tools": ["query_loki"]},
        )

        mapping = build_route_map([claude, codex], "a" * 64)
        payload = verify_route_map(mapping, "a" * 64)

        self.assertEqual(len(payload["routes"]), 2)
        self.assertNotEqual(payload["routes"][0]["route_id"], payload["routes"][1]["route_id"])
        self.assertNotEqual(payload["routes"][0]["source_hmac"], payload["routes"][1]["source_hmac"])
        self.assertNotIn("synthetic-read", json.dumps(mapping))
        self.assertNotIn("synthetic-write", json.dumps(mapping))

    def test_claude_only_inventory_never_requires_codex_config(self):
        from client_sources import inventory_sources

        source = {"command": "npx", "args": ["-y", "simple-loki-mcp"],
                  "env": {"LOKI_ADDR": "synthetic", "LOKI_DATASOURCE_ID": "id",
                          "LOKI_BEARER_TOKEN": "synthetic-secret"}}
        config = self.write("claude/.claude.json", json.dumps({"mcpServers": {"loki-stg": source}}).encode())
        settings = self.write("claude/settings.json", b"{}")
        rows = inventory_sources(self.context(self.client("claude", config, settings)))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].ref.client, "claude")
        self.assertEqual(rows[0].ref.scope, "global")
        self.assertEqual(rows[0].family, "loki")
        self.assertTrue(rows[0].enabled)
        self.assertEqual(rows[0].source, source)
        self.assertFalse(rows[0].blockers)

    def test_codex_quoted_toml_keys_and_disabled_state_are_preserved(self):
        from client_sources import inventory_sources

        config = self.write("codex/config.toml", b'''[mcp_servers."mysql-primary-dev"]\ncommand = "npx"\nargs = ["-y", "@benborla29/mcp-server-mysql"]\nenabled = false\n[mcp_servers."mysql-primary-dev".env]\nMYSQL_HOST = "synthetic.invalid"\nMYSQL_PORT = "3306"\nMYSQL_DB = "direct"\nMYSQL_USER = "synthetic-user"\nMYSQL_PASS = "synthetic-secret"\n''')
        rows = inventory_sources(self.context(self.client("codex", config)))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].ref.name, "mysql-primary-dev")
        self.assertEqual(rows[0].family, "mysql")
        self.assertFalse(rows[0].enabled)
        self.assertIn("DISABLED", json.dumps(__import__("client_sources").public_plan(rows)))

    def test_claude_config_over_one_megabyte_is_read_completely(self):
        from client_sources import inventory_sources

        source = {"command": "npx", "args": ["-y", "simple-loki-mcp"],
                  "env": {"LOKI_ADDR": "synthetic", "LOKI_DATASOURCE_ID": "id",
                          "LOKI_BEARER_TOKEN": "synthetic-secret"}}
        payload = {"mcpServers": {"loki-stg": source}, "unrelated": "x" * (1024 * 1024 + 8192)}
        config = self.write("claude/.claude.json", json.dumps(payload).encode())

        rows = inventory_sources(self.context(self.client("claude", config)))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].source, source)

    def test_oversized_claude_config_is_refused_without_truncation(self):
        from client_sources import inventory_sources

        config = self.write("claude/.claude.json", b"{" + b" " * (16 * 1024 * 1024))
        with self.assertRaisesRegex(SafeError, "SOURCE_INPUT_INVALID"):
            inventory_sources(self.context(self.client("claude", config)))

    def test_claude_project_scope_uses_only_registered_project_entries(self):
        from client_sources import inventory_sources, public_plan

        source = {"command": "uvx", "args": ["--with", "mcp[cli]<2", "langfuse-mcp"],
                  "env": {"LANGFUSE_HOST": "https://synthetic.invalid", "LANGFUSE_PUBLIC_KEY": "pk-synthetic",
                          "LANGFUSE_SECRET_KEY": "sk-synthetic"}}
        project_path = "/synthetic/private/project"
        config = self.write("claude/.claude.json", json.dumps({"projects": {
            project_path: {"mcpServers": {"langfuse-traces": source}},
        }}).encode())

        self.assertEqual(inventory_sources(self.context(self.client("claude", config))), [])
        rows = inventory_sources(self.context(self.client("claude", config)),
                                 projects=(Path(project_path),))
        public = json.dumps(public_plan(rows))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].ref.scope, "project")
        self.assertEqual(rows[0].ref.selector, ("projects", project_path, "mcpServers", "langfuse-traces"))
        self.assertNotIn(project_path, public)

    def test_generic_langfuse_profile_accepts_standard_uvx_source(self):
        from client_sources import inventory_sources

        source = {
            "command": "uvx",
            "args": ["--with", "mcp[cli]<2", "langfuse-mcp"],
            "env": {"LANGFUSE_HOST": "https://synthetic.invalid",
                    "LANGFUSE_PUBLIC_KEY": "pk-synthetic",
                    "LANGFUSE_SECRET_KEY": "sk-synthetic"},
            "startup_timeout_sec": 60,
            "tool_timeout_sec": 60,
        }
        config = self.write("claude/.claude.json", json.dumps({
            "mcpServers": {"worker-prod": source}}).encode())

        rows = inventory_sources(self.context(self.client("claude", config)))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].family, "langfuse")
        self.assertEqual(rows[0].source, source)
        self.assertEqual(rows[0].ref.name, "worker-prod")
        self.assertFalse(rows[0].blockers)

    def test_read_source_resolves_current_mapping_from_the_original_reference(self):
        from client_sources import SourceRef, read_source

        path = self.write("claude/.claude.json", b'{"mcpServers":{"mysql-primary-dev":{"env":{"A":"old"}}}}')
        ref = SourceRef("claude", "global", "mysql-primary-dev", path, ("mcpServers", "mysql-primary-dev"))
        self.write("claude/.claude.json", b'{"mcpServers":{"mysql-primary-dev":{"env":{"A":"new"}}}}')

        self.assertEqual(read_source(self.context(self.client("claude", path)), ref), {"env": {"A": "new"}})

    def test_unknown_wrapper_remains_direct_with_a_reason_code(self):
        from client_sources import inventory_sources, public_plan

        source = {"command": "node", "args": ["/synthetic/unknown/mysql.cjs", "write"],
                  "env": {"MYSQL_PASS": "synthetic-secret"}}
        config = self.write("claude/.claude.json", json.dumps({"mcpServers": {"mysql-custom": source}}).encode())
        rows = inventory_sources(self.context(self.client("claude", config)))

        self.assertEqual(rows[0].family, "unknown")
        self.assertTrue(rows[0].blockers)
        self.assertIn("UNSUPPORTED", json.dumps(public_plan(rows)))

    def test_custom_mysql_launcher_is_unsupported_while_standard_source_is_admissible(self):
        from client_sources import inventory_sources, public_plan

        custom = {
            "command": "node",
            "args": ["/synthetic/custom-mysql-wrapper.cjs"],
            "env": {"MYSQL_PASS": "synthetic-secret"},
        }
        standard = {
            "command": "npx",
            "args": ["-y", "@benborla29/mcp-server-mysql"],
            "env": {
                "MYSQL_HOST": "synthetic.invalid",
                "MYSQL_PORT": "3306",
                "MYSQL_DB": "sample",
                "MYSQL_USER": "sample-user",
                "MYSQL_PASS": "synthetic-secret",
            },
        }
        config = self.write("claude/.claude.json", json.dumps({
            "mcpServers": {
                "mysql-primary-dev": custom,
                "mysql-secondary-dev": standard,
            },
        }).encode())

        candidates = inventory_sources(self.context(self.client("claude", config)))
        plan = {row["name"]: row for row in public_plan(candidates)}

        self.assertEqual(plan["mysql-primary-dev"]["status"], "UNSUPPORTED")
        self.assertEqual(plan["mysql-primary-dev"]["reason"], "MYSQL_SOURCE_INVALID")
        self.assertEqual(plan["mysql-secondary-dev"]["family"], "mysql")
        self.assertEqual(plan["mysql-secondary-dev"]["status"], "ELIGIBLE")

if __name__ == "__main__":
    unittest.main()
