import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pilot import SafeError


TOKEN = "a" * 64
INSTALL_KEY = b"client-projection-test-key-32-bytes!!"


class ClientProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="mcp-client-projection-", dir=Path(__file__).resolve().parents[1]
        )
        self.home = Path(self.temp.name)
        self.home.chmod(0o700)
        self.runtime = self.home / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.release = self.home / "release"
        self.release.mkdir(mode=0o700)
        self.root = self.home / "Library" / "Application Support" / "Personal MCP Manager"
        self.root.mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, raw):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def claude_context(self, source, *, project=None):
        client_dir = self.home / ".claude"
        client_dir.mkdir(mode=0o700, exist_ok=True)
        config_data = {"mcpServers": {"loki-stg": source}}
        if project:
            config_data["projects"] = {project: {"mcpServers": {"loki-stg": source}}}
            config_data["mcpServers"] = {}
        config = self.write(self.home / ".claude.json", json.dumps(config_data).encode())
        settings = self.write(client_dir / "settings.json", b"{}")
        client = SimpleNamespace(kind="claude", config=config, settings=settings,
                                 plugin_roots=(), owner_executables=())
        return SimpleNamespace(root=self.root, release=self.release, runtime=self.runtime,
                               python=Path("/usr/bin/python3"), node=Path("/usr/bin/node"),
                               port=18765, clients=(client,)), config, settings

    def codex_context(self, source, name="grafana-dev"):
        config = self.write(self.home / ".codex" / "config.toml", b"")
        import migrate
        lines = [f"[mcp_servers.{json.dumps(name)}]"]
        for key in ("command", "args", "enabled", "required", "startup_timeout_sec",
                    "startup_timeout_ms", "tool_timeout_sec", "enabled_tools",
                    "disabled_tools", "tools", "cwd"):
            if key in source:
                lines.append(f"{key} = {migrate.literal(source[key])}")
        if "env" in source:
            lines.append(f"[mcp_servers.{json.dumps(name)}.env]")
            lines.extend(f"{key} = {migrate.literal(value)}" for key, value in source["env"].items())
        config.write_text("\n".join(lines) + "\n")
        config.chmod(0o600)
        client = SimpleNamespace(kind="codex", config=config, settings=None,
                                 plugin_roots=(), owner_executables=())
        return SimpleNamespace(root=self.root, release=self.release, runtime=self.runtime,
                               python=Path("/usr/bin/python3"), node=Path("/usr/bin/node"),
                               port=18765, clients=(client,)), config

    def test_codex_source_moves_to_disabled_same_file_backup_and_offline_rollback_restores_it(self):
        import client_projection
        from client_sources import inventory_sources

        native = {"command": "uvx", "args": ["mcp-grafana"], "env": {
            "GRAFANA_URL": "https://synthetic.invalid",
            "GRAFANA_SERVICE_ACCOUNT_TOKEN": "synthetic-secret",
        }, "enabled_tools": ["list_datasources"]}
        context, config = self.codex_context(native)
        before = tomllib.loads(config.read_text())
        selected = inventory_sources(context)

        result = client_projection.project_clients(
            context, selected, token=TOKEN, install_key=INSTALL_KEY
        )
        installed = tomllib.loads(config.read_text())["mcp_servers"]

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["operation"], "PROJECTED")
        self.assertEqual(installed["grafana-dev"]["url"], "http://127.0.0.1:18765/mcp/grafana-dev")
        self.assertFalse(installed["personal-manager-source-grafana-dev"]["enabled"])
        self.assertEqual(installed["personal-manager-source-grafana-dev"]["env"], native["env"])
        self.assertNotIn("synthetic-secret", config_projection_journal(context).read_text())
        restored = client_projection.restored_sources(
            context, install_key=INSTALL_KEY, token=TOKEN
        )
        self.assertEqual([(row.ref.client, row.ref.scope, row.ref.name) for row in restored],
                         [("codex", "global", "grafana-dev")])
        self.assertEqual(restored[0].source, native)
        self.assertTrue(client_projection.verify_projections(
            context, selected, token=TOKEN, install_key=INSTALL_KEY
        )["verified"])

        rollback = client_projection.rollback_clients(context, install_key=INSTALL_KEY)
        self.assertEqual(rollback["operation"], "ROLLED_BACK")
        self.assertEqual(tomllib.loads(config.read_text()), before)

    def test_claude_denies_backup_before_same_file_replacement_and_offline_recovery(self):
        import client_projection
        from client_sources import inventory_sources

        source = {"command": "npx", "args": ["-y", "simple-loki-mcp"], "env": {
            "LOKI_ADDR": "synthetic", "LOKI_DATASOURCE_ID": "synthetic-id",
            "LOKI_BEARER_TOKEN": "synthetic-secret",
        }}
        context, config, settings = self.claude_context(source)
        selected = inventory_sources(context)
        original_replace = client_projection._atomic_replace
        writes = []

        def interrupt_after_denial(path, before, after, *, create=False):
            writes.append(Path(path))
            if Path(path) == config:
                self.assertIn({"serverName": "personal-manager-source-loki-stg"},
                              json.loads(settings.read_text())["deniedMcpServers"])
                self.assertEqual(json.loads(config.read_text())["mcpServers"]["loki-stg"], source)
                raise RuntimeError("synthetic-interruption")
            return original_replace(path, before, after, create=create)

        with patch.object(client_projection, "_atomic_replace", side_effect=interrupt_after_denial):
            with self.assertRaisesRegex(RuntimeError, "synthetic-interruption"):
                client_projection.project_clients(context, selected, token=TOKEN,
                                                  install_key=INSTALL_KEY)

        self.assertEqual(writes, [settings, config])
        self.assertIn("synthetic-secret", config.read_text())
        recovered = client_projection.rollback_clients(context, install_key=INSTALL_KEY)
        self.assertEqual(recovered["operation"], "ROLLED_BACK")
        self.assertEqual(json.loads(config.read_text())["mcpServers"]["loki-stg"], source)
        self.assertNotIn("deniedMcpServers", json.loads(settings.read_text()))

    def test_project_scope_stays_project_scoped_and_rollback_restores_it(self):
        import client_projection
        from client_sources import inventory_sources

        source = {"command": "npx", "args": ["-y", "simple-loki-mcp"], "env": {
            "LOKI_ADDR": "synthetic", "LOKI_DATASOURCE_ID": "synthetic-id",
            "LOKI_BEARER_TOKEN": "project-secret",
        }}
        project = "/synthetic/work tree"
        context, config, _ = self.claude_context(source, project=project)
        selected = inventory_sources(context, projects=(Path(project),))
        selected = [candidate for candidate in selected if candidate.ref.scope == "project"]
        before = json.loads(config.read_text())

        client_projection.project_clients(context, selected, token=TOKEN, install_key=INSTALL_KEY)
        projected = json.loads(config.read_text())
        project_servers = projected["projects"][project]["mcpServers"]
        self.assertIn("loki-stg", project_servers)
        self.assertNotIn("loki-stg", projected["mcpServers"])
        self.assertTrue(client_projection.verify_projections(
            context, selected, token=TOKEN, install_key=INSTALL_KEY
        )["verified"])
        self.assertEqual(client_projection.rollback_clients(context, install_key=INSTALL_KEY)["operation"],
                         "ROLLED_BACK")
        self.assertEqual(json.loads(config.read_text()), before)

    def test_codex_plugin_projection_only_adds_and_removes_its_own_scoped_disable(self):
        import client_projection
        import source_inputs
        from client_sources import inventory_sources
        from migrate import literal

        plugin_id = "external-mcp@synthetic-marketplace"
        plugin_root = self.home / ".codex" / "plugins" / "cache" / "synthetic-marketplace" / "external-mcp" / "1.0.0"
        plugin_root.mkdir(parents=True, mode=0o700)
        plugin_source = {"command": "npx", "args": ["-y", "simple-loki-mcp"], "env": {
            "LOKI_ADDR": "synthetic", "LOKI_DATASOURCE_ID": "synthetic-id",
            "LOKI_BEARER_TOKEN": "plugin-secret",
        }}
        codex_config = self.write(self.home / ".codex" / "config.toml",
            f"[plugins.{literal(plugin_id)}]\nenabled = true\n".encode())
        client = SimpleNamespace(kind="codex", config=codex_config, settings=None,
                                 plugin_roots=(plugin_root,), owner_executables=())
        context = SimpleNamespace(root=self.root, release=self.release, runtime=self.runtime,
            python=Path("/usr/bin/python3"), node=Path("/usr/bin/node"), port=18765,
            clients=(client,))
        plugin = {"id": plugin_id, "path": str(plugin_root), "sourcePath": ".mcp.json",
                  "servers": {"loki-stg": plugin_source}, "reviewed": True}
        with patch.object(source_inputs, "read_plugins", return_value=[plugin]):
            selected = inventory_sources(context)
            self.assertEqual(len(selected), 1)
            client_projection.project_clients(context, selected, token=TOKEN,
                                              install_key=INSTALL_KEY)
            projected = tomllib.loads(codex_config.read_text())
            self.assertFalse(projected["plugins"][plugin_id]["mcp_servers"]["loki-stg"]["enabled"])
            self.assertEqual(projected["mcp_servers"]["loki-stg"]["url"],
                             "http://127.0.0.1:18765/mcp/loki-stg")
            self.assertTrue(client_projection.verify_projections(
                context, selected, token=TOKEN, install_key=INSTALL_KEY
            )["verified"])
            self.assertEqual(client_projection.rollback_clients(
                context, install_key=INSTALL_KEY
            )["operation"], "ROLLED_BACK")
        restored = tomllib.loads(codex_config.read_text())
        self.assertNotIn("mcp_servers", restored["plugins"][plugin_id])
        self.assertNotIn("mcp_servers", restored)

    def test_two_clients_with_same_name_and_different_credentials_get_distinct_routes(self):
        import client_projection
        from client_sources import inventory_sources

        claude_source = {"command": "npx", "args": ["-y", "simple-loki-mcp"], "env": {
            "LOKI_ADDR": "synthetic-a", "LOKI_DATASOURCE_ID": "datasource-a",
            "LOKI_BEARER_TOKEN": "secret-a",
        }}
        codex_source = {"command": "npx", "args": ["-y", "simple-loki-mcp"], "env": {
            "LOKI_ADDR": "synthetic-b", "LOKI_DATASOURCE_ID": "datasource-b",
            "LOKI_BEARER_TOKEN": "secret-b",
        }}
        claude_context, claude_config, claude_settings = self.claude_context(claude_source)
        codex_context, codex_config = self.codex_context(codex_source, "loki-stg")
        context = SimpleNamespace(**{**vars(claude_context), "clients":
                                     (claude_context.clients[0], codex_context.clients[0])})
        selected = inventory_sources(context)
        self.assertEqual(len(selected), 2)
        client_projection.project_clients(context, selected, token=TOKEN, install_key=INSTALL_KEY)

        from portable_engine import read_routes
        routes = read_routes(context, TOKEN)
        self.assertEqual(len({row["route_id"] for row in routes}), 2)
        self.assertEqual(len({row["source_hmac"] for row in routes}), 2)
        for candidate in selected:
            ref = candidate.ref
            native = client_projection.resolve_native_source(
                context, ref, install_key=INSTALL_KEY
            )
            self.assertEqual(native, candidate.source)
        persisted = (Path(context.runtime) / "routes.json").read_text() + config_projection_journal(context).read_text()
        self.assertNotIn("secret-a", persisted)
        self.assertNotIn("secret-b", persisted)
        self.assertEqual(client_projection.rollback_clients(context, install_key=INSTALL_KEY)["operation"],
                         "ROLLED_BACK")
        self.assertEqual(json.loads(claude_config.read_text())["mcpServers"]["loki-stg"], claude_source)
        self.assertEqual(tomllib.loads(codex_config.read_text())["mcp_servers"]["loki-stg"], codex_source)

    def test_offline_recovery_after_second_client_write_fails_preserves_both_sources(self):
        import client_projection
        from client_sources import inventory_sources

        claude_source = {"command": "npx", "args": ["-y", "simple-loki-mcp"], "env": {
            "LOKI_ADDR": "synthetic-a", "LOKI_DATASOURCE_ID": "datasource-a",
            "LOKI_BEARER_TOKEN": "secret-a",
        }}
        codex_source = {"command": "npx", "args": ["-y", "simple-loki-mcp"], "env": {
            "LOKI_ADDR": "synthetic-b", "LOKI_DATASOURCE_ID": "datasource-b",
            "LOKI_BEARER_TOKEN": "secret-b",
        }}
        claude_context, claude_config, claude_settings = self.claude_context(claude_source)
        codex_context, codex_config = self.codex_context(codex_source, "loki-stg")
        context = SimpleNamespace(**{**vars(claude_context), "clients":
                                     (claude_context.clients[0], codex_context.clients[0])})
        selected = inventory_sources(context)
        original_replace = client_projection._atomic_replace

        def fail_codex(path, before, after, *, create=False):
            if Path(path) == codex_config:
                raise RuntimeError("synthetic second-client interruption")
            return original_replace(path, before, after, create=create)

        with patch.object(client_projection, "_atomic_replace", side_effect=fail_codex):
            with self.assertRaisesRegex(RuntimeError, "second-client interruption"):
                client_projection.project_clients(context, selected, token=TOKEN,
                                                  install_key=INSTALL_KEY)

        claude_servers = json.loads(claude_config.read_text())["mcpServers"]
        self.assertTrue(any(row.get("url", "").startswith("http://127.0.0.1:18765/mcp/")
                            for row in claude_servers.values()))
        self.assertTrue(any(row.get("serverName", "").startswith("personal-manager-source-loki-stg-")
                            for row in json.loads(claude_settings.read_text())["deniedMcpServers"]))
        self.assertEqual(tomllib.loads(codex_config.read_text())["mcp_servers"]["loki-stg"], codex_source)
        result = client_projection.rollback_clients(context, install_key=INSTALL_KEY)
        self.assertEqual(result["operation"], "ROLLED_BACK")
        self.assertEqual(json.loads(claude_config.read_text())["mcpServers"]["loki-stg"], claude_source)
        self.assertEqual(tomllib.loads(codex_config.read_text())["mcp_servers"]["loki-stg"], codex_source)
        self.assertNotIn("deniedMcpServers", json.loads(claude_settings.read_text()))

    def test_rollback_refuses_an_edited_managed_route_and_keeps_recovery_journal(self):
        import client_projection
        from client_sources import inventory_sources

        native = {"command": "uvx", "args": ["mcp-grafana"], "env": {
            "GRAFANA_URL": "https://synthetic.invalid",
            "GRAFANA_SERVICE_ACCOUNT_TOKEN": "synthetic-secret",
        }}
        context, config = self.codex_context(native)
        selected = inventory_sources(context)
        client_projection.project_clients(context, selected, token=TOKEN,
                                          install_key=INSTALL_KEY)
        text = config.read_text().replace("mcp/grafana-dev", "mcp/foreign")
        config.write_text(text)
        config.chmod(0o600)

        with self.assertRaisesRegex(SafeError, "PROJECTION_CONFLICT"):
            client_projection.rollback_clients(context, install_key=INSTALL_KEY)
        self.assertTrue(config_projection_journal(context).exists())


def config_projection_journal(context):
    return Path(context.runtime) / "client-projections.jsonl"


if __name__ == "__main__":
    unittest.main()
