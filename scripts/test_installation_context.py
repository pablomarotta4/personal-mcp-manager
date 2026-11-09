import json
from dataclasses import replace
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


class InstallationContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name).resolve()
        self.root = self.home / "Library/Application Support/Personal MCP Manager"
        self.config = self.home / ".codex/config.toml"
        self.settings = self.home / ".claude/settings.json"
        self.context_type = __import__("installation_context").InstallContext
        self.client_type = __import__("installation_context").ClientPaths

    def tearDown(self):
        self.temporary.cleanup()

    def context(self, *, port=18765, root=None):
        module = __import__("installation_context")
        actual_root = root or self.root
        clients = (
            self.client_type(
                kind="claude",
                config=self.home / ".claude.json",
                settings=self.settings,
                plugin_roots=(self.home / ".claude/plugins",),
                owner_executables=(),
            ),
            self.client_type(
                kind="codex",
                config=self.config,
                settings=None,
                plugin_roots=(self.home / ".codex/plugins",),
                owner_executables=(),
            ),
        )
        return self.context_type(
            version=1,
            root=actual_root,
            release=actual_root / "app/releases/0.1.0-fixture",
            runtime=actual_root / "runtime",
            artifacts=actual_root / "artifacts",
            python=Path("/usr/bin/python3"),
            node=Path("/usr/local/bin/node"),
            port=port,
            clients=clients,
        )

    def test_default_root_and_descriptor_round_trip(self):
        from installation_context import default_root, load_context, write_context

        expected = self.home / "Library/Application Support/Personal MCP Manager"
        self.assertEqual(default_root(self.home), expected)
        context = self.context()
        write_context(context)
        loaded = load_context(context.root / "installation.json")
        self.assertEqual(loaded, context)
        self.assertEqual(stat.S_IMODE(context.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((context.root / "installation.json").stat().st_mode), 0o600)

    def test_replace_context_updates_only_release_and_reads_back_exact_descriptor(self):
        import installation_context
        from installation_context import load_context, replace_context, write_context

        previous = self.context()
        write_context(previous)
        updated = replace(previous, release=previous.root / "app/releases/0.2.0-next")

        replace_context(previous, updated)

        descriptor = previous.root / "installation.json"
        self.assertEqual(descriptor.read_bytes(), installation_context._serialize_context(updated))
        self.assertEqual(load_context(descriptor), updated)
        self.assertEqual(stat.S_IMODE(descriptor.stat().st_mode), 0o600)

    def test_replace_context_refuses_scope_or_descriptor_conflict_without_edit(self):
        import installation_context
        from installation_context import InstallationContextError, replace_context, write_context

        previous = self.context()
        write_context(previous)
        descriptor = previous.root / "installation.json"
        original = descriptor.read_bytes()
        updated = replace(previous, release=previous.root / "app/releases/0.2.0-next")
        with self.assertRaises(InstallationContextError):
            replace_context(previous, replace(updated, port=previous.port + 1))
        self.assertEqual(descriptor.read_bytes(), original)

        descriptor.write_bytes(original + b" ")
        os.chmod(descriptor, 0o600)
        conflicting = descriptor.read_bytes()
        with self.assertRaises(InstallationContextError):
            replace_context(previous, updated)
        self.assertEqual(descriptor.read_bytes(), conflicting)

    def test_helper_argv_round_trips_shell_metacharacters_without_execution(self):
        from installation_context import helper_argv

        root = self.home / "O'Brien $(false)"
        context = self.context(root=root)
        argv = helper_argv(context, "loki-prd")
        self.assertEqual(shlex.split(shlex.join(argv)), argv)
        self.assertTrue(any("O'Brien $(false)" in item for item in argv))

    def test_missing_descriptor_is_refused(self):
        from installation_context import InstallationContextError, load_context

        with self.assertRaises(InstallationContextError):
            load_context(self.root / "installation.json")

    def test_symlinked_root_is_refused(self):
        from installation_context import InstallationContextError, load_context, write_context

        context = self.context()
        write_context(context)
        alias = self.home / "manager-alias"
        alias.symlink_to(context.root, target_is_directory=True)
        with self.assertRaises(InstallationContextError):
            load_context(alias / "installation.json")

    def test_extra_descriptor_fields_are_refused(self):
        from installation_context import InstallationContextError, load_context, write_context

        context = self.context()
        write_context(context)
        descriptor = context.root / "installation.json"
        value = json.loads(descriptor.read_text())
        value["credential"] = "synthetic-secret"
        descriptor.write_text(json.dumps(value))
        os.chmod(descriptor, 0o600)
        with self.assertRaises(InstallationContextError):
            load_context(descriptor)

    def test_wrong_descriptor_mode_and_owner_are_refused(self):
        from installation_context import InstallationContextError, load_context, write_context

        context = self.context()
        write_context(context)
        descriptor = context.root / "installation.json"
        os.chmod(descriptor, 0o640)
        with self.assertRaises(InstallationContextError):
            load_context(descriptor)
        os.chmod(descriptor, 0o600)
        with mock.patch("installation_context.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(InstallationContextError):
                load_context(descriptor)

    def test_out_of_range_ports_are_refused(self):
        from installation_context import InstallationContextError, write_context

        for port in (0, 65536, True):
            with self.subTest(port=port):
                with self.assertRaises(InstallationContextError):
                    write_context(self.context(port=port, root=self.home / f"root-{port}"))

    def test_discovery_uses_only_the_explicit_home_and_verified_client_binaries(self):
        from installation_context import discover_clients

        codex_config = self.home / ".codex/config.toml"
        codex_config.parent.mkdir(parents=True)
        codex_config.write_text("# synthetic\n")
        claude_config = self.home / ".claude.json"
        claude_config.write_text("{}\n")
        codex = self.home / "Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
        codex.parent.mkdir(parents=True)
        codex.write_text("synthetic codex executable")
        claude = self.home / ".local/share/claude/versions/2.1"
        claude.parent.mkdir(parents=True)
        claude.write_text("synthetic claude executable")
        os.chmod(codex, 0o755)
        os.chmod(claude, 0o755)

        with mock.patch("installation_context.platform.system", return_value="Darwin"), mock.patch(
            "installation_context.subprocess.run", return_value=subprocess.CompletedProcess([], 0)
        ) as verify, mock.patch("installation_context.Path.home", side_effect=AssertionError("implicit home")):
            clients = discover_clients(self.home)

        by_kind = {client.kind: client for client in clients}
        self.assertEqual(set(by_kind), {"claude", "codex"})
        self.assertEqual(by_kind["codex"].config, codex_config)
        self.assertEqual(by_kind["claude"].config, claude_config)
        self.assertIn(codex, by_kind["codex"].owner_executables)
        self.assertIn(claude, by_kind["claude"].owner_executables)
        self.assertGreaterEqual(verify.call_count, 2)

    def test_discovery_does_not_claim_an_unsigned_binary(self):
        from installation_context import discover_clients

        config = self.home / ".codex/config.toml"
        config.parent.mkdir(parents=True)
        config.write_text("# synthetic\n")
        codex = self.home / "Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
        codex.parent.mkdir(parents=True)
        codex.write_text("unsigned fixture")
        os.chmod(codex, 0o755)

        with mock.patch("installation_context.platform.system", return_value="Darwin"), mock.patch(
            "installation_context.subprocess.run", return_value=subprocess.CompletedProcess([], 1)
        ):
            clients = discover_clients(self.home)

        self.assertEqual([client.kind for client in clients], ["codex"])
        self.assertEqual(clients[0].owner_executables, ())

    def test_discovery_includes_only_exact_installed_plugin_roots(self):
        from installation_context import discover_clients

        codex_config = self.home / ".codex/config.toml"
        codex_config.parent.mkdir(parents=True)
        codex_config.write_text('[plugins."external-mcp@marketplace"]\nenabled = true\n')
        claude_config = self.home / ".claude.json"
        claude_config.write_text("{}\n")

        codex_root = self.home / ".codex/plugins/cache/marketplace/external-mcp/1.7.0"
        (codex_root / ".codex-plugin").mkdir(parents=True)
        (codex_root / ".codex-plugin/plugin.json").write_text(json.dumps({"name": "external-mcp", "version": "1.7.0"}))
        (codex_root / ".mcp.json").write_text('{"mcpServers":{}}')
        claude_root = self.home / ".claude/plugins/cache/marketplace/external-mcp/1.7.0"
        (claude_root / ".claude-plugin").mkdir(parents=True)
        (claude_root / ".claude-plugin/plugin.json").write_text(json.dumps({"name": "external-mcp", "version": "1.7.0"}))
        (claude_root / ".mcp.json").write_text('{"mcpServers":{}}')
        installed = self.home / ".claude/plugins/installed_plugins.json"
        installed.write_text(json.dumps({"plugins": {
            "external-mcp@marketplace": [{"installPath": str(claude_root)}],
        }}))
        claude_settings = self.home / ".claude/settings.json"
        claude_settings.parent.mkdir(parents=True, exist_ok=True)
        claude_settings.write_text(json.dumps({"enabledPlugins": {"external-mcp@marketplace": True}}))
        unused = self.home / ".codex/plugins/cache/unused/other/1.0.0"
        (unused / ".codex-plugin").mkdir(parents=True)
        (unused / ".codex-plugin/plugin.json").write_text(json.dumps({"name": "other", "version": "1.0.0"}))
        (unused / ".mcp.json").write_text('{"mcpServers":{}}')

        with mock.patch("installation_context.platform.system", return_value="Darwin"), mock.patch(
            "installation_context.subprocess.run", return_value=subprocess.CompletedProcess([], 0)
        ):
            clients = {client.kind: client for client in discover_clients(self.home)}

        self.assertEqual(clients["codex"].plugin_roots, (codex_root,))
        self.assertEqual(clients["claude"].plugin_roots, (claude_root,))
        self.assertNotIn(unused, clients["codex"].plugin_roots)

    def test_unselected_or_stale_plugin_roots_do_not_block_discovery(self):
        from installation_context import discover_clients

        codex_config = self.home / ".codex/config.toml"
        codex_config.parent.mkdir(parents=True)
        codex_config.write_text('[plugins."stale@marketplace"]\nenabled = false\n')
        codex_root = self.home / ".codex/plugins/cache/marketplace/stale/1.0.0"
        (codex_root / ".codex-plugin").mkdir(parents=True)
        (codex_root / ".codex-plugin/plugin.json").write_text(json.dumps({"name": "stale", "version": "1.0.0"}))
        (codex_root / ".mcp.json").write_text('{"mcpServers":{}}')
        (self.home / ".claude.json").write_text("{}\n")
        settings = self.home / ".claude/settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"enabledPlugins": {"active@marketplace": True}}))
        registry = self.home / ".claude/plugins/installed_plugins.json"
        registry.parent.mkdir(parents=True)
        registry.write_text(json.dumps({"plugins": {
            "stale@marketplace": [{"installPath": str(self.home / "missing/stale")}],
        }}))

        with mock.patch("installation_context.platform.system", return_value="Darwin"):
            clients = {client.kind: client for client in discover_clients(self.home)}

        self.assertEqual(clients["codex"].plugin_roots, ())
        self.assertEqual(clients["claude"].plugin_roots, ())

    def test_ambiguous_codex_plugin_versions_fail_discovery(self):
        from installation_context import InstallationContextError, discover_clients

        config = self.home / ".codex/config.toml"
        config.parent.mkdir(parents=True)
        config.write_text('[plugins."external-mcp@marketplace"]\nenabled = true\n')
        for version in ("1.0.0", "1.1.0"):
            root = self.home / f".codex/plugins/cache/marketplace/external-mcp/{version}"
            (root / ".codex-plugin").mkdir(parents=True)
            (root / ".codex-plugin/plugin.json").write_text(json.dumps({"name": "external-mcp", "version": version}))
            (root / ".mcp.json").write_text('{"mcpServers":{}}')

        with mock.patch("installation_context.platform.system", return_value="Darwin"):
            with self.assertRaisesRegex(InstallationContextError, "CODEX_PLUGIN_ROOT_AMBIGUOUS"):
                discover_clients(self.home)

    def test_incomplete_active_codex_plugin_reports_bounded_missing_root(self):
        from installation_context import InstallationContextError, discover_clients

        config = self.home / ".codex/config.toml"
        config.parent.mkdir(parents=True)
        config.write_text('[plugins."external-mcp@marketplace"]\nenabled = true\n')
        root = self.home / ".codex/plugins/cache/marketplace/external-mcp/1.7.0"
        (root / ".codex-plugin").mkdir(parents=True)
        (root / ".codex-plugin/plugin.json").write_text(json.dumps({"name": "external-mcp", "version": "1.7.0"}))

        with mock.patch("installation_context.platform.system", return_value="Darwin"):
            with self.assertRaisesRegex(InstallationContextError, "CODEX_PLUGIN_ROOT_MISSING"):
                discover_clients(self.home)

    def test_explicit_claude_discovery_does_not_read_codex_plugin_state(self):
        from installation_context import discover_clients

        config = self.home / ".codex/config.toml"
        config.parent.mkdir(parents=True)
        config.write_text('[plugins."external-mcp@marketplace"]\nenabled = true\n')
        claude = self.home / ".claude.json"
        claude.write_text("{}\n")

        with mock.patch("installation_context.platform.system", return_value="Darwin"):
            clients = discover_clients(self.home, kinds={"claude"})

        self.assertEqual([client.kind for client in clients], ["claude"])


if __name__ == "__main__":
    unittest.main()
