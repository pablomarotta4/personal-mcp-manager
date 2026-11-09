"""Local pipeline fixtures; acquisition and signed host clients are separate proof.

These tests use a synthetic backend at the artifact-admission boundary. Source
inventory, provisioning, manifest verification, HTTP runtime, conditional client
projection and offline restoration execute their real implementations.
"""
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from unittest.mock import patch

from installation_context import ClientPaths, InstallContext
from pilot import read_token


RELEASE = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")


@unittest.skipUnless(NODE and (RELEASE / "dist/index.js").is_file(), "build manager first")
class InstallationPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="portable-install-e2e-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name).resolve()
        self.home.chmod(0o700)
        self.root = self.home / "Library/Application Support/Personal MCP Manager"
        self.root.mkdir(parents=True, mode=0o700)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.artifacts = self.root / "artifacts"
        self.artifact_root = self.artifacts / "grafana" / ("a" * 64)
        self.artifact_root.mkdir(parents=True, mode=0o700)
        self.node = Path(NODE).resolve()
        executable = self.artifact_root / "synthetic-backend"
        executable.write_text("#!/bin/sh\nexec " + shlex.quote(str(self.node)) + " "
                              + shlex.quote(str(RELEASE / "test/fixtures/backend.mjs")) + "\n")
        executable.chmod(0o700)
        self.artifact = {"family": "grafana", "profileIds": ["grafana-dev"],
            "sourceIdentity": "synthetic-fixture:1", "artifactRoot": str(self.artifact_root),
            "closureDigest": "a" * 64, "dependencyReportSha256": "b" * 64,
            "nativeCommand": [str(executable)],
            "artifactSha256": hashlib.sha256(executable.read_bytes()).hexdigest()}
        self.before = {}

    def context(self, kinds):
        clients = []
        for kind in kinds:
            source = {"command": "uvx", "args": ["mcp-grafana"], "env": {
                "GRAFANA_URL": "https://synthetic.invalid",
                "GRAFANA_SERVICE_ACCOUNT_TOKEN": "synthetic-secret-" + kind}}
            if kind == "claude":
                config = self.home / ".claude.json"
                config.write_text(json.dumps({"mcpServers": {"grafana-dev": source}}))
                directory = self.home / ".claude"
                directory.mkdir(mode=0o700)
                settings = directory / "settings.json"
                settings.write_text("{}")
                settings.chmod(0o600)
            else:
                directory = self.home / ".codex"
                directory.mkdir(mode=0o700)
                config = directory / "config.toml"
                settings = None
                config.write_text('[mcp_servers.grafana-dev]\ncommand = "uvx"\n'
                    'args = ["mcp-grafana"]\n[mcp_servers.grafana-dev.env]\n'
                    'GRAFANA_URL = "https://synthetic.invalid"\n'
                    'GRAFANA_SERVICE_ACCOUNT_TOKEN = "synthetic-secret-codex"\n')
            config.chmod(0o600)
            self.before[config] = self.semantic(config)
            if settings is not None:
                self.before[settings] = self.semantic(settings)
            clients.append(ClientPaths(kind, config, settings, (), ()))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        return InstallContext(1, self.root, RELEASE, self.runtime, self.artifacts,
                              Path(sys.executable).resolve(), self.node, port, tuple(clients))

    @staticmethod
    def semantic(path):
        return tomllib.loads(path.read_text()) if path.suffix == ".toml" else json.loads(path.read_bytes())

    def capture_catalog(self):
        script = """
import {BackendPool} from './dist/pool.js';
import {parseConfig} from './dist/policy.js';
import {fingerprintDescription} from './dist/manifest.js';
let raw='';for await(const c of process.stdin)raw+=c;
const input=JSON.parse(raw),pool=new BackendPool(parseConfig({mcpServers:{fixture:input.policy}}),{ownershipDir:input.ownership});
try{const catalog=await pool.describe('fixture');process.stdout.write(JSON.stringify({catalog,catalogFingerprint:fingerprintDescription(catalog)}));}
finally{await pool.shutdown();}
"""
        ownership = self.home / "catalog-ownership"
        ownership.mkdir(mode=0o700)
        payload = {"ownership": str(ownership), "policy": {
            "command": self.artifact["nativeCommand"][0], "args": [], "cwd": str(self.home),
            "env": {}, "shared": True, "allowedTools": ["read", "write"]}}
        result = subprocess.run([str(self.node), "--input-type=module", "-e", script],
            input=json.dumps(payload).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=RELEASE, timeout=30)
        self.assertEqual(result.returncode, 0, "synthetic catalog discovery failed")
        self.artifact.update(json.loads(result.stdout))
        self.assertEqual(list(ownership.iterdir()), [])

    def exercise_http(self, context, policies, route_ids):
        from portable_engine import _candidate_status
        child = subprocess.Popen([str(self.node), str(RELEASE / "dist/index.js"),
            "--config-stdin", "--token-file", str(self.runtime / "token"),
            "--port", str(context.port), "--manifest-dir", str(self.runtime / "manifests")],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=RELEASE)
        try:
            child.stdin.write(json.dumps({"mcpServers": policies}).encode())
            child.stdin.close()
            deadline = time.monotonic() + 10
            while True:
                self.assertIsNone(child.poll(), "fixture daemon exited during startup")
                try:
                    status = _candidate_status(context)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        self.fail("fixture daemon readiness timed out")
                    time.sleep(0.05)
            self.assertTrue(status["quiescent"])
            script = """
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
let raw='';for await(const c of process.stdin)raw+=c;const input=JSON.parse(raw);
for(const route of input.routes){const client=new Client({name:'fixture',version:'1'});
try{await client.connect(new StreamableHTTPClientTransport(new URL(input.url+'/mcp/'+route),{requestInit:{headers:{Authorization:'Bearer '+input.token}}}));
const tools=await client.listTools();if(tools.tools.length!==2)throw Error('catalog mismatch');
const read=await client.callTool({name:'read',arguments:{}});if(read.isError||read.structuredContent?.ok!==true)throw Error('synthetic read failed');}
finally{await client.close();}}
process.stdout.write('PASS');
"""
            payload = {"url": f"http://127.0.0.1:{context.port}",
                       "token": read_token(self.runtime / "token"), "routes": route_ids}
            result = subprocess.run([str(self.node), "--input-type=module", "-e", script],
                input=json.dumps(payload).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=RELEASE, timeout=30)
            self.assertEqual(result.returncode, 0, "fixture HTTP catalog/read failed")
            self.assertEqual(result.stdout, b"PASS")
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            self.assertEqual(child.wait(timeout=20), 0, "owned fixture shutdown failed")
        self.assertEqual(list((self.runtime / "ownership").iterdir()), [])

    def run_matrix(self, kinds):
        from client_sources import inventory_sources
        from client_projection import project_clients, verify_projections, rollback_clients
        from portable_engine import prepare_runtime, load_runtime
        context = self.context(kinds)
        selected = inventory_sources(context)
        self.assertEqual(len(selected), len(kinds))
        self.capture_catalog()
        # The only substituted boundary is acquisition: no registry/network or
        # external provider is involved in this deterministic pipeline fixture.
        with patch("artifact_install.verify_artifact_admission", create=True, return_value=None):
            result = prepare_runtime(context, selected, {"grafana": self.artifact})
            self.assertEqual(result["profile_count"], len(kinds))
            token = read_token(self.runtime / "token")
            key = bytes.fromhex(token)
            policies, _, records = load_runtime(context)
            self.assertEqual(len(policies), len(kinds))
            if len(kinds) == 2:
                self.assertEqual(len({row["env"]["GRAFANA_SERVICE_ACCOUNT_TOKEN"] for row in policies.values()}), 2)
                self.assertTrue(all(name.startswith("grafana-dev-") for name in policies))
            self.assertEqual(project_clients(context, selected, token=token, install_key=key)["operation"], "PROJECTED")
            self.assertTrue(verify_projections(context, selected, token=token, install_key=key)["verified"])
            self.assertEqual(project_clients(context, selected, token=token, install_key=key)["operation"], "ALREADY_PROJECTED")
            loaded, _, _ = load_runtime(context)
            self.assertEqual(loaded, policies)
            self.exercise_http(context, policies, list(records))
            self.assertEqual(rollback_clients(context, install_key=key)["operation"], "ROLLED_BACK")
            for path, before in self.before.items():
                self.assertEqual(self.semantic(path), before)
            # Restore is offline and does not invalidate the source-bound policy.
            self.assertEqual(load_runtime(context)[0], policies)
        for path in self.runtime.rglob("*.json"):
            raw = path.read_bytes()
            self.assertNotIn(b"synthetic-secret-claude", raw)
            self.assertNotIn(b"synthetic-secret-codex", raw)

    def test_claude_only_pipeline_and_offline_restore(self):
        self.run_matrix(("claude",))

    def test_codex_only_pipeline_and_offline_restore(self):
        self.run_matrix(("codex",))

    def test_both_clients_keep_unequal_sources_separate(self):
        self.run_matrix(("claude", "codex"))


if __name__ == "__main__":
    unittest.main()
