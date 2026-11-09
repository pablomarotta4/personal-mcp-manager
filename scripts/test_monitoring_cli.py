"""Regression coverage for read-only, bounded manager monitoring."""

from __future__ import annotations

from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


OLD_STATUS = {
    "draining": False,
    "quiescent": False,
    "pending": 3,
    "requests": 3,
    "active": 3,
    "backendStarts": 24,
    "backendLive": 11,
    "retained": 15,
}

GENERATION_A = "2e3587a1-a5cb-4ce8-a7d6-01508f390231"
GENERATION_B = "d5b7ec22-4b63-4a7f-93ce-62884cb33711"
TRAFFIC = {
    "generation": GENERATION_A,
    "profiles": {
        "demo": {
            "catalogRequests": 4,
            "toolAttempts": 3,
            "toolSuccesses": 2,
            "toolFailures": 1,
        }
    },
}
MONITORING = {
    "version": 1,
    "uptimeSeconds": 123.5,
    "sessions": 2,
    "idleSessions": 1,
    "busySessions": 1,
    "subscriptions": 1,
    "profiles": {
        "demo": {
            "sessions": 2,
            "idleSessions": 1,
            "busySessions": 1,
            "subscriptions": 1,
            "requests": 3,
            "active": 1,
            "backendLive": 1,
            "retained": 2,
        }
    },
}


class MonitoringCliTests(unittest.TestCase):
    def start_http_fixture(self, handler):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        except PermissionError:
            self.skipTest("sandbox does not permit loopback listeners")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_old_status_keeps_health_but_marks_unavailable_sessions(self):
        import monitoring_cli

        snapshot = monitoring_cli.validate_status_snapshot(OLD_STATUS)

        self.assertEqual(snapshot["health"], "UP")
        self.assertEqual(snapshot["active"], 3)
        self.assertEqual(snapshot["backendLive"], 11)
        self.assertEqual(snapshot["retained"], 15)
        self.assertEqual(snapshot["connections"]["status"], "UNAVAILABLE")
        self.assertIsNone(snapshot["connections"]["sessions"])
        self.assertIsNone(snapshot["connections"]["profiles"])

    def test_new_status_projects_only_bounded_supported_metrics(self):
        import monitoring_cli

        snapshot = monitoring_cli.validate_status_snapshot({
            **OLD_STATUS,
            "trafficCounters": TRAFFIC,
            "monitoring": MONITORING,
        })

        self.assertEqual(snapshot["generation"], GENERATION_A)
        self.assertEqual(snapshot["uptimeSeconds"], 123.5)
        self.assertEqual(snapshot["connections"]["sessions"], 2)
        self.assertEqual(snapshot["connections"]["profiles"]["demo"]["retained"], 2)
        self.assertEqual(snapshot["traffic"]["profiles"]["demo"]["toolAttempts"], 3)
        self.assertNotIn("trafficCounters", snapshot)
        self.assertNotIn("monitoring", snapshot)

    def test_malformed_or_sensitive_status_fields_fail_closed_without_echo(self):
        import monitoring_cli

        oversized_profiles = {f"profile-{i}": {} for i in range(65)}
        cases = [
            {**OLD_STATUS, "args": "synthetic-secret-argv"},
            {**OLD_STATUS, "active": True},
            {**OLD_STATUS, "retained": -1},
            {**OLD_STATUS, "monitoring": {**MONITORING, "profiles": oversized_profiles}},
            {**OLD_STATUS, "trafficCounters": {
                **TRAFFIC,
                "profiles": {"demo": {**TRAFFIC["profiles"]["demo"], "result": "private"}},
            }},
        ]
        for payload in cases:
            with self.subTest(payload=type(payload).__name__):
                with self.assertRaises(monitoring_cli.MonitorDataError) as raised:
                    monitoring_cli.validate_status_snapshot(payload)
                self.assertEqual(str(raised.exception), "MONITOR_RESPONSE_INVALID")
                self.assertNotIn("synthetic-secret-argv", str(raised.exception))

    def test_generation_change_discards_old_counter_deltas(self):
        import monitoring_cli

        previous = monitoring_cli.validate_status_snapshot({**OLD_STATUS, "trafficCounters": TRAFFIC})
        changed_traffic = {
            "generation": GENERATION_B,
            "profiles": {"demo": {key: 1 for key in TRAFFIC["profiles"]["demo"]}},
        }
        current = monitoring_cli.validate_status_snapshot({
            **OLD_STATUS, "trafficCounters": changed_traffic,
        })

        delta = monitoring_cli.generation_aware_delta(previous, current, elapsed_seconds=2)
        self.assertEqual(delta["status"], "RESET")
        self.assertTrue(all(value["delta"] is None for value in delta["profiles"]["demo"].values()))
        self.assertTrue(all(value["perSecond"] is None for value in delta["profiles"]["demo"].values()))

    def test_counter_saturation_and_counter_regression_never_make_negative_rates(self):
        import monitoring_cli

        max_safe = monitoring_cli.MAX_SAFE_INTEGER
        old_row = {key: max_safe - 2 for key in TRAFFIC["profiles"]["demo"]}
        new_row = {key: max_safe for key in TRAFFIC["profiles"]["demo"]}
        before = monitoring_cli.validate_status_snapshot({
            **OLD_STATUS, "trafficCounters": {"generation": GENERATION_A, "profiles": {"demo": old_row}},
        })
        after = monitoring_cli.validate_status_snapshot({
            **OLD_STATUS, "trafficCounters": {"generation": GENERATION_A, "profiles": {"demo": new_row}},
        })
        delta = monitoring_cli.generation_aware_delta(before, after, elapsed_seconds=0.5)
        self.assertEqual(delta["profiles"]["demo"]["toolAttempts"]["delta"], 2)
        self.assertEqual(delta["profiles"]["demo"]["toolAttempts"]["perSecond"], 4.0)

        reset_counter = {key: 0 for key in new_row}
        regressed = monitoring_cli.validate_status_snapshot({
            **OLD_STATUS, "trafficCounters": {"generation": GENERATION_A, "profiles": {"demo": reset_counter}},
        })
        safe_delta = monitoring_cli.generation_aware_delta(after, regressed, elapsed_seconds=1)
        self.assertTrue(all(value["delta"] is None for value in safe_delta["profiles"]["demo"].values()))
        self.assertTrue(all(value["perSecond"] is None for value in safe_delta["profiles"]["demo"].values()))

    def test_missing_descriptor_does_not_fall_back_to_home_discovery(self):
        import monitoring_cli

        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "installation.json"
            with patch.object(Path, "home", side_effect=AssertionError("home fallback attempted")):
                with self.assertRaises(monitoring_cli.MonitorDataError) as caught:
                    monitoring_cli.discover_context(missing)

        self.assertEqual(str(caught.exception), "MONITOR_INSTALLATION_UNAVAILABLE")

    def test_existing_descriptor_loads_the_portable_context(self):
        import monitoring_cli

        with tempfile.TemporaryDirectory() as temporary:
            descriptor = Path(temporary) / "installation.json"
            descriptor.write_text("{}\n", encoding="utf-8")
            context = SimpleNamespace(root=Path(temporary))
            with patch("installation_context.load_context", return_value=context) as load:
                self.assertIs(monitoring_cli.discover_context(descriptor), context)
            load.assert_called_once_with(descriptor)

    def test_portable_service_identity_does_not_import_legacy_adapter(self):
        import builtins
        import monitoring_cli
        import service_install

        context = SimpleNamespace()
        launcher = SimpleNamespace(pid=321, ppid=1, uid=501, seconds=10, microseconds=1, path="/synthetic/python")
        manager = SimpleNamespace(pid=322, ppid=321, uid=501, seconds=11, microseconds=2, path="/synthetic/node")
        native = SimpleNamespace(process=lambda pid: {321: launcher, 322: manager}[pid])
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name.startswith("legacy_"):
                raise AssertionError("unsupported adapter import")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=guarded_import), \
             patch.object(service_install, "_manager_identity", return_value=({"pid": 322, "launcher_pid": 321}, native)), \
             patch.object(service_install, "_assert_launchd_binding"):
            identity = monitoring_cli.validate_service_identity(context)

        self.assertEqual(identity.kind, "portable")
        self.assertEqual(identity.launcher.pid, 321)
        self.assertEqual(identity.manager.pid, 322)

    def test_real_loopback_http_read_is_authenticated_get_without_side_effect_calls(self):
        import monitoring_cli
        import monitoring_memory

        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.command, self.path, self.headers.get("Authorization")))
                body = json.dumps(OLD_STATUS).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                self.send_error(405)

            def log_message(self, *_args):
                return

        server, thread = self.start_http_fixture(Handler)
        try:
            with tempfile.TemporaryDirectory() as directory:
                runtime = Path(directory) / "runtime"
                runtime.mkdir(mode=0o700)
                token = "a" * 64
                (runtime / "token").write_text(token, encoding="ascii")
                (runtime / "token").chmod(0o600)
                context = SimpleNamespace(
                    root=Path(directory), release=Path(directory) / "program", runtime=runtime,
                    port=server.server_address[1],
                )
                identity = monitoring_cli.ServiceIdentity(
                    kind="fixture", launcher=None, manager=monitoring_cli.ProcessIdentity(
                        pid=321, ppid=123, uid=501, seconds=10, microseconds=20,
                        path="/synthetic/node"),
                )
                output = io.StringIO()
                with patch.object(monitoring_cli, "validate_service_identity", return_value=identity), \
                     patch.object(monitoring_memory, "sample_owned_memory", return_value={
                         "status": "UNAVAILABLE", "managerRssBytes": None,
                         "ownedDescendantTreeRssBytes": None, "summedOwnedRssBytes": None,
                         "ownedDescendantProcessCount": None,
                     }) as memory, \
                     redirect_stdout(output):
                    result = monitoring_cli.run_monitor(context, command="status", json_output=True)

                self.assertEqual(result, 0)
                self.assertEqual(len(requests), 1)
                self.assertEqual(requests[0], (
                    "GET", "/_control/status", "Bearer " + token,
                ))
                self.assertEqual(memory.call_count, 1)
                printed = json.loads(output.getvalue())
                self.assertEqual(printed["health"], "UP")
                self.assertNotIn(token, output.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_http_redirect_is_not_followed_and_unreachable_is_not_zero(self):
        import monitoring_cli
        import monitoring_memory

        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/redirect-target")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                return

        server, thread = self.start_http_fixture(Handler)
        try:
            with tempfile.TemporaryDirectory() as directory:
                runtime = Path(directory) / "runtime"
                runtime.mkdir(mode=0o700)
                (runtime / "token").write_text("b" * 64, encoding="ascii")
                (runtime / "token").chmod(0o600)
                context = SimpleNamespace(root=Path(directory), release=Path(directory) / "program",
                                          runtime=runtime, port=server.server_address[1])
                identity = monitoring_cli.ServiceIdentity(kind="fixture", launcher=None,
                    manager=monitoring_cli.ProcessIdentity(321, 123, 501, 10, 20, "/synthetic/node"))
                output = io.StringIO()
                with patch.object(monitoring_cli, "validate_service_identity", return_value=identity), \
                     patch.object(monitoring_memory, "sample_owned_memory", return_value={
                         "status": "UNAVAILABLE", "managerRssBytes": None,
                         "ownedDescendantTreeRssBytes": None, "summedOwnedRssBytes": None,
                         "ownedDescendantProcessCount": None,
                     }), redirect_stdout(output):
                    result = monitoring_cli.run_monitor(context, command="status", json_output=True)

                self.assertEqual(result, 1)
                self.assertEqual(requests, ["/_control/status"])
                printed = json.loads(output.getvalue())
                self.assertEqual(printed["health"], "DOWN")
                self.assertIsNone(printed["active"])
                self.assertIsNone(printed["connections"]["sessions"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
