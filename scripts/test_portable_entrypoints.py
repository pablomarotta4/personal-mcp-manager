"""Portable daemon and header entrypoints require explicit installation context."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import manage
import pilot


class PortableEntrypointTests(unittest.TestCase):
    def test_manage_run_delegates_without_legacy_required_flags(self):
        context = SimpleNamespace(root=Path("/synthetic/global"))
        with patch("installation_context.load_context", return_value=context), \
             patch("portable_engine.run_service", return_value=0) as service:
            self.assertEqual(manage.main(["run", "--installation", "/synthetic/global/installation.json"]), 0)
        service.assert_called_once_with(context)

    def test_header_helper_uses_authenticated_route_owner_requirement(self):
        context = SimpleNamespace(runtime=Path("/synthetic/runtime"))
        with patch("installation_context.load_context", return_value=context), \
             patch("portable_engine.requires_owner", return_value=False), \
             patch("pilot.headers") as output, \
             patch("sys.argv", ["pilot.py", "headers", "--installation", "/synthetic/installation.json", "--backend", "grafana-dev"]):
            self.assertEqual(pilot.main(), 0)
        output.assert_called_once_with(context.runtime / "token", backend=None)

    def test_mismatching_header_runtime_is_rejected(self):
        context = SimpleNamespace(runtime=Path("/synthetic/runtime"))
        with patch("installation_context.load_context", return_value=context), \
             patch("pilot.headers") as output, \
             patch("sys.argv", ["pilot.py", "headers", "--installation", "/synthetic/installation.json", "--runtime", "/different", "--backend", "loki-prd"]):
            with self.assertRaises(pilot.SafeError):
                pilot.main()
        output.assert_not_called()


if __name__ == "__main__":
    unittest.main()
