"""Fresh owner environment binding for portable aliased routes."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from owner_watch import Identity, CwdBinding, OwnerError


class PortableEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        info = self.root.stat()
        self.cwd = CwdBinding(str(self.root), info.st_dev, info.st_ino)
        self.owner = Identity(12345, 1, os.getuid(), 1, 0, "/synthetic/claude", 1)
        self.identity = SimpleNamespace(process=lambda pid: self.owner, cwd=lambda pid: self.cwd)
        self.environment = {"HOME": str(self.root), "PATH": "/usr/bin:/bin"}
        self.reader = SimpleNamespace(read=lambda pid, *args, **kwargs:
            (self.owner, SimpleNamespace(environment=dict(self.environment))))

    def make_guard(self, source, family="mysql", expected=None):
        from portable_owner_environment import PortableEnvironmentGuard
        return PortableEnvironmentGuard(
            {"alias": {"family": family, "source": source,
                       "expected_env": expected or {}, "clients": ("claude",)}},
            identity=self.identity, reader=self.reader,
            client_kind=lambda path: "claude" if path == "/synthetic/claude" else None)

    def test_mysql_context_reconstructed_for_aliased_route_and_changed_dotenv(self):
        source = {"env": {"MYSQL_PASS": "synthetic-pass"}}
        (self.root / ".env").write_text("MYSQL_DB=first\n")
        guard = self.make_guard(source)
        first = guard("alias", self.owner, self.cwd)
        self.assertEqual(first["environment"]["MYSQL_DB"], "first")
        self.assertEqual(first["environment"]["MYSQL_PASS"], "synthetic-pass")
        (self.root / ".env").write_text("MYSQL_DB=second\n")
        second = guard("alias", self.owner, self.cwd)
        self.assertEqual(second["environment"]["MYSQL_DB"], "second")
        self.assertEqual(first["environment"]["MYSQL_DB"], "first")

    def test_wrong_client_or_process_birth_refused(self):
        guard = self.make_guard({"env": {}})
        wrong = Identity(12345, 1, os.getuid(), 2, 0, "/synthetic/claude", 1)
        with self.assertRaises(OwnerError):
            guard("alias", wrong, self.cwd)
        self.owner = Identity(12345, 1, os.getuid(), 1, 0, "/synthetic/unselected", 1)
        with self.assertRaises(OwnerError):
            guard("alias", self.owner, self.cwd)

    def test_owner_code_loading_override_refused(self):
        guard = self.make_guard({"env": {}})
        self.environment["NODE_OPTIONS"] = "--import=/synthetic/unreviewed.mjs"
        with self.assertRaises(OwnerError):
            guard("alias", self.owner, self.cwd)


if __name__ == "__main__":
    unittest.main()
