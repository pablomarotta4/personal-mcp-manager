"""Selected signed clients do not require an unrelated Codex installation."""
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest

import owner_watch as ow


class PortableOwnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.channel, self.other = socket.socketpair()
        self.addCleanup(self.channel.close)
        self.addCleanup(self.other.close)
        self.identities = SimpleNamespace(boot=lambda: "synthetic-boot")

    def watch(self, paths, signature):
        value = ow.OwnerWatch(Path(self.directory.name), self.channel,
            backends={"fixture"}, identity=self.identities,
            events=SimpleNamespace(close=lambda: None), signature=signature,
            owner_paths=paths, claude_match=lambda path: path == "/synthetic/claude/1.0.0",
            claude_signature=lambda path: "claude-digest", claude_root=None)
        self.addCleanup(value.close)
        return value

    def test_claude_only_never_verifies_an_unselected_codex(self):
        def unexpected(path):
            self.fail("Unselected executable was verified")
        watch = self.watch((), unexpected)
        self.assertTrue(watch.client_path("/synthetic/claude/1.0.0"))
        self.assertFalse(watch.client_path(ow.REVIEWED_CODEX))

    def test_selected_codex_path_is_pinned_and_rechecked(self):
        executable = "/synthetic/Other App.app/codex"
        calls = []
        def signature(path):
            calls.append(path)
            return "initial" if len(calls) == 1 else "changed"
        watch = self.watch((executable,), signature)
        self.assertTrue(watch.client_path(executable))
        self.assertFalse(watch.client_path(ow.REVIEWED_CODEX))
        self.identities.process = lambda pid: ow.Identity(pid, 1, os.getuid(), 1, 0, executable, 1)
        with self.assertRaises(ow.OwnerError):
            watch.owner_for((9999, os.getuid()))
        self.assertEqual(calls, [executable, executable])

    def test_duplicate_or_relative_owner_path_is_refused(self):
        for paths in (("relative",), ("/synthetic/codex", "/synthetic/codex")):
            with self.subTest(paths=paths), self.assertRaises(ow.OwnerError):
                self.watch(paths, lambda path: "digest")

    def test_portable_family_guard_scope_cannot_be_omitted(self):
        from portable_owner_environment import PortableEnvironmentGuard
        guard = PortableEnvironmentGuard({"alias": {"family": "mysql", "source": {"env": {}},
            "expected_env": {}, "clients": ("claude",)}}, identity=self.identities,
            reader=SimpleNamespace(), client_kind=lambda path: "claude")
        with self.assertRaises(ow.OwnerError):
            ow.OwnerWatch(Path(self.directory.name), self.channel, backends={"different"},
                identity=self.identities, events=SimpleNamespace(close=lambda: None),
                signature=lambda path: "digest", portable_environment_guard=guard)
        value = ow.OwnerWatch(Path(self.directory.name), self.channel, backends={"alias"},
            identity=self.identities, events=SimpleNamespace(close=lambda: None),
            signature=lambda path: "digest", portable_environment_guard=guard)
        self.addCleanup(value.close)
        self.assertEqual(set(value.mysql_guards), {"alias"})


if __name__ == "__main__":
    unittest.main()
