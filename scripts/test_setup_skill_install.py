import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pilot import SafeError, setup_token


class SetupSkillInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="portable-skill-install-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name).resolve()
        self.home.chmod(0o700)
        self.root = self.home / "Library/Application Support/Personal MCP Manager"
        self.root.mkdir(parents=True, mode=0o700)
        self.release = self.root / "app/releases/fixture"
        self.source = self.release / "skills/mcp-manager-setup/SKILL.md"
        self.source.parent.mkdir(parents=True, mode=0o700)
        self.source.write_text("---\nname: mcp-manager-setup\n---\nFixture setup instructions.\n")
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        setup_token(self.runtime)
        self.context = SimpleNamespace(root=self.root, release=self.release,
            runtime=self.runtime, clients=(SimpleNamespace(kind="claude"), SimpleNamespace(kind="codex")))

    def target(self, kind):
        return self.home / (".claude" if kind == "claude" else ".codex") / "skills/mcp-manager-setup/SKILL.md"

    def existing(self, kind, content):
        path = self.target(kind)
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_text(content)
        path.chmod(0o644)
        return path

    def test_installs_only_selected_clients_with_readback_and_no_op_repeat(self):
        from setup_skill_install import install_setup_skill, rollback_setup_skill, inspect_setup_skill
        self.context.clients = (SimpleNamespace(kind="claude"),)
        self.assertEqual(install_setup_skill(self.context)["status"], "INSTALLED")
        self.assertEqual(self.target("claude").read_bytes(), self.source.read_bytes())
        self.assertFalse(self.target("codex").exists())
        self.assertEqual(install_setup_skill(self.context)["status"], "ALREADY_INSTALLED")
        self.assertTrue(inspect_setup_skill(self.context)["replaceable"])
        self.assertEqual(rollback_setup_skill(self.context)["status"], "ROLLED_BACK")
        self.assertFalse(self.target("claude").exists())

    def test_foreign_skill_is_preserved_before_any_selected_skill_is_written(self):
        from setup_skill_install import install_setup_skill
        path = self.existing("codex", "Foreign skill.\n")
        with self.assertRaises(SafeError):
            install_setup_skill(self.context)
        self.assertEqual(path.read_text(), "Foreign skill.\n")
        self.assertFalse(self.target("claude").exists())
        self.assertFalse((self.runtime / "setup-skills.json").exists())

    def test_matching_preexisting_skill_is_not_claimed_or_removed(self):
        from setup_skill_install import install_setup_skill, rollback_setup_skill, inspect_setup_skill
        existing = self.existing("codex", self.source.read_text())
        install_setup_skill(self.context)
        self.assertFalse(inspect_setup_skill(self.context)["replaceable"])
        rollback_setup_skill(self.context)
        self.assertEqual(existing.read_bytes(), self.source.read_bytes())
        self.assertFalse(self.target("claude").exists())

    def test_later_user_edit_blocks_rollback_without_deleting_other_skill(self):
        from setup_skill_install import install_setup_skill, rollback_setup_skill
        install_setup_skill(self.context)
        edited = self.target("codex")
        edited.write_text("Later user edit.\n")
        with self.assertRaises(SafeError):
            rollback_setup_skill(self.context)
        self.assertEqual(edited.read_text(), "Later user edit.\n")
        self.assertTrue(self.target("claude").is_file())

    def test_tampered_receipt_never_deletes_skill(self):
        from setup_skill_install import install_setup_skill, rollback_setup_skill
        install_setup_skill(self.context)
        receipt = self.runtime / "setup-skills.json"
        value = json.loads(receipt.read_bytes())
        value["payload"]["entries"][0]["created"] = False
        receipt.write_text(json.dumps(value))
        with self.assertRaises(SafeError):
            rollback_setup_skill(self.context)
        self.assertTrue(self.target("claude").is_file())
        self.assertTrue(self.target("codex").is_file())

    def test_symlink_skill_directory_is_refused(self):
        from setup_skill_install import install_setup_skill
        outside = self.home / "outside"
        outside.mkdir(mode=0o700)
        parent = self.home / ".codex/skills"
        parent.mkdir(parents=True, mode=0o700)
        (parent / "mcp-manager-setup").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(SafeError):
            install_setup_skill(self.context)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse(self.target("claude").exists())

    def test_interrupted_copy_resumes_from_authenticated_intent(self):
        import os
        from setup_skill_install import install_setup_skill, rollback_setup_skill
        original_open = os.open
        def fail_second_target(path, flags, *args, **kwargs):
            if Path(path) == self.target("codex") and flags & os.O_CREAT:
                raise OSError("synthetic interrupted copy")
            return original_open(path, flags, *args, **kwargs)
        with patch("setup_skill_install.os.open", side_effect=fail_second_target):
            with self.assertRaises(OSError):
                install_setup_skill(self.context)
        self.assertTrue(self.target("claude").exists())
        self.assertFalse(self.target("codex").exists())
        self.assertEqual(install_setup_skill(self.context)["status"], "INSTALLED")
        self.assertEqual(rollback_setup_skill(self.context)["status"], "ROLLED_BACK")
        self.assertFalse(self.target("claude").exists())
        self.assertFalse(self.target("codex").exists())


if __name__ == "__main__":
    unittest.main()
