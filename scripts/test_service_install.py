import json
import os
from pathlib import Path
import plistlib
import shlex
import tempfile
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pilot import SafeError


class ServiceInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mcp-service-install-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.home.chmod(0o700)
        self.root = self.home / "Library" / "Application Support" / "Personal MCP Manager"
        self.root.mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        self.release = self.root / "app" / "releases" / "release one"
        self.release.mkdir(parents=True, mode=0o700)
        (self.release / "scripts").mkdir(mode=0o700)
        (self.release / "scripts" / "manage.py").write_text("# fixture\n")
        (self.release / "scripts" / "mcp_manager.py").write_text("# fixture\n")
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        (self.runtime / "token").write_text("a" * 64)
        (self.runtime / "token").chmod(0o600)
        self.context = SimpleNamespace(
            version=1, root=self.root, release=self.release, runtime=self.runtime,
            artifacts=self.root / "artifacts", python=Path("/usr/bin/python3"),
            node=Path("/usr/bin/node"), port=18765, clients=(),
        )

    def test_launchagent_uses_exact_canonical_argv_and_never_expands_shell(self):
        from service_install import LABEL, make_plist

        value = make_plist(self.context)
        self.assertEqual(value["Label"], LABEL)
        self.assertEqual(value["ProgramArguments"], [str(self.context.python),
            str(self.release / "scripts/manage.py"), "run", "--installation",
            str(self.root / "installation.json")])
        self.assertTrue(value["RunAtLoad"])
        self.assertFalse(value["KeepAlive"])
        self.assertEqual(value["EnvironmentVariables"], {"HOME": str(self.home)})
        self.assertNotIn("synthetic-secret", json.dumps(value))

    def test_owned_launchagent_rejects_unexpected_environment_and_top_level_keys(self):
        import service_install

        path = service_install.plist_path(self.context)
        path.parent.mkdir(parents=True, mode=0o700)
        value = service_install.make_plist(self.context)
        value.setdefault("EnvironmentVariables", {"HOME": str(self.home)})
        value["EnvironmentVariables"]["NODE_OPTIONS"] = "--require=/tmp/untrusted.js"
        path.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True))
        path.chmod(0o600)
        self.assertFalse(service_install._owned_plist(path, self.context))

        value = service_install.make_plist(self.context)
        value["Unexpected"] = "preserve this foreign edit"
        path.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True))
        path.chmod(0o600)
        self.assertFalse(service_install._owned_plist(path, self.context))

    def test_stable_wrapper_quotes_interpreter_and_canonical_manager_path(self):
        from service_install import install_command, stable_command_path

        context = SimpleNamespace(**{**vars(self.context),
            "python": self.home / "Tools" / "O'Brien $(false)" / "python3"})
        result = install_command(context)
        path = stable_command_path(context)
        lines = path.read_text().splitlines()
        self.assertEqual(result["status"], "INSTALLED")
        self.assertEqual(shlex.split(lines[-1][len("exec "):-len(' "$@"')]),
                         [str(context.python), str(context.release / "scripts/mcp_manager.py")])
        self.assertTrue(path.stat().st_mode & 0o111)
        self.assertEqual(install_command(context)["status"], "ALREADY_INSTALLED")

    def test_nonmatching_stable_command_is_preserved_and_refused(self):
        from service_install import install_command, stable_command_path

        path = stable_command_path(self.context)
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_text("#!/bin/sh\nprintf unrelated\n")
        path.chmod(0o700)
        before = path.read_bytes()
        with self.assertRaisesRegex(SafeError, "COMMAND_PATH_CONFLICT"):
            install_command(self.context)
        self.assertEqual(path.read_bytes(), before)

    def test_register_writes_private_plist_and_bootstraps_only_its_owned_label(self):
        import service_install

        calls = []
        with patch.object(service_install, "_launchctl_service", return_value=None), \
             patch.object(service_install, "_run_launchctl", side_effect=lambda *args: calls.append(args) or (0, b"", b"")), \
             patch.object(service_install, "_launchctl_loaded_path", return_value=str(self.home / "Library/LaunchAgents/local.personal-mcp-manager.plist")):
            (self.home / ".local" / "bin").mkdir(parents=True, mode=0o700)
            service_install.install_command(self.context)
            result = service_install.register_service(self.context)

        plist_path = service_install.plist_path(self.context)
        record = plistlib.loads(plist_path.read_bytes())
        self.assertEqual(result, {"status": "PASS", "label": service_install.LABEL})
        self.assertEqual(plist_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record, service_install.make_plist(self.context))
        self.assertEqual(calls[0][0], "bootstrap")
        self.assertEqual(calls[0][1], "gui/" + str(os.getuid()))

    def test_foreign_loaded_label_is_refused_without_replacing_plist(self):
        import service_install

        path = service_install.plist_path(self.context)
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_bytes(plistlib.dumps({"Label": service_install.LABEL, "ProgramArguments": ["foreign"]}))
        path.chmod(0o600)
        before = path.read_bytes()
        with patch.object(service_install, "_launchctl_service", return_value="path = /foreign/job.plist"):
            with self.assertRaisesRegex(SafeError, "LAUNCHAGENT_LABEL_CONFLICT"):
                service_install.register_service(self.context)
        self.assertEqual(path.read_bytes(), before)

    def test_rollback_boots_out_only_the_exact_owned_agent_before_removing_files(self):
        import service_install

        with patch.object(service_install, "_launchctl_service", return_value=None), \
             patch.object(service_install, "_run_launchctl", return_value=(0, b"", b"")), \
             patch.object(service_install, "_launchctl_loaded_path",
                          return_value=str(service_install.plist_path(self.context))), \
             patch.object(service_install, "_port_listener", return_value=False):
            service_install.install_command(self.context)
            service_install.register_service(self.context)
            with patch.object(service_install, "_launchctl_service", return_value=None), \
                 patch.object(service_install, "_launchctl_loaded_path",
                              return_value=str(service_install.plist_path(self.context))), \
                 patch.object(service_install, "_run_launchctl", return_value=(0, b"", b"")) as launchctl:
                result = service_install.rollback_service_files(self.context)

        self.assertEqual(result["status"], "PASS")
        launchctl.assert_called_once_with("bootout", service_install.service_name(self.context))
        self.assertFalse(service_install.stable_command_path(self.context).exists())
        self.assertFalse(service_install.plist_path(self.context).exists())

    def test_rollback_refuses_a_foreign_loaded_path_before_removing_owned_command(self):
        import service_install

        service_install.install_command(self.context)
        path = service_install.stable_command_path(self.context)
        before = path.read_bytes()
        with patch.object(service_install, "_manager_record_path", return_value=self.runtime / "missing-process.json"), \
             patch.object(service_install, "_port_listener", return_value=False), \
             patch.object(service_install, "_launchctl_loaded_path", return_value="/foreign/job.plist"), \
             self.assertRaisesRegex(SafeError, "LAUNCHAGENT_LABEL_CONFLICT"):
            service_install.rollback_service_files(self.context)
        self.assertEqual(path.read_bytes(), before)

    def _update_contexts(self):
        from dataclasses import replace
        from installation_context import InstallContext, load_or_create_install_key, write_context
        root = self.home / "Library" / "Application Support" / "Personal MCP Manager"
        old_release = root / "app" / "releases" / "0.1.0-old"
        new_release = root / "app" / "releases" / "0.2.0-new"
        old_release.mkdir(parents=True, mode=0o700)
        new_release.mkdir(mode=0o700)
        context = InstallContext(1, root, old_release, root / "runtime", root / "artifacts",
                                 Path("/usr/bin/python3"), Path("/usr/bin/node"), 18765, ())
        write_context(context)
        key = load_or_create_install_key(context)
        import service_install
        service_install._atomic_file(service_install.stable_command_path(context),
                                     service_install._wrapper_bytes(context), mode=0o700)
        service_install._atomic_file(service_install.plist_path(context),
                                     service_install._plist_bytes(context), mode=0o600)
        return context, replace(context, release=new_release), key

    def test_update_journal_authenticates_recovery_bytes_without_persisting_install_key(self):
        import service_install

        context, updated, key = self._update_contexts()
        with patch.object(service_install, "_launchctl_loaded_path",
                          return_value=str(service_install.plist_path(context))):
            result = service_install.begin_update(context, updated, install_key=key)

        payload, decoded = service_install._read_update(context, key)
        raw = service_install.update_journal_path(context).read_bytes()
        self.assertEqual(result, {"status": "PASS", "state": "prepared"})
        self.assertEqual(payload["state"], "prepared")
        self.assertEqual(decoded["descriptor_before"],
                         __import__("installation_context")._serialize_context(context))
        self.assertNotIn(key.hex().encode(), raw)

    def test_update_journal_rejects_tampered_state_and_keeps_recovery_evidence(self):
        import service_install

        context, updated, key = self._update_contexts()
        with patch.object(service_install, "_launchctl_loaded_path",
                          return_value=str(service_install.plist_path(context))):
            service_install.begin_update(context, updated, install_key=key)
        path = service_install.update_journal_path(context)
        envelope = json.loads(path.read_bytes())
        envelope["payload"]["state"] = "verified"
        path.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":")))
        path.chmod(0o600)

        with self.assertRaisesRegex(SafeError, "UPDATE_JOURNAL_INVALID"):
            service_install._read_update(context, key)
        self.assertTrue(path.exists())

    def test_update_journal_binds_owned_setup_skill_hash_transition(self):
        import service_install

        context, updated, key = self._update_contexts()
        skill_update = ("a" * 64, "b" * 64)
        with patch.object(service_install, "_launchctl_loaded_path",
                          return_value=str(service_install.plist_path(context))):
            service_install.begin_update(context, updated, install_key=key,
                                         skill_update=skill_update)

        payload, _ = service_install._read_update(context, key)
        self.assertEqual(payload["skill_before_sha"], skill_update[0])
        self.assertEqual(payload["skill_after_sha"], skill_update[1])

    def test_owned_setup_skill_update_and_rollback_follow_authenticated_release_hashes(self):
        import hashlib
        import service_install
        from artifact_install import inspect_setup_skill, install_setup_skill
        from installation_context import ClientPaths

        context, updated, _key = self._update_contexts()
        clients = (ClientPaths("codex", self.home / ".codex/config.toml", None, (), ()),)
        context = replace(context, clients=clients)
        updated = replace(updated, clients=clients)
        old_source = context.release / "skills/mcp-manager-setup/SKILL.md"
        new_source = updated.release / "skills/mcp-manager-setup/SKILL.md"
        old_source.parent.mkdir(parents=True, mode=0o700)
        new_source.parent.mkdir(parents=True, mode=0o700)
        old_source.write_bytes(b"old setup instructions\n")
        new_source.write_bytes(b"new setup instructions\n")
        install_setup_skill(context)
        before = hashlib.sha256(old_source.read_bytes()).hexdigest()
        after = hashlib.sha256(new_source.read_bytes()).hexdigest()
        payload = {"skill_before_sha": before, "skill_after_sha": after}
        self.assertTrue(inspect_setup_skill(context)["replaceable"])

        service_install._apply_update_skill(updated, payload)
        self.assertEqual(inspect_setup_skill(updated)["sha256"], after)
        service_install._restore_update_skill(updated, context, payload)
        self.assertEqual(inspect_setup_skill(context)["sha256"], before)

    def test_interrupted_update_conditionally_restores_old_descriptor_and_service_files(self):
        from installation_context import replace_context
        import service_install

        context, updated, key = self._update_contexts()
        plist = service_install.plist_path(context)
        with patch.object(service_install, "_launchctl_loaded_path", return_value=str(plist)):
            service_install.begin_update(context, updated, install_key=key)
        replace_context(context, updated)
        service_install._atomic_file(service_install.stable_command_path(updated),
                                     service_install._wrapper_bytes(updated), mode=0o700)
        service_install._atomic_file(plist, service_install._plist_bytes(updated), mode=0o600)
        service_install.advance_update(context, install_key=key, state="descriptor-published")

        with patch.object(service_install, "_launchctl_loaded_path", return_value=None), \
             patch.object(service_install, "register_service", return_value={"status": "PASS"}), \
             patch.object(service_install, "service_action", side_effect=lambda _ctx, action: {
                 "status": "PASS", "service": "STOPPED" if action == "status" else "RUNNING"}), \
             patch.object(service_install, "verify_service", return_value={"status": "PASS"}):
            result = service_install.recover_update(context, install_key=key)

        from installation_context import load_context
        self.assertEqual(result["operation"], "ROLLED_BACK")
        self.assertEqual(load_context(context.root / "installation.json"), context)
        self.assertEqual(service_install.stable_command_path(context).read_bytes(),
                         service_install._wrapper_bytes(context))
        self.assertEqual(plist.read_bytes(), service_install._plist_bytes(context))
        self.assertFalse(service_install.update_journal_path(context).exists())

    def test_interrupted_update_preserves_changed_command_and_journal_for_manual_recovery(self):
        from installation_context import replace_context
        import service_install

        context, updated, key = self._update_contexts()
        plist = service_install.plist_path(context)
        with patch.object(service_install, "_launchctl_loaded_path", return_value=str(plist)):
            service_install.begin_update(context, updated, install_key=key)
        replace_context(context, updated)
        command = service_install.stable_command_path(updated)
        command.write_bytes(b"foreign edit\n")
        command.chmod(0o700)
        changed = command.read_bytes()

        with patch.object(service_install, "service_action",
                          return_value={"status": "PASS", "service": "STOPPED"}):
            with self.assertRaisesRegex(SafeError, "UPDATE_COMMAND_CONFLICT"):
                service_install.recover_update(context, install_key=key)

        self.assertEqual(command.read_bytes(), changed)
        self.assertTrue(service_install.update_journal_path(context).exists())


if __name__ == "__main__":
    unittest.main()
