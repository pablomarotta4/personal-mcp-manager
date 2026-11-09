import argparse
import importlib.util
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('entry', Path(__file__).with_name('langfuse-entry.py'))
entry = importlib.util.module_from_spec(SPEC)
if SPEC.loader and Path(SPEC.origin).exists():
    # The real entrypoint intentionally sets a private process umask at import.
    # Loading it as a test module must not affect unrelated test fixtures.
    previous_mask = os.umask(0o077)
    try:
        SPEC.loader.exec_module(entry)
    finally:
        os.umask(previous_mask)


class EntryTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(entry, 'parse_manager'), 'private wrapper is not implemented')
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.mask = os.umask(0o077)

    def tearDown(self):
        os.umask(self.mask)
        self.temp.cleanup()

    def test_test_module_import_restores_callers_umask(self):
        import subprocess
        import sys
        code = 'import os; os.umask(0o022); import test_langfuse_entry; assert os.umask(0o022) == 0o022'
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).parent,
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_manager_preserves_app_sequence(self):
        root, profile, flags = entry.parse_manager(['--manager-profile', 'abc', '--manager-data-root', str(self.root), '--', '--dump=x', '--secret-key', 'synthetic'])
        self.assertEqual((root, profile, flags), (self.root, 'abc', ['--dump=x', '--secret-key', 'synthetic']))

    def test_manager_rejects_missing_duplicate_unknown_and_bad_id(self):
        base = ['--manager-data-root', str(self.root), '--manager-profile', 'abc']
        for flags in (base, base + ['--manager-profile', 'abc', '--'], base + ['--manager-prof', 'abc', '--'], ['--manager-data-root', str(self.root), '--manager-profile', 'constructor', '--']):
            with self.subTest(flags=flags), self.assertRaises(entry.SafeError):
                entry.parse_manager(flags)

    def test_private_creation_and_instance_persistence(self):
        first = entry.instance_directory(self.root, 'abc')
        second = entry.instance_directory(self.root, 'abc')
        self.assertNotEqual(first, second)
        self.assertEqual(first.stat().st_mode & 0o777, 0o700)
        self.assertTrue(first.exists())

    def test_directory_rejects_shared_symlink_and_unsafe_ancestor(self):
        shared = self.root / 'shared'; shared.mkdir(mode=0o755); shared.chmod(0o755)
        link = self.root / 'link'; link.symlink_to(self.root, target_is_directory=True)
        for path in (shared, link, shared / 'child'):
            with self.subTest(path=path), self.assertRaises(entry.SafeError):
                entry.private_directory(path, create=True)
        self.assertFalse((shared / 'child').exists())

    def test_log_rejects_symlink_hardlink_rotation_and_permissions(self):
        log = self.root / 'log'; entry.secure_log(log)
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        os.link(log, self.root / 'hard')
        with self.assertRaises(entry.SafeError): entry.secure_log(log)
        (self.root / 'hard').unlink()
        backup = self.root / 'log.5'; backup.symlink_to(log)
        with self.assertRaises(entry.SafeError): entry.secure_log(log)
        backup.unlink(); log.chmod(0o644)
        with self.assertRaises(entry.SafeError): entry.secure_log(log)

    def test_rotation_remains_private(self):
        log = self.root / 'log'; entry.secure_log(log)
        handler = RotatingFileHandler(log, maxBytes=20, backupCount=5)
        try:
            for _ in range(20): handler.emit(logging.LogRecord('test', 20, '', 1, 'synthetic message', (), None))
        finally: handler.close()
        self.assertTrue((self.root / 'log.1').exists())
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in self.root.glob('log*')))

    def test_original_parser_dump_semantics(self):
        class App:
            @staticmethod
            def _read_env_defaults(): return {}
            @staticmethod
            def _build_arg_parser(defaults):
                parser = argparse.ArgumentParser()
                parser.add_argument('--dump-dir', default='/tmp/native')
                parser.add_argument('--secret-key')
                return parser
        destination = self.root / 'dumps'
        self.assertEqual(entry.forward_args(App, ['--secret-key', 'synthetic'], destination), ['--secret-key', 'synthetic', '--dump-dir', str(destination)])
        for flags in (['--dump', ''], ['--dump-d='], ['--dump-dir=', '--dump-dir', ''], ['--dump-dir', str(destination)], ['--dump-dir', '', '--dump=' + str(destination)]):
            with self.subTest(flags=flags): self.assertEqual(entry.forward_args(App, flags, destination), flags)
        with self.assertRaises(entry.SafeError): entry.forward_args(App, ['--dump=/tmp/native'], destination)

    def test_origin_rejects_external_and_namespace_location(self):
        from types import SimpleNamespace
        entry.validate_spec(SimpleNamespace(origin='built-in', submodule_search_locations=None), self.root)
        for spec in (SimpleNamespace(origin='/tmp/hostile.py', submodule_search_locations=None), SimpleNamespace(origin=None, submodule_search_locations=[str(self.root), '/tmp'])):
            with self.assertRaises(entry.SafeError): entry.validate_spec(spec, self.root)

    def test_isolated_wrong_interpreter_refuses_without_cwd_import_or_raw_error(self):
        import subprocess
        import sys
        cwd = self.root / 'unicode-ñ'; cwd.mkdir()
        (cwd / 'hashlib.py').write_text("raise RuntimeError('hostile cwd executed')")
        environment = dict(os.environ, PYTHONPATH=str(cwd))
        result = subprocess.run([sys.executable, '-I', '-S', '-B', str(Path(SPEC.origin).absolute()), '--manager-data-root', str(self.root), '--manager-profile', 'abc', '--', '--secret-key', 'synthetic-secret'], cwd=cwd, env=environment, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'RUNTIME_UNSAFE\n')
        self.assertFalse((self.root / 'abc').exists())

    def test_parser_errors_do_not_echo_arguments(self):
        from contextlib import redirect_stderr
        from io import StringIO
        from types import SimpleNamespace
        def parser(defaults):
            result = argparse.ArgumentParser()
            result.add_argument('--dump-dir')
            return result
        app = SimpleNamespace(_read_env_defaults=lambda: {}, _build_arg_parser=parser)
        output = StringIO()
        with redirect_stderr(output), self.assertRaises(SystemExit) as failure:
            entry.forward_args(app, ['--unknown=synthetic-secret'], self.root / 'dumps')
        self.assertEqual(failure.exception.code, 2)
        self.assertEqual(output.getvalue(), 'APP_ARGUMENTS_INVALID\n')

    def test_help_preserves_native_program_name(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from types import SimpleNamespace
        from unittest.mock import patch
        def parser(defaults):
            result=argparse.ArgumentParser()
            result.add_argument('--dump-dir')
            return result
        app=SimpleNamespace(_read_env_defaults=lambda:{},_build_arg_parser=parser)
        output=StringIO()
        with patch.object(entry.sys,'argv',['/artifact/manager/langfuse-entry.py']),redirect_stdout(output),self.assertRaises(SystemExit) as failure:
            entry.forward_args(app,['--help'],self.root/'dumps')
        self.assertEqual(failure.exception.code,0)
        self.assertIn('usage: langfuse-mcp',output.getvalue())
        self.assertNotIn('langfuse-entry.py',output.getvalue())

    def test_fresh_wheel_closure_needs_no_virtualenv_hook_or_import(self):
        from unittest.mock import patch
        packages = self.root / 'packages'
        packages.mkdir(mode=0o700)
        with patch.object(entry.importlib, 'import_module') as imported:
            self.assertFalse(entry.approved_hook(packages, self.root))
            imported.assert_not_called()

    def test_partial_or_preloaded_virtualenv_hook_is_not_a_fresh_closure(self):
        from unittest.mock import patch
        packages = self.root / 'packages'
        packages.mkdir(mode=0o700)
        (packages / '_virtualenv.pth').write_text('import _virtualenv\n')
        with self.assertRaises(entry.SafeError):
            entry.approved_hook(packages, self.root)
        (packages / '_virtualenv.pth').unlink()
        with patch.dict(entry.sys.modules, {'_virtualenv': object()}):
            with self.assertRaises(entry.SafeError):
                entry.approved_hook(packages, self.root)

    def test_hook_checks_and_executes_only_once(self):
        self.assertTrue(hasattr(entry, 'approved_hook'), 'approved hook validation is missing')
        from unittest.mock import patch
        import hashlib
        packages = self.root / 'packages'; packages.mkdir()
        for name in entry.HOOKS: (packages / name).write_text('synthetic reviewed hook')
        hashes = {name: hashlib.sha256((packages / name).read_bytes()).hexdigest() for name in entry.HOOKS}
        with patch.dict(entry.HOOKS, hashes, clear=True), patch.object(entry.importlib, 'import_module') as imported:
            entry.approved_hook(packages, self.root)
            imported.assert_called_once_with('_virtualenv')
            (packages / '_virtualenv.py').write_text('changed')
            with self.assertRaises(entry.SafeError): entry.approved_hook(packages, self.root)
            self.assertEqual(imported.call_count, 1)
        for name in ('.env', 'evil.pth', 'sitecustomize.py', 'usercustomize.py'):
            (packages / name).write_text('synthetic')
            with self.assertRaises(entry.SafeError): entry.approved_hook(packages, self.root)
            (packages / name).unlink()

    def test_run_selects_log_before_import_and_main_once_preserving_cwd_env(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        cwd = os.getcwd()
        calls = []
        def parser(defaults):
            result = argparse.ArgumentParser()
            result.add_argument('--dump-dir')
            result.add_argument('--secret-key')
            return result
        app = SimpleNamespace(_read_env_defaults=lambda: {}, _build_arg_parser=parser,
                              main=lambda: calls.append((os.getcwd(), list(entry.sys.argv), os.getenv('SYNTHETIC_STATE'))))
        def imported(name):
            self.assertEqual(name, 'langfuse_mcp.__main__')
            log = Path(os.environ['LANGFUSE_MCP_LOG_FILE'])
            self.assertTrue(log.exists())
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            return app
        with patch.object(entry, 'prepare_runtime'), patch.object(entry, 'validate_loaded'), patch.object(entry.importlib, 'import_module', side_effect=imported), patch.dict(os.environ, {'SYNTHETIC_STATE': 'preserved'}, clear=True), patch.object(entry.sys, 'argv', ['original']):
            entry.run(['--manager-data-root', str(self.root), '--manager-profile', 'abc', '--', '--secret-key', 'synthetic'])
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], cwd)
            self.assertEqual(calls[0][1][:3], ['langfuse-mcp', '--secret-key', 'synthetic'])
            self.assertEqual(calls[0][2], 'preserved')
            self.assertTrue(Path(calls[0][1][-1]).is_dir())
        self.assertTrue(Path(calls[0][1][-1]).exists())

    def test_run_explicit_unsafe_log_refuses_before_app_import(self):
        from unittest.mock import patch
        with patch.object(entry, 'prepare_runtime'), patch.object(entry.importlib, 'import_module') as imported, patch.dict(os.environ, {'LANGFUSE_MCP_LOG_FILE': ''}, clear=True):
            with self.assertRaises(entry.SafeError):
                entry.run(['--manager-data-root', str(self.root), '--manager-profile', 'abc', '--'])
            imported.assert_not_called()



if __name__ == '__main__': unittest.main()
