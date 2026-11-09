#!/usr/bin/env python3
"""Private isolated startup for the reviewed, immutable Langfuse closure.

The manager verifies the complete closure before spawn. This entrypoint checks
startup origins and writable destinations; it does not replace that verifier.
"""
import os
import sys

# Apply before any file creation or application import.
os.umask(0o077)

from contextlib import redirect_stderr
from io import StringIO
import hashlib
import importlib
import importlib.util
from pathlib import Path
import re
import secrets
import stat

HOOKS = {
    '_virtualenv.pth': '69ac3d8f27e679c81b94ab30b3b56e9cd138219b1ba94a1fa3606d5a76a1433d',
    '_virtualenv.py': '6cf30c56faf2a55228914dbbd17f8088ed371ebb08f5e7fa6fd931f913fcaf1d',
}


class SafeError(Exception):
    """Only fixed, non-sensitive wrapper error codes cross the boundary."""


def parse_manager(argv):
    if '--' not in argv:
        raise SafeError('MANAGER_ARGUMENTS_INVALID')
    boundary = argv.index('--')
    options = argv[:boundary]
    values = {}
    while options:
        name = options[0]
        if '=' in name:
            name, value = name.split('=', 1)
            options = options[1:]
        else:
            if len(options) < 2:
                raise SafeError('MANAGER_ARGUMENTS_INVALID')
            value = options[1]
            options = options[2:]
        if name not in ('--manager-data-root', '--manager-profile') or name in values:
            raise SafeError('MANAGER_ARGUMENTS_INVALID')
        values[name] = value
    if len(values) != 2:
        raise SafeError('MANAGER_ARGUMENTS_INVALID')
    profile = values['--manager-profile']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', profile) or profile in ('__proto__', 'prototype', 'constructor'):
        raise SafeError('MANAGER_ARGUMENTS_INVALID')
    root = Path(values['--manager-data-root'])
    if not root.is_absolute() or str(root) != values['--manager-data-root']:
        raise SafeError('DATA_ROOT_UNSAFE')
    return root, profile, argv[boundary + 1:]


def private_directory(path, create=False):
    """Walk from / with no-follow descriptors; create only below private parents."""
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                parent = os.fstat(fd)
                if not create or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
                    raise SafeError('DIRECTORY_UNSAFE') from None
                os.mkdir(component, mode=0o700, dir_fd=fd)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                os.close(child)
                raise SafeError('DIRECTORY_UNSAFE')
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SafeError('DIRECTORY_UNSAFE')
        return path
    except OSError:
        raise SafeError('DIRECTORY_UNSAFE') from None
    finally:
        os.close(fd)


def instance_directory(root, profile):
    root = private_directory(root)
    if root.resolve() != root:
        raise SafeError('DATA_ROOT_UNSAFE')
    parent = private_directory(root / profile, create=True)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        name = secrets.token_hex(16)
        os.mkdir(name, mode=0o700, dir_fd=fd)
    finally:
        os.close(fd)
    return parent / name


def secure_log(path):
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    parent = private_directory(path.parent, create=True)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for suffix in ('', '.1', '.2', '.3', '.4', '.5'):
            name = path.name + suffix
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if suffix:
                    continue
                leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                os.close(leaf)
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise SafeError('LOG_UNSAFE')
    except OSError:
        raise SafeError('LOG_UNSAFE') from None
    finally:
        os.close(fd)
    return path


def forward_args(app, flags, dumps):
    sentinel = object()
    parser = app._build_arg_parser(app._read_env_defaults())
    parser.prog = 'langfuse-mcp'
    parser.set_defaults(dump_dir=sentinel)
    # Preserve parser behavior/help/status; redact only argument-error diagnostics.
    try:
        with redirect_stderr(StringIO()):
            args = parser.parse_args(flags)
    except SystemExit as error:
        if error.code:
            print('APP_ARGUMENTS_INVALID', file=sys.stderr)
        raise
    if args.dump_dir is sentinel:
        private_directory(dumps, create=True)
        return [*flags, '--dump-dir', str(dumps)]
    if args.dump_dir:
        private_directory(Path(args.dump_dir), create=True)
    return list(flags)


def inside(path, root):
    try:
        resolved = Path(path).resolve(strict=True)
        return resolved.is_relative_to(root)
    except (OSError, ValueError):
        return False


def validate_spec(spec, root):
    if spec is None:
        raise SafeError('IMPORT_ORIGIN_UNSAFE')
    if spec.origin not in (None, 'built-in', 'frozen') and not inside(spec.origin, root):
        raise SafeError('IMPORT_ORIGIN_UNSAFE')
    locations = spec.submodule_search_locations
    if locations is not None and any(not inside(path, root) for path in locations):
        raise SafeError('IMPORT_ORIGIN_UNSAFE')
    if spec.origin is None and not locations:
        raise SafeError('IMPORT_ORIGIN_UNSAFE')


def validate_loaded(root):
    for name, module in tuple(sys.modules.items()):
        if name == '__main__' or module is None:
            continue
        spec = getattr(module, '__spec__', None)
        if spec is not None:
            validate_spec(spec, root)
        elif getattr(module, '__file__', None) and not inside(module.__file__, root):
            raise SafeError('IMPORT_ORIGIN_UNSAFE')


def approved_hook(packages, root):
    if any(path.name not in HOOKS for path in packages.glob('*.pth')) or any((packages / name).exists() or (packages / name).is_symlink() for name in ('sitecustomize.py', 'usercustomize.py', 'sitecustomize', 'usercustomize')):
        raise SafeError('IMPORT_HOOK_UNSAFE')
    if (packages / '.env').exists() or (packages / '.env').is_symlink():
        raise SafeError('ENV_FILE_UNSAFE')
    present = {name for name in HOOKS if (packages / name).exists() or (packages / name).is_symlink()}
    if '_virtualenv' in sys.modules:
        raise SafeError('IMPORT_HOOK_UNSAFE')
    # Fresh wheel closures are not virtualenvs and contain no activation hooks.
    # Absence permits no imports; a partial or changed legacy pair still fails.
    if not present:
        return False
    if present != set(HOOKS):
        raise SafeError('IMPORT_HOOK_UNSAFE')
    for name, digest in HOOKS.items():
        path = packages / name
        if not inside(path, root) or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SafeError('IMPORT_HOOK_UNSAFE')
    importlib.import_module('_virtualenv')
    return True


def prepare_runtime():
    wrapper = Path(__file__)
    if not wrapper.is_absolute() or wrapper.resolve(strict=True) != wrapper or wrapper.name != 'langfuse-entry.py' or wrapper.parent.name != 'manager':
        raise SafeError('RUNTIME_UNSAFE')
    root = wrapper.parent.parent
    executable = root / 'python/bin/python3.13'
    if Path(sys.executable) != executable or executable.resolve(strict=True) != executable or not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise SafeError('RUNTIME_UNSAFE')
    stdlib = root / 'python/lib/python3.13'
    packages = root / 'app/site-packages'
    paths = [stdlib, stdlib / 'lib-dynload', packages]
    archive = root / 'python/lib/python313.zip'
    if archive.exists():
        paths.insert(0, archive)
    if any(not inside(path, root) for path in paths):
        raise SafeError('RUNTIME_UNSAFE')
    sys.path[:] = [str(path) for path in paths]
    validate_loaded(root)
    for name in ('langfuse_mcp', 'langfuse', 'mcp', 'pydantic'):
        validate_spec(importlib.util.find_spec(name), root)
    approved_hook(packages, root)
    validate_loaded(root)
    return root


def run(argv):
    root, profile, flags = parse_manager(argv)
    prepare_runtime()
    instance = instance_directory(root, profile)
    if 'LANGFUSE_MCP_LOG_FILE' in os.environ:
        value = os.environ['LANGFUSE_MCP_LOG_FILE']
        if not value:
            raise SafeError('LOG_UNSAFE')
        secure_log(Path(value).expanduser())
    else:
        value = str(instance / 'langfuse.log')
        secure_log(value)
        os.environ['LANGFUSE_MCP_LOG_FILE'] = value
    app = importlib.import_module('langfuse_mcp.__main__')
    validate_loaded(Path(__file__).parent.parent)
    flags = forward_args(app, flags, instance / 'dumps')
    sys.argv = ['langfuse-mcp', *flags]
    return app.main()


if __name__ == '__main__':
    try:
        run(sys.argv[1:])
    except SafeError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print('STARTUP_FAILED', file=sys.stderr)
        raise SystemExit(1) from None
