#!/usr/bin/env python3
"""Offline, content-addressed copy; never imports or executes the source environment.

Copy app55 site-packages only, not the uv venv/bin or source-bound pyvenv.cfg.
Keep CPython's auxiliary pip26.0.1 separately inventoried; the packaged -I -S
manager wrapper excludes its site-packages from imports and is included in the
closure digest. LC_ID_DYLIB labels are metadata, not LOAD dependencies.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess
import tempfile

from manage import publish
from migrate import sync_directory
from pilot import SafeError, private, write_private

VERSIONS = '''annotated-doc==0.0.5 annotated-types==0.8.0 anyio==4.15.1 attrs==26.1.0 backoff==2.2.1 cachetools==7.2.1 certifi==2026.7.22 cffi==2.1.1 charset-normalizer==3.5.2 click==8.5.0 cryptography==50.0.2 googleapis-common-protos==1.75.5 h11==0.16.0 httpcore==1.0.9 httpx==0.28.1 httpx-sse==0.4.3 idna==3.20 jsonschema==4.26.0 jsonschema-specifications==2025.9.1 langfuse==4.17.0 langfuse-mcp==0.10.1 markdown-it-py==4.2.0 mcp==1.30.0 mdurl==0.1.2 opentelemetry-api==1.45.1 opentelemetry-exporter-http-transport==0.66b1 opentelemetry-exporter-otlp-common==0.66b1 opentelemetry-exporter-otlp-proto-common==1.45.1 opentelemetry-exporter-otlp-proto-http==1.45.1 opentelemetry-proto==1.45.1 opentelemetry-sdk==1.45.1 opentelemetry-semantic-conventions==0.66b1 packaging==26.3 protobuf==7.36.2 pycparser==3.11 pydantic==2.14.1 pydantic-core==2.50.1 pydantic-settings==2.15.0 pygments==2.21.0 pyjwt==2.15.1 python-dotenv==1.2.4 python-multipart==0.0.32 referencing==0.37.0 requests==2.34.2 rich==15.0.0 rpds-py==2026.9.1 shellingham==1.5.4 sse-starlette==3.5.0 starlette==1.7.0 typer==0.27.3 typing-extensions==4.16.0 typing-inspection==0.4.4 urllib3==2.8.0 uvicorn==0.54.0 wrapt==2.5.0'''
DISTRIBUTIONS = dict(item.split('==') for item in VERSIONS.split())
HOOKS = {'_virtualenv.pth': '69ac3d8f27e679c81b94ab30b3b56e9cd138219b1ba94a1fa3606d5a76a1433d',
         '_virtualenv.py': '6cf30c56faf2a55228914dbbd17f8088ed371ebb08f5e7fa6fd931f913fcaf1d'}
REVIEWED = {'langfuse_mcp/__main__.py': '8e9b83d3ba6b59b7dc3852299534d9602be3892dc082583ab66aac1b6599a12c',
            'langfuse/_client/client.py': '520fe7cf675bf716fd7b70d5b11ce64962cef064f066fe7d36256660ebf5e2a1',
            'langfuse/_client/resource_manager.py': 'f7f1002ae5b6c09596a24fb0ae296d1d35248107c3a7ca31ce4019073d5782de',
            'langfuse/_utils/prompt_cache.py': 'bb208dbf89e91db5595783217953115f61a8409ec7f6c00e525eebc79f1c716e'}
MAGIC = {bytes.fromhex(value) for value in ('feedface', 'cefaedfe', 'feedfacf', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca')}
SYSTEM = ('/usr/lib/', '/System/Library/')
MAX_BYTES, MAX_ENTRIES = 512 * 1024 * 1024, 10000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def safe_relative(value):
    value = os.fspath(value)
    parts = Path(value).parts
    if not parts or Path(value).as_posix() != value or Path(value).is_absolute() or any(part in ('.', '..') for part in parts) or any(ord(char) < 32 for char in value):
        raise SafeError('PATH_INVALID')
    return Path(value)


def ancestors(path):
    identities = {}
    for current in (path, *path.parents):
        info = current.lstat()
        sticky_tmp = current == Path('/private/tmp') and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not sticky_tmp):
            raise SafeError('ANCESTOR_UNTRUSTED')
        identities[current] = (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
    return identities


def check_ancestors(identities):
    for path, identity in identities.items():
        info = path.lstat()
        if (info.st_dev, info.st_ino, info.st_uid, info.st_mode) != identity:
            raise SafeError('ANCESTOR_CHANGED')


def root_directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise SafeError('SOURCE_DIRECTORY_INVALID')
    ancestors(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o7022:
        raise SafeError('SOURCE_DIRECTORY_INVALID')
    return path


@contextmanager
def opened(root, relative):
    """No-follow each parent and leaf, including an attacker-swapped directory."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = safe_relative(relative).parts
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        file = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            yield file
        finally:
            os.close(file)
    finally:
        os.close(fd)


def read_file(root, relative):
    with opened(root, relative) as fd:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o7022 or before.st_nlink != 1 or before.st_size > 128 * 1024 * 1024:
            raise SafeError('SOURCE_FILE_INVALID')
        chunks, total = [], 0
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
            total += len(chunk)
            if total > 128 * 1024 * 1024:
                raise SafeError('SOURCE_FILE_TOO_LARGE')
        if stamp(before) != stamp(os.fstat(fd)):
            raise SafeError('SOURCE_CHANGED')
        return b''.join(chunks), stamp(before)


def inspect_macho(path):
    """Static Apple tooling only; it does not load the binary or its dependencies."""
    try:
        arches = subprocess.run(['/usr/bin/lipo', '-archs', str(path)], check=True, capture_output=True, timeout=10).stdout.decode().split()
        text = subprocess.run(['/usr/bin/otool', '-l', str(path)], check=True, capture_output=True, timeout=10).stdout.decode()
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise SafeError('MACHO_INSPECTION_FAILED') from error
    if len(text) > 1024 * 1024:
        raise SafeError('MACHO_INSPECTION_FAILED')
    result = {'architectures': sorted(set(arches)), 'loads': [], 'rpaths': [], 'installIds': []}
    for block in text.split('Load command '):
        cmd = re.search(r'^\s*cmd (LC_[A-Z_]+)\s*$', block, re.M)
        if not cmd: continue
        if cmd[1] == 'LC_RPATH':
            match = re.search(r'^\s*path (.*?) \(offset ', block, re.M)
            if match: result['rpaths'].append(match[1])
        elif cmd[1] in ('LC_LOAD_DYLIB', 'LC_LOAD_WEAK_DYLIB', 'LC_REEXPORT_DYLIB', 'LC_LAZY_LOAD_DYLIB', 'LC_LOAD_UPWARD_DYLIB', 'LC_ID_DYLIB'):
            match = re.search(r'^\s*name (.*?) \(offset ', block, re.M)
            if match: result['installIds' if cmd[1] == 'LC_ID_DYLIB' else 'loads'].append(match[1])
    return {key: sorted(set(values)) for key, values in result.items()}


def system_path(value):
    # System dylibs may exist only in dyld's shared cache: lexical containment,
    # never Path.resolve(strict=True), establishes this platform-only category.
    if not value.startswith(SYSTEM): return None
    normalized = posixpath.normpath(value)
    if not normalized.startswith(SYSTEM) and normalized not in ('/usr/lib', '/System/Library'):
        raise SafeError('MACHO_SYSTEM_ESCAPE')
    return normalized


def native_closure(native, origins, python_root):
    system = set()
    admitted = {root/relative for root, relative in origins.values()}
    def expand(value, loader, source_root):
        # app/ and python/ move to different layout prefixes. Reject relative
        # @loader_path crossings; @executable_path always follows copied Python.
        component = python_root if value.startswith('@executable_path') else source_root
        value = value.replace('@loader_path', str(loader.parent)).replace('@executable_path', str(python_root/'bin'))
        path = Path(value).resolve(strict=True)
        if path != component and component not in path.parents:
            raise SafeError('MACHO_DEPENDENCY_EXTERNAL')
        return path
    for relative, record in native.items():
        if set(record) != {'architectures', 'loads', 'rpaths', 'installIds'} or any(not isinstance(values, list) or not all(isinstance(value, str) for value in values) for values in record.values()) or 'arm64' not in record['architectures']:
            raise SafeError('MACHO_INVALID')
        root, source = origins[relative]
        loader = root/source
        rpaths = record['rpaths'] + ['@executable_path/../lib']
        for rpath in record['rpaths']:
            if system_path(rpath): continue
            if not rpath.startswith(('@loader_path/', '@executable_path/')): raise SafeError('MACHO_RPATH_EXTERNAL')
            expand(rpath, loader, root)
        for dependency in record['loads']:
            platform = system_path(dependency)
            if platform: system.add(platform); continue
            if dependency.startswith('@rpath/'):
                candidates = []
                for rpath in rpaths:
                    try: candidates.append(expand(rpath+'/'+dependency[len('@rpath/'):], loader, root))
                    except FileNotFoundError: continue
            elif dependency.startswith(('@loader_path/', '@executable_path/')):
                candidates = [expand(dependency, loader, root)]
            else: raise SafeError('MACHO_DEPENDENCY_EXTERNAL')
            if not any(candidate in admitted and candidate.is_file() for candidate in candidates):
                raise SafeError('MACHO_DEPENDENCY_MISSING')
    return sorted(system)


@dataclass(frozen=True)
class Snapshot:
    document: dict
    origins: dict
    identities: dict
    options: dict
    app: Path
    python: Path

    @property
    def digest(self):
        return hashlib.sha256(canonical(self.document)).hexdigest()


def inventory(package_root, python_root, **options):
    try:
        return _inventory(package_root, python_root, **options)
    except (OSError, ValueError, RuntimeError, UnicodeError) as error:
        raise SafeError('SOURCE_SCAN_FAILED') from error


def _inventory(package_root, python_root, *, expected_distributions=None, expected_runtime=None, approved_hooks=None, macho=inspect_macho, wrapper_source=None, wrapper_sha256=None):
    app, python = root_directory(package_root), root_directory(python_root)
    if (wrapper_source is None) != (wrapper_sha256 is None): raise SafeError('WRAPPER_REVIEW_REQUIRED')
    wrapper = None
    if wrapper_source is not None:
        wrapper = Path(wrapper_source)
        if wrapper.name != 'langfuse-entry.py' or not isinstance(wrapper_sha256, str) or not re.fullmatch('[0-9a-f]{64}', wrapper_sha256): raise SafeError('WRAPPER_REVIEW_INVALID')
        root_directory(wrapper.parent)
        if wrapper.lstat().st_size > 1024*1024: raise SafeError('WRAPPER_TOO_LARGE')
    expected = DISTRIBUTIONS if expected_distributions is None else dict(expected_distributions)
    hooks = HOOKS if approved_hooks is None else dict(approved_hooks)
    runtime_expected = {'pip': '26.0.1'} if expected_runtime is None else dict(expected_runtime)
    options = dict(expected_distributions=dict(expected), expected_runtime=dict(runtime_expected), approved_hooks=dict(hooks), macho=macho, wrapper_source=wrapper, wrapper_sha256=wrapper_sha256)
    entries = [{'path': 'app', 'kind': 'directory', 'mode': 0o500}]
    origins, identities, native, distributions, runtime_distributions, dependencies = {}, {}, {}, {}, {}, {}
    total, seen = 0, 0
    for prefix, root in [('app/site-packages', app), ('python', python)]:
        for directory, dirs, files in os.walk(root, followlinks=False):
            for path in [Path(directory), *[Path(directory)/name for name in sorted(files+dirs)]]:
                relative = path.relative_to(root)
                mapped = prefix + ('/'+relative.as_posix() if relative.parts else '')
                if mapped in identities: continue
                info = path.lstat()
                name = path.name
                if name.startswith('.env') or name.endswith('.egg-link') or name.split('.')[0] in ('sitecustomize', 'usercustomize') or (name.endswith('.pth') and (prefix != 'app/site-packages' or relative.as_posix() not in hooks)):
                    raise SafeError('UNAPPROVED_SOURCE_FILE')
                if '__pycache__' in relative.parts or path.suffix == '.pyc': continue
                seen += 1
                if seen > MAX_ENTRIES: raise SafeError('SOURCE_TOO_LARGE')
                if not relative.parts:
                    entry = {'path': mapped, 'kind': 'directory', 'mode': 0o500}
                elif stat.S_ISLNK(info.st_mode):
                    if info.st_uid != os.getuid(): raise SafeError('SOURCE_LINK_INVALID')
                    target = os.readlink(path)
                    resolved = path.resolve(strict=True)
                    if Path(target).is_absolute() or root not in resolved.parents: raise SafeError('EXTERNAL_SYMLINK')
                    entry = {'path': mapped, 'kind': 'symlink', 'mode': 0o500, 'target': target}
                elif stat.S_ISDIR(info.st_mode):
                    if info.st_uid != os.getuid() or info.st_mode & 0o7022: raise SafeError('SOURCE_DIRECTORY_INVALID')
                    entry = {'path': mapped, 'kind': 'directory', 'mode': 0o500}
                elif stat.S_ISREG(info.st_mode):
                    data, identity = read_file(root, relative)
                    if stamp(info) != identity: raise SafeError('SOURCE_CHANGED')
                    total += len(data)
                    if total > MAX_BYTES: raise SafeError('SOURCE_TOO_LARGE')
                    digest = hashlib.sha256(data).hexdigest()
                    if prefix == 'app/site-packages' and relative.as_posix() in hooks and digest != hooks[relative.as_posix()]: raise SafeError('HOOK_CHANGED')
                    if expected_distributions is None and prefix == 'app/site-packages' and relative.as_posix() in REVIEWED and digest != REVIEWED[relative.as_posix()]: raise SafeError('REVIEWED_SOURCE_CHANGED')
                    if name == 'direct_url.json' and json.loads(data).get('dir_info', {}).get('editable'): raise SafeError('EDITABLE_INSTALL')
                    if relative.parts[:1] == ('bin',) and data.startswith(b'#!'):
                        if data.splitlines()[0] not in (b'#!/bin/sh', b'#!/bin/bash') or re.search(rb'/(?:Users|opt|home|install|build|private)/', data): raise SafeError('EXTERNAL_LAUNCHER')
                    entry = {'path': mapped, 'kind': 'file', 'mode': 0o500 if info.st_mode & 0o111 else 0o400, 'size': len(data), 'sha256': digest}
                    if data[:4] in MAGIC: native[mapped] = macho(path)
                    if name == 'METADATA' and path.parent.name.endswith('.dist-info'):
                        meta = BytesParser().parsebytes(data, headersonly=True)
                        if len(meta.get_all('Name', [])) != 1 or len(meta.get_all('Version', [])) != 1: raise SafeError('DISTRIBUTION_INVALID')
                        package = re.sub(r'[-_.]+', '-', meta.get('Name', '')).lower()
                        version = meta.get('Version', '')
                        selected = distributions if prefix == 'app/site-packages' else runtime_distributions
                        if not package or not version or package in selected: raise SafeError('DISTRIBUTION_INVALID')
                        selected[package] = version
                        dependencies[mapped] = sorted(set(re.match(r'[A-Za-z0-9_.-]+', value)[0].lower() for value in meta.get_all('Requires-Dist', []) if re.match(r'[A-Za-z0-9_.-]+', value)))
                else: raise SafeError('SPECIAL_SOURCE_FILE')
                entries.append(entry)
                origins[mapped] = (root, relative)
                identities[mapped] = stamp(info)
    if distributions != expected or runtime_distributions != runtime_expected: raise SafeError('DISTRIBUTION_MISMATCH')
    if wrapper is not None:
        data, identity = read_file(wrapper.parent, Path(wrapper.name))
        if hashlib.sha256(data).hexdigest() != wrapper_sha256 or b'\0' in data: raise SafeError('WRAPPER_CHANGED')
        data.decode('utf-8')
        mapped = 'manager/langfuse-entry.py'
        entries.extend([{'path': 'manager', 'kind': 'directory', 'mode': 0o500},
                        {'path': mapped, 'kind': 'file', 'mode': 0o400, 'size': len(data), 'sha256': wrapper_sha256}])
        origins[mapped] = (wrapper.parent, Path(wrapper.name))
        identities[mapped] = identity
    admitted = {entry['path']: entry for entry in entries}
    for name in ('python/bin/python3.13', 'python/lib/libpython3.13.dylib'):
        if name not in native or (name.endswith('/python3.13') and admitted[name]['mode'] != 0o500): raise SafeError('PYTHON_BINARY_MISSING')
    source_paths = {root/relative for root, relative in origins.values()}
    for entry in entries:
        if entry['kind'] == 'symlink':
            root, relative = origins[entry['path']]
            if (root/relative).resolve(strict=True) not in source_paths: raise SafeError('UNADMITTED_LINK_TARGET')
    if any('app/site-packages/'+name not in admitted for name in hooks): raise SafeError('HOOK_MISSING')
    if expected_distributions is None and any('app/site-packages/'+name not in admitted for name in REVIEWED): raise SafeError('REVIEWED_SOURCE_MISSING')
    version, _ = read_file(python, Path('include/python3.13/patchlevel.h'))
    if not re.search(rb'^#define\s+PY_VERSION\s+"3\.13\.12"', version, re.M): raise SafeError('PYTHON_VERSION_MISMATCH')
    document = {'version': 1, 'pythonVersion': '3.13.12', 'distributions': distributions, 'runtimeDistributions': runtime_distributions,
                'dependencies': dependencies, 'dependencyValidation': 'declared names only; version and marker validation pending', 'exclusions': ['__pycache__', '*.pyc'], 'entries': sorted(entries, key=lambda entry: entry['path']),
                'native': native, 'systemDependencies': native_closure(native, origins, python)}
    return Snapshot(document, origins, identities, options, app, python)


def unchanged(snapshot):
    current = inventory(snapshot.app, snapshot.python, **snapshot.options)
    if current.document != snapshot.document or current.identities != snapshot.identities:
        raise SafeError('SOURCE_CHANGED')


def verify(artifact, *, expected_digest=None):
    try:
        return _verify(artifact, expected_digest=expected_digest)
    except (OSError, ValueError, RuntimeError, UnicodeError, KeyError, TypeError) as error:
        raise SafeError('CLOSURE_INVALID') from error


def _verify(artifact, *, expected_digest=None):
    artifact = root_directory(artifact)
    data, _ = read_file(artifact, Path('closure.json'))
    if len(data) > 4 * 1024 * 1024: raise SafeError('MANIFEST_TOO_LARGE')
    document = json.loads(data)
    digest = hashlib.sha256(canonical(document)).hexdigest()
    if digest != (expected_digest or artifact.name) or data != canonical(document): raise SafeError('CLOSURE_DIGEST_MISMATCH')
    entries = document.get('entries')
    if not isinstance(entries, list): raise SafeError('CLOSURE_INVALID')
    expected = {'closure.json'}
    for entry in entries:
        relative = safe_relative(entry['path'])
        if entry['path'] in expected: raise SafeError('CLOSURE_INVALID')
        expected.add(entry['path'])
        path = artifact/relative
        info = path.lstat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != entry['mode']: raise SafeError('CLOSURE_MODE_CHANGED')
        if entry['kind'] == 'file':
            content, _ = read_file(artifact, relative)
            if len(content) != entry['size'] or hashlib.sha256(content).hexdigest() != entry['sha256']: raise SafeError('CLOSURE_FILE_CHANGED')
        elif entry['kind'] == 'directory':
            if not stat.S_ISDIR(info.st_mode): raise SafeError('CLOSURE_KIND_CHANGED')
        elif entry['kind'] == 'symlink':
            if not stat.S_ISLNK(info.st_mode) or os.readlink(path) != entry['target'] or artifact not in path.resolve(strict=True).parents: raise SafeError('CLOSURE_LINK_CHANGED')
        else: raise SafeError('CLOSURE_KIND_CHANGED')
    actual = {'closure.json'}
    for directory, dirs, files in os.walk(artifact, followlinks=False):
        actual.update((Path(directory)/name).relative_to(artifact).as_posix() for name in dirs+files)
    if actual != expected or stat.S_IMODE((artifact/'closure.json').stat().st_mode) != 0o400 or stat.S_IMODE(artifact.stat().st_mode) != 0o500: raise SafeError('CLOSURE_TREE_CHANGED')
    return document


def materialize(snapshot, parent, *, recheck=None, source_reader=None):
    # app/python are legacy names for the two generic protected source roots.
    recheck = unchanged if recheck is None else recheck
    source_reader = read_file if source_reader is None else source_reader
    parent = Path(parent)
    if parent.resolve(strict=True) != parent: raise SafeError('DESTINATION_INVALID')
    private(parent, directory=True)
    parent_identities = ancestors(parent)
    if any(parent == root or root in parent.parents for root in (snapshot.app, snapshot.python)): raise SafeError('DESTINATION_INSIDE_SOURCE')
    recheck(snapshot)
    destination = parent/snapshot.digest
    stage = Path(tempfile.mkdtemp(prefix='.langfuse-stage-', dir=parent))
    stage_identity = stamp(stage.lstat())[:2]
    published = False
    try:
        directories = []
        for entry in snapshot.document['entries']:
            relative = safe_relative(entry['path'])
            path = stage/relative
            if entry['kind'] == 'directory': path.mkdir(mode=0o700); directories.append(path)
            elif entry['kind'] == 'symlink':
                path.symlink_to(entry['target'])
                path.chmod(entry['mode'], follow_symlinks=False)
            else:
                root, source = snapshot.origins[entry['path']]
                data, identity = source_reader(root, source)
                if identity != snapshot.identities[entry['path']] or hashlib.sha256(data).hexdigest() != entry['sha256']: raise SafeError('SOURCE_CHANGED')
                write_private(path, data, exclusive=True)
                if path.stat().st_ino == identity[1] and path.stat().st_dev == identity[0]: raise SafeError('COPY_NOT_INDEPENDENT')
                path.chmod(entry['mode'])
        write_private(stage/'closure.json', canonical(snapshot.document), exclusive=True)
        (stage/'closure.json').chmod(0o400)
        for path in reversed(directories): sync_directory(path); path.chmod(0o500)
        sync_directory(stage); stage.chmod(0o500)
        verify(stage, expected_digest=snapshot.digest)
        recheck(snapshot)
        check_ancestors(parent_identities)
        if stamp(stage.lstat())[:2] != stage_identity: raise SafeError('STAGE_CHANGED')
        publish(stage, destination)
        published = True
        sync_directory(parent, require_private=True)
        verify(destination)
        return destination
    except (OSError, ValueError, RuntimeError) as error:
        raise SafeError('MATERIALIZATION_FAILED') from error
    finally:
        if not published:
            # Only our exclusive stage is writable/removed; never touch a collision.
            check_ancestors(parent_identities)
            if stamp(stage.lstat())[:2] != stage_identity: raise SafeError('STAGE_CHANGED')
            for directory, dirs, files in os.walk(stage):
                Path(directory).chmod(0o700)
            shutil.rmtree(stage)


def inventory_tree(root, prefix, *, reject_name=None, exclude_paths=(), source_reader=None):
    """Generic protected complete tree; language-specific admission stays with caller.

    Python inventory deliberately retains its original exclusions and document.
    All leaf reads share opened/read_file's no-follow and identity checks.
    """
    root = root_directory(root)
    safe_relative(prefix)
    source_reader = read_file if source_reader is None else source_reader
    exclusions = frozenset(exclude_paths)
    for excluded in exclusions: safe_relative(excluded)
    entries, origins, identities = [], {}, {}
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(directory), *[Path(directory)/name for name in sorted(dirs+files)]]:
            relative = path.relative_to(root)
            mapped = prefix + ('/'+relative.as_posix() if relative.parts else '')
            if relative.as_posix() in exclusions:
                if not stat.S_ISREG(path.lstat().st_mode): raise SafeError('EXCLUSION_NOT_REGULAR_FILE')
                continue
            if mapped in identities: continue
            if reject_name is not None and reject_name(path.name): raise SafeError('UNAPPROVED_SOURCE_FILE')
            if len(identities) >= MAX_ENTRIES: raise SafeError('SOURCE_TOO_LARGE')
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                if info.st_uid != os.getuid(): raise SafeError('SOURCE_LINK_INVALID')
                target = os.readlink(path)
                resolved = path.resolve(strict=True)
                if Path(target).is_absolute() or root not in resolved.parents: raise SafeError('EXTERNAL_SYMLINK')
                entry = dict(path=mapped, kind='symlink', mode=0o500, target=target)
            elif stat.S_ISDIR(info.st_mode):
                if info.st_uid != os.getuid() or info.st_mode & 0o7022: raise SafeError('SOURCE_DIRECTORY_INVALID')
                entry = dict(path=mapped, kind='directory', mode=0o500)
            elif stat.S_ISREG(info.st_mode):
                data, identity = source_reader(root, relative)
                if stamp(info) != identity: raise SafeError('SOURCE_CHANGED')
                total += len(data)
                if total > MAX_BYTES: raise SafeError('SOURCE_TOO_LARGE')
                entry = dict(path=mapped, kind='file', mode=0o500 if info.st_mode & 0o111 else 0o400,
                             size=len(data), sha256=hashlib.sha256(data).hexdigest())
            else: raise SafeError('SPECIAL_SOURCE_FILE')
            entries.append(entry); origins[mapped] = (root, relative); identities[mapped] = stamp(info)
    admitted = {root/relative for root, relative in origins.values()}
    for entry in entries:
        if entry['kind'] == 'symlink':
            source, relative = origins[entry['path']]
            if (source/relative).resolve(strict=True) not in admitted: raise SafeError('UNADMITTED_LINK_TARGET')
    return sorted(entries, key=lambda entry: entry['path']), origins, identities
