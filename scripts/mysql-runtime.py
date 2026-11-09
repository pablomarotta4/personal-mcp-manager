#!/usr/bin/env python3
"""Offline MySQL npm closure materializer. Never invokes npm or package code."""
import argparse
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import sys

_spec = importlib.util.spec_from_file_location('_mysql_dependencies', Path(__file__).with_name('verify-loki-dependencies.py'))
dependencies = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dependencies)
integrity = dependencies.integrity
NODE = Path.home() / '.nvm/versions/node/v25.3.0/bin/node'
NODE_SHA = '8caca2f5548d6f5359a817a73fcc307d66033846d1917647c9560e838621ecb2'
CACHE = Path.home() / '.npm/_npx/57e5b9c57ed85305/node_modules'
PINS = Path(__file__).resolve().parent.parent / 'docs/evidence/2026-10-15-mysql-npm-pins.json'
WRAPPER = Path(__file__).with_name('mysql-entry.mjs')
ESBUILD_SHA = 'b82c6243eb58d520d0bc55cddcf6993dd0f5572f3ab8dc2ba6d77058be043e62'
FSEVENTS_SHA = '40f2f51199e4f5fc46fa6b985fb3461bb63e6cd86c62bfa9bcee45ed4438d5fb'
ESBUILD_PATHS = frozenset({'esbuild/bin/esbuild', '@esbuild/darwin-arm64/bin/esbuild'})
SYSTEM_LOADS = sorted(['/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation', '/System/Library/Frameworks/Security.framework/Versions/A/Security', '/usr/lib/libSystem.B.dylib', '/usr/lib/libc++.1.dylib'])


def credential_name(name):
    return name.startswith('.env') or name in {'.npmrc', '.my.cnf'}


def satisfies(version, expression):
    # Exact reviewed prerelease in formdata-node's mandatory dependency. Existing
    # semver helper intentionally handles only stable numeric versions.
    if version == '4.0.0-beta.3' or expression == '4.0.0-beta.3':
        return version == expression
    if expression == '*':
        return dependencies.numeric(version)[1] == 3
    if expression == '^18 || ^19 || ^19.0.0-rc':
        # No React package is installed in this closure; this optional peer is
        # recorded absent. A future present prerelease must be reviewed separately.
        return dependencies.satisfies(version, '^18 || ^19')
    return dependencies.satisfies(version, expression)


def dependency_report(root):
    packages = {}
    for path in dependencies.package_paths(root):
        metadata, _ = integrity.read_file(root, Path(path) / 'package.json')
        meta = json.loads(metadata)
        name, version = meta['name'], meta['version']
        if path.split('/node_modules/')[-1] != name:
            raise integrity.SafeError('MYSQL_PACKAGE_IDENTITY_INVALID')
        if version != '4.0.0-beta.3' and dependencies.numeric(version)[1] != 3:
            raise integrity.SafeError('MYSQL_PACKAGE_VERSION_INVALID')
        packages[path] = dict(name=name, version=version, metadataSha256=hashlib.sha256(metadata).hexdigest(), dependencies=[], _metadata=meta)
    for path, record in packages.items():
        meta = record.pop('_metadata')
        optional = meta.get('optionalDependencies', {})
        for kind, declared in [('mandatory', meta.get('dependencies', {})), ('optional', optional), ('peer', meta.get('peerDependencies', {}))]:
            for name, requested in sorted(declared.items()):
                if kind == 'mandatory' and name in optional:
                    continue
                candidate, resolved = Path(path), None
                while True:
                    location = (candidate / 'node_modules' / name).as_posix()
                    if location in packages:
                        resolved = location
                        break
                    if candidate == Path('.'):
                        break
                    candidate = candidate.parent
                if resolved is None and name in packages:
                    resolved = name
                allowed_absent = kind == 'optional' or (kind == 'peer' and meta.get('peerDependenciesMeta', {}).get(name, {}).get('optional') is True)
                if resolved is None and not allowed_absent:
                    raise integrity.SafeError('MYSQL_DEPENDENCY_MISSING')
                if resolved is not None and not satisfies(packages[resolved]['version'], requested):
                    raise integrity.SafeError('MYSQL_DEPENDENCY_VERSION_MISMATCH')
                record['dependencies'].append(dict(name=name, kind=kind, requested=requested, resolvedPath=resolved, resolvedVersion=packages[resolved]['version'] if resolved else None, outcome='resolved' if resolved else 'absent-optional'))
    return dict(version=1, validation='mysql-static-reviewed-semver-no-execution', packages=packages)


def source_read(root, relative):
    if relative.as_posix() not in ESBUILD_PATHS:
        return integrity.read_file(root, relative)
    with integrity.opened(root, relative) as fd:
        before = os.fstat(fd)
        # The historical npm-cache source is an exact hardlink pair. A clean
        # standalone install is independently extracted from a registry-pinned
        # tarball, so its matching reviewed binary is expected to have one link.
        # This exception remains limited to these two paths and the exact bytes.
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o7022 or before.st_size > 16 * 1024 * 1024 or before.st_nlink not in (1, 2):
            raise integrity.SafeError('MYSQL_ESBUILD_SOURCE_INVALID')
        chunks = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        data = b''.join(chunks)
        if integrity.stamp(before) != integrity.stamp(os.fstat(fd)) or hashlib.sha256(data).hexdigest() != ESBUILD_SHA:
            raise integrity.SafeError('MYSQL_ESBUILD_SOURCE_DRIFT')
        os.lseek(fd, 0, os.SEEK_SET)
        repeated = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            repeated.update(chunk)
        if repeated.hexdigest() != ESBUILD_SHA or integrity.stamp(before) != integrity.stamp(os.fstat(fd)):
            raise integrity.SafeError('MYSQL_ESBUILD_SOURCE_DRIFT')
        return data, integrity.stamp(before)


def tree(root):
    return integrity.inventory_tree(root, 'app/node_modules', reject_name=credential_name, exclude_paths=('@benborla29/mcp-server-mysql/dist/.env',), source_reader=source_read)


def inventory(root=CACHE, node=NODE, wrapper=WRAPPER, *, pins=None):
    root = integrity.root_directory(root)
    runtime = integrity.root_directory(Path(node).parent)
    pins = json.loads(PINS.read_bytes()) if pins is None else pins
    entries, origins, identities = tree(root)
    report = dependency_report(root)
    wrapper_data, wrapper_id = integrity.read_file(wrapper.parent, Path(wrapper.name))
    node_data, node_id = integrity.read_file(runtime, Path('node'))
    native = integrity.inspect_macho(node)
    if (entries != pins['entries'] or report != pins['dependencyReport'] or hashlib.sha256(wrapper_data).hexdigest() != pins['wrapperSha256']
            or hashlib.sha256(node_data).hexdigest() != NODE_SHA or native['architectures'] != ['arm64'] or native['rpaths'] or native['installIds'] or sorted(native['loads']) != SYSTEM_LOADS):
        raise integrity.SafeError('MYSQL_CLOSURE_SOURCE_DRIFT')
    native_entries = {'runtime/bin/node': native}
    system_dependencies = set(SYSTEM_LOADS)
    for entry in entries:
        if entry['kind'] != 'file':
            continue
        source, relative = origins[entry['path']]
        data, identity = source_read(source, relative)
        if data[:4] in integrity.MAGIC:
            edge = integrity.inspect_macho(source / relative)
            if relative.as_posix() in ESBUILD_PATHS and hashlib.sha256(data).hexdigest() == ESBUILD_SHA:
                expected = sorted([item for item in SYSTEM_LOADS if item != '/usr/lib/libc++.1.dylib'] + ['/usr/lib/libresolv.9.dylib'])
                architectures = ['arm64']
            elif relative.as_posix() == 'fsevents/fsevents.node' and hashlib.sha256(data).hexdigest() == FSEVENTS_SHA:
                expected = sorted([item for item in SYSTEM_LOADS if item != '/System/Library/Frameworks/Security.framework/Versions/A/Security'] + ['/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices'])
                architectures = ['arm64', 'x86_64']
            else:
                raise integrity.SafeError('MYSQL_NATIVE_EDGE_UNREVIEWED')
            if edge['architectures'] != architectures or edge['rpaths'] or edge['installIds'] or sorted(edge['loads']) != expected:
                raise integrity.SafeError('MYSQL_NATIVE_EDGE_CHANGED')
            native_entries[entry['path']] = edge
            system_dependencies.update(expected)
        if identity != identities[entry['path']] or data.startswith((b'\x7fELF', b'MZ')):
            raise integrity.SafeError('MYSQL_NATIVE_EDGE_UNREVIEWED')
    entries += [dict(path=name, kind='directory', mode=0o500) for name in ('app', 'manager', 'runtime', 'runtime/bin')]
    for mapped, content, identity, source, relative, mode in [
        ('manager/mysql-entry.mjs', wrapper_data, wrapper_id, wrapper.parent, Path(wrapper.name), 0o400),
        ('runtime/bin/node', node_data, node_id, runtime, Path('node'), 0o500),
    ]:
        entries.append(dict(path=mapped, kind='file', mode=mode, size=len(content), sha256=hashlib.sha256(content).hexdigest()))
        origins[mapped], identities[mapped] = (source, relative), identity
    document = dict(version=1, runtime='node', entries=sorted(entries, key=lambda item: item['path']), native=native_entries, systemDependencies=sorted(system_dependencies),
                    dependencyReport=report, dependencyReportDigest=hashlib.sha256(integrity.canonical(report)).hexdigest())
    return integrity.Snapshot(document, origins, identities, dict(pins=pins, node=node, wrapper=wrapper), root, runtime)


def unchanged(snapshot):
    current = inventory(snapshot.app, **snapshot.options)
    if current.document != snapshot.document or current.identities != snapshot.identities:
        raise integrity.SafeError('MYSQL_CLOSURE_SOURCE_DRIFT')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        snapshot = inventory()
        target = integrity.materialize(snapshot, Path(args.output), recheck=unchanged, source_reader=source_read)
        print(json.dumps(dict(status='MATERIALIZED', root=str(target), digest=snapshot.digest,
                              dependencyReportSha256=snapshot.document['dependencyReportDigest'])))
        return 0
    except Exception:
        print('MYSQL_MATERIALIZATION_FAILED', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
